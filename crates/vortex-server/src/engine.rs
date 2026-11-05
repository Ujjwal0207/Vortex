use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use tokio::sync::RwLock;
use tracing::{info, warn};

use vortex_core::error::Result;
use vortex_guard::{IngressValidator, QuarantinedEvent, ValidationConfig, ValidationOutcome};
use vortex_protocol::{
    CreateTopicRequest, CreateTopicResponse, ErrorResponse, FetchRequest, FetchResponse, Frame,
    ProduceRequest, ProduceResponse,
};
use vortex_storage::{check_ingress_watermark, AdaptiveLingerQueue, PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

#[derive(Clone)]
pub struct PartitionHandle {
    pub log: Arc<RwLock<PartitionLog>>,
    pub linger: AdaptiveLingerQueue,
}

pub struct Engine {
    data_dir: PathBuf,
    validator: IngressValidator,
    partitions: RwLock<HashMap<(String, u32), PartitionHandle>>,
    #[allow(dead_code)]
    pub reactor: crate::reactor::PartitionAffinityRouter,
}

impl Engine {
    pub fn new(data_dir: PathBuf) -> Self {
        let validator = IngressValidator::new(ValidationConfig::default());
        let num_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let reactor = crate::reactor::PartitionAffinityRouter::new(num_workers, 1024);
        Self {
            data_dir,
            validator,
            partitions: RwLock::new(HashMap::new()),
            reactor,
        }
    }

    /// Returns a reference to the partition affinity reactor router.
    #[allow(dead_code)]
    pub fn reactor(&self) -> &crate::reactor::PartitionAffinityRouter {
        &self.reactor
    }

    /// Dispatches a partition task with CPU cache affinity via the reactor router (Flaw 6.4).
    #[allow(dead_code)]
    pub async fn dispatch_on_partition<F, R>(&self, topic: &str, partition: u32, op: F) -> Result<R>
    where
        F: FnOnce() -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        self.reactor.dispatch(topic, partition, op).await
    }

    /// Handles a raw client frame and produces an appropriate response frame.
    pub async fn handle_frame(&self, frame: Frame) -> Frame {
        let req_id = frame.req_id;
        let mut payload = frame.payload;

        match frame.msg_type {
            vortex_protocol::MessageType::ProduceReq => {
                match ProduceRequest::decode(&mut payload) {
                    Ok(req) => match self.produce(req).await {
                        Ok(resp) => resp.encode(req_id),
                        Err(e) => Self::error_frame(req_id, 400, e.to_string()),
                    },
                    Err(e) => Self::error_frame(req_id, 400, format!("Malformed produce payload: {}", e)),
                }
            }
            vortex_protocol::MessageType::FetchReq => {
                match FetchRequest::decode(&mut payload) {
                    Ok(req) => match self.fetch(req).await {
                        Ok(resp) => resp.encode(req_id),
                        Err(e) => Self::error_frame(req_id, 400, e.to_string()),
                    },
                    Err(e) => Self::error_frame(req_id, 400, format!("Malformed fetch payload: {}", e)),
                }
            }
            vortex_protocol::MessageType::CreateTopicReq => {
                match CreateTopicRequest::decode(&mut payload) {
                    Ok(req) => match self.create_topic(&req.topic, req.partitions).await {
                        Ok(resp) => resp.encode(req_id),
                        Err(e) => Self::error_frame(req_id, 500, e.to_string()),
                    },
                    Err(e) => Self::error_frame(req_id, 400, format!("Malformed create topic payload: {}", e)),
                }
            }
            _ => Self::error_frame(req_id, 405, "Unsupported message type".to_string()),
        }
    }

    pub async fn produce(&self, req: ProduceRequest) -> Result<ProduceResponse> {
        // 0. Proactive storage watermark fencing (Gap 9): reject writes if disk usage >= 92%
        check_ingress_watermark(&self.data_dir)?;

        // 1. Ingress validation & Poison-Pill Quarantine check
        let final_value = match self.validator.validate_outcome(&req.topic, req.key.as_ref(), &req.value) {
            Ok(ValidationOutcome::Allowed) => req.value,
            Ok(ValidationOutcome::Sanitized(clean)) => clean,
            Err(e) => {
                warn!("Poison pill rejected on topic '{}': {}", req.topic, e);
                // Route to quarantine
                let quarantined = QuarantinedEvent::new(
                    &req.topic,
                    &e.to_string(),
                    req.key.as_ref(),
                    &req.value,
                );
                self.route_to_quarantine(quarantined).await?;
                return Err(e);
            }
        };

        // 2. Fetch or create partition log and submit via adaptive linger queue
        let partition = self.get_or_create_partition(&req.topic, req.partition).await?;
        let append_res = partition.linger.submit(req.key, final_value, None).await?;

        Ok(ProduceResponse {
            offset: append_res.record.offset,
            timestamp: append_res.record.timestamp,
            record_hash: append_res.record.record_hash,
        })
    }

    /// Validates every record before appending any of them. This prevents a
    /// later policy rejection from leaving the accepted prefix of a Kafka batch
    /// in the user partition.
    pub async fn produce_batch(
        &self,
        topic: &str,
        partition_id: u32,
        records: Vec<(Option<Bytes>, Bytes, Option<u64>)>,
    ) -> Result<Vec<ProduceResponse>> {
        check_ingress_watermark(&self.data_dir)?;

        let mut validated_records = Vec::with_capacity(records.len());
        for (key, value, ts) in records {
            match self.validator.validate_outcome(topic, key.as_ref(), &value) {
                Ok(ValidationOutcome::Allowed) => {
                    validated_records.push((key, value, ts));
                }
                Ok(ValidationOutcome::Sanitized(clean)) => {
                    validated_records.push((key, clean, ts));
                }
                Err(error) => {
                    warn!("Poison pill rejected on topic '{}': {}", topic, error);
                    let quarantined = QuarantinedEvent::new(topic, &error.to_string(), key.as_ref(), &value);
                    self.route_to_quarantine(quarantined).await?;
                    return Err(error);
                }
            }
        }

        let partition = self.get_or_create_partition(topic, partition_id).await?;
        let mut log = partition.log.write().await;
        let records = log.append_batch(validated_records)?;
        let responses = records
            .into_iter()
            .map(|record| ProduceResponse {
                offset: record.offset,
                timestamp: record.timestamp,
                record_hash: record.record_hash,
            })
            .collect();
        Ok(responses)
    }

    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResponse> {
        let partition = self.get_or_create_partition(&req.topic, req.partition).await?;
        let log = partition.log.read().await;

        let records = log.read(req.start_offset, req.max_bytes as usize)?;
        Ok(FetchResponse { records })
    }

    /// Returns retained and next offsets without reading record payloads.
    pub async fn partition_bounds(&self, topic: &str, partition_id: u32) -> Result<(u64, u64)> {
        let partition = self.get_or_create_partition(topic, partition_id).await?;
        let log = partition.log.read().await;
        Ok((log.earliest_offset(), log.next_offset()))
    }

    pub async fn create_topic(&self, topic: &str, partitions: u32) -> Result<CreateTopicResponse> {
        for p in 0..partitions {
            self.get_or_create_partition(topic, p).await?;
        }
        info!("Created topic '{}' with {} partitions", topic, partitions);
        Ok(CreateTopicResponse { success: true })
    }

    async fn route_to_quarantine(&self, event: QuarantinedEvent) -> Result<()> {
        let quarantine_topic = format!("{}.__quarantine", event.topic);
        let partition = self.get_or_create_partition(&quarantine_topic, 0).await?;
        let _ = partition.linger.submit(None, event.to_bytes(), None).await?;
        Ok(())
    }

    async fn get_or_create_partition(
        &self,
        topic: &str,
        partition_id: u32,
    ) -> Result<PartitionHandle> {
        let key = (topic.to_string(), partition_id);

        // Fast path: concurrent read lock for existing partitions
        {
            let parts = self.partitions.read().await;
            if let Some(part) = parts.get(&key) {
                return Ok(part.clone());
            }
        }

        // Slow path: write lock to initialize and insert new partition log
        let mut parts = self.partitions.write().await;
        if let Some(part) = parts.get(&key) {
            return Ok(part.clone());
        }

        let log = PartitionLog::open_or_create(
            &self.data_dir,
            topic,
            partition_id,
            DEFAULT_MAX_SEGMENT_BYTES,
        )?;

        let shared = Arc::new(RwLock::new(log));
        let linger = AdaptiveLingerQueue::from_shared(
            Arc::clone(&shared),
            std::time::Duration::from_millis(2),
            1000,
            64 * 1024,
        );

        let handle = PartitionHandle {
            log: shared,
            linger,
        };

        parts.insert(key, handle.clone());
        Ok(handle)
    }

    fn error_frame(req_id: u32, code: u16, message: String) -> Frame {
        ErrorResponse { code, message }.encode(req_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_engine_dispatch_on_partition_affinity() {
        let dir = tempdir().unwrap();
        let engine = Engine::new(dir.path().to_path_buf());

        let res = engine
            .dispatch_on_partition("orders", 0, || {
                Ok(42u64)
            })
            .await
            .unwrap();

        assert_eq!(res, 42);
    }
}
