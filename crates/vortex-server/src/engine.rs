use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use tokio::sync::RwLock;
use tracing::{info, warn};

use vortex_core::error::Result;
use vortex_guard::{IngressValidator, QuarantinedEvent, ValidationConfig};
use vortex_protocol::{
    CreateTopicRequest, CreateTopicResponse, ErrorResponse, FetchRequest, FetchResponse, Frame,
    ProduceRequest, ProduceResponse,
};
use vortex_storage::{check_ingress_watermark, PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

pub struct Engine {
    data_dir: PathBuf,
    validator: IngressValidator,
    partitions: RwLock<HashMap<(String, u32), Arc<RwLock<PartitionLog>>>>,
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
        if let Err(e) = self.validator.validate(&req.topic, req.key.as_ref(), &req.value) {
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

        // 2. Fetch or create partition log
        let partition = self.get_or_create_partition(&req.topic, req.partition).await?;
        let mut log = partition.write().await;

        // 3. Append to partition
        let record = log.append(req.key, req.value)?;

        Ok(ProduceResponse {
            offset: record.offset,
            timestamp: record.timestamp,
            record_hash: record.record_hash,
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

        for (key, value, _) in &records {
            if let Err(error) = self.validator.validate(topic, key.as_ref(), value) {
                warn!("Poison pill rejected on topic '{}': {}", topic, error);
                let quarantined = QuarantinedEvent::new(topic, &error.to_string(), key.as_ref(), value);
                self.route_to_quarantine(quarantined).await?;
                return Err(error);
            }
        }

        let partition = self.get_or_create_partition(topic, partition_id).await?;
        let mut log = partition.write().await;
        let records = log.append_batch(records)?;
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
        let log = partition.read().await;

        let records = log.read(req.start_offset, req.max_bytes as usize)?;
        Ok(FetchResponse { records })
    }

    /// Returns retained and next offsets without reading record payloads.
    pub async fn partition_bounds(&self, topic: &str, partition_id: u32) -> Result<(u64, u64)> {
        let partition = self.get_or_create_partition(topic, partition_id).await?;
        let log = partition.read().await;
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
        let mut log = partition.write().await;
        log.append(None, event.to_bytes())?;
        Ok(())
    }

    async fn get_or_create_partition(
        &self,
        topic: &str,
        partition_id: u32,
    ) -> Result<Arc<RwLock<PartitionLog>>> {
        let key = (topic.to_string(), partition_id);

        // Fast path: concurrent read lock for existing partitions
        {
            let parts = self.partitions.read().await;
            if let Some(part) = parts.get(&key) {
                return Ok(Arc::clone(part));
            }
        }

        // Slow path: write lock to initialize and insert new partition log
        let mut parts = self.partitions.write().await;
        if let Some(part) = parts.get(&key) {
            return Ok(Arc::clone(part));
        }

        let log = PartitionLog::open_or_create(
            &self.data_dir,
            topic,
            partition_id,
            DEFAULT_MAX_SEGMENT_BYTES,
        )?;

        let shared = Arc::new(RwLock::new(log));
        parts.insert(key, Arc::clone(&shared));
        Ok(shared)
    }

    fn error_frame(req_id: u32, code: u16, message: String) -> Frame {
        ErrorResponse { code, message }.encode(req_id)
    }
}
