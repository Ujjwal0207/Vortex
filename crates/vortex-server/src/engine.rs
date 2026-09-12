use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use vortex_core::error::Result;
use vortex_guard::{IngressValidator, QuarantinedEvent, ValidationConfig};
use vortex_protocol::{
    CreateTopicRequest, CreateTopicResponse, ErrorResponse, FetchRequest, FetchResponse, Frame,
    ProduceRequest, ProduceResponse,
};
use vortex_storage::{PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

pub struct Engine {
    data_dir: PathBuf,
    validator: IngressValidator,
    partitions: Mutex<HashMap<(String, u32), Arc<Mutex<PartitionLog>>>>,
}

impl Engine {
    pub fn new(data_dir: PathBuf) -> Self {
        let validator = IngressValidator::new(ValidationConfig::default());
        Self {
            data_dir,
            validator,
            partitions: Mutex::new(HashMap::new()),
        }
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
        let mut log = partition.lock().await;

        // 3. Append to partition
        let record = log.append(req.key, req.value)?;

        Ok(ProduceResponse {
            offset: record.offset,
            timestamp: record.timestamp,
            record_hash: record.record_hash,
        })
    }

    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResponse> {
        let partition = self.get_or_create_partition(&req.topic, req.partition).await?;
        let mut log = partition.lock().await;

        let records = log.read(req.start_offset, req.max_bytes as usize)?;
        Ok(FetchResponse { records })
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
        let mut log = partition.lock().await;
        log.append(None, event.to_bytes())?;
        Ok(())
    }

    async fn get_or_create_partition(
        &self,
        topic: &str,
        partition_id: u32,
    ) -> Result<Arc<Mutex<PartitionLog>>> {
        let mut parts = self.partitions.lock().await;
        let key = (topic.to_string(), partition_id);

        if let Some(part) = parts.get(&key) {
            return Ok(Arc::clone(part));
        }

        let log = PartitionLog::open_or_create(
            &self.data_dir,
            topic,
            partition_id,
            DEFAULT_MAX_SEGMENT_BYTES,
        )?;

        let shared = Arc::new(Mutex::new(log));
        parts.insert(key, Arc::clone(&shared));
        Ok(shared)
    }

    fn error_frame(req_id: u32, code: u16, message: String) -> Frame {
        ErrorResponse { code, message }.encode(req_id)
    }
}
