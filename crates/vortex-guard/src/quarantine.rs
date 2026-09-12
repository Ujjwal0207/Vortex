use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedEvent {
    pub topic: String,
    pub timestamp: u64,
    pub reason: String,
    pub key_hex: Option<String>,
    pub payload_preview: String,
}

impl QuarantinedEvent {
    pub fn new(topic: &str, reason: &str, key: Option<&Bytes>, value: &Bytes) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let key_hex = key.map(|k| format!("0x{}", hex::encode(k)));
        let preview_len = value.len().min(128);
        let payload_preview = String::from_utf8_lossy(&value[..preview_len]).to_string();

        Self {
            topic: topic.to_string(),
            timestamp,
            reason: reason.to_string(),
            key_hex,
            payload_preview,
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let json = serde_json::to_vec(self).unwrap_or_default();
        Bytes::from(json)
    }
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
