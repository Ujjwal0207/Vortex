use bytes::{Buf, BufMut, Bytes, BytesMut};
use vortex_core::{error::Result, record::Record, HashDigest, VortexError};

use crate::frame::{Frame, MessageType};

// --- PRODUCE REQUEST & RESPONSE ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceRequest {
    pub topic: String,
    pub partition: u32,
    pub key: Option<Bytes>,
    pub value: Bytes,
}

impl ProduceRequest {
    pub fn encode(&self, req_id: u32) -> Frame {
        let topic_bytes = self.topic.as_bytes();
        let mut buf = BytesMut::new();
        buf.put_u16(topic_bytes.len() as u16);
        buf.put_slice(topic_bytes);
        buf.put_u32(self.partition);

        if let Some(ref k) = self.key {
            buf.put_i32(k.len() as i32);
            buf.put_slice(k);
        } else {
            buf.put_i32(-1);
        }

        buf.put_u32(self.value.len() as u32);
        buf.put_slice(&self.value);

        Frame::new(MessageType::ProduceReq, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        if payload.remaining() < 2 {
            return Err(VortexError::BufferUnderflow { needed: 2, available: payload.remaining() });
        }
        let topic_len = payload.get_u16() as usize;
        if payload.remaining() < topic_len + 4 + 4 + 4 {
            return Err(VortexError::BufferUnderflow { needed: topic_len + 12, available: payload.remaining() });
        }

        let topic = String::from_utf8(payload.copy_to_bytes(topic_len).to_vec())
            .map_err(|e| VortexError::Io(e.to_string()))?;
        let partition = payload.get_u32();

        let key_len = payload.get_i32();
        let key = if key_len >= 0 {
            Some(payload.copy_to_bytes(key_len as usize))
        } else {
            None
        };

        let val_len = payload.get_u32() as usize;
        let value = payload.copy_to_bytes(val_len);

        Ok(Self {
            topic,
            partition,
            key,
            value,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceResponse {
    pub offset: u64,
    pub timestamp: u64,
    pub record_hash: HashDigest,
}

impl ProduceResponse {
    pub fn encode(&self, req_id: u32) -> Frame {
        let mut buf = BytesMut::with_capacity(8 + 8 + 32);
        buf.put_u64(self.offset);
        buf.put_u64(self.timestamp);
        buf.put_slice(&self.record_hash);
        Frame::new(MessageType::ProduceResp, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        if payload.remaining() < 8 + 8 + 32 {
            return Err(VortexError::BufferUnderflow { needed: 48, available: payload.remaining() });
        }

        let offset = payload.get_u64();
        let timestamp = payload.get_u64();
        let mut record_hash = [0u8; 32];
        payload.copy_to_slice(&mut record_hash);

        Ok(Self {
            offset,
            timestamp,
            record_hash,
        })
    }
}

// --- FETCH REQUEST & RESPONSE ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub topic: String,
    pub partition: u32,
    pub start_offset: u64,
    pub max_bytes: u32,
}

impl FetchRequest {
    pub fn encode(&self, req_id: u32) -> Frame {
        let topic_bytes = self.topic.as_bytes();
        let mut buf = BytesMut::new();
        buf.put_u16(topic_bytes.len() as u16);
        buf.put_slice(topic_bytes);
        buf.put_u32(self.partition);
        buf.put_u64(self.start_offset);
        buf.put_u32(self.max_bytes);
        Frame::new(MessageType::FetchReq, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        if payload.remaining() < 2 {
            return Err(VortexError::BufferUnderflow { needed: 2, available: payload.remaining() });
        }
        let topic_len = payload.get_u16() as usize;
        if payload.remaining() < topic_len + 4 + 8 + 4 {
            return Err(VortexError::BufferUnderflow { needed: topic_len + 16, available: payload.remaining() });
        }

        let topic = String::from_utf8(payload.copy_to_bytes(topic_len).to_vec())
            .map_err(|e| VortexError::Io(e.to_string()))?;
        let partition = payload.get_u32();
        let start_offset = payload.get_u64();
        let max_bytes = payload.get_u32();

        Ok(Self {
            topic,
            partition,
            start_offset,
            max_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub records: Vec<Record>,
}

impl FetchResponse {
    pub fn encode(&self, req_id: u32) -> Frame {
        let mut buf = BytesMut::new();
        buf.put_u32(self.records.len() as u32);
        for rec in &self.records {
            buf.extend_from_slice(&rec.encode());
        }
        Frame::new(MessageType::FetchResp, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        if payload.remaining() < 4 {
            return Err(VortexError::BufferUnderflow { needed: 4, available: payload.remaining() });
        }

        let count = payload.get_u32() as usize;
        let mut records = Vec::with_capacity(count);

        for _ in 0..count {
            let rec = Record::decode(payload)?;
            records.push(rec);
        }

        Ok(Self { records })
    }
}

// --- CREATE TOPIC ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTopicRequest {
    pub topic: String,
    pub partitions: u32,
}

impl CreateTopicRequest {
    pub fn encode(&self, req_id: u32) -> Frame {
        let topic_bytes = self.topic.as_bytes();
        let mut buf = BytesMut::new();
        buf.put_u16(topic_bytes.len() as u16);
        buf.put_slice(topic_bytes);
        buf.put_u32(self.partitions);
        Frame::new(MessageType::CreateTopicReq, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        let topic_len = payload.get_u16() as usize;
        let topic = String::from_utf8(payload.copy_to_bytes(topic_len).to_vec())
            .map_err(|e| VortexError::Io(e.to_string()))?;
        let partitions = payload.get_u32();
        Ok(Self { topic, partitions })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTopicResponse {
    pub success: bool,
}

impl CreateTopicResponse {
    pub fn encode(&self, req_id: u32) -> Frame {
        let mut buf = BytesMut::with_capacity(1);
        buf.put_u8(if self.success { 1 } else { 0 });
        Frame::new(MessageType::CreateTopicResp, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        let success = payload.get_u8() == 1;
        Ok(Self { success })
    }
}

// --- ERROR RESPONSE ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    pub code: u16,
    pub message: String,
}

impl ErrorResponse {
    pub fn encode(&self, req_id: u32) -> Frame {
        let msg_bytes = self.message.as_bytes();
        let mut buf = BytesMut::new();
        buf.put_u16(self.code);
        buf.put_u16(msg_bytes.len() as u16);
        buf.put_slice(msg_bytes);
        Frame::new(MessageType::ErrorResp, req_id, buf.freeze())
    }

    pub fn decode(payload: &mut impl Buf) -> Result<Self> {
        let code = payload.get_u16();
        let msg_len = payload.get_u16() as usize;
        let message = String::from_utf8(payload.copy_to_bytes(msg_len).to_vec())
            .map_err(|e| VortexError::Io(e.to_string()))?;
        Ok(Self { code, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_produce_request_response_roundtrip() {
        let req = ProduceRequest {
            topic: "financial-stream".to_string(),
            partition: 3,
            key: Some(Bytes::from_static(b"k1")),
            value: Bytes::from_static(b"v1"),
        };

        let frame = req.encode(101);
        let mut payload = frame.payload;
        let decoded = ProduceRequest::decode(&mut payload).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_fetch_request_roundtrip() {
        let req = FetchRequest {
            topic: "logs".to_string(),
            partition: 0,
            start_offset: 1050,
            max_bytes: 65536,
        };

        let frame = req.encode(102);
        let mut payload = frame.payload;
        let decoded = FetchRequest::decode(&mut payload).unwrap();
        assert_eq!(req, decoded);
    }
}
