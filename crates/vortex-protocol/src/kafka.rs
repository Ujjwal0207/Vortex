use bytes::{Buf, BufMut, Bytes, BytesMut};
use vortex_core::error::{Result, VortexError};

/// Standard Kafka API Keys supported by Vortex-Bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KafkaApiKey {
    Produce,
    Fetch,
    ListOffsets,
    Metadata,
    OffsetCommit,
    OffsetFetch,
    FindCoordinator,
    JoinGroup,
    Heartbeat,
    LeaveGroup,
    SyncGroup,
    ApiVersions,
    InitProducerId,
    Unknown(i16),
}

impl From<i16> for KafkaApiKey {
    fn from(v: i16) -> Self {
        match v {
            0 => KafkaApiKey::Produce,
            1 => KafkaApiKey::Fetch,
            2 => KafkaApiKey::ListOffsets,
            3 => KafkaApiKey::Metadata,
            8 => KafkaApiKey::OffsetCommit,
            9 => KafkaApiKey::OffsetFetch,
            10 => KafkaApiKey::FindCoordinator,
            11 => KafkaApiKey::JoinGroup,
            12 => KafkaApiKey::Heartbeat,
            13 => KafkaApiKey::LeaveGroup,
            14 => KafkaApiKey::SyncGroup,
            18 => KafkaApiKey::ApiVersions,
            22 => KafkaApiKey::InitProducerId,
            other => KafkaApiKey::Unknown(other),
        }
    }
}

impl From<KafkaApiKey> for i16 {
    fn from(k: KafkaApiKey) -> Self {
        match k {
            KafkaApiKey::Produce => 0,
            KafkaApiKey::Fetch => 1,
            KafkaApiKey::ListOffsets => 2,
            KafkaApiKey::Metadata => 3,
            KafkaApiKey::OffsetCommit => 8,
            KafkaApiKey::OffsetFetch => 9,
            KafkaApiKey::FindCoordinator => 10,
            KafkaApiKey::JoinGroup => 11,
            KafkaApiKey::Heartbeat => 12,
            KafkaApiKey::LeaveGroup => 13,
            KafkaApiKey::SyncGroup => 14,
            KafkaApiKey::ApiVersions => 18,
            KafkaApiKey::InitProducerId => 22,
            KafkaApiKey::Unknown(k) => k,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaRequestHeader {
    pub api_key: KafkaApiKey,
    pub api_version: i16,
    pub correlation_id: i32,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KafkaFrame {
    pub header: KafkaRequestHeader,
    pub payload: Bytes,
}

impl KafkaFrame {
    /// Decodes a complete Kafka frame from `buf` if enough bytes are present.
    /// Format: [Size: 4B][ApiKey: 2B][ApiVersion: 2B][CorrelationId: 4B][ClientId: String][Payload]
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.len() < 4 {
            return Ok(None);
        }

        let total_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + total_size {
            return Ok(None);
        }

        // Consume 4-byte size header
        buf.advance(4);
        let mut frame_bytes = buf.split_to(total_size).freeze();

        if frame_bytes.len() < 8 {
            return Err(VortexError::BufferUnderflow {
                needed: 8,
                available: frame_bytes.len(),
            });
        }

        let api_key = KafkaApiKey::from(frame_bytes.get_i16());
        let api_version = frame_bytes.get_i16();
        let correlation_id = frame_bytes.get_i32();

        // Decode nullable client_id string
        let client_id = if frame_bytes.remaining() >= 2 {
            let str_len = frame_bytes.get_i16();
            if str_len > 0 && frame_bytes.remaining() >= str_len as usize {
                let s_bytes = frame_bytes.copy_to_bytes(str_len as usize);
                String::from_utf8(s_bytes.to_vec()).ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok(Some(Self {
            header: KafkaRequestHeader {
                api_key,
                api_version,
                correlation_id,
                client_id,
            },
            payload: frame_bytes,
        }))
    }

    /// Wraps response payload with standard Kafka response envelope: [Size: 4B][CorrelationId: 4B][Payload]
    pub fn build_response(correlation_id: i32, payload: Bytes) -> Bytes {
        let total_size = 4 + payload.len() as i32;
        let mut buf = BytesMut::with_capacity(4 + 4 + payload.len());
        buf.put_i32(total_size);
        buf.put_i32(correlation_id);
        buf.put_slice(&payload);
        buf.freeze()
    }
}

/// Variable-length integer codec for Kafka RecordBatch (v2 format).
pub struct Varint;

impl Varint {
    pub fn put_uvarint(buf: &mut BytesMut, mut val: u64) {
        while val >= 0x80 {
            buf.put_u8(((val & 0x7F) | 0x80) as u8);
            val >>= 7;
        }
        buf.put_u8(val as u8);
    }

    pub fn put_varint(buf: &mut BytesMut, val: i64) {
        let zigzag = ((val << 1) ^ (val >> 63)) as u64;
        Self::put_uvarint(buf, zigzag);
    }

    pub fn get_uvarint<B: Buf>(buf: &mut B) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            if !buf.has_remaining() {
                return Err(VortexError::BufferUnderflow {
                    needed: 1,
                    available: 0,
                });
            }
            let byte = buf.get_u8();
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(VortexError::BufferUnderflow {
                    needed: 1,
                    available: 0,
                });
            }
        }
    }

    pub fn get_varint<B: Buf>(buf: &mut B) -> Result<i64> {
        let u = Self::get_uvarint(buf)?;
        let n = (u >> 1) as i64;
        if (u & 1) != 0 {
            Ok(!n)
        } else {
            Ok(n)
        }
    }
}

/// Helper functions for Kafka binary types.
pub struct KafkaCodec;

impl KafkaCodec {
    pub fn put_string(buf: &mut BytesMut, s: &str) {
        buf.put_i16(s.len() as i16);
        buf.put_slice(s.as_bytes());
    }

    pub fn get_string<B: Buf>(buf: &mut B) -> Result<String> {
        if buf.remaining() < 2 {
            return Err(VortexError::BufferUnderflow {
                needed: 2,
                available: buf.remaining(),
            });
        }
        let len = buf.get_i16();
        if len <= 0 {
            return Ok(String::new());
        }
        if buf.remaining() < len as usize {
            return Err(VortexError::BufferUnderflow {
                needed: len as usize,
                available: buf.remaining(),
            });
        }
        let bytes = buf.copy_to_bytes(len as usize);
        String::from_utf8(bytes.to_vec())
            .map_err(|e| VortexError::SchemaValidationFailed {
                topic: "kafka-wire".into(),
                reason: format!("Invalid UTF-8 string: {}", e),
            })
    }

    pub fn put_bytes(buf: &mut BytesMut, b: &[u8]) {
        buf.put_i32(b.len() as i32);
        buf.put_slice(b);
    }

    pub fn get_bytes<B: Buf>(buf: &mut B) -> Result<Option<Bytes>> {
        if buf.remaining() < 4 {
            return Err(VortexError::BufferUnderflow {
                needed: 4,
                available: buf.remaining(),
            });
        }
        let len = buf.get_i32();
        if len < 0 {
            return Ok(None);
        }
        if buf.remaining() < len as usize {
            return Err(VortexError::BufferUnderflow {
                needed: len as usize,
                available: buf.remaining(),
            });
        }
        Ok(Some(buf.copy_to_bytes(len as usize)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kafka_frame_decode_and_response() {
        let mut buf = BytesMut::new();

        // Build a mock ApiVersions request
        let correlation_id = 12345;
        let mut body = BytesMut::new();
        body.put_i16(18); // ApiVersions
        body.put_i16(3);  // Version 3
        body.put_i32(correlation_id);
        KafkaCodec::put_string(&mut body, "vortex-python-client");

        let total_size = body.len() as i32;
        buf.put_i32(total_size);
        buf.put_slice(&body);

        let decoded = KafkaFrame::decode(&mut buf).unwrap().expect("Frame decoded");
        assert_eq!(decoded.header.api_key, KafkaApiKey::ApiVersions);
        assert_eq!(decoded.header.api_version, 3);
        assert_eq!(decoded.header.correlation_id, correlation_id);
        assert_eq!(
            decoded.header.client_id.as_deref(),
            Some("vortex-python-client")
        );

        // Build mock response
        let resp_payload = Bytes::from_static(b"api-versions-response-data");
        let resp_envelope = KafkaFrame::build_response(correlation_id, resp_payload.clone());

        assert_eq!(resp_envelope.len(), 4 + 4 + resp_payload.len());
        let mut r = &resp_envelope[..];
        assert_eq!(r.get_i32(), 4 + resp_payload.len() as i32);
        assert_eq!(r.get_i32(), correlation_id);
        assert_eq!(&r[..], &resp_payload[..]);
    }

    #[test]
    fn test_varint_codec() {
        let mut buf = BytesMut::new();
        Varint::put_varint(&mut buf, 0);
        Varint::put_varint(&mut buf, -1);
        Varint::put_varint(&mut buf, 1);
        Varint::put_varint(&mut buf, 123456789);
        Varint::put_varint(&mut buf, -987654321);

        let mut r = &buf[..];
        assert_eq!(Varint::get_varint(&mut r).unwrap(), 0);
        assert_eq!(Varint::get_varint(&mut r).unwrap(), -1);
        assert_eq!(Varint::get_varint(&mut r).unwrap(), 1);
        assert_eq!(Varint::get_varint(&mut r).unwrap(), 123456789);
        assert_eq!(Varint::get_varint(&mut r).unwrap(), -987654321);
    }
}
