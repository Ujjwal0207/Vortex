use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher as Crc32Hasher;
use vortex_core::{error::Result, VortexError};

pub const VTX_MAGIC: u32 = 0x56545831; // "VTX1"
pub const VTX_VERSION: u8 = 1;
pub const FRAME_HEADER_LEN: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    ProduceReq = 1,
    ProduceResp = 2,
    FetchReq = 3,
    FetchResp = 4,
    CreateTopicReq = 5,
    CreateTopicResp = 6,
    MetadataReq = 7,
    MetadataResp = 8,
    ErrorResp = 9,
}

impl TryFrom<u8> for MessageType {
    type Error = VortexError;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            1 => Ok(Self::ProduceReq),
            2 => Ok(Self::ProduceResp),
            3 => Ok(Self::FetchReq),
            4 => Ok(Self::FetchResp),
            5 => Ok(Self::CreateTopicReq),
            6 => Ok(Self::CreateTopicResp),
            7 => Ok(Self::MetadataReq),
            8 => Ok(Self::MetadataResp),
            9 => Ok(Self::ErrorResp),
            _ => Err(VortexError::Io(format!("Unknown message type: {}", val))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub msg_type: MessageType,
    pub req_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(msg_type: MessageType, req_id: u32, payload: Bytes) -> Self {
        Self {
            msg_type,
            req_id,
            payload,
        }
    }

    /// Encodes the entire frame into binary format:
    /// [magic: 4B][version: 1B][msg_type: 1B][req_id: 4B][payload_len: 4B][crc32: 4B][payload]
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len() as u32;

        let mut crc_hasher = Crc32Hasher::new();
        crc_hasher.update(&self.payload);
        let crc32 = crc_hasher.finalize();

        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        buf.put_u32(VTX_MAGIC);
        buf.put_u8(VTX_VERSION);
        buf.put_u8(self.msg_type as u8);
        buf.put_u32(self.req_id);
        buf.put_u32(payload_len);
        buf.put_u32(crc32);
        buf.extend_from_slice(&self.payload);

        buf.freeze()
    }

    /// Attempts to decode a frame from a buffer. If not enough bytes are present, returns Ok(None).
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != VTX_MAGIC {
            return Err(VortexError::InvalidMagic {
                expected: VTX_MAGIC,
                actual: magic,
            });
        }

        let _version = buf[4];
        let msg_type_raw = buf[5];
        let msg_type = MessageType::try_from(msg_type_raw)?;
        let req_id = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let payload_len = u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]) as usize;
        let expected_crc = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);

        if buf.len() < FRAME_HEADER_LEN + payload_len {
            // Wait for remaining frame bytes to arrive over TCP
            return Ok(None);
        }

        // Advance past header
        buf.advance(FRAME_HEADER_LEN);
        let payload = buf.split_to(payload_len).freeze();

        // Verify CRC32
        let mut crc_hasher = Crc32Hasher::new();
        crc_hasher.update(&payload);
        let actual_crc = crc_hasher.finalize();

        if expected_crc != actual_crc {
            return Err(VortexError::CorruptedRecordCrc {
                offset: 0,
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        Ok(Some(Self {
            msg_type,
            req_id,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_codec_roundtrip() {
        let payload = Bytes::from_static(b"HELLO_VORTEX_STREAM");
        let frame = Frame::new(MessageType::ProduceReq, 42, payload.clone());

        let encoded = frame.encode();
        let mut buf = BytesMut::from(&encoded[..]);

        let decoded = Frame::decode(&mut buf).unwrap().expect("Frame decoded");
        assert_eq!(decoded.msg_type, MessageType::ProduceReq);
        assert_eq!(decoded.req_id, 42);
        assert_eq!(decoded.payload, payload);
        assert_eq!(buf.len(), 0);
    }
}
