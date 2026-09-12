use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher as Crc32Hasher;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, VortexError};
use crate::hash::{compute_record_hash, verify_record_integrity, HashDigest};

/// Minimum overhead of a serialized record (excluding key and value payloads):
/// total_len (4) + crc32 (4) + offset (8) + timestamp (8) + prev_hash (32) + record_hash (32) + key_len (4) + val_len (4) = 96 bytes.
pub const RECORD_HEADER_SIZE: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub offset: u64,
    pub timestamp: u64,
    pub prev_hash: HashDigest,
    pub record_hash: HashDigest,
    pub key: Option<Bytes>,
    pub value: Bytes,
}

impl Record {
    /// Creates a new Record with automatic timestamping and cryptographic Blake3 hash calculation.
    pub fn new(prev_hash: HashDigest, offset: u64, key: Option<Bytes>, value: Bytes) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record_hash = compute_record_hash(
            &prev_hash,
            offset,
            timestamp,
            key.as_deref(),
            &value,
        );

        Self {
            offset,
            timestamp,
            prev_hash,
            record_hash,
            key,
            value,
        }
    }

    /// Explicit constructor allowing specific timestamp and pre-calculated hashes (e.g. for replication or recovery).
    pub fn with_metadata(
        offset: u64,
        timestamp: u64,
        prev_hash: HashDigest,
        record_hash: HashDigest,
        key: Option<Bytes>,
        value: Bytes,
    ) -> Self {
        Self {
            offset,
            timestamp,
            prev_hash,
            record_hash,
            key,
            value,
        }
    }

    /// Serializes the record into its deterministic binary format.
    /// Format:
    /// [total_len: u32][crc32: u32][offset: u64][timestamp: u64][prev_hash: 32B][record_hash: 32B][key_len: i32][key][val_len: u32][val]
    pub fn encode(&self) -> Bytes {
        let key_len = self.key.as_ref().map(|k| k.len()).unwrap_or(0);
        let val_len = self.value.len();
        let payload_size = 8 + 8 + 32 + 32 + 4 + key_len + 4 + val_len;
        let total_len = 4 + payload_size as u32; // Includes crc32 (4) + payload_size

        let mut payload_buf = BytesMut::with_capacity(payload_size);
        payload_buf.put_u64(self.offset);
        payload_buf.put_u64(self.timestamp);
        payload_buf.put_slice(&self.prev_hash);
        payload_buf.put_slice(&self.record_hash);

        if let Some(ref k) = self.key {
            payload_buf.put_i32(k.len() as i32);
            payload_buf.put_slice(k);
        } else {
            payload_buf.put_i32(-1);
        }

        payload_buf.put_u32(val_len as u32);
        payload_buf.put_slice(&self.value);

        // Hardware CRC32 over the payload
        let mut crc_hasher = Crc32Hasher::new();
        crc_hasher.update(&payload_buf);
        let crc32 = crc_hasher.finalize();

        let mut full_buf = BytesMut::with_capacity(4 + 4 + payload_size);
        full_buf.put_u32(total_len);
        full_buf.put_u32(crc32);
        full_buf.extend_from_slice(&payload_buf);

        full_buf.freeze()
    }

    /// Decodes a binary record from a byte buffer and verifies both CRC32 and cryptographic integrity.
    pub fn decode(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(VortexError::BufferUnderflow {
                needed: 8,
                available: buf.remaining(),
            });
        }

        let total_len = buf.get_u32() as usize;
        if buf.remaining() < total_len {
            return Err(VortexError::BufferUnderflow {
                needed: total_len,
                available: buf.remaining(),
            });
        }

        let expected_crc = buf.get_u32();
        let payload_len = total_len - 4; // Minus the 4 bytes of crc32

        let payload_bytes = buf.copy_to_bytes(payload_len);

        // 1. Verify CRC32 fast-path
        let mut crc_hasher = Crc32Hasher::new();
        crc_hasher.update(&payload_bytes);
        let actual_crc = crc_hasher.finalize();

        if expected_crc != actual_crc {
            return Err(VortexError::CorruptedRecordCrc {
                offset: 0, // Fallback placeholder if CRC corrupts header
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        // 2. Parse fields
        let mut reader = payload_bytes;
        let offset = reader.get_u64();
        let timestamp = reader.get_u64();

        let mut prev_hash = [0u8; 32];
        reader.copy_to_slice(&mut prev_hash);

        let mut record_hash = [0u8; 32];
        reader.copy_to_slice(&mut record_hash);

        let key_len = reader.get_i32();
        let key = if key_len >= 0 {
            Some(reader.copy_to_bytes(key_len as usize))
        } else {
            None
        };

        let val_len = reader.get_u32() as usize;
        let value = reader.copy_to_bytes(val_len);

        // 3. Verify Blake3 cryptographic integrity
        if !verify_record_integrity(
            &prev_hash,
            &record_hash,
            offset,
            timestamp,
            key.as_deref(),
            &value,
        ) {
            return Err(VortexError::CryptographicLineageBroken {
                offset,
                expected: hex::encode(record_hash),
                actual: hex::encode(compute_record_hash(
                    &prev_hash,
                    offset,
                    timestamp,
                    key.as_deref(),
                    &value,
                )),
            });
        }

        Ok(Self {
            offset,
            timestamp,
            prev_hash,
            record_hash,
            key,
            value,
        })
    }
}

// Simple hex helper for error messages without external heavy dependencies
mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::compute_genesis_hash;

    #[test]
    fn test_record_encode_decode_roundtrip() {
        let genesis = compute_genesis_hash("transactions", 0);
        let key = Some(Bytes::from_static(b"order-9981"));
        let val = Bytes::from_static(b"{\"amount\": 420.50, \"status\": \"settled\"}");

        let record = Record::new(genesis, 0, key.clone(), val.clone());
        let encoded = record.encode();

        let mut slice = &encoded[..];
        let decoded = Record::decode(&mut slice).expect("Decoded record must succeed");

        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.prev_hash, genesis);
        assert_eq!(decoded.record_hash, record.record_hash);
        assert_eq!(decoded.key, key);
        assert_eq!(decoded.value, val);
        assert_eq!(slice.len(), 0, "All bytes must be consumed");
    }

    #[test]
    fn test_corrupted_crc_rejected() {
        let genesis = compute_genesis_hash("sensor-feed", 0);
        let record = Record::new(genesis, 10, None, Bytes::from_static(b"temp=23.5"));
        let mut encoded = record.encode().to_vec();

        // Intentionally flip a byte in the payload
        let last_idx = encoded.len() - 1;
        encoded[last_idx] ^= 0xFF;

        let mut slice = &encoded[..];
        let result = Record::decode(&mut slice);

        assert!(matches!(result, Err(VortexError::CorruptedRecordCrc { .. })));
    }
}
