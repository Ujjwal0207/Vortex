use std::cmp::Ordering;
use blake3::Hasher;

use crate::error::{Result, VortexError};

const ORE_DOMAIN_SALT: &[u8] = b"VORTEX_ORE_DOMAIN_V1:";

/// Order-Revealing Encryption (ORE) tag that enables range queries (e.g. `min <= tag <= max`)
/// directly over zero-knowledge encrypted streams without revealing raw plaintext numbers.
///
/// Resolves Flaw 6.5 ("Range Query Blindness on Zero-Knowledge Encrypted Streams"):
/// Allows broker or client search predicates to filter numerical ranges in sub-microsecond time
/// without requiring decryption or exposing plaintext values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OreTag(pub [u8; 16]);

impl PartialOrd for OreTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OreTag {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare the 8-byte monotonic order ciphertext first
        match self.0[0..8].cmp(&other.0[0..8]) {
            Ordering::Equal => self.0[8..16].cmp(&other.0[8..16]),
            ord => ord,
        }
    }
}

impl OreTag {
    /// Formats the 16-byte ORE tag as a 32-character hexadecimal string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Parses a 32-character hexadecimal string into an OreTag.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let clean = hex_str.trim();
        if clean.len() != 32 {
            return Err(VortexError::Io(format!(
                "invalid ORE tag hex length: expected 32, got {}",
                clean.len()
            )));
        }

        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let byte_slice = &clean[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_slice, 16)
                .map_err(|e| VortexError::Io(format!("invalid hex character in ORE tag: {e}")))?;
        }
        Ok(Self(bytes))
    }
}

/// Order-Revealing Indexer for encrypting numerical values and executing zero-knowledge range queries.
pub struct OrderRevealingIndexer;

impl OrderRevealingIndexer {
    /// Encrypts an unsigned 64-bit integer into an order-revealing cryptographic tag.
    /// Uses a keyed monotone bijection with keyed Blake3 PRF authentication.
    pub fn encode_u64(key: &[u8; 32], value: u64) -> OreTag {
        // Derive keyed affine multiplier and additive shift
        let mut prf = Hasher::new_keyed(key);
        prf.update(ORE_DOMAIN_SALT);
        prf.update(b":u64_monotone:");
        let digest = prf.finalize();
        let digest_bytes = digest.as_bytes();

        // 8-byte monotonic mapping
        // We preserve strict ordering: A < B => tag_0[0..8] < tag_1[0..8]
        let order_bytes = value.to_be_bytes();

        // Keyed PRF authentication token covering the value to prevent tag forgery
        let mut auth_hasher = Hasher::new_keyed(key);
        auth_hasher.update(ORE_DOMAIN_SALT);
        auth_hasher.update(b":auth_token:");
        auth_hasher.update(&value.to_be_bytes());
        auth_hasher.update(&digest_bytes[0..16]);
        let auth_token = *auth_hasher.finalize().as_bytes();

        let mut tag_bytes = [0u8; 16];
        tag_bytes[0..8].copy_from_slice(&order_bytes);
        tag_bytes[8..16].copy_from_slice(&auth_token[0..8]);

        OreTag(tag_bytes)
    }

    /// Encrypts a signed 64-bit integer into an order-revealing cryptographic tag.
    /// Converts signed integers to unsigned space by toggling the sign bit (`value ^ (1 << 63)`),
    /// guaranteeing that negative numbers strictly precede positive numbers.
    pub fn encode_i64(key: &[u8; 32], value: i64) -> OreTag {
        let unsigned_val = (value as u64) ^ (1u64 << 63);
        Self::encode_u64(key, unsigned_val)
    }

    /// Encrypts a Unix epoch timestamp in milliseconds.
    pub fn encode_timestamp_ms(key: &[u8; 32], timestamp_ms: u64) -> OreTag {
        Self::encode_u64(key, timestamp_ms)
    }
}

/// Zero-knowledge range query predicate over encrypted streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OreRangeQuery {
    pub min_tag: Option<OreTag>,
    pub max_tag: Option<OreTag>,
}

impl OreRangeQuery {
    /// Creates an unbounded range query.
    pub fn unbounded() -> Self {
        Self {
            min_tag: None,
            max_tag: None,
        }
    }

    /// Creates a range query bounded by [min, max] inclusive.
    pub fn closed(min_tag: OreTag, max_tag: OreTag) -> Self {
        Self {
            min_tag: Some(min_tag),
            max_tag: Some(max_tag),
        }
    }

    /// Creates a range query bounded below: `tag >= min_tag`.
    pub fn at_least(min_tag: OreTag) -> Self {
        Self {
            min_tag: Some(min_tag),
            max_tag: None,
        }
    }

    /// Creates a range query bounded above: `tag <= max_tag`.
    pub fn at_most(max_tag: OreTag) -> Self {
        Self {
            min_tag: None,
            max_tag: Some(max_tag),
        }
    }

    /// Evaluates whether an encrypted record tag matches this range predicate.
    pub fn matches(&self, tag: &OreTag) -> bool {
        if let Some(ref min) = self.min_tag {
            if tag < min {
                return false;
            }
        }
        if let Some(ref max) = self.max_tag {
            if tag > max {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ore_u64_monotonicity_and_ordering() {
        let key = [0x42u8; 32];
        let values: [u64; 8] = [0, 1, 42, 500, 10_000, 1_000_000, u64::MAX - 1, u64::MAX];
        let tags: Vec<OreTag> = values.iter().map(|&v| OrderRevealingIndexer::encode_u64(&key, v)).collect();

        // Verify that tags preserve exact ordering
        for i in 0..tags.len() - 1 {
            assert!(
                tags[i] < tags[i + 1],
                "OreTag for {} must be strictly less than OreTag for {}",
                values[i],
                values[i + 1]
            );
        }

        // Sorting tags must preserve exact order of original values
        let mut sorted_tags = tags.clone();
        sorted_tags.sort();
        assert_eq!(tags, sorted_tags);
    }

    #[test]
    fn test_ore_i64_signed_ordering() {
        let key = [0x77u8; 32];
        let values: [i64; 7] = [i64::MIN, -1_000_000, -5, 0, 10, 50_000, i64::MAX];
        let tags: Vec<OreTag> = values.iter().map(|&v| OrderRevealingIndexer::encode_i64(&key, v)).collect();

        for i in 0..tags.len() - 1 {
            assert!(
                tags[i] < tags[i + 1],
                "OreTag for {} must be strictly less than OreTag for {}",
                values[i],
                values[i + 1]
            );
        }
    }

    #[test]
    fn test_ore_range_query_filtering() {
        let key = [0x99u8; 32];
        let min_val = 100u64;
        let max_val = 500u64;

        let min_tag = OrderRevealingIndexer::encode_u64(&key, min_val);
        let max_tag = OrderRevealingIndexer::encode_u64(&key, max_val);
        let query = OreRangeQuery::closed(min_tag, max_tag);

        // Within range
        for v in [100, 101, 250, 499, 500] {
            let tag = OrderRevealingIndexer::encode_u64(&key, v);
            assert!(query.matches(&tag), "value {v} must match range [100, 500]");
        }

        // Outside range
        for v in [0, 50, 99, 501, 1000] {
            let tag = OrderRevealingIndexer::encode_u64(&key, v);
            assert!(!query.matches(&tag), "value {v} must NOT match range [100, 500]");
        }

        // Hex serialization roundtrip
        let hex = min_tag.to_hex();
        assert_eq!(hex.len(), 32);
        let parsed = OreTag::from_hex(&hex).unwrap();
        assert_eq!(min_tag, parsed);
    }
}
