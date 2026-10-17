use crate::error::{Result, VortexError};

/// BlindIndexer computes deterministic, one-way keyed cryptographic hashes
/// for searchable fields over encrypted streams.
///
/// This enables zero-knowledge brokers:
/// clients tag messages with `BlindTag = Blake3_keyed(salt, value)`;
/// the broker matches queries against tags in microseconds without having access
/// to the underlying plaintext or encryption keys.
pub struct BlindIndexer;

impl BlindIndexer {
    /// Computes a 32-byte blind index tag for a searchable field value using Blake3 keyed hashing.
    pub fn compute_tag(search_salt: &[u8; 32], raw_value: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(search_salt);
        hasher.update(b"vortex-blind-index-v1:");
        // Normalize whitespace and lowercase for consistent deterministic lookup
        hasher.update(raw_value.trim().to_lowercase().as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Constant-time comparison of two blind index tags to prevent timing attacks.
    pub fn matches(tag_a: &[u8; 32], tag_b: &[u8; 32]) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= tag_a[i] ^ tag_b[i];
        }
        diff == 0
    }

    /// Formats a 32-byte tag into a 64-character hex string.
    pub fn to_hex(tag: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in tag {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Parses a 64-character hex string into a 32-byte tag.
    pub fn from_hex(hex_str: &str) -> Result<[u8; 32]> {
        let clean = hex_str.trim();
        if clean.len() != 64 {
            return Err(VortexError::Io(format!(
                "Invalid blind index hex length: expected 64, got {}",
                clean.len()
            )));
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_slice = &clean[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_slice, 16).map_err(|e| {
                VortexError::Io(format!("Invalid hex character in blind tag: {}", e))
            })?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_indexer_determinism_and_normalization() {
        let salt = [0x55u8; 32];
        let tag1 = BlindIndexer::compute_tag(&salt, "Alice.Smith@bank.com");
        let tag2 = BlindIndexer::compute_tag(&salt, " alice.smith@bank.com  ");
        let tag3 = BlindIndexer::compute_tag(&salt, "bob@bank.com");

        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
        assert!(BlindIndexer::matches(&tag1, &tag2));
        assert!(!BlindIndexer::matches(&tag1, &tag3));

        let hex = BlindIndexer::to_hex(&tag1);
        let parsed = BlindIndexer::from_hex(&hex).unwrap();
        assert_eq!(tag1, parsed);
    }
}
