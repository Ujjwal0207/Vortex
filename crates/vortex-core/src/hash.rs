use blake3::Hasher;

/// 32-byte Blake3 cryptographic digest
pub type HashDigest = [u8; 32];

/// Genesis anchor constant seed for initializing new partition streams
const GENESIS_SALT: &[u8; 32] = b"VORTEX_STREAM_GENESIS_SALT_V1.00";

/// Computes the deterministic Genesis Hash for a new topic partition.
/// Guarantees that each partition has a cryptographically distinct starting root.
pub fn compute_genesis_hash(topic: &str, partition: u32) -> HashDigest {
    let mut hasher = Hasher::new_keyed(GENESIS_SALT);
    hasher.update(topic.as_bytes());
    hasher.update(&partition.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the cryptographic hash of a record, chaining it to the previous record's hash.
/// Hashes: [prev_hash (32B)] + [offset (8B)] + [timestamp (8B)] + [key_len (4B)] + [key] + [val_len (4B)] + [val]
pub fn compute_record_hash(
    prev_hash: &HashDigest,
    offset: u64,
    timestamp: u64,
    key: Option<&[u8]>,
    value: &[u8],
) -> HashDigest {
    let mut hasher = Hasher::new();
    hasher.update(prev_hash);
    hasher.update(&offset.to_be_bytes());
    hasher.update(&timestamp.to_be_bytes());

    if let Some(k) = key {
        hasher.update(&(k.len() as u32).to_be_bytes());
        hasher.update(k);
    } else {
        hasher.update(&0u32.to_be_bytes());
    }

    hasher.update(&(value.len() as u32).to_be_bytes());
    hasher.update(value);

    *hasher.finalize().as_bytes()
}

/// Verifies whether the record's embedded hash matches the cryptographic computation
/// given the expected predecessor hash.
pub fn verify_record_integrity(
    prev_hash: &HashDigest,
    expected_hash: &HashDigest,
    offset: u64,
    timestamp: u64,
    key: Option<&[u8]>,
    value: &[u8],
) -> bool {
    let computed = compute_record_hash(prev_hash, offset, timestamp, key, value);
    computed == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_determinism_and_uniqueness() {
        let h1 = compute_genesis_hash("orders", 0);
        let h2 = compute_genesis_hash("orders", 0);
        let h3 = compute_genesis_hash("orders", 1);
        let h4 = compute_genesis_hash("payments", 0);

        assert_eq!(h1, h2, "Genesis hash must be completely deterministic");
        assert_ne!(h1, h3, "Partitions must produce different genesis roots");
        assert_ne!(h1, h4, "Topics must produce different genesis roots");
    }

    #[test]
    fn test_hash_chain_tamper_detection() {
        let genesis = compute_genesis_hash("audit-trail", 0);
        let payload = b"User #4092 deposited $100,000.00";
        let record_hash = compute_record_hash(&genesis, 0, 1700000000000, None, payload);

        // Verification passes with correct payload
        assert!(verify_record_integrity(
            &genesis,
            &record_hash,
            0,
            1700000000000,
            None,
            payload
        ));

        // Tampering 1 single byte in the payload fails verification immediately!
        let tampered_payload = b"User #4092 deposited $900,000.00";
        assert!(!verify_record_integrity(
            &genesis,
            &record_hash,
            0,
            1700000000000,
            None,
            tampered_payload
        ));

        // Tampering with timestamp or offset also fails verification
        assert!(!verify_record_integrity(
            &genesis,
            &record_hash,
            1, // changed offset
            1700000000000,
            None,
            payload
        ));
    }
}
