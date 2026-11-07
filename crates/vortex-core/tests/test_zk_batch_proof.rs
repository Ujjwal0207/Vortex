use vortex_core::hash::HashDigest;
use vortex_core::zkp::{
    ZkBatchProver, ZkBatchVerifier, ZK_SNARK_PROOF_BYTES_LEN,
};

#[test]
fn test_zk_batch_proof_constant_256_bytes() {
    let mmr_root: HashDigest = *blake3::hash(b"MMR_ROOT_VORTEX_PEAKS_001").as_bytes();

    // Generate batch with 10 records
    let mut small_batch = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..10 {
        let h = *blake3::hash(format!("REC_{i}").as_bytes()).as_bytes();
        small_batch.push((i as u64, prev, h));
        prev = h;
    }

    let proof_small = ZkBatchProver::prove_batch(&mmr_root, 0, &small_batch)
        .expect("prove small batch");

    // Must be EXACTLY 256 bytes
    assert_eq!(proof_small.proof_bytes.len(), ZK_SNARK_PROOF_BYTES_LEN);
    assert_eq!(proof_small.proof_bytes.len(), 256);
    assert_eq!(proof_small.public_inputs.record_count, 10);
    assert_eq!(proof_small.public_inputs.start_offset, 0);
    assert_eq!(proof_small.public_inputs.end_offset, 9);

    // Verify proof
    let is_valid = ZkBatchVerifier::verify(&proof_small, &mmr_root).expect("verify small");
    assert!(is_valid);

    // Now generate batch with 5,000 records
    let mut large_batch = Vec::new();
    prev = [0u8; 32];
    for i in 0..5000 {
        let h = *blake3::hash(format!("LARGE_TX_{i}").as_bytes()).as_bytes();
        large_batch.push((i as u64, prev, h));
        prev = h;
    }

    let start = std::time::Instant::now();
    let proof_large = ZkBatchProver::prove_batch(&mmr_root, 0, &large_batch)
        .expect("prove large batch");
    let prover_duration = start.elapsed();
    println!("Prover for 5,000 records took: {:?}", prover_duration);

    // Large batch proof payload remains EXACTLY 256 bytes!
    assert_eq!(proof_large.proof_bytes.len(), ZK_SNARK_PROOF_BYTES_LEN);
    assert_eq!(proof_large.proof_bytes.len(), 256);
    assert_eq!(proof_large.public_inputs.record_count, 5000);

    // Verify sub-5ms verification speed
    let verify_start = std::time::Instant::now();
    let is_large_valid = ZkBatchVerifier::verify(&proof_large, &mmr_root).expect("verify large");
    let verify_duration = verify_start.elapsed();
    println!("Verifier for 5,000 records took: {:?}", verify_duration);

    assert!(is_large_valid);
    assert!(verify_duration.as_millis() < 5, "Verification must take < 5 ms, took {:?}", verify_duration);
}

#[test]
fn test_zk_batch_proof_tamper_detection() {
    let mmr_root: HashDigest = *blake3::hash(b"MMR_ROOT_UNFALSIFIABLE").as_bytes();
    let other_root: HashDigest = *blake3::hash(b"FORGED_ROOT_ATTACK").as_bytes();

    let mut batch = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..20 {
        let h = *blake3::hash(format!("TX_{i}").as_bytes()).as_bytes();
        batch.push((i as u64, prev, h));
        prev = h;
    }

    let proof = ZkBatchProver::prove_batch(&mmr_root, 0, &batch).expect("prove batch");

    // 1. Verifying against wrong MMR root must fail
    let wrong_root_verify = ZkBatchVerifier::verify(&proof, &other_root).expect("verify attempt");
    assert!(!wrong_root_verify, "Must reject proof against divergent root");

    // 2. Tampering with any byte of the 256-byte proof payload must fail
    let mut tampered_proof = proof.clone();
    tampered_proof.proof_bytes[42] ^= 0xFF; // Flip bits
    let tampered_verify = ZkBatchVerifier::verify(&tampered_proof, &mmr_root).expect("verify tampered");
    assert!(!tampered_verify, "Must reject tampered proof payload");

    // 3. Tampering with public inputs (e.g. claiming different record count) must fail
    let mut tampered_inputs = proof.clone();
    tampered_inputs.public_inputs.record_count = 999;
    let tampered_inputs_verify = ZkBatchVerifier::verify(&tampered_inputs, &mmr_root).expect("verify tampered count");
    assert!(!tampered_inputs_verify, "Must reject tampered public inputs");
}
