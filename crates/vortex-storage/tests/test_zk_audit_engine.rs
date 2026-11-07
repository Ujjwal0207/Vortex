use bytes::Bytes;
use tempfile::tempdir;
use vortex_storage::partition::{PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};
use vortex_storage::zk_audit::ZkAuditEngine;

#[test]
fn test_zk_audit_engine_partition_integration() {
    let dir = tempdir().unwrap();
    let mut partition = PartitionLog::open_or_create(dir.path(), "financial_audit", 0, DEFAULT_MAX_SEGMENT_BYTES)
        .expect("create partition");

    // Ingest 50 high-stakes financial records
    for i in 0..50 {
        let payload = format!("WIRE_TRANSFER_PAYMENT_TX_{i:04}");
        partition.append(None, Bytes::from(payload)).expect("append record");
    }

    let active_root = partition.active_mmr_root();

    // Generate ZK Batch Audit Proof for records [10..40] (30 records)
    let proof = ZkAuditEngine::generate_batch_proof(&partition, 10, 30)
        .expect("generate batch proof");

    // Proof must be constant 256 bytes
    assert_eq!(proof.proof_bytes.len(), 256);
    assert_eq!(proof.public_inputs.record_count, 30);
    assert_eq!(proof.public_inputs.start_offset, 10);
    assert_eq!(proof.public_inputs.end_offset, 39);
    assert_eq!(proof.public_inputs.mmr_root, active_root);

    // Verify proof
    let is_valid = ZkAuditEngine::verify_batch_proof(&proof, &active_root)
        .expect("verify proof");
    assert!(is_valid);

    // Verify with divergent root fails
    let fake_root = [77u8; 32];
    let is_fake_valid = ZkAuditEngine::verify_batch_proof(&proof, &fake_root)
        .expect("verify fake root");
    assert!(!is_fake_valid);
}

