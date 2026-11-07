use bytes::Bytes;
use tempfile::tempdir;
use vortex_storage::partition::PartitionLog;

#[path = "../src/verifier_cmd.rs"]
mod verifier_cmd;

use verifier_cmd::{execute_verify, VerifyOptions};

#[test]
fn test_cli_verify_intact_and_tampered() {
    let tmp = tempdir().unwrap();
    let topic = "compliance-audit-topic";
    let partition_id = 0;

    let mut partition = PartitionLog::open_or_create(tmp.path(), topic, partition_id, 10 * 1024 * 1024).unwrap();

    // 1. Ingest 50 verified records
    for i in 0..50 {
        let key = Bytes::from(format!("agent-key-{}", i));
        let val = Bytes::from(format!("{{\"action\":\"db_migrate\",\"step\":{}}}", i));
        partition.append(Some(key), val).unwrap();
    }
    partition.flush().unwrap();

    let part_dir = tmp.path().join(topic).join(format!("partition-{}", partition_id));

    // 2. Execute verification on untampered log -> MUST PASS
    let opts_clean = VerifyOptions {
        path: part_dir.clone(),
        topic: Some(topic.to_string()),
        partition: partition_id,
        pubkey: None,
        receipts: None,
        witness: None,
        strict: true,
    };

    let result = execute_verify(opts_clean);
    assert_eq!(result, Ok(()), "Untampered partition must pass compliance verification");

    // 3. Intentionally tamper with a byte in the segment file on disk
    let seg_path = part_dir.join("00000000000000000000.vtx");
    assert!(seg_path.exists());

    let mut data = std::fs::read(&seg_path).unwrap();
    // Tamper with byte inside the payload region near the end of the file
    let tamper_pos = data.len() - 50;
    data[tamper_pos] ^= 0xFF; // Flip all bits of the byte
    std::fs::write(&seg_path, &data).unwrap();

    // 4. Re-run verification on tampered log -> MUST FAIL with exit code 1
    let opts_tampered = VerifyOptions {
        path: part_dir,
        topic: Some(topic.to_string()),
        partition: partition_id,
        pubkey: None,
        receipts: None,
        witness: None,
        strict: true,
    };

    let tampered_result = execute_verify(opts_tampered);
    assert_eq!(tampered_result, Err(1), "Tampered partition MUST fail compliance audit with exit code 1");
}
