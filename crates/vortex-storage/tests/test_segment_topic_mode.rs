use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use tempfile::tempdir;
use bytes::Bytes;
use vortex_core::{compute_genesis_hash, TopicMode};
use vortex_storage::segment::{commit_state_path, Segment};

#[test]
fn test_segment_raw_mode_persistence_and_recovery() {
    let dir = tempdir().unwrap();
    let genesis = compute_genesis_hash("telemetry.raw", 0);

    // 1. Create segment in Raw mode
    let mut seg = Segment::open_or_create_with_mode(dir.path(), 0, genesis, TopicMode::Raw).unwrap();
    assert_eq!(seg.topic_mode, TopicMode::Raw);
    assert!(seg.topic_mode.is_raw());

    // 2. Append 15 records in Raw mode
    for i in 0..15 {
        let key = Some(Bytes::from(format!("device-{i}")));
        let val = Bytes::from(format!("telemetry-reading-{i}"));
        let rec = seg.append(key, val).unwrap();
        assert_eq!(rec.offset, i as u64);
        assert_eq!(rec.prev_hash, [0u8; 32]); // Raw records omit chained prev_hash
    }

    assert_eq!(seg.next_offset, 15);
    // Raw mode bypasses MMR leaf appending
    assert_eq!(seg.mmr_count(), 0);

    let seg_path = seg.path.clone();
    let commit_path = commit_state_path(&seg_path);

    // Verify Region A header byte 59 has TopicMode::Raw (1)
    let file = File::open(&seg_path).unwrap();
    let mut header_buf = [0u8; 64];
    file.read_exact_at(&mut header_buf, 0).unwrap();
    assert_eq!(header_buf[59], 1, "Region A byte 59 must be 1 (Raw mode)");

    // Verify CommitMarkerV2 byte 5 has TopicMode::Raw (1)
    let commit_bytes = std::fs::read(&commit_path).unwrap();
    assert_eq!(commit_bytes[5], 1, "CommitMarkerV2 byte 5 must be 1 (Raw mode)");

    // 3. Read back in raw mode
    let records = seg.read(0, 1024 * 1024).unwrap();
    assert_eq!(records.len(), 15);
    assert_eq!(records[0].key, Some(Bytes::from("device-0")));

    drop(seg);

    // 4. Recover segment: open_or_create without explicit mode must recover TopicMode::Raw from disk!
    let recovered = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
    assert_eq!(recovered.topic_mode, TopicMode::Raw);
    assert_eq!(recovered.next_offset, 15);
    assert_eq!(recovered.mmr_count(), 0);

    let recovered_recs = recovered.read(5, 1024 * 1024).unwrap();
    assert_eq!(recovered_recs.len(), 10);
    assert_eq!(recovered_recs[0].offset, 5);
}

#[test]
fn test_segment_verifiable_mode_persistence_and_recovery() {
    let dir = tempdir().unwrap();
    let genesis = compute_genesis_hash("audit.verifiable", 0);

    let mut seg = Segment::open_or_create_with_mode(dir.path(), 100, genesis, TopicMode::Verifiable).unwrap();
    assert_eq!(seg.topic_mode, TopicMode::Verifiable);
    assert!(seg.topic_mode.is_verifiable());

    for i in 0..10 {
        let val = Bytes::from(format!("audit-event-{i}"));
        seg.append(None, val).unwrap();
    }

    assert_eq!(seg.next_offset, 110);
    assert_eq!(seg.mmr_count(), 10);
    let root = seg.mmr_root();
    assert_ne!(root, [0u8; 32]);

    // Inclusion proof works
    let proof = seg.generate_inclusion_proof(103).unwrap();
    assert!(proof.verify(&root, &proof.leaf_hash));

    let seg_path = seg.path.clone();
    let commit_path = commit_state_path(&seg_path);

    let file = File::open(&seg_path).unwrap();
    let mut header_buf = [0u8; 64];
    file.read_exact_at(&mut header_buf, 0).unwrap();
    assert_eq!(header_buf[59], 0, "Region A byte 59 must be 0 (Verifiable mode)");

    let commit_bytes = std::fs::read(&commit_path).unwrap();
    assert_eq!(commit_bytes[5], 0, "CommitMarkerV2 byte 5 must be 0 (Verifiable mode)");

    drop(seg);

    let recovered = Segment::open_or_create(dir.path(), 100, genesis).unwrap();
    assert_eq!(recovered.topic_mode, TopicMode::Verifiable);
    assert_eq!(recovered.next_offset, 110);
    assert_eq!(recovered.mmr_count(), 10);
    assert_eq!(recovered.mmr_root(), root);
}
