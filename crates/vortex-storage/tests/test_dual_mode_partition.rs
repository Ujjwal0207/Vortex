use tempfile::tempdir;
use bytes::Bytes;
use vortex_core::TopicMode;
use vortex_storage::partition::PartitionLog;

#[test]
fn test_partition_raw_mode_rolling_and_verification() {
    let dir = tempdir().unwrap();
    // Use very small segment limit (4 KB) so 50 records roll across multiple segments
    let max_seg_bytes = 4 * 1024;

    let mut partition = PartitionLog::open_or_create_with_mode(
        dir.path(),
        "telemetry.raw",
        0,
        max_seg_bytes,
        TopicMode::Raw,
    )
    .unwrap();

    assert_eq!(partition.topic_mode, TopicMode::Raw);
    assert!(partition.topic_mode.is_raw());

    // Append 50 records in batches
    for b in 0..5 {
        let batch: Vec<_> = (0..10)
            .map(|i| {
                let idx = b * 10 + i;
                (
                    Some(Bytes::from(format!("key-{idx}"))),
                    Bytes::from(format!("payload-value-{idx}-padding-bytes-for-segment-roll")),
                    None,
                )
            })
            .collect();
        let results = partition.append_batch_authenticated(batch).unwrap();
        assert_eq!(results.len(), 10);
        for res in results {
            // Raw mode omits writer MAC computation (zero ratchet crypto cycles)
            assert_eq!(res.writer_mac, [0u8; 32]);
            assert_eq!(res.record.prev_hash, [0u8; 32]);
        }
    }

    assert_eq!(partition.next_offset(), 50);
    // Rolled across multiple segments
    assert!(partition.segments.len() > 1, "Must have rolled across multiple segments");

    // All rolled segments must inherit TopicMode::Raw
    for seg in &partition.segments {
        assert_eq!(seg.topic_mode, TopicMode::Raw);
        assert_eq!(seg.mmr_count(), 0);
    }

    // Read across rolled segments
    let records = partition.read(0, 1024 * 1024).unwrap();
    assert_eq!(records.len(), 50);
    assert_eq!(records[0].offset, 0);
    assert_eq!(records[49].offset, 49);

    partition.flush().unwrap();
    drop(partition);

    // Reopen without explicit mode: must automatically detect TopicMode::Raw from disk
    let reopened = PartitionLog::open_or_create(dir.path(), "telemetry.raw", 0, max_seg_bytes).unwrap();
    assert_eq!(reopened.topic_mode, TopicMode::Raw);
    assert_eq!(reopened.next_offset(), 50);

    // Offline verification must succeed for raw partition without requiring partition.macs
    let partition_dir = dir.path().join("telemetry.raw").join("partition-0");
    let report = PartitionLog::verify_offline(&partition_dir, "telemetry.raw", 0).unwrap();
    assert!(report.is_valid);
    assert_eq!(report.total_records, 50);
}

#[test]
fn test_partition_verifiable_mode_rolling_and_verification() {
    let dir = tempdir().unwrap();
    let max_seg_bytes = 4 * 1024;
    let genesis_seed = [7u8; 32];

    let mut partition = PartitionLog::open_or_create_with_seed_and_mode(
        dir.path(),
        "audit.verifiable",
        0,
        max_seg_bytes,
        genesis_seed,
        TopicMode::Verifiable,
    )
    .unwrap();

    assert_eq!(partition.topic_mode, TopicMode::Verifiable);

    for b in 0..5 {
        let batch: Vec<_> = (0..10)
            .map(|i| {
                let idx = b * 10 + i;
                (
                    Some(Bytes::from(format!("audit-key-{idx}"))),
                    Bytes::from(format!("audit-action-{idx}-payload-with-padding")),
                    None,
                )
            })
            .collect();
        let results = partition.append_batch_authenticated(batch).unwrap();
        assert_eq!(results.len(), 10);
        for res in results {
            // Verifiable mode generates cryptographically valid writer MACs
            assert_ne!(res.writer_mac, [0u8; 32]);
        }
    }

    assert_eq!(partition.next_offset(), 50);
    assert!(partition.segments.len() > 1);

    for seg in &partition.segments {
        assert_eq!(seg.topic_mode, TopicMode::Verifiable);
        assert!(seg.mmr_count() > 0);
        assert_ne!(seg.mmr_root(), [0u8; 32]);
    }

    partition.flush().unwrap();
    drop(partition);

    // Reopen without explicit mode: must detect TopicMode::Verifiable from disk
    let reopened = PartitionLog::open_or_create(dir.path(), "audit.verifiable", 0, max_seg_bytes).unwrap();
    assert_eq!(reopened.topic_mode, TopicMode::Verifiable);
    assert_eq!(reopened.next_offset(), 50);

    let partition_dir = dir.path().join("audit.verifiable").join("partition-0");
    let report = PartitionLog::verify_offline_with_seed(&partition_dir, "audit.verifiable", 0, Some(&genesis_seed)).unwrap();
    assert!(report.is_valid);
    assert!(report.macs_verified);
    assert_eq!(report.total_records, 50);
}

