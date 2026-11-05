use bytes::Bytes;
use tempfile::tempdir;
use vortex_storage::PartitionLog;

#[test]
fn test_mmr_retention_pruning_anchors_auditability() {
    let dir = tempdir().unwrap();

    // 1. Rapid rolling partition: 500 bytes per segment to force frequent segment rolls
    let mut log = PartitionLog::open_or_create(dir.path(), "prune-anchor-topic", 0, 500).unwrap();

    let total_records = 150;
    let mut segment_roots_before = Vec::new();

    for i in 0..total_records {
        let payload = Bytes::from(format!("payload-data-for-audit-sequence-{:06}", i));
        log.append(Some(Bytes::from(format!("k-{}", i))), payload).unwrap();
    }

    assert!(
        log.segments.len() > 10,
        "Expected at least 10 segments rolled, got {}",
        log.segments.len()
    );

    // Record base_offset and mmr_root for all segments prior to pruning
    for seg in &log.segments {
        segment_roots_before.push((seg.base_offset, seg.next_offset, seg.mmr_root()));
    }

    // 2. Prune all but the latest 2 segments
    let keep_bytes = log.segments[log.segments.len() - 2].size() + log.segments.last().unwrap().size();
    let pruned_offsets = log.prune_retention(1_000_000, None, Some(keep_bytes)).unwrap();

    assert!(
        !pruned_offsets.is_empty(),
        "Expected multiple segments to be pruned"
    );

    println!(
        "Pruned {} segments out of initial {}. Retained {} segments.",
        pruned_offsets.len(),
        segment_roots_before.len(),
        log.segments.len()
    );

    // 3. Mathematical Auditability Test: Verify that all pruned offsets (150 test queries)
    // can retrieve their exact historical MMR root from the anchor ledger!
    for &(base, next, expected_root) in &segment_roots_before {
        // If this segment was pruned:
        if base < log.segments[0].base_offset {
            for off in base..next {
                let anchor_root = log.get_pruned_anchor_root(off);
                assert_eq!(
                    anchor_root,
                    Some(expected_root),
                    "Archived anchor root for offset {} must match exact pre-pruning MMR root",
                    off
                );
            }
        }
    }

    // 4. Broker Reboot: Reopen partition from disk and verify anchor ledger persists across reboots
    drop(log);
    let recovered_log = PartitionLog::open_or_create(dir.path(), "prune-anchor-topic", 0, 500).unwrap();

    for &(base, next, expected_root) in &segment_roots_before {
        if base < recovered_log.segments[0].base_offset {
            for off in base..next {
                assert_eq!(
                    recovered_log.get_pruned_anchor_root(off),
                    Some(expected_root),
                    "Recovered log must serve archived anchor root for pruned offset {}",
                    off
                );
            }
        }
    }
}
