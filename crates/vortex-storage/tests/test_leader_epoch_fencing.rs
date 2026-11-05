use bytes::Bytes;
use tempfile::tempdir;
use vortex_core::VortexError;
use vortex_storage::PartitionLog;

#[test]
fn test_leader_epoch_monotonic_120_transitions_and_zombie_fencing() {
    let dir = tempdir().unwrap();
    let mut log = PartitionLog::open_or_create(dir.path(), "epoch-ledger", 0, 1024 * 1024).unwrap();

    assert_eq!(log.leader_epoch(), 0);

    // Initial write at epoch 0
    let res = log
        .append_authenticated_with_epoch(None, Bytes::from_static(b"epoch-0-record"), 0)
        .expect("Epoch 0 initial write must succeed");
    assert_eq!(res.record.offset, 0);

    // Test 120 monotonic epoch transitions and adversarial zombie rejections
    for target_epoch in 1u32..=120u32 {
        // 1. Advance to target_epoch
        log.advance_leader_epoch(target_epoch).unwrap();
        assert_eq!(log.leader_epoch(), target_epoch);

        // 2. Negative: Zombie append with stale epoch (target_epoch - 1, or 0) must be fenced
        let stale_epoch = target_epoch - 1;
        let err = log
            .append_authenticated_with_epoch(None, Bytes::from_static(b"zombie-write"), stale_epoch)
            .unwrap_err();
        match err {
            VortexError::FencedLeaderEpoch { current: c, attempted: a } => {
                assert_eq!(c, target_epoch);
                assert_eq!(a, stale_epoch);
            }
            other => panic!("Expected FencedLeaderEpoch, got {:?}", other),
        }

        // 3. Negative: Attempting to advance backwards or same epoch must be rejected
        let regress_err = log.advance_leader_epoch(target_epoch).unwrap_err();
        assert!(matches!(regress_err, VortexError::FencedLeaderEpoch { .. }));

        let back_err = log.advance_leader_epoch(target_epoch - 1).unwrap_err();
        assert!(matches!(back_err, VortexError::FencedLeaderEpoch { .. }));

        // 4. Valid write at target_epoch
        let record = log
            .append_authenticated_with_epoch(
                Some(Bytes::from(format!("k-{}", target_epoch))),
                Bytes::from(format!("data-epoch-{}", target_epoch)),
                target_epoch,
            )
            .unwrap();
        assert_eq!(record.record.offset, target_epoch as u64);

        // 5. Roll segment every 10 epochs: verifies epoch propagates to rolled segment
        if target_epoch % 10 == 0 {
            log.roll_segment().unwrap();
            assert_eq!(log.active_segment().leader_epoch, target_epoch);
        }
    }

    assert_eq!(log.leader_epoch(), 120);
    assert_eq!(log.next_offset(), 121);
}

#[test]
fn test_leader_epoch_persistence_across_broker_restart() {
    let dir = tempdir().unwrap();
    let topic = "epoch-persistence";

    {
        let mut log = PartitionLog::open_or_create(dir.path(), topic, 0, 500).unwrap();
        log.advance_leader_epoch(10).unwrap();
        log.append_authenticated_with_epoch(None, Bytes::from_static(b"epoch-10-item"), 10)
            .unwrap();
        log.roll_segment().unwrap();
        log.advance_leader_epoch(11).unwrap();
        log.append_authenticated_with_epoch(None, Bytes::from_static(b"epoch-11-item"), 11)
            .unwrap();
        assert_eq!(log.leader_epoch(), 11);
    }

    // Reopen partition from disk — must recover leader_epoch = 11 from commit state and header
    let mut recovered = PartitionLog::open_or_create(dir.path(), topic, 0, 500).unwrap();
    assert_eq!(recovered.leader_epoch(), 11);

    // Stale write from zombie leader with epoch 10 must be fenced
    let err = recovered
        .append_authenticated_with_epoch(None, Bytes::from_static(b"stale-zombie"), 10)
        .unwrap_err();
    assert!(matches!(err, VortexError::FencedLeaderEpoch { current: 11, attempted: 10 }));

    // Valid write with epoch 11 must succeed
    let rec = recovered
        .append_authenticated_with_epoch(None, Bytes::from_static(b"valid-resumed"), 11)
        .unwrap();
    assert_eq!(rec.record.offset, 2);

    // Advancing to epoch 12
    recovered.advance_leader_epoch(12).unwrap();
    assert_eq!(recovered.leader_epoch(), 12);
}

#[test]
fn test_leader_epoch_batch_verification_and_quarantined_zombie_splits() {
    let dir = tempdir().unwrap();
    let mut log = PartitionLog::open_or_create(dir.path(), "epoch-batch", 0, 1024 * 1024).unwrap();

    log.advance_leader_epoch(5).unwrap();

    let batch = vec![
        (None, Bytes::from_static(b"msg-1"), None),
        (None, Bytes::from_static(b"msg-2"), None),
    ];

    // Batch append with stale epoch 4 must be rejected before touching disk
    let err = log
        .append_batch_authenticated_with_epoch(batch.clone(), 4)
        .unwrap_err();
    assert!(matches!(err, VortexError::FencedLeaderEpoch { current: 5, attempted: 4 }));
    assert_eq!(log.next_offset(), 0); // No torn batch state!

    // Batch append with correct epoch 5 succeeds
    let results = log
        .append_batch_authenticated_with_epoch(batch, 5)
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(log.next_offset(), 2);
}
