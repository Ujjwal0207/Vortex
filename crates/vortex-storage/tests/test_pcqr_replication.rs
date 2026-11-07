use tempfile::tempdir;
use vortex_core::hash::HashDigest;
use vortex_storage::pcqr::{
    MMRCommitPulse, ReplicationAck, ReplicaStatus, QuorumCommitTracker,
    ZeroDivergenceValidator, PcqrLeaderReplicator, PcqrFollowerNode,
};

#[test]
fn test_pcqr_quorum_consensus_success() {
    // 3-node cluster: quorum threshold Q = floor(3/2) + 1 = 2
    let mut tracker = QuorumCommitTracker::new(3);
    assert_eq!(tracker.quorum_size(), 2);

    let mmr_root_1: HashDigest = [1u8; 32];
    let blake3_hash_1: HashDigest = [2u8; 32];

    let pulse = MMRCommitPulse {
        partition_id: 0,
        leader_epoch: 1,
        offset: 0,
        mmr_root: mmr_root_1,
        blake3_hash: blake3_hash_1,
        timestamp: 1_700_000_000,
        payload: b"TEST_TRANSACTION_0".to_vec(),
    };

    tracker.register_pulse(pulse.clone());
    assert_eq!(tracker.highest_committed_offset(), None);

    // Leader self-ack
    let ack_leader = ReplicationAck {
        replica_id: "node-1-leader".to_string(),
        partition_id: 0,
        leader_epoch: 1,
        acked_offset: 0,
        acked_mmr_root: mmr_root_1,
        success: true,
        error_message: None,
    };
    let commit_1 = tracker.record_ack(ack_leader).expect("record ack");
    // 1 of 2: Not yet quorum
    assert_eq!(commit_1, None);

    // Follower 1 ack
    let ack_follower = ReplicationAck {
        replica_id: "node-2-follower".to_string(),
        partition_id: 0,
        leader_epoch: 1,
        acked_offset: 0,
        acked_mmr_root: mmr_root_1,
        success: true,
        error_message: None,
    };
    let commit_2 = tracker.record_ack(ack_follower).expect("record ack");
    // 2 of 2: Quorum reached!
    assert_eq!(commit_2, Some(0));
    assert_eq!(tracker.highest_committed_offset(), Some(0));
    assert!(tracker.is_quorum_committed(0, &mmr_root_1));
}

#[test]
fn test_pcqr_zero_divergence_fork_quarantine() {
    // Test that history is NEVER truncated when an inconsistent MMR root arrives
    let validator = ZeroDivergenceValidator::new();

    let root_initial: HashDigest = [10u8; 32];
    let root_divergent: HashDigest = [99u8; 32];

    // Node is at offset 5 with root_initial
    let status = validator.validate_append(
        5,              // current_offset
        &root_initial,  // current_root
        5,              // incoming_offset
        &root_divergent // divergent_root attempting to overwrite/truncate history
    );

    // Must be rejected with QuarantinedFork error - no truncation allowed!
    assert!(status.is_err());
    let err = status.unwrap_err();
    assert!(err.to_string().contains("Zero-divergence violation"));
    assert!(err.to_string().contains("quarantined as corrupt fork"));
}

#[test]
fn test_pcqr_leader_and_follower_pipeline() {
    let dir_leader = tempdir().unwrap();
    let dir_follower = tempdir().unwrap();

    let mut leader = PcqrLeaderReplicator::new("broker-leader", dir_leader.path(), 3).expect("create leader");
    let mut follower = PcqrFollowerNode::new("broker-follower-1", dir_follower.path()).expect("create follower");

    // Leader appends a record
    let pulse = leader.replicate_record(
        0, // partition_id
        1, // leader_epoch
        b"HIGH_STAKES_PAYMENT_TX_9921",
    ).expect("replicate record");

    assert_eq!(pulse.offset, 0);
    assert_eq!(pulse.leader_epoch, 1);

    // Follower receives and processes pulse
    let ack = follower.handle_pulse(&pulse).expect("handle pulse");
    assert!(ack.success, "Follower ack failed: {:?}", ack.error_message);
    assert_eq!(ack.acked_offset, 0);
    assert_eq!(ack.acked_mmr_root, pulse.mmr_root);

    // Leader processes follower ack
    let committed_offset = leader.record_replica_ack(ack).expect("record ack");
    // Leader (1) + Follower (1) = 2/3 (Quorum achieved!)
    assert_eq!(committed_offset, Some(0));
    assert_eq!(leader.committed_offset(), Some(0));
}

#[test]
fn test_pcqr_leader_election_failover_check() {
    use vortex_storage::pcqr::PcqrElectionValidator;

    let candidate_a_state = vortex_storage::pcqr::ReplicaState {
        replica_id: "node-2".to_string(),
        last_offset: 100,
        last_mmr_root: [1u8; 32],
        last_leader_epoch: 2,
        status: ReplicaStatus::InSync,
    };

    let candidate_b_stale = vortex_storage::pcqr::ReplicaState {
        replica_id: "node-3".to_string(),
        last_offset: 95,
        last_mmr_root: [2u8; 32],
        last_leader_epoch: 1, // Stale epoch!
        status: ReplicaStatus::InSync,
    };

    let candidate_c_quarantined = vortex_storage::pcqr::ReplicaState {
        replica_id: "node-4".to_string(),
        last_offset: 105,
        last_mmr_root: [3u8; 32],
        last_leader_epoch: 2,
        status: ReplicaStatus::QuarantinedFork {
            divergent_offset: 50,
            expected_root: [1u8; 32],
            actual_root: [3u8; 32],
        },
    };

    // Candidate A vs Stale B: Candidate A wins because higher epoch and offset
    assert!(PcqrElectionValidator::is_candidate_eligible(&candidate_a_state, 2, 98));
    // Candidate B loses because stale epoch
    assert!(!PcqrElectionValidator::is_candidate_eligible(&candidate_b_stale, 2, 98));
    // Candidate C loses because it is quarantined as a corrupt fork!
    assert!(!PcqrElectionValidator::is_candidate_eligible(&candidate_c_quarantined, 2, 98));
}
