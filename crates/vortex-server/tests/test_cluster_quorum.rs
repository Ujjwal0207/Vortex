use tempfile::tempdir;
use tokio::sync::mpsc;
use vortex_storage::pcqr::{
    MMRCommitPulse, PcqrElectionValidator, PcqrFollowerNode, PcqrLeaderReplicator,
    ReplicaState, ReplicaStatus, ReplicationAck,
};

#[tokio::test]
async fn test_three_node_cluster_replication_and_failover() {
    let dir_leader = tempdir().unwrap();
    let dir_follower_2 = tempdir().unwrap();
    let dir_follower_3 = tempdir().unwrap();

    // Initialize 3-broker cluster
    let mut leader = PcqrLeaderReplicator::new("broker-1-leader", dir_leader.path(), 3)
        .expect("init leader");
    let mut follower_2 = PcqrFollowerNode::new("broker-2-follower", dir_follower_2.path())
        .expect("init follower 2");
    let mut follower_3 = PcqrFollowerNode::new("broker-3-follower", dir_follower_3.path())
        .expect("init follower 3");

    // Inter-broker asynchronous pulse channels (simulating cluster network transport)
    let (pulse_tx_2, mut pulse_rx_2) = mpsc::channel::<MMRCommitPulse>(100);
    let (pulse_tx_3, mut pulse_rx_3) = mpsc::channel::<MMRCommitPulse>(100);
    let (ack_tx, mut ack_rx) = mpsc::channel::<ReplicationAck>(100);

    // Leader produces high-stakes financial ledger transaction
    let pulse = leader.replicate_record(0, 1, b"AUDIT_LEDGER_ENTRY_#88419")
        .expect("leader replicate");
    assert_eq!(pulse.offset, 0);

    // Broadcast pulse to both followers
    pulse_tx_2.send(pulse.clone()).await.unwrap();
    pulse_tx_3.send(pulse.clone()).await.unwrap();

    // Follower 2 receives and processes pulse
    let pulse_for_2 = pulse_rx_2.recv().await.unwrap();
    let ack_2 = follower_2.handle_pulse(&pulse_for_2).expect("follower 2 handle");
    assert!(ack_2.success);
    ack_tx.send(ack_2).await.unwrap();

    // Follower 3 receives and processes pulse
    let pulse_for_3 = pulse_rx_3.recv().await.unwrap();
    let ack_3 = follower_3.handle_pulse(&pulse_for_3).expect("follower 3 handle");
    assert!(ack_3.success);
    ack_tx.send(ack_3).await.unwrap();

    // Leader collects incoming acks
    let mut quorum_reached_offset = None;
    while let Ok(ack) = ack_rx.try_recv() {
        if let Ok(Some(committed_off)) = leader.record_replica_ack(ack) {
            quorum_reached_offset = Some(committed_off);
        }
    }

    assert_eq!(quorum_reached_offset, Some(0));
    assert_eq!(leader.committed_offset(), Some(0));

    // Test Failover: If Leader dies, Candidate 2 with offset 0 and matching MMR is elected
    let candidate_2_state = ReplicaState {
        replica_id: "broker-2".to_string(),
        last_offset: 0,
        last_mmr_root: pulse.mmr_root,
        last_leader_epoch: 1,
        status: ReplicaStatus::InSync,
    };

    assert!(PcqrElectionValidator::is_candidate_eligible(&candidate_2_state, 1, 0));
}
