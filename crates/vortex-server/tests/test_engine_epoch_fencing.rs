use bytes::Bytes;
use tempfile::tempdir;
use vortex_core::VortexError;
use vortex_protocol::ProduceRequest;
use vortex_server::Engine;

#[tokio::test]
async fn test_engine_produce_with_epoch_zombie_fencing_and_concurrency() {
    let dir = tempdir().unwrap();
    let engine = Engine::new(dir.path().to_path_buf());
    let topic = "distributed-consensus-ledger";

    // 1. Initial write with default epoch 0
    let req0 = ProduceRequest {
        topic: topic.to_string(),
        partition: 0,
        key: None,
        value: Bytes::from_static(b"epoch-0-entry"),
    };
    let resp0 = engine.produce_with_epoch(req0, 0).await.expect("Epoch 0 produce succeeds");
    assert_eq!(resp0.offset, 0);

    // 2. Simulate cluster leader election: partition advances to epoch 10
    engine.advance_leader_epoch(topic, 0, 10).await.unwrap();
    assert_eq!(engine.leader_epoch(topic, 0).await.unwrap(), 10);

    // 3. 100 requests from stale/zombie leader with epoch 9 vs 100 requests with epoch 10
    for i in 0..100 {
        let zombie_req = ProduceRequest {
            topic: topic.to_string(),
            partition: 0,
            key: Some(Bytes::from(format!("zombie-key-{}", i))),
            value: Bytes::from(format!("zombie-val-{}", i)),
        };
        let err = engine.produce_with_epoch(zombie_req, 9).await.unwrap_err();
        match err {
            VortexError::FencedLeaderEpoch { current, attempted } => {
                assert_eq!(current, 10);
                assert_eq!(attempted, 9);
            }
            other => panic!("Expected FencedLeaderEpoch, got {:?}", other),
        }

        let valid_req = ProduceRequest {
            topic: topic.to_string(),
            partition: 0,
            key: Some(Bytes::from(format!("leader-key-{}", i))),
            value: Bytes::from(format!("leader-val-{}", i)),
        };
        let resp = engine.produce_with_epoch(valid_req, 10).await.unwrap();
        assert_eq!(resp.offset, (i + 1) as u64);
    }

    // 4. Verify partition bounds: exactly 101 records (offset 0 + 100 valid writes)
    let (earliest, next) = engine.partition_bounds(topic, 0).await.unwrap();
    assert_eq!(earliest, 0);
    assert_eq!(next, 101);
}
