use tempfile::tempdir;
use bytes::Bytes;
use vortex_core::TopicMode;
use vortex_protocol::{FetchRequest, ProduceRequest};
use vortex_server::engine::Engine;

#[tokio::test]
async fn test_engine_dynamic_dual_mode_provisioning() {
    let dir = tempdir().unwrap();
    let engine = Engine::new(dir.path().to_path_buf());

    // 1. Topic ending in ".raw" dynamically defaults to TopicMode::Raw
    let mode_raw = engine.topic_mode("clickstream.raw", 0).await.unwrap();
    assert_eq!(mode_raw, TopicMode::Raw);
    assert!(mode_raw.is_raw());

    // 2. Standard topic defaults to TopicMode::Verifiable
    let mode_verifiable = engine.topic_mode("agent.decisions", 0).await.unwrap();
    assert_eq!(mode_verifiable, TopicMode::Verifiable);
    assert!(mode_verifiable.is_verifiable());

    // 3. Explicit creation with mode
    engine.create_topic_with_mode("high-throughput-iot", 3, TopicMode::Raw).await.unwrap();
    for p in 0..3 {
        let mode = engine.topic_mode("high-throughput-iot", p).await.unwrap();
        assert_eq!(mode, TopicMode::Raw);
    }
}

#[tokio::test]
async fn test_engine_produce_fetch_raw_mode_end_to_end() {
    let dir = tempdir().unwrap();
    let engine = Engine::new(dir.path().to_path_buf());

    // Produce 20 raw records
    for i in 0..20 {
        let req = ProduceRequest {
            topic: "telemetry.raw".to_string(),
            partition: 0,
            key: Some(Bytes::from(format!("sensor-{i}"))),
            value: Bytes::from(format!("reading-value-{i}")),
        };
        let resp = engine.produce(req).await.unwrap();
        assert_eq!(resp.offset, i as u64);
        assert_ne!(resp.record_hash, [0u8; 32]);
    }

    // Fetch back
    let fetch_req = FetchRequest {
        topic: "telemetry.raw".to_string(),
        partition: 0,
        start_offset: 0,
        max_bytes: 1024 * 1024,
    };
    let fetch_resp = engine.fetch(fetch_req).await.unwrap();
    assert_eq!(fetch_resp.records.len(), 20);
    assert_eq!(fetch_resp.records[0].offset, 0);
    assert_eq!(fetch_resp.records[0].prev_hash, [0u8; 32]); // Raw mode record has blank prev_hash
    assert_eq!(fetch_resp.records[19].offset, 19);

    // Verify partition bounds
    let (earliest, next) = engine.partition_bounds("telemetry.raw", 0).await.unwrap();
    assert_eq!(earliest, 0);
    assert_eq!(next, 20);
}

#[tokio::test]
async fn test_engine_produce_fetch_verifiable_mode_end_to_end() {
    let dir = tempdir().unwrap();
    let engine = Engine::new(dir.path().to_path_buf());

    // Produce 10 verifiable records
    for i in 0..10 {
        let req = ProduceRequest {
            topic: "financial.audit".to_string(),
            partition: 0,
            key: Some(Bytes::from(format!("tx-{i}"))),
            value: Bytes::from(format!("settlement-amount-{i}")),
        };
        let resp = engine.produce(req).await.unwrap();
        assert_eq!(resp.offset, i as u64);
        assert_ne!(resp.record_hash, [0u8; 32]);
    }

    let fetch_req = FetchRequest {
        topic: "financial.audit".to_string(),
        partition: 0,
        start_offset: 0,
        max_bytes: 1024 * 1024,
    };
    let fetch_resp = engine.fetch(fetch_req).await.unwrap();
    assert_eq!(fetch_resp.records.len(), 10);
    assert_eq!(fetch_resp.records[0].offset, 0);
    // Verifiable records have continuous cryptographic hash chain
    assert_eq!(fetch_resp.records[1].prev_hash, fetch_resp.records[0].record_hash);
}

