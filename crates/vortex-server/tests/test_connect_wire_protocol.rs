use std::sync::Arc;
use bytes::{Buf, BufMut, BytesMut};
use tempfile::tempdir;

use vortex_protocol::kafka::{KafkaApiKey, KafkaCodec, KafkaFrame, KafkaRequestHeader};
use vortex_server::bridge::KafkaBridge;
use vortex_server::coordinator::ConsumerGroupCoordinator;
use vortex_server::engine::Engine;

#[tokio::test]
async fn test_kafka_connect_admin_apis_roundtrip() {
    let dir = tempdir().unwrap();
    let engine = Arc::new(Engine::new(dir.path().to_path_buf()));
    let coordinator = Arc::new(
        ConsumerGroupCoordinator::new(dir.path(), std::time::Duration::from_secs(10)).unwrap(),
    );

    // 1. ApiVersions includes Connect APIs (CreateTopics, DeleteTopics, DescribeGroups, DescribeConfigs)
    let api_versions_frame = KafkaFrame {
        header: KafkaRequestHeader {
            api_key: KafkaApiKey::ApiVersions,
            api_version: 1,
            correlation_id: 101,
            client_id: Some("connect-distributed-worker".into()),
        },
        payload: BytesMut::new().freeze(),
    };
    let mut resp = KafkaBridge::handle_frame(api_versions_frame, engine.clone(), coordinator.clone()).await;
    let _len = resp.get_i32();
    let corr_id = resp.get_i32();
    assert_eq!(corr_id, 101);
    let err_code = resp.get_i16();
    assert_eq!(err_code, 0);

    // 2. CreateTopics Request (e.g. creating "connect-offsets", "snowflake-sink-topic")
    let mut create_payload = BytesMut::new();
    create_payload.put_i32(2); // 2 topics
    KafkaCodec::put_string(&mut create_payload, "connect-offsets");
    create_payload.put_i32(25); // 25 partitions
    create_payload.put_i16(1);  // replication factor
    create_payload.put_i32(0);  // assignments
    create_payload.put_i32(0);  // configs

    KafkaCodec::put_string(&mut create_payload, "snowflake-sink-topic");
    create_payload.put_i32(10);
    create_payload.put_i16(1);
    create_payload.put_i32(0);
    create_payload.put_i32(0);

    create_payload.put_i32(5000); // timeout
    create_payload.put_u8(0);    // validate_only

    let create_frame = KafkaFrame {
        header: KafkaRequestHeader {
            api_key: KafkaApiKey::CreateTopics,
            api_version: 1,
            correlation_id: 102,
            client_id: Some("connect-admin".into()),
        },
        payload: create_payload.freeze(),
    };
    let mut create_resp = KafkaBridge::handle_frame(create_frame, engine.clone(), coordinator.clone()).await;
    let _ = create_resp.get_i32(); // total size
    let c_corr = create_resp.get_i32();
    assert_eq!(c_corr, 102);
    let topic_count = create_resp.get_i32();
    assert_eq!(topic_count, 2);

    let t1_name = KafkaCodec::get_string(&mut create_resp).unwrap();
    assert_eq!(t1_name, "connect-offsets");
    let t1_err = create_resp.get_i16();
    assert_eq!(t1_err, 0);

    // 3. DescribeConfigs Request
    let mut describe_cfg_payload = BytesMut::new();
    describe_cfg_payload.put_i32(1); // 1 resource
    describe_cfg_payload.put_i8(2);  // ResourceType: TOPIC
    KafkaCodec::put_string(&mut describe_cfg_payload, "connect-offsets");
    describe_cfg_payload.put_i32(0); // all keys

    let desc_cfg_frame = KafkaFrame {
        header: KafkaRequestHeader {
            api_key: KafkaApiKey::DescribeConfigs,
            api_version: 0,
            correlation_id: 103,
            client_id: Some("connect-worker".into()),
        },
        payload: describe_cfg_payload.freeze(),
    };
    let mut desc_resp = KafkaBridge::handle_frame(desc_cfg_frame, engine.clone(), coordinator.clone()).await;
    let _ = desc_resp.get_i32();
    let d_corr = desc_resp.get_i32();
    assert_eq!(d_corr, 103);
    let _throttle = desc_resp.get_i32();
    let res_count = desc_resp.get_i32();
    assert_eq!(res_count, 1);
    let r_err = desc_resp.get_i16();
    assert_eq!(r_err, 0);

    // 4. DescribeGroups Request
    let mut desc_groups_payload = BytesMut::new();
    desc_groups_payload.put_i32(1);
    KafkaCodec::put_string(&mut desc_groups_payload, "connect-cluster-group");

    let desc_groups_frame = KafkaFrame {
        header: KafkaRequestHeader {
            api_key: KafkaApiKey::DescribeGroups,
            api_version: 1,
            correlation_id: 104,
            client_id: Some("connect-worker".into()),
        },
        payload: desc_groups_payload.freeze(),
    };
    let mut desc_g_resp = KafkaBridge::handle_frame(desc_groups_frame, engine.clone(), coordinator.clone()).await;
    let _ = desc_g_resp.get_i32();
    let g_corr = desc_g_resp.get_i32();
    assert_eq!(g_corr, 104);
    let _throttle = desc_g_resp.get_i32();
    let g_count = desc_g_resp.get_i32();
    assert_eq!(g_count, 1);
    let g_err = desc_g_resp.get_i16();
    assert_eq!(g_err, 0);
    let g_name = KafkaCodec::get_string(&mut desc_g_resp).unwrap();
    assert_eq!(g_name, "connect-cluster-group");
}
