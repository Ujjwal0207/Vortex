use vortex_core::{Record, TopicMode};
use bytes::Bytes;

#[test]
fn test_topic_mode_default_and_u8_mapping() {
    let default_mode = TopicMode::default();
    assert_eq!(default_mode, TopicMode::Verifiable);
    assert_eq!(default_mode.to_u8(), 0);
    assert!(default_mode.is_verifiable());
    assert!(!default_mode.is_raw());

    let raw_mode = TopicMode::Raw;
    assert_eq!(raw_mode.to_u8(), 1);
    assert!(raw_mode.is_raw());
    assert!(!raw_mode.is_verifiable());

    assert_eq!(TopicMode::from_u8(0), TopicMode::Verifiable);
    assert_eq!(TopicMode::from_u8(1), TopicMode::Raw);
    // Any unrecognized byte safely defaults to Verifiable (fail-safe principle)
    assert_eq!(TopicMode::from_u8(2), TopicMode::Verifiable);
    assert_eq!(TopicMode::from_u8(255), TopicMode::Verifiable);
}

#[test]
fn test_topic_mode_serde_roundtrip() {
    let mode = TopicMode::Raw;
    let serialized = serde_json::to_string(&mode).unwrap();
    let deserialized: TopicMode = serde_json::from_str(&serialized).unwrap();
    assert_eq!(mode, deserialized);

    let ver_mode = TopicMode::Verifiable;
    let serialized = serde_json::to_string(&ver_mode).unwrap();
    let deserialized: TopicMode = serde_json::from_str(&serialized).unwrap();
    assert_eq!(ver_mode, deserialized);
}

#[test]
fn test_record_new_raw_constructs_valid_header() {
    let key = Some(Bytes::from("order-99"));
    let val = Bytes::from("telemetry-payload-data");
    let rec = Record::new_raw(42, key.clone(), val.clone(), 1700000000);

    assert_eq!(rec.offset, 42);
    assert_eq!(rec.timestamp, 1700000000);
    assert_eq!(rec.prev_hash, [0u8; 32]);
    assert_ne!(rec.record_hash, [0u8; 32]);
    assert_eq!(rec.key, key);
    assert_eq!(rec.value, val);

    // Verify record encoding and decoding in Raw mode
    let bytes = rec.encode();
    let decoded_raw = Record::decode_raw(&mut bytes.clone()).unwrap();
    assert_eq!(decoded_raw.offset, 42);
    assert_eq!(decoded_raw.timestamp, 1700000000);
    assert_eq!(decoded_raw.key, rec.key);
    assert_eq!(decoded_raw.value, rec.value);
    assert_eq!(decoded_raw.record_hash, rec.record_hash);

    let decoded_with_mode = Record::decode_with_mode(&mut bytes.clone(), TopicMode::Raw).unwrap();
    assert_eq!(decoded_with_mode.offset, 42);

    // Verifiable decode on raw record must fail cryptographic lineage check (proves cryptographic fencing!)
    let verifiable_err = Record::decode(&mut bytes.clone());
    assert!(verifiable_err.is_err(), "Raw record decoded with Blake3 verification must fail");
}

#[test]
fn test_verifiable_record_roundtrip_with_topic_mode() {
    let rec = Record::new([0u8; 32], 100, None, Bytes::from("verifiable-event"));
    let bytes = rec.encode();

    // Verifiable decode succeeds
    let decoded = Record::decode(&mut bytes.clone()).unwrap();
    assert_eq!(decoded.offset, 100);

    // Raw decode also succeeds (CRC32 matches)
    let decoded_raw = Record::decode_raw(&mut bytes.clone()).unwrap();
    assert_eq!(decoded_raw.offset, 100);
}
