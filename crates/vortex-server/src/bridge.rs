use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tracing::warn;

use vortex_core::error::VortexError;
use vortex_core::record::Record;
use vortex_protocol::kafka::{KafkaApiKey, KafkaCodec, KafkaFrame, Varint};
use vortex_protocol::FetchRequest;

use crate::coordinator::ConsumerGroupCoordinator;
use crate::engine::Engine;

pub struct KafkaBridge;

impl KafkaBridge {
    pub const SUPPORTED_API_VERSIONS: &'static [(i16, i16, i16)] = &[
        (0, 5, 5),   // Produce
        (1, 5, 5),   // Fetch
        (2, 0, 5),   // ListOffsets
        (3, 1, 1),   // Metadata
        (8, 2, 5),   // OffsetCommit
        (9, 2, 5),   // OffsetFetch
        (10, 0, 2),  // FindCoordinator
        (11, 0, 5),  // JoinGroup
        (12, 0, 0),  // Heartbeat
        (13, 0, 0),  // LeaveGroup
        (14, 0, 0),  // SyncGroup
        (18, 1, 1),  // ApiVersions
    ];

    fn build_unsupported_version_response(api_key: i16) -> Bytes {
        let mut buf = BytesMut::with_capacity(16);
        if api_key == 18 {
            buf.put_i16(35); // UNSUPPORTED_VERSION
            buf.put_i32(0);  // Empty api_keys array
            buf.put_i32(0);  // ThrottleTimeMs
        } else {
            buf.put_i32(0);  // ThrottleTimeMs
            buf.put_i16(35); // UNSUPPORTED_VERSION
        }
        buf.freeze()
    }

    pub async fn handle_frame(
        frame: KafkaFrame,
        engine: Arc<Engine>,
        coordinator: Arc<ConsumerGroupCoordinator>,
    ) -> Bytes {
        let correlation_id = frame.header.correlation_id;
        let api_version = frame.header.api_version;
        let mut payload = frame.payload;

        let api_key_num = match frame.header.api_key {
            KafkaApiKey::Produce => 0,
            KafkaApiKey::Fetch => 1,
            KafkaApiKey::ListOffsets => 2,
            KafkaApiKey::Metadata => 3,
            KafkaApiKey::OffsetCommit => 8,
            KafkaApiKey::OffsetFetch => 9,
            KafkaApiKey::FindCoordinator => 10,
            KafkaApiKey::JoinGroup => 11,
            KafkaApiKey::Heartbeat => 12,
            KafkaApiKey::LeaveGroup => 13,
            KafkaApiKey::SyncGroup => 14,
            KafkaApiKey::ApiVersions => 18,
            KafkaApiKey::InitProducerId => 22,
            KafkaApiKey::Unknown(k) => k,
        };

        // Strict API version validation against advertised schema matrix
        if let Some(&(_, min_v, max_v)) = Self::SUPPORTED_API_VERSIONS
            .iter()
            .find(|&&(k, _, _)| k == api_key_num)
        {
            if api_version < min_v || api_version > max_v {
                let err_body = Self::build_unsupported_version_response(api_key_num);
                return KafkaFrame::build_response(correlation_id, err_body);
            }
        }

        let response_body = match frame.header.api_key {
            KafkaApiKey::ApiVersions => Self::handle_api_versions(api_version),
            KafkaApiKey::Metadata => Self::handle_metadata(&mut payload, api_version),
            KafkaApiKey::Produce => Self::handle_produce(&mut payload, &engine).await,
            KafkaApiKey::Fetch => Self::handle_fetch(&mut payload, &engine).await,
            KafkaApiKey::ListOffsets => Self::handle_list_offsets(&mut payload, &engine, api_version).await,
            KafkaApiKey::FindCoordinator => Self::handle_find_coordinator(&mut payload),
            KafkaApiKey::JoinGroup => Self::handle_join_group(&mut payload, &coordinator),
            KafkaApiKey::SyncGroup => Self::handle_sync_group(&mut payload, &coordinator),
            KafkaApiKey::Heartbeat => Self::handle_heartbeat(&mut payload, &coordinator),
            KafkaApiKey::LeaveGroup => Self::handle_leave_group(&mut payload, &coordinator),
            KafkaApiKey::OffsetCommit => Self::handle_offset_commit(&mut payload, &coordinator),
            KafkaApiKey::OffsetFetch => Self::handle_offset_fetch(&mut payload, &coordinator),
            KafkaApiKey::InitProducerId => Self::handle_init_producer_id(),
            KafkaApiKey::Unknown(k) => {
                warn!("Unsupported Kafka ApiKey {}; returning empty response", k);
                Bytes::new()
            }
        };

        KafkaFrame::build_response(correlation_id, response_body)
    }

    fn handle_api_versions(_version: i16) -> Bytes {
        let mut buf = BytesMut::with_capacity(128);
        buf.put_i16(0); // ErrorCode: NONE

        buf.put_i32(Self::SUPPORTED_API_VERSIONS.len() as i32);
        for &(key, min_v, max_v) in Self::SUPPORTED_API_VERSIONS {
            buf.put_i16(key);
            buf.put_i16(min_v);
            buf.put_i16(max_v);
        }

        buf.put_i32(0); // ThrottleTimeMs
        buf.freeze()
    }

    fn handle_metadata(payload: &mut Bytes, _version: i16) -> Bytes {
        // Read requested topics array
        let mut requested_topics = Vec::new();
        if payload.remaining() >= 4 {
            let topic_count = payload.get_i32();
            if topic_count > 0 {
                for _ in 0..topic_count {
                    if let Ok(topic) = KafkaCodec::get_string(payload) {
                        requested_topics.push(topic);
                    }
                }
            }
        }

        if requested_topics.is_empty() {
            requested_topics.push("default".to_string());
        }

        let mut buf = BytesMut::with_capacity(256);
        buf.put_i32(0); // ThrottleTimeMs

        // Brokers Array: 1 broker (node 0 @ 127.0.0.1:9092)
        buf.put_i32(1); // Broker count
        buf.put_i32(0); // NodeId: 0
        KafkaCodec::put_string(&mut buf, "127.0.0.1");
        buf.put_i32(9092); // Port
        buf.put_i16(-1);   // Rack: null

        // ClusterId
        KafkaCodec::put_string(&mut buf, "vortex-cluster");
        buf.put_i32(0); // ControllerId: 0

        // Topics Array
        buf.put_i32(requested_topics.len() as i32);
        for topic in requested_topics {
            buf.put_i16(0); // ErrorCode: NONE
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_u8(0); // IsInternal: false

            // Partitions array: 1 partition (partition 0)
            buf.put_i32(1); // Partition count
            buf.put_i16(0); // ErrorCode: NONE
            buf.put_i32(0); // PartitionIndex: 0
            buf.put_i32(0); // LeaderId: 0
            buf.put_i32(1); // LeaderEpoch: 1
            
            // Replicas: [0]
            buf.put_i32(1);
            buf.put_i32(0);

            // ISR: [0]
            buf.put_i32(1);
            buf.put_i32(0);

            // OfflineReplicas: []
            buf.put_i32(0);
        }

        buf.freeze()
    }

    async fn handle_produce(payload: &mut Bytes, engine: &Engine) -> Bytes {
        // Parse ProduceRequest fields
        let tx_id = if payload.remaining() >= 2 {
            let len = payload.get_i16();
            if len == -1 {
                None
            } else if len >= 0 && payload.remaining() >= len as usize {
                Some(payload.copy_to_bytes(len as usize))
            } else {
                // The request cannot be safely parsed. Preserve enough state to fail
                // each partition rather than treating a malformed ID as null.
                Some(Bytes::new())
            }
        } else {
            None
        };

        let _acks = if payload.remaining() >= 2 { payload.get_i16() } else { 1 };
        let _timeout_ms = if payload.remaining() >= 4 { payload.get_i32() } else { 1500 };

        let mut produced_results = Vec::new();

        if payload.remaining() >= 4 {
            let topic_count = payload.get_i32();
            for _ in 0..topic_count {
                if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                    if payload.remaining() >= 4 {
                        let part_count = payload.get_i32();
                        for _ in 0..part_count {
                            if payload.remaining() >= 8 {
                                let partition_idx = payload.get_i32() as u32;
                                let record_bytes_len = payload.get_i32();

                                if record_bytes_len > 0 && payload.remaining() >= record_bytes_len as usize {
                                    let mut record_data = payload.copy_to_bytes(record_bytes_len as usize);
                                    let parsed = Self::parse_records(&mut record_data);

                                    let mut first_offset = None;
                                    let (mut error_code, records) = match parsed {
                                        Ok(records) if records.is_empty() => (42, Vec::new()),
                                        Ok(records) => (0, records),
                                        Err(code) => (code, Vec::new()),
                                    };

                                    if error_code == 0 && tx_id.is_some() {
                                        // Transactional Produce is rejected until the broker has
                                        // durable transaction state, markers, and LSO tracking.
                                        error_code = 48; // INVALID_TXN_STATE
                                    }

                                    if error_code == 0 {
                                        match engine
                                            .produce_batch(&topic_name, partition_idx, records)
                                            .await
                                        {
                                            Ok(responses) => {
                                                if let Some(first) = responses.first() {
                                                    first_offset = Some(first.offset);
                                                }
                                            }
                                            Err(error) => {
                                                error_code = kafka_error_code(&error);
                                            }
                                        }
                                    }

                                    let log_start = engine
                                        .partition_bounds(&topic_name, partition_idx)
                                        .await
                                        .map_or(0, |(earliest, _)| earliest);
                                    produced_results.push((
                                        topic_name.clone(),
                                        partition_idx,
                                        first_offset,
                                        error_code,
                                        log_start,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build ProduceResponse
        let mut buf = BytesMut::with_capacity(256);
        buf.put_i32(produced_results.len() as i32); // Topic count

        for (topic, partition_idx, offset, error_code, log_start) in produced_results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partition count
            buf.put_i32(partition_idx as i32);
            buf.put_i16(error_code);
            // Kafka ProduceResponse reports the first offset in the appended batch.
            buf.put_i64(offset.map_or(-1, |offset| offset as i64));
            buf.put_i64(-1); // CreateTime is preserved; no LogAppendTime topic mode is configured.
            buf.put_i64(log_start as i64);
        }

        buf.put_i32(0); // ThrottleTimeMs
        buf.freeze()
    }

    async fn handle_fetch(payload: &mut Bytes, engine: &Engine) -> Bytes {
        let _replica_id = if payload.remaining() >= 4 { payload.get_i32() } else { -1 };
        let _max_wait_ms = if payload.remaining() >= 4 { payload.get_i32() } else { 500 };
        let _min_bytes = if payload.remaining() >= 4 { payload.get_i32() } else { 1 };
        let _max_bytes = if payload.remaining() >= 4 { payload.get_i32() } else { 1024 * 1024 };
        let isolation = if payload.remaining() >= 1 { payload.get_i8() } else { 0 };

        let mut fetch_results = Vec::new();

        if payload.remaining() >= 4 {
            let topic_count = payload.get_i32();
            for _ in 0..topic_count {
                if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                    if payload.remaining() >= 4 {
                        let part_count = payload.get_i32();
                        for _ in 0..part_count {
                            if payload.remaining() >= 16 {
                                let partition_idx = payload.get_i32() as u32;
                                let fetch_offset = payload.get_i64() as u64;
                                let _log_start_offset = payload.get_i64();
                                let max_bytes = if payload.remaining() >= 4 { payload.get_i32() } else { 64 * 1024 };

                                let req = FetchRequest {
                                    topic: topic_name.clone(),
                                    partition: partition_idx,
                                    start_offset: fetch_offset,
                                    max_bytes: max_bytes as u32,
                                };

                                let (records, error_code) = if isolation == 1 {
                                    // Historical segments do not record producer metadata, so
                                    // ReadCommitted cannot prove whether an old batch was open.
                                    // Reject the request rather than risk returning in-flight data.
                                    (Vec::new(), 43) // UNSUPPORTED_FOR_MESSAGE_FORMAT
                                } else {
                                    match engine.fetch(req).await {
                                        // Transactional and producer-sequenced batches are
                                        // rejected at ingress, and user payload bytes stay opaque.
                                        Ok(resp) => (resp.records, 0),
                                        Err(error) => (Vec::new(), kafka_error_code(&error)),
                                    }
                                };

                                let (earliest, latest) = engine
                                    .partition_bounds(&topic_name, partition_idx)
                                    .await
                                    .unwrap_or((0, 0));
                                fetch_results.push((
                                    topic_name.clone(),
                                    partition_idx,
                                    records,
                                    error_code,
                                    earliest,
                                    latest,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Build FetchResponse
        let mut buf = BytesMut::with_capacity(512);
        buf.put_i32(0); // ThrottleTimeMs

        buf.put_i32(fetch_results.len() as i32);
        for (topic, partition_idx, records, error_code, earliest, latest) in fetch_results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partitions count
            buf.put_i32(partition_idx as i32);
            buf.put_i16(error_code);

            buf.put_i64(latest as i64); // HighWatermark
            buf.put_i64(latest as i64); // LastStableOffset
            buf.put_i64(earliest as i64); // LogStartOffset
            buf.put_i32(0); // AbortedTransactions count

            // Encode records as Kafka RecordBatch frame
            let batch_bytes = Self::encode_record_batch(&records);
            KafkaCodec::put_bytes(&mut buf, &batch_bytes);
        }

        buf.freeze()
    }

    async fn handle_list_offsets(payload: &mut Bytes, engine: &Engine, api_version: i16) -> Bytes {
        let mut results = Vec::new();

        if payload.remaining() >= 4 {
            let _replica_id = payload.get_i32();
            if api_version >= 2 && payload.remaining() >= 1 {
                let _isolation = payload.get_i8();
            }

            if payload.remaining() >= 4 {
                let topic_count = payload.get_i32();
                for _ in 0..topic_count {
                    if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                        if payload.remaining() >= 4 {
                            let part_count = payload.get_i32();
                            for _ in 0..part_count {
                                if payload.remaining() >= 12 {
                                    let partition_idx = payload.get_i32() as u32;
                                    if api_version >= 4 && payload.remaining() >= 4 {
                                        let _current_leader_epoch = payload.get_i32();
                                    }
                                    let timestamp = payload.get_i64();
                                    if api_version == 0 && payload.remaining() >= 4 {
                                        let _max_num_offsets = payload.get_i32();
                                    }

                                    let (earliest, latest) = engine
                                        .partition_bounds(&topic_name, partition_idx)
                                        .await
                                        .unwrap_or((0, 0));
                                    let (offset, error_code) = match timestamp {
                                        -2 => (earliest as i64, 0),
                                        -1 => (latest as i64, 0),
                                        _ => (-1, 42), // INVALID_REQUEST: timestamp lookup is not implemented.
                                    };
                                    results.push((topic_name.clone(), partition_idx, offset, error_code));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut buf = BytesMut::with_capacity(256);
        if api_version >= 2 {
            buf.put_i32(0); // ThrottleTimeMs
        }
        buf.put_i32(results.len() as i32);

        for (topic, part, offset, error_code) in results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partitions count
            buf.put_i32(part as i32);
            buf.put_i16(error_code);
            if api_version == 0 {
                buf.put_i32(1); // One offset result
                buf.put_i64(offset);
                continue;
            }
            buf.put_i64(-1); // Timestamp is unavailable for earliest/latest lookup.
            buf.put_i64(offset);
            if api_version >= 4 {
                buf.put_i32(1); // LeaderEpoch
            }
        }

        buf.freeze()
    }

    fn handle_find_coordinator(payload: &mut Bytes) -> Bytes {
        let _key = KafkaCodec::get_string(payload).unwrap_or_default();
        let _key_type = if payload.remaining() >= 1 { payload.get_i8() } else { 0 };

        let mut buf = BytesMut::with_capacity(64);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE
        buf.put_i16(-1); // ErrorMessage: null
        buf.put_i32(0); // NodeId: 0
        KafkaCodec::put_string(&mut buf, "127.0.0.1");
        buf.put_i32(9092); // Port: 9092
        buf.freeze()
    }

    fn handle_join_group(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let group_id = KafkaCodec::get_string(payload).unwrap_or_else(|_| "default-group".to_string());
        let _session_timeout = if payload.remaining() >= 4 { payload.get_i32() } else { 30000 };
        let _rebalance_timeout = if payload.remaining() >= 4 { payload.get_i32() } else { 30000 };
        let mut member_id = KafkaCodec::get_string(payload).unwrap_or_default();
        if member_id.is_empty() {
            member_id = format!(
                "vortex-member-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(1)
            );
        }
        let instance_id = if payload.remaining() >= 2 {
            let s = KafkaCodec::get_string(payload).ok();
            s.filter(|v| !v.is_empty())
        } else {
            None
        };
        let _protocol_type = KafkaCodec::get_string(payload).unwrap_or_else(|_| "consumer".to_string());

        // Parse subscribed protocols/topics
        let mut topics = Vec::new();
        if payload.remaining() >= 4 {
            let proto_count = payload.get_i32();
            for _ in 0..proto_count {
                if let Ok(p_name) = KafkaCodec::get_string(payload) {
                    if let Ok(metadata_bytes) = KafkaCodec::get_bytes(payload) {
                        topics.push(p_name);
                        let _ = metadata_bytes;
                    }
                }
            }
        }
        if topics.is_empty() {
            topics.push("default".to_string());
        }

        let reg_res = coordinator.register_or_heartbeat(&group_id, &member_id, instance_id, &topics, 1);
        let (error_code, generation_id, assigned_parts) = match reg_res {
            Ok(state) => (0i16, state.member_epoch as i32, state.assigned_partitions),
            Err(_) => (25i16, 0i32, Vec::new()), // UNKNOWN_MEMBER_ID
        };

        let mut buf = BytesMut::with_capacity(128);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(error_code);
        buf.put_i32(generation_id);
        KafkaCodec::put_string(&mut buf, "range"); // ProtocolName
        KafkaCodec::put_string(&mut buf, &member_id); // LeaderId
        KafkaCodec::put_string(&mut buf, &member_id); // MemberId

        // Members array (leader receives all members)
        buf.put_i32(1); // 1 member
        KafkaCodec::put_string(&mut buf, &member_id);
        buf.put_i16(-1); // GroupInstanceId: null

        // Member metadata (assigned partitions or subscription)
        let mut meta_buf = BytesMut::with_capacity(64);
        meta_buf.put_i16(0); // Version: 0
        meta_buf.put_i32(assigned_parts.len() as i32);
        for (top, part) in assigned_parts {
            KafkaCodec::put_string(&mut meta_buf, &top);
            meta_buf.put_i32(1); // 1 partition
            meta_buf.put_i32(part as i32);
        }
        meta_buf.put_i32(0); // UserData: null
        KafkaCodec::put_bytes(&mut buf, &meta_buf.freeze());

        buf.freeze()
    }

    fn handle_sync_group(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let _group_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let _generation_id = if payload.remaining() >= 4 { payload.get_i32() } else { 1 };
        let _member_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let _instance_id = if payload.remaining() >= 2 { KafkaCodec::get_string(payload).ok() } else { None };

        let _ = coordinator;

        let mut buf = BytesMut::with_capacity(128);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE

        // Member assignment: ConsumerProtocolAssignment version 0
        let mut assign_buf = BytesMut::with_capacity(64);
        assign_buf.put_i16(0); // Version 0
        assign_buf.put_i32(1); // 1 topic
        KafkaCodec::put_string(&mut assign_buf, "default");
        assign_buf.put_i32(1); // 1 partition
        assign_buf.put_i32(0); // Partition 0
        assign_buf.put_i32(0); // UserData: null
        KafkaCodec::put_bytes(&mut buf, &assign_buf.freeze());

        buf.freeze()
    }

    fn handle_heartbeat(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let group_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let _generation_id = if payload.remaining() >= 4 { payload.get_i32() } else { 1 };
        let member_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let instance_id = if payload.remaining() >= 2 { KafkaCodec::get_string(payload).ok() } else { None };

        let _ = coordinator.register_or_heartbeat(&group_id, &member_id, instance_id, &[], 1);

        let mut buf = BytesMut::with_capacity(16);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE
        buf.freeze()
    }

    fn handle_leave_group(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let group_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let member_id = KafkaCodec::get_string(payload).unwrap_or_default();

        let _ = coordinator.leave_group(&group_id, &member_id);

        let mut buf = BytesMut::with_capacity(16);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE
        buf.freeze()
    }

    fn handle_offset_commit(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let group_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let generation_id = if payload.remaining() >= 4 { payload.get_i32() } else { 1 };
        let member_id = KafkaCodec::get_string(payload).unwrap_or_default();

        let mut commit_results = Vec::new();

        if payload.remaining() >= 4 {
            let topic_count = payload.get_i32();
            for _ in 0..topic_count {
                if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                    if payload.remaining() >= 4 {
                        let part_count = payload.get_i32();
                        for _ in 0..part_count {
                            if payload.remaining() >= 12 {
                                let partition_idx = payload.get_i32() as u32;
                                let committed_offset = payload.get_i64();
                                let _leader_epoch = if payload.remaining() >= 4 { payload.get_i32() } else { -1 };
                                let _metadata = KafkaCodec::get_string(payload).ok();

                                let err_code = match coordinator.commit_offset(
                                    &group_id,
                                    &member_id,
                                    generation_id as u32,
                                    &topic_name,
                                    partition_idx,
                                    committed_offset,
                                ) {
                                    Ok(_) => 0i16,
                                    Err(VortexError::FencedMemberEpoch { .. }) => 22i16, // ILLEGAL_GENERATION
                                    Err(_) => 25i16, // UNKNOWN_MEMBER_ID
                                };

                                commit_results.push((topic_name.clone(), partition_idx, err_code));
                            }
                        }
                    }
                }
            }
        }

        let mut buf = BytesMut::with_capacity(128);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i32(commit_results.len() as i32);
        for (top, part, err) in commit_results {
            KafkaCodec::put_string(&mut buf, &top);
            buf.put_i32(1); // 1 partition
            buf.put_i32(part as i32);
            buf.put_i16(err);
        }
        buf.freeze()
    }

    fn handle_offset_fetch(payload: &mut Bytes, coordinator: &ConsumerGroupCoordinator) -> Bytes {
        let group_id = KafkaCodec::get_string(payload).unwrap_or_default();
        let mut fetch_results = Vec::new();

        if payload.remaining() >= 4 {
            let topic_count = payload.get_i32();
            for _ in 0..topic_count {
                if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                    if payload.remaining() >= 4 {
                        let part_count = payload.get_i32();
                        for _ in 0..part_count {
                            if payload.remaining() >= 4 {
                                let partition_idx = payload.get_i32() as u32;
                                let committed = coordinator
                                    .fetch_offset(&group_id, &topic_name, partition_idx)
                                    .unwrap_or(-1);
                                fetch_results.push((topic_name.clone(), partition_idx, committed));
                            }
                        }
                    }
                }
            }
        }

        let mut buf = BytesMut::with_capacity(128);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i32(fetch_results.len() as i32);
        for (top, part, offset) in fetch_results {
            KafkaCodec::put_string(&mut buf, &top);
            buf.put_i32(1); // 1 partition
            buf.put_i32(part as i32);
            buf.put_i64(offset);
            buf.put_i32(1); // LeaderEpoch
            buf.put_i16(-1); // Metadata: null
            buf.put_i16(0); // ErrorCode: NONE
        }
        buf.put_i16(0); // Top-level ErrorCode: NONE
        buf.freeze()
    }

    fn handle_init_producer_id() -> Bytes {
        // This API is intentionally not advertised. Returning a synthetic ID
        // would imply idempotence support that is not durable or connected to
        // the Produce path.
        let mut buf = BytesMut::with_capacity(32);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(35); // UNSUPPORTED_VERSION / feature unavailable
        buf.put_i64(-1); // ProducerId
        buf.put_i16(-1); // ProducerEpoch
        buf.freeze()
    }

    /// Parses only uncompressed, non-transactional Kafka RecordBatch data that the
    /// current storage model can represent without losing transaction semantics.
    fn parse_records(data: &mut Bytes) -> Result<Vec<(Option<Bytes>, Bytes, Option<u64>)>, i16> {
        let mut parsed = Vec::new();
        while data.has_remaining() {
            if data.remaining() < 12 {
                return Err(87); // INVALID_RECORD
            }
            let batch_size = i32::from_be_bytes(data[..12][8..12].try_into().unwrap());
            if batch_size < 49 {
                return Err(87);
            }
            let total_size = 12usize.checked_add(batch_size as usize).ok_or(87i16)?;
            if total_size > data.remaining() {
                return Err(87);
            }
            let mut batch = data.split_to(total_size);
            let (expected_crc, actual_crc) = {
                let batch_bytes = batch.as_ref();
                (
                    u32::from_be_bytes(batch_bytes[17..21].try_into().unwrap()),
                    crc32c(&batch_bytes[21..]),
                )
            };
            if actual_crc != expected_crc {
                return Err(87);
            }

            let _base_offset = batch.get_i64();
            let declared_batch_size = batch.get_i32();
            let _partition_leader_epoch = batch.get_i32();
            let magic = batch.get_i8();
            let _crc_field = batch.get_u32();
            if magic != 2 || declared_batch_size as usize + 12 != total_size {
                return Err(87);
            }

            let attributes = batch.get_i16() as u16;
            if attributes & 0x07 != 0 {
                return Err(76); // UNSUPPORTED_COMPRESSION_TYPE
            }
            if attributes & (1 << 3) != 0 {
                return Err(43); // LogAppendTime mode is not configured for this topic.
            }
            if attributes & (1 << 4) != 0 || attributes & (1 << 5) != 0 {
                return Err(48); // INVALID_TXN_STATE
            }
            let last_offset_delta = batch.get_i32();
            let first_timestamp = batch.get_i64();
            let _max_timestamp = batch.get_i64();
            let producer_id = batch.get_i64();
            let producer_epoch = batch.get_i16();
            let base_sequence = batch.get_i32();
            let record_count = batch.get_i32();
            if producer_id != -1 || producer_epoch != -1 || base_sequence != -1 {
                return Err(43); // UNSUPPORTED_FOR_MESSAGE_FORMAT
            }
            if record_count <= 0 || last_offset_delta < 0 || record_count > batch.remaining() as i32 {
                return Err(87);
            }

            let mut last_seen_offset_delta = -1i64;
            for _ in 0..record_count {
                let record_len = read_kafka_varint(&mut batch).ok_or(87i16)?;
                if record_len < 0 || record_len as usize > batch.remaining() {
                    return Err(87);
                }
                let mut record = batch.split_to(record_len as usize);
                if !record.has_remaining() || record.get_i8() != 0 {
                    return Err(87);
                }
                let timestamp_delta = read_kafka_varint(&mut record).ok_or(87i16)?;
                let timestamp = first_timestamp
                    .checked_add(timestamp_delta)
                    .filter(|timestamp| *timestamp >= 0)
                    .ok_or(87i16)? as u64;
                let offset_delta = read_kafka_varint(&mut record).ok_or(87i16)?;
                if offset_delta < 0 || offset_delta > last_offset_delta as i64 || offset_delta <= last_seen_offset_delta {
                    return Err(87);
                }
                last_seen_offset_delta = offset_delta;

                let key_len = read_kafka_varint(&mut record).ok_or(87i16)?;
                let key = match key_len {
                    -1 => None,
                    n if n >= 0 && n as usize <= record.remaining() => Some(record.split_to(n as usize)),
                    _ => return Err(87),
                };
                let value_len = read_kafka_varint(&mut record).ok_or(87i16)?;
                // Vortex's current Record model cannot represent Kafka tombstones.
                let value = match value_len {
                    n if n >= 0 && n as usize <= record.remaining() => record.split_to(n as usize),
                    _ => return Err(87),
                };
                let header_count = read_kafka_varint(&mut record).ok_or(87i16)?;
                if header_count != 0 || record.has_remaining() {
                    return Err(87);
                }
                parsed.push((key, value, Some(timestamp)));
            }
            if batch.has_remaining() {
                return Err(87);
            }
        }
        Ok(parsed)
    }

    /// Serializes native Vortex Records into a standard Kafka RecordBatch frame (magic = 2).
    fn encode_record_batch(records: &[Record]) -> Bytes {
        if records.is_empty() {
            return Bytes::new();
        }

        let first_offset = records[0].offset;
        let first_timestamp = records[0].timestamp as i64;
        let max_timestamp = records
            .iter()
            .map(|record| record.timestamp)
            .max()
            .unwrap_or_default() as i64;
        let mut records_buf = BytesMut::new();

        for r in records {
            let offset_delta = (r.offset - first_offset) as i64;
            let mut single_rec = BytesMut::new();
            single_rec.put_u8(0); // Attributes
            Varint::put_varint(&mut single_rec, r.timestamp as i64 - first_timestamp);
            Varint::put_varint(&mut single_rec, offset_delta);

            if let Some(ref k) = r.key {
                Varint::put_varint(&mut single_rec, k.len() as i64);
                single_rec.put_slice(k);
            } else {
                Varint::put_varint(&mut single_rec, -1);
            }

            Varint::put_varint(&mut single_rec, r.value.len() as i64);
            single_rec.put_slice(&r.value);
            Varint::put_varint(&mut single_rec, 0); // Headers count

            Varint::put_varint(&mut records_buf, single_rec.len() as i64);
            records_buf.put_slice(&single_rec);
        }

        let batch_body_len = 49 + records_buf.len();
        let mut batch = BytesMut::with_capacity(12 + batch_body_len);

        batch.put_i64(first_offset as i64); // BaseOffset
        batch.put_i32(batch_body_len as i32); // BatchLength
        batch.put_i32(1); // PartitionLeaderEpoch: 1
        batch.put_u8(2);  // Magic: 2 (RecordBatch)
        batch.put_u32(0); // CRC placeholder
        batch.put_i16(0); // Attributes
        batch.put_i32((records.last().unwrap().offset - first_offset) as i32); // LastOffsetDelta
        batch.put_i64(first_timestamp); // FirstTimestamp
        batch.put_i64(max_timestamp); // MaxTimestamp
        batch.put_i64(-1); // ProducerId: -1
        batch.put_i16(-1); // ProducerEpoch: -1
        batch.put_i32(-1); // BaseSequence: -1
        batch.put_i32(records.len() as i32); // RecordsCount
        batch.put_slice(&records_buf);

        let crc = crc32c(&batch[21..]);
        batch[17..21].copy_from_slice(&crc.to_be_bytes());

        batch.freeze()
    }
}

fn read_kafka_varint(data: &mut Bytes) -> Option<i64> {
    let mut value = 0u64;
    for index in 0..10 {
        if !data.has_remaining() {
            return None;
        }
        let byte = data.get_u8();
        if index == 9 && byte > 1 {
            return None;
        }
        value |= ((byte & 0x7f) as u64) << (index * 7);
        if byte & 0x80 == 0 {
            return Some(((value >> 1) as i64) ^ (-((value & 1) as i64)));
        }
    }
    None
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn kafka_error_code(error: &VortexError) -> i16 {
    match error {
        VortexError::OffsetOutOfRange { .. } => 1, // OFFSET_OUT_OF_RANGE
        VortexError::TopicNotFound(_) | VortexError::PartitionNotFound { .. } => 3, // UNKNOWN_TOPIC_OR_PARTITION
        VortexError::PoisonPillDetected { .. }
        | VortexError::SecurityViolation { .. }
        | VortexError::SchemaValidationFailed { .. } => 44, // POLICY_VIOLATION
        VortexError::DiskQuasiFull { .. } | VortexError::Io(_) => 56, // KAFKA_STORAGE_ERROR
        _ => -1, // UNKNOWN_SERVER_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vortex_protocol::ProduceRequest;

    fn produce_payload(topic: &str, records: &[u8], tx_id: Option<&[u8]>) -> Bytes {
        let mut payload = BytesMut::new();
        if let Some(tx_id) = tx_id {
            KafkaCodec::put_string(&mut payload, std::str::from_utf8(tx_id).unwrap());
        } else {
            payload.put_i16(-1);
        }
        payload.put_i16(1); // Acks
        payload.put_i32(1000); // Timeout
        payload.put_i32(1); // Topic count
        KafkaCodec::put_string(&mut payload, topic);
        payload.put_i32(1); // Partition count
        payload.put_i32(0);
        KafkaCodec::put_bytes(&mut payload, records);
        payload.freeze()
    }

    #[test]
    fn kafka_error_mapping_uses_protocol_codes() {
        assert_eq!(kafka_error_code(&VortexError::OffsetOutOfRange { requested: 9, earliest: 2, latest: 5 }), 1);
        assert_eq!(kafka_error_code(&VortexError::PoisonPillDetected { reason: "secret".into() }), 44);
        assert_eq!(
            kafka_error_code(&VortexError::SchemaValidationFailed {
                topic: "events".into(),
                reason: "invalid payload".into(),
            }),
            44
        );
        assert_eq!(kafka_error_code(&VortexError::DiskQuasiFull { usage_percent: 93, threshold: 92 }), 56);
    }

    #[test]
    fn record_batch_encoder_writes_a_valid_crc_and_parser_roundtrips_payload() {
        let source = Record::new(
            [0u8; 32],
            17,
            Some(Bytes::from_static(b"key")),
            Bytes::from_static(b"value"),
        );
        let source_timestamp = source.timestamp;
        let batch = KafkaBridge::encode_record_batch(&[source]);
        assert_eq!(
            u32::from_be_bytes(batch[17..21].try_into().unwrap()),
            crc32c(&batch[21..])
        );
        let mut input = batch;
        assert_eq!(
            KafkaBridge::parse_records(&mut input).unwrap(),
            vec![(Some(Bytes::from_static(b"key")), Bytes::from_static(b"value"), Some(source_timestamp))]
        );
    }

    #[test]
    fn record_batch_parser_rejects_corruption_and_transaction_metadata() {
        let source = Record::new(
            [0u8; 32],
            0,
            None,
            Bytes::from_static(b"payload"),
        );
        let valid = KafkaBridge::encode_record_batch(&[source]);

        let mut corrupted = BytesMut::from(&valid[..]);
        let end = corrupted.len() - 1;
        corrupted[end] ^= 1;
        let mut corrupted = corrupted.freeze();
        assert_eq!(KafkaBridge::parse_records(&mut corrupted), Err(87));

        let mut transactional = BytesMut::from(&valid[..]);
        transactional[21..23].copy_from_slice(&16u16.to_be_bytes());
        let crc = crc32c(&transactional[21..]);
        transactional[17..21].copy_from_slice(&crc.to_be_bytes());
        let mut transactional = transactional.freeze();
        assert_eq!(KafkaBridge::parse_records(&mut transactional), Err(48));

        let mut producer_sequenced = BytesMut::from(&valid[..]);
        producer_sequenced[43..51].copy_from_slice(&123u64.to_be_bytes());
        let crc = crc32c(&producer_sequenced[21..]);
        producer_sequenced[17..21].copy_from_slice(&crc.to_be_bytes());
        let mut producer_sequenced = producer_sequenced.freeze();
        assert_eq!(KafkaBridge::parse_records(&mut producer_sequenced), Err(43));
    }

    #[tokio::test]
    async fn produce_error_is_returned_to_kafka_client() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        let mut payload = BytesMut::new();
        payload.put_i16(-1); // Null transactional ID
        payload.put_i16(1); // Acks
        payload.put_i32(1000); // Timeout
        payload.put_i32(1);
        KafkaCodec::put_string(&mut payload, "secrets");
        payload.put_i32(1);
        payload.put_i32(0);
        let batch = KafkaBridge::encode_record_batch(&[Record::new(
            [0u8; 32],
            0,
            None,
            Bytes::from_static(b"AKIAIOSFODNN7EXAMPLE"),
        )]);
        KafkaCodec::put_bytes(&mut payload, &batch);

        let mut payload = payload.freeze();
        let response = KafkaBridge::handle_produce(&mut payload, &engine).await;
        let mut response = &response[..];
        assert_eq!(response.get_i32(), 1);
        assert_eq!(KafkaCodec::get_string(&mut response).unwrap(), "secrets");
        assert_eq!(response.get_i32(), 1);
        assert_eq!(response.get_i32(), 0);
        assert_eq!(response.get_i16(), 44); // POLICY_VIOLATION, never NONE.
    }

    #[tokio::test]
    async fn rejected_kafka_batch_does_not_append_its_valid_prefix() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        let batch = KafkaBridge::encode_record_batch(&[
            Record::new([0u8; 32], 0, None, Bytes::from_static(b"valid")),
            Record::new([0u8; 32], 1, None, Bytes::from_static(b"AKIAIOSFODNN7EXAMPLE")),
        ]);
        let mut payload = produce_payload("atomic-policy", &batch, None);
        let response = KafkaBridge::handle_produce(&mut payload, &engine).await;
        let mut response = &response[..];
        assert_eq!(response.get_i32(), 1);
        let _ = KafkaCodec::get_string(&mut response).unwrap();
        assert_eq!(response.get_i32(), 1);
        let _ = response.get_i32();
        assert_eq!(response.get_i16(), 44);
        assert_eq!(engine.partition_bounds("atomic-policy", 0).await.unwrap().1, 0);
    }

    #[tokio::test]
    async fn transactional_kafka_batch_is_rejected_without_persisting_records() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        let valid = KafkaBridge::encode_record_batch(&[Record::new(
            [0u8; 32],
            0,
            None,
            Bytes::from_static(b"private until commit"),
        )]);
        let mut transactional = BytesMut::from(&valid[..]);
        transactional[21..23].copy_from_slice(&(1u16 << 4).to_be_bytes());
        let crc = crc32c(&transactional[21..]);
        transactional[17..21].copy_from_slice(&crc.to_be_bytes());
        let mut payload = produce_payload("transactional", &transactional, None);
        let response = KafkaBridge::handle_produce(&mut payload, &engine).await;
        let mut response = &response[..];
        assert_eq!(response.get_i32(), 1);
        let _ = KafkaCodec::get_string(&mut response).unwrap();
        assert_eq!(response.get_i32(), 1);
        let _ = response.get_i32();
        assert_eq!(response.get_i16(), 48); // INVALID_TXN_STATE
        assert_eq!(engine.partition_bounds("transactional", 0).await.unwrap().1, 0);
    }

    #[tokio::test]
    async fn list_offsets_latest_uses_partition_head_not_a_probe_record() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        for index in 0..10 {
            engine.produce(ProduceRequest {
                topic: "offsets".into(),
                partition: 0,
                key: None,
                value: Bytes::from(format!("record-{index}")),
            }).await.unwrap();
        }

        let mut payload = BytesMut::new();
        payload.put_i32(-1); // Replica ID
        payload.put_i32(1);
        KafkaCodec::put_string(&mut payload, "offsets");
        payload.put_i32(1);
        payload.put_i32(0);
        payload.put_i64(-1); // Latest offset
        let mut payload = payload.freeze();
        let response = KafkaBridge::handle_list_offsets(&mut payload, &engine, 1).await;
        let mut response = &response[..];
        assert_eq!(response.get_i32(), 1);
        assert_eq!(KafkaCodec::get_string(&mut response).unwrap(), "offsets");
        assert_eq!(response.get_i32(), 1);
        assert_eq!(response.get_i32(), 0);
        assert_eq!(response.get_i16(), 0);
        let _timestamp = response.get_i64();
        assert_eq!(response.get_i64(), 10);
    }

    #[tokio::test]
    async fn fetch_beyond_partition_head_returns_offset_out_of_range() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        engine.produce(ProduceRequest {
            topic: "bounded".into(),
            partition: 0,
            key: None,
            value: Bytes::from_static(b"only-record"),
        }).await.unwrap();

        let mut payload = BytesMut::new();
        payload.put_i32(-1); // Replica ID
        payload.put_i32(0); // Max wait
        payload.put_i32(1); // Min bytes
        payload.put_i32(1024); // Max bytes
        payload.put_i8(0); // Read uncommitted
        payload.put_i32(1);
        KafkaCodec::put_string(&mut payload, "bounded");
        payload.put_i32(1);
        payload.put_i32(0);
        payload.put_i64(20); // Beyond the current head (1)
        payload.put_i64(0);
        payload.put_i32(1024);

        let mut payload = payload.freeze();
        let response = KafkaBridge::handle_fetch(&mut payload, &engine).await;
        let mut response = &response[..];
        let _throttle_time = response.get_i32();
        assert_eq!(response.get_i32(), 1);
        let _topic = KafkaCodec::get_string(&mut response).unwrap();
        assert_eq!(response.get_i32(), 1);
        assert_eq!(response.get_i32(), 0);
        assert_eq!(response.get_i16(), 1); // OFFSET_OUT_OF_RANGE
        assert_eq!(response.get_i64(), 1); // Actual high watermark
        assert_eq!(response.get_i64(), 1); // Last stable offset
        assert_eq!(response.get_i64(), 0); // Log start offset
    }

    #[tokio::test]
    async fn read_committed_fetch_fails_closed_without_leaking_old_records() {
        let tmp = tempdir().unwrap();
        let engine = Engine::new(tmp.path().to_path_buf());
        engine
            .produce(ProduceRequest {
                topic: "legacy-data".into(),
                partition: 0,
                key: None,
                value: Bytes::from_static(b"may have unknown transaction state"),
            })
            .await
            .unwrap();

        let mut payload = BytesMut::new();
        payload.put_i32(-1); // Replica ID
        payload.put_i32(0); // Max wait
        payload.put_i32(1); // Min bytes
        payload.put_i32(1024); // Max bytes
        payload.put_i8(1); // ReadCommitted
        payload.put_i32(1);
        KafkaCodec::put_string(&mut payload, "legacy-data");
        payload.put_i32(1);
        payload.put_i32(0);
        payload.put_i64(0);
        payload.put_i64(0);
        payload.put_i32(1024);

        let mut payload = payload.freeze();
        let response = KafkaBridge::handle_fetch(&mut payload, &engine).await;
        let mut response = &response[..];
        let _throttle = response.get_i32();
        assert_eq!(response.get_i32(), 1);
        let _topic = KafkaCodec::get_string(&mut response).unwrap();
        assert_eq!(response.get_i32(), 1);
        let _partition = response.get_i32();
        assert_eq!(response.get_i16(), 43); // UNSUPPORTED_FOR_MESSAGE_FORMAT
        let _high_watermark = response.get_i64();
        let _last_stable_offset = response.get_i64();
        let _log_start = response.get_i64();
        let _aborted_transactions = response.get_i32();
        assert!(KafkaCodec::get_bytes(&mut response).unwrap().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_kafka_api_versions_and_metadata_flow() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        // 1. ApiVersions Request
        let mut req_buf = BytesMut::new();
        req_buf.put_i16(18); // ApiVersions
        req_buf.put_i16(1);  // v1
        req_buf.put_i32(999); // CorrelationId
        KafkaCodec::put_string(&mut req_buf, "kafka-python");

        let total_size = req_buf.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&req_buf);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 999); // Matching correlation ID
        assert_eq!(r.get_i16(), 0);   // ErrorCode: NONE
        assert_eq!(r.get_i32(), 12);  // Only APIs currently exposed by the bridge.
    }

    #[tokio::test]
    async fn test_kafka_consumer_group_and_commit_flow() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        let group_id = "test-group";
        let topic = "test-topic";

        // 1. JoinGroup (ApiKey 11)
        let mut join_req = BytesMut::new();
        join_req.put_i16(11); // JoinGroup
        join_req.put_i16(5);  // v5
        join_req.put_i32(2001); // CorrelationId
        KafkaCodec::put_string(&mut join_req, "client-app");
        KafkaCodec::put_string(&mut join_req, group_id);
        join_req.put_i32(30000); // SessionTimeout
        join_req.put_i32(30000); // RebalanceTimeout
        KafkaCodec::put_string(&mut join_req, "member-1");
        KafkaCodec::put_string(&mut join_req, "consumer"); // ProtocolType
        join_req.put_i32(1); // 1 protocol
        KafkaCodec::put_string(&mut join_req, "range");
        KafkaCodec::put_bytes(&mut join_req, b"metadata");

        let total_size = join_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&join_req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 2001); // CorrelationId
        let _throttle = r.get_i32();
        assert_eq!(r.get_i16(), 0); // ErrorCode: NONE
        let generation_id = r.get_i32();
        assert_eq!(generation_id, 2); // Initial group epoch starts at 1, rebalances to 2

        // 2. OffsetCommit (ApiKey 8)
        let mut commit_req = BytesMut::new();
        commit_req.put_i16(8); // OffsetCommit
        commit_req.put_i16(5); // v5
        commit_req.put_i32(2002);
        KafkaCodec::put_string(&mut commit_req, "client-app");
        KafkaCodec::put_string(&mut commit_req, group_id);
        commit_req.put_i32(generation_id); // generation_id
        KafkaCodec::put_string(&mut commit_req, "member-1");

        commit_req.put_i32(1); // 1 topic
        KafkaCodec::put_string(&mut commit_req, topic);
        commit_req.put_i32(1); // 1 partition
        commit_req.put_i32(0); // partition 0
        commit_req.put_i64(42); // committed offset 42

        let total_size = commit_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&commit_req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 2002);
        let _throttle = r.get_i32();
        let topic_count = r.get_i32();
        assert_eq!(topic_count, 1);
        let committed_top = KafkaCodec::get_string(&mut r).unwrap();
        assert_eq!(committed_top, topic);
        let part_count = r.get_i32();
        assert_eq!(part_count, 1);
        let part_idx = r.get_i32();
        assert_eq!(part_idx, 0);
        let commit_err = r.get_i16();
        assert_eq!(commit_err, 0); // Commit succeeded!

        // 3. OffsetFetch (ApiKey 9)
        let mut fetch_off_req = BytesMut::new();
        fetch_off_req.put_i16(9); // OffsetFetch
        fetch_off_req.put_i16(5); // v5
        fetch_off_req.put_i32(2003);
        KafkaCodec::put_string(&mut fetch_off_req, "client-app");
        KafkaCodec::put_string(&mut fetch_off_req, group_id);
        fetch_off_req.put_i32(1); // 1 topic
        KafkaCodec::put_string(&mut fetch_off_req, topic);
        fetch_off_req.put_i32(1); // 1 partition
        fetch_off_req.put_i32(0); // partition 0

        let total_size = fetch_off_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&fetch_off_req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 2003);
        let _throttle = r.get_i32();
        let fetch_top_count = r.get_i32();
        assert_eq!(fetch_top_count, 1);
        let _ = KafkaCodec::get_string(&mut r).unwrap();
        let _ = r.get_i32();
        let _ = r.get_i32();
        let retrieved_offset = r.get_i64();
        assert_eq!(retrieved_offset, 42); // Offset verified!
    }

    #[tokio::test]
    async fn unsupported_init_producer_id_is_not_fabricated() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        let mut init_req = BytesMut::new();
        init_req.put_i16(22); // InitProducerId
        init_req.put_i16(3);  // v3
        init_req.put_i32(3001);
        KafkaCodec::put_string(&mut init_req, "txn-producer");
        init_req.put_i16(-1); // TransactionalId: null
        init_req.put_i32(60000); // TransactionTimeoutMs
        init_req.put_i64(-1); // ProducerId: -1 (new allocation)
        init_req.put_i16(-1); // ProducerEpoch: -1

        let total_size = init_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&init_req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 3001);
        let _throttle = r.get_i32();
        assert_eq!(r.get_i16(), 35); // UNSUPPORTED_VERSION: idempotence is not implemented
        let pid = r.get_i64();
        assert_eq!(pid, -1); // No fake producer identity
        let epoch = r.get_i16();
        assert_eq!(epoch, -1);
    }

    #[tokio::test]
    async fn test_kafka_produce_and_fetch_end_to_end() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        let topic = "sensor_metrics";
        let message_payload = b"temperature: 24.5C, humidity: 48%";

        // 1. Send Kafka Produce Request (ApiKey = 0)
        let mut produce_req = BytesMut::new();
        produce_req.put_i16(0); // Produce
        produce_req.put_i16(5); // v5
        produce_req.put_i32(1001); // CorrelationId
        KafkaCodec::put_string(&mut produce_req, "sensor-iot-gateway");

        // TransactionalId: null
        produce_req.put_i16(-1);
        produce_req.put_i16(1); // Acks: 1
        produce_req.put_i32(1500); // TimeoutMs

        // Topics array: 1 topic
        produce_req.put_i32(1);
        KafkaCodec::put_string(&mut produce_req, topic);

        // Partitions array: 1 partition (partition 0)
        produce_req.put_i32(1);
        produce_req.put_i32(0); // Partition 0

        // Records payload
        let kafka_record = Record::new(
            [0u8; 32],
            0,
            None,
            Bytes::copy_from_slice(message_payload),
        );
        let expected_timestamp = kafka_record.timestamp;
        let batch = KafkaBridge::encode_record_batch(&[kafka_record]);
        KafkaCodec::put_bytes(&mut produce_req, &batch);

        let total_size = produce_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&produce_req);

        let produce_frame = KafkaFrame::decode(&mut frame_buf).unwrap().expect("Produce frame decoded");
        let produce_resp_bytes = KafkaBridge::handle_frame(produce_frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &produce_resp_bytes[..];
        let _resp_len = r.get_i32();
        assert_eq!(r.get_i32(), 1001); // Correlation ID match
        let topic_count = r.get_i32();
        assert_eq!(topic_count, 1);
        let resp_topic = KafkaCodec::get_string(&mut r).unwrap();
        assert_eq!(resp_topic, topic);
        let part_count = r.get_i32();
        assert_eq!(part_count, 1);
        let part_idx = r.get_i32();
        assert_eq!(part_idx, 0);
        let err_code = r.get_i16();
        assert_eq!(err_code, 0); // No error
        let committed_offset = r.get_i64();
        assert_eq!(committed_offset, 0); // First message at offset 0

        // 2. Send Kafka Fetch Request (ApiKey = 1)
        let mut fetch_req = BytesMut::new();
        fetch_req.put_i16(1); // Fetch
        fetch_req.put_i16(5); // v5
        fetch_req.put_i32(1002); // CorrelationId
        KafkaCodec::put_string(&mut fetch_req, "sensor-consumer");

        fetch_req.put_i32(-1); // ReplicaId
        fetch_req.put_i32(500); // MaxWaitMs
        fetch_req.put_i32(1); // MinBytes
        fetch_req.put_i32(65536); // MaxBytes
        fetch_req.put_i8(0); // IsolationLevel: ReadUncommitted

        // Topics array: 1 topic
        fetch_req.put_i32(1);
        KafkaCodec::put_string(&mut fetch_req, topic);

        // Partitions array: 1 partition
        fetch_req.put_i32(1);
        fetch_req.put_i32(0); // Partition 0
        fetch_req.put_i64(0); // FetchOffset: 0
        fetch_req.put_i64(0); // LogStartOffset: 0
        fetch_req.put_i32(65536); // PartitionMaxBytes

        let total_size = fetch_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&fetch_req);

        let fetch_frame = KafkaFrame::decode(&mut frame_buf).unwrap().expect("Fetch frame decoded");
        let fetch_resp_bytes = KafkaBridge::handle_frame(fetch_frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut fr = &fetch_resp_bytes[..];
        let _resp_len = fr.get_i32();
        assert_eq!(fr.get_i32(), 1002); // Matching correlation ID
        let _throttle = fr.get_i32();

        let resp_topic_count = fr.get_i32();
        assert_eq!(resp_topic_count, 1);
        let fetched_topic = KafkaCodec::get_string(&mut fr).unwrap();
        assert_eq!(fetched_topic, topic);
        let fetched_part_count = fr.get_i32();
        assert_eq!(fetched_part_count, 1);
        let fetched_part_idx = fr.get_i32();
        assert_eq!(fetched_part_idx, 0);
        let part_err = fr.get_i16();
        assert_eq!(part_err, 0);
        let high_watermark = fr.get_i64();
        assert_eq!(high_watermark, 1); // 1 record committed
        assert_eq!(fr.get_i64(), 1); // LastStableOffset
        assert_eq!(fr.get_i64(), 0); // LogStartOffset
        assert_eq!(fr.get_i32(), 0); // No aborted transaction ranges
        let mut returned_records = KafkaCodec::get_bytes(&mut fr).unwrap().unwrap();
        let decoded = KafkaBridge::parse_records(&mut returned_records).unwrap();
        assert_eq!(decoded[0].1, Bytes::copy_from_slice(message_payload));
        assert_eq!(decoded[0].2, Some(expected_timestamp));
    }

    #[tokio::test]
    async fn test_unsupported_api_version_returns_error_code_35() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        // 1. Send Produce request with unsupported version 99
        let mut req = BytesMut::new();
        req.put_i16(0);  // Produce ApiKey
        req.put_i16(99); // Unsupported api_version 99
        req.put_i32(888); // CorrelationId
        KafkaCodec::put_string(&mut req, "test-client");

        let total_size = req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 888); // CorrelationId matches
        let _throttle = r.get_i32();
        assert_eq!(r.get_i16(), 35); // UNSUPPORTED_VERSION

        // 2. Send ApiVersions request with unsupported version 99
        let mut api_req = BytesMut::new();
        api_req.put_i16(18); // ApiVersions ApiKey
        api_req.put_i16(99); // Unsupported api_version 99
        api_req.put_i32(999); // CorrelationId
        KafkaCodec::put_string(&mut api_req, "test-client");

        let total_size = api_req.len() as i32;
        let mut frame_buf = BytesMut::new();
        frame_buf.put_i32(total_size);
        frame_buf.put_slice(&api_req);

        let frame = KafkaFrame::decode(&mut frame_buf).unwrap().unwrap();
        let resp = KafkaBridge::handle_frame(frame, Arc::clone(&engine), Arc::clone(&coordinator)).await;

        let mut r = &resp[..];
        let _size = r.get_i32();
        assert_eq!(r.get_i32(), 999); // CorrelationId matches
        assert_eq!(r.get_i16(), 35);  // UNSUPPORTED_VERSION
    }
}

