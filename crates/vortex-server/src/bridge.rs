use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tracing::warn;

use vortex_core::error::VortexError;
use vortex_core::record::Record;
use vortex_core::tx::{IsolationLevel, TransactionCoordinator};
use vortex_protocol::kafka::{KafkaApiKey, KafkaCodec, KafkaFrame, Varint};
use vortex_protocol::{FetchRequest, ProduceRequest};

use crate::coordinator::ConsumerGroupCoordinator;
use crate::engine::Engine;

pub struct KafkaBridge;

impl KafkaBridge {
    /// Dispatches a decoded Kafka protocol frame to the appropriate engine handler
    /// and returns the complete serialized Kafka wire response.
    pub async fn handle_frame(
        frame: KafkaFrame,
        engine: Arc<Engine>,
        coordinator: Arc<ConsumerGroupCoordinator>,
    ) -> Bytes {
        let correlation_id = frame.header.correlation_id;
        let api_version = frame.header.api_version;
        let mut payload = frame.payload;

        let response_body = match frame.header.api_key {
            KafkaApiKey::ApiVersions => Self::handle_api_versions(api_version),
            KafkaApiKey::Metadata => Self::handle_metadata(&mut payload, api_version),
            KafkaApiKey::Produce => Self::handle_produce(&mut payload, &engine).await,
            KafkaApiKey::Fetch => Self::handle_fetch(&mut payload, &engine).await,
            KafkaApiKey::ListOffsets => Self::handle_list_offsets(&mut payload, &engine).await,
            KafkaApiKey::FindCoordinator => Self::handle_find_coordinator(&mut payload),
            KafkaApiKey::JoinGroup => Self::handle_join_group(&mut payload, &coordinator),
            KafkaApiKey::SyncGroup => Self::handle_sync_group(&mut payload, &coordinator),
            KafkaApiKey::Heartbeat => Self::handle_heartbeat(&mut payload, &coordinator),
            KafkaApiKey::LeaveGroup => Self::handle_leave_group(&mut payload, &coordinator),
            KafkaApiKey::OffsetCommit => Self::handle_offset_commit(&mut payload, &coordinator),
            KafkaApiKey::OffsetFetch => Self::handle_offset_fetch(&mut payload, &coordinator),
            KafkaApiKey::InitProducerId => Self::handle_init_producer_id(&mut payload, engine.tx_coordinator()),
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

        // 13 Supported Kafka ApiKeys
        let apis: [(i16, i16, i16); 13] = [
            (0, 0, 8),   // Produce
            (1, 0, 11),  // Fetch
            (2, 0, 5),   // ListOffsets
            (3, 0, 9),   // Metadata
            (8, 0, 8),   // OffsetCommit
            (9, 0, 7),   // OffsetFetch
            (10, 0, 3),  // FindCoordinator
            (11, 0, 7),  // JoinGroup
            (12, 0, 4),  // Heartbeat
            (13, 0, 4),  // LeaveGroup
            (14, 0, 5),  // SyncGroup
            (18, 0, 3),  // ApiVersions
            (22, 0, 3),  // InitProducerId
        ];

        buf.put_i32(apis.len() as i32);
        for (key, min_v, max_v) in apis {
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
        let _tx_id = if payload.remaining() >= 2 {
            let len = payload.get_i16();
            if len > 0 && payload.remaining() >= len as usize {
                Some(payload.copy_to_bytes(len as usize))
            } else {
                None
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
                                    let records = Self::parse_records(&mut record_data);

                                    let mut last_offset = 0u64;
                                    let mut last_ts = 0u64;

                                    for (k, v) in records {
                                        let req = ProduceRequest {
                                            topic: topic_name.clone(),
                                            partition: partition_idx,
                                            key: k,
                                            value: v,
                                        };
                                        if let Ok(resp) = engine.produce(req).await {
                                            last_offset = resp.offset;
                                            last_ts = resp.timestamp;
                                        }
                                    }

                                    produced_results.push((topic_name.clone(), partition_idx, last_offset, last_ts));
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

        for (topic, partition_idx, offset, ts) in produced_results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partition count
            buf.put_i32(partition_idx as i32);
            buf.put_i16(0); // ErrorCode: NONE
            buf.put_i64(offset as i64);
            buf.put_i64(ts as i64);
            buf.put_i64(0); // LogStartOffset
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

                                let records = match engine.fetch(req).await {
                                    Ok(resp) => {
                                        if isolation == 1 {
                                            TransactionCoordinator::filter_by_isolation(&resp.records, IsolationLevel::ReadCommitted)
                                        } else {
                                            TransactionCoordinator::filter_by_isolation(&resp.records, IsolationLevel::ReadUncommitted)
                                        }
                                    }
                                    Err(_) => Vec::new(),
                                };

                                fetch_results.push((topic_name.clone(), partition_idx, records));
                            }
                        }
                    }
                }
            }
        }

        // Build FetchResponse
        let mut buf = BytesMut::with_capacity(512);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE
        buf.put_i32(0); // SessionId: 0

        buf.put_i32(fetch_results.len() as i32);
        for (topic, partition_idx, records) in fetch_results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partitions count
            buf.put_i32(partition_idx as i32);
            buf.put_i16(0); // ErrorCode: NONE

            let latest_offset = records.last().map_or(0, |r| r.offset + 1);
            buf.put_i64(latest_offset as i64); // HighWatermark
            buf.put_i64(latest_offset as i64); // LastStableOffset
            buf.put_i64(0); // LogStartOffset
            buf.put_i32(0); // AbortedTransactions count

            // Encode records as Kafka RecordBatch frame
            let batch_bytes = Self::encode_record_batch(&records);
            KafkaCodec::put_bytes(&mut buf, &batch_bytes);
        }

        buf.freeze()
    }

    async fn handle_list_offsets(payload: &mut Bytes, engine: &Engine) -> Bytes {
        let mut results = Vec::new();

        if payload.remaining() >= 4 {
            let _replica_id = payload.get_i32();
            let _isolation = if payload.remaining() >= 1 { payload.get_i8() } else { 0 };

            if payload.remaining() >= 4 {
                let topic_count = payload.get_i32();
                for _ in 0..topic_count {
                    if let Ok(topic_name) = KafkaCodec::get_string(payload) {
                        if payload.remaining() >= 4 {
                            let part_count = payload.get_i32();
                            for _ in 0..part_count {
                                if payload.remaining() >= 12 {
                                    let partition_idx = payload.get_i32() as u32;
                                    let timestamp = payload.get_i64();

                                    // Probe partition offset via engine fetch
                                    let req = FetchRequest {
                                        topic: topic_name.clone(),
                                        partition: partition_idx,
                                        start_offset: 0,
                                        max_bytes: 1,
                                    };
                                    let offset = match engine.fetch(req).await {
                                        Ok(resp) => {
                                            if timestamp == -2 {
                                                resp.records.first().map_or(0, |r| r.offset)
                                            } else {
                                                resp.records.last().map_or(0, |r| r.offset + 1)
                                            }
                                        }
                                        Err(_) => 0,
                                    };

                                    results.push((topic_name.clone(), partition_idx, offset as i64));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut buf = BytesMut::with_capacity(256);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i32(results.len() as i32);

        for (topic, part, offset) in results {
            KafkaCodec::put_string(&mut buf, &topic);
            buf.put_i32(1); // Partitions count
            buf.put_i32(part as i32);
            buf.put_i16(0); // ErrorCode: NONE
            buf.put_i64(0); // Timestamp
            buf.put_i64(offset);
            buf.put_i32(1); // LeaderEpoch
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

    fn handle_init_producer_id(payload: &mut Bytes, tx_coordinator: &TransactionCoordinator) -> Bytes {
        let _tx_id = if payload.remaining() >= 2 { KafkaCodec::get_string(payload).ok() } else { None };
        let _timeout_ms = if payload.remaining() >= 4 { payload.get_i32() } else { 60000 };
        let current_pid = if payload.remaining() >= 8 { payload.get_i64() } else { -1 };
        let (pid, epoch) = tx_coordinator.init_producer_id(if current_pid > 0 {
            Some(current_pid as u64)
        } else {
            None
        });

        let mut buf = BytesMut::with_capacity(32);
        buf.put_i32(0); // ThrottleTimeMs
        buf.put_i16(0); // ErrorCode: NONE
        buf.put_i64(pid as i64);
        buf.put_i16(epoch as i16);
        buf.freeze()
    }

    /// Parses incoming Kafka records, handling modern RecordBatch (magic = 2) or raw bytes.
    fn parse_records(data: &mut Bytes) -> Vec<(Option<Bytes>, Bytes)> {
        let mut list = Vec::new();
        if data.is_empty() {
            return list;
        }

        // Check if data matches Kafka RecordBatch header (magic byte at offset 16 is 2)
        if data.len() >= 61 && data[16] == 2 {
            let _base_offset = data.get_i64();
            let _batch_len = data.get_i32();
            let _epoch = data.get_i32();
            let _magic = data.get_u8();
            let _crc = data.get_u32();
            let _attrs = data.get_i16();
            let _last_offset_delta = data.get_i32();
            let _first_ts = data.get_i64();
            let _max_ts = data.get_i64();
            let _producer_id = data.get_i64();
            let _producer_epoch = data.get_i16();
            let _base_seq = data.get_i32();
            let records_count = data.get_i32();

            for _ in 0..records_count {
                if let Ok(_rec_len) = Varint::get_varint(data) {
                    if !data.has_remaining() {
                        break;
                    }
                    let _attrs = data.get_u8();
                    let _ts_delta = Varint::get_varint(data).unwrap_or(0);
                    let _offset_delta = Varint::get_varint(data).unwrap_or(0);

                    // Decode Key
                    let key = if let Ok(key_len) = Varint::get_varint(data) {
                        if key_len > 0 && data.remaining() >= key_len as usize {
                            Some(data.copy_to_bytes(key_len as usize))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Decode Value
                    let value = if let Ok(val_len) = Varint::get_varint(data) {
                        if val_len > 0 && data.remaining() >= val_len as usize {
                            data.copy_to_bytes(val_len as usize)
                        } else {
                            Bytes::new()
                        }
                    } else {
                        Bytes::new()
                    };

                    // Headers count
                    let _headers_count = Varint::get_varint(data).unwrap_or(0);

                    list.push((key, value));
                }
            }
        } else {
            // Raw value payload
            list.push((None, data.clone()));
        }

        list
    }

    /// Serializes native Vortex Records into a standard Kafka RecordBatch frame (magic = 2).
    fn encode_record_batch(records: &[Record]) -> Bytes {
        if records.is_empty() {
            return Bytes::new();
        }

        let first_offset = records[0].offset;
        let mut records_buf = BytesMut::new();

        for r in records {
            let offset_delta = (r.offset - first_offset) as i64;
            let mut single_rec = BytesMut::new();
            single_rec.put_u8(0); // Attributes
            Varint::put_varint(&mut single_rec, 0); // Timestamp delta
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
        batch.put_i32(records.len().saturating_sub(1) as i32); // LastOffsetDelta
        batch.put_i64(records[0].timestamp as i64); // FirstTimestamp
        batch.put_i64(records.last().unwrap().timestamp as i64); // MaxTimestamp
        batch.put_i64(-1); // ProducerId: -1
        batch.put_i16(-1); // ProducerEpoch: -1
        batch.put_i32(-1); // BaseSequence: -1
        batch.put_i32(records.len() as i32); // RecordsCount
        batch.put_slice(&records_buf);

        batch.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_kafka_api_versions_and_metadata_flow() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(std::time::Duration::from_secs(30)));

        // 1. ApiVersions Request
        let mut req_buf = BytesMut::new();
        req_buf.put_i16(18); // ApiVersions
        req_buf.put_i16(3);  // v3
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
        assert_eq!(r.get_i32(), 13);  // 13 supported APIs advertised!
    }

    #[tokio::test]
    async fn test_kafka_consumer_group_and_commit_flow() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(std::time::Duration::from_secs(30)));

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
    async fn test_kafka_init_producer_id_flow() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(std::time::Duration::from_secs(30)));

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
        assert_eq!(r.get_i16(), 0); // ErrorCode: NONE
        let pid = r.get_i64();
        assert!(pid >= 1000); // Allocated producer ID
        let epoch = r.get_i16();
        assert_eq!(epoch, 0); // Initial epoch 0
    }

    #[tokio::test]
    async fn test_kafka_produce_and_fetch_end_to_end() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(std::time::Duration::from_secs(30)));

        let topic = "sensor_metrics";
        let message_payload = b"temperature: 24.5C, humidity: 48%";

        // 1. Send Kafka Produce Request (ApiKey = 0)
        let mut produce_req = BytesMut::new();
        produce_req.put_i16(0); // Produce
        produce_req.put_i16(7); // v7
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
        KafkaCodec::put_bytes(&mut produce_req, message_payload);

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
        fetch_req.put_i16(11); // v11
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
        let fetch_err = fr.get_i16();
        assert_eq!(fetch_err, 0);
        let _session_id = fr.get_i32();

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
    }
}

