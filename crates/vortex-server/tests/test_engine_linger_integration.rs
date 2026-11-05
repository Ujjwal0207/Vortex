use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use vortex_protocol::{FetchRequest, ProduceRequest};
use vortex_server::engine::Engine;

#[tokio::test]
async fn test_engine_unbatched_produce_micro_batching_and_concurrency() {
    let dir = tempdir().unwrap();
    let engine = Arc::new(Engine::new(dir.path().to_path_buf()));
    let topic = "unbatched-linger-topic";
    let partition_id = 0;

    // Create topic
    engine.create_topic(topic, 1).await.unwrap();

    let total_requests = 150;
    let mut handles = Vec::with_capacity(total_requests);

    let start_time = Instant::now();

    // Spawn 150 concurrent tasks, each submitting an unbatched ProduceRequest
    for i in 0..total_requests {
        let engine_clone = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let key = if i % 3 == 0 {
                Some(Bytes::from(format!("tenant-key-uuid-{:04}", i)))
            } else if i % 3 == 1 {
                Some(Bytes::from(format!("k-{}", i)))
            } else {
                None
            };

            let payload_size = match i % 5 {
                0 => 16,
                1 => 128,
                2 => 1024,
                3 => 4096,
                _ => 64,
            };
            let value = Bytes::from(vec![(i % 255) as u8; payload_size]);

            let req = ProduceRequest {
                topic: topic.to_string(),
                partition: partition_id,
                key,
                value,
            };

            engine_clone.produce(req).await
        });
        handles.push(handle);
    }

    // Await all 150 produce responses
    let mut responses = Vec::with_capacity(total_requests);
    for h in handles {
        let resp = h.await.unwrap().expect("Produce must succeed");
        responses.push(resp);
    }

    let elapsed = start_time.elapsed();
    println!(
        "Engine processed {} unbatched produce requests in {:?}",
        total_requests, elapsed
    );

    // CRITICAL REALITY CHECK:
    // 150 individual NVMe physical syncs (11.14ms each) would take >1,600ms if unbatched.
    // With AdaptiveLingerQueue micro-batching (2ms / 64KB window), it must complete in <450ms!
    assert!(
        elapsed < Duration::from_millis(450),
        "Unbatched produce took {:?}, exceeding 450ms! Linger micro-batching not active.",
        elapsed
    );

    // Verify all 150 offsets are strictly sequential from 0 to 149
    responses.sort_by_key(|r| r.offset);
    assert_eq!(responses.len(), total_requests);
    for (expected_offset, resp) in (0..total_requests as u64).zip(responses.iter()) {
        assert_eq!(
            expected_offset, resp.offset,
            "Offset sequence gap detected at expected offset {}",
            expected_offset
        );
    }

    // Verify Fetch recovers all 150 records with intact hashes
    let fetch_req = FetchRequest {
        topic: topic.to_string(),
        partition: partition_id,
        start_offset: 0,
        max_bytes: 1024 * 1024 * 10,
    };

    let fetch_resp = engine.fetch(fetch_req).await.unwrap();
    assert_eq!(
        fetch_resp.records.len(),
        total_requests,
        "Fetch must return all 150 committed records"
    );

    for (i, rec) in fetch_resp.records.iter().enumerate() {
        assert_eq!(rec.offset, i as u64);
        assert_eq!(rec.record_hash, responses[i].record_hash);
    }
}
