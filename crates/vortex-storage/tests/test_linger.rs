use bytes::Bytes;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use vortex_storage::linger::AdaptiveLingerQueue;
use vortex_storage::PartitionLog;

#[tokio::test]
async fn test_adaptive_linger_queue_micro_batching() {
    let dir = tempdir().unwrap();
    let log = PartitionLog::open_or_create(dir.path(), "linger-test", 0, 1024 * 1024).unwrap();

    // 5ms linger, max 100 records, max 64KB
    let queue = AdaptiveLingerQueue::new(log, Duration::from_millis(5), 100, 64 * 1024);

    let start = Instant::now();
    let mut handles = Vec::new();
    let total_records = 50;

    for i in 0..total_records {
        let q = queue.clone();
        let handle = tokio::spawn(async move {
            let key = Some(Bytes::from(format!("key-{}", i)));
            let payload = Bytes::from(format!("payload-data-{}", i));
            q.submit(key, payload, None).await
        });
        handles.push(handle);
    }

    let mut offsets = Vec::new();
    for handle in handles {
        let res = handle.await.unwrap().expect("append must succeed");
        offsets.push(res.record.offset);
    }

    let elapsed = start.elapsed();
    assert_eq!(offsets.len(), total_records);
    // Offsets must be strictly sequential 0..50
    offsets.sort();
    for (expected, &actual) in (0..total_records as u64).zip(offsets.iter()) {
        assert_eq!(expected, actual);
    }

    // Crucial: 50 individual physical syncs on disk would take >500ms (10ms+ each).
    // Batched with linger, it should complete in under 200ms.
    println!("50 unbatched appends via linger completed in {:?}", elapsed);
    assert!(elapsed < Duration::from_millis(350), "Linger queue should batch appends instead of sequential syncs");

    queue.shutdown().await;
}

