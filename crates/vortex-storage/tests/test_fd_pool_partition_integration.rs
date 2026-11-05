use bytes::Bytes;
use std::sync::Arc;
use tempfile::tempdir;
use vortex_storage::{FdPool, PartitionLog};

#[test]
fn test_fd_pool_150_segment_rollovers_bounded_descriptors() {
    let dir = tempdir().unwrap();
    let fd_limit = 16;
    let pool = Arc::new(FdPool::new(fd_limit));

    // Configure small segment size to force a rollover almost every record
    let mut log = PartitionLog::open_or_create_with_pool(
        dir.path(),
        "heavy-roll",
        0,
        350, // Small segment byte threshold
        pool.clone(),
    )
    .expect("Failed to create partition with custom FdPool");

    // 150 sequential appends with forced rollovers
    for i in 0..150 {
        let val = Bytes::from(format!("payload-for-roll-test-message-number-{:04}", i));
        log.append(None, val).unwrap();
        // Explicitly roll every 2nd append to guarantee at least 75-100 segments
        if i % 2 == 0 {
            log.roll_segment().unwrap();
        }
    }

    let segment_count = log.segments.len();
    assert!(
        segment_count >= 75,
        "Expected at least 75 rolled segments, got {segment_count}"
    );

    // Verify all historical segments are sealed
    for (idx, seg) in log.segments.iter().enumerate() {
        if idx + 1 < segment_count {
            assert!(
                seg.is_sealed(),
                "Historical segment {idx} should be sealed and have no dedicated descriptor"
            );
        }
    }

    // Concurrent random reads across all 150 records from multiple threads
    let log_arc = Arc::new(log);
    let mut handles = Vec::new();
    for thread_id in 0..8 {
        let log_clone = Arc::clone(&log_arc);
        let pool_clone = Arc::clone(&pool);
        handles.push(std::thread::spawn(move || {
            for i in 0..150 {
                let target_offset = (i * 7 + thread_id * 13) % 150;
                let records = log_clone.read(target_offset as u64, 512).unwrap();
                assert!(!records.is_empty(), "Failed to read back offset {target_offset}");
                assert_eq!(records[0].offset, target_offset as u64);

                let expected_payload =
                    format!("payload-for-roll-test-message-number-{:04}", target_offset);
                assert_eq!(records[0].value.as_ref(), expected_payload.as_bytes());

                // Check descriptor bound invariant on every single read iteration
                let open_count = pool_clone.current_open_count();
                assert!(
                    open_count <= fd_limit,
                    "Open descriptor count {open_count} exceeded pool limit {fd_limit}"
                );
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Final invariant check: open files in the pool must strictly obey limit
    assert!(
        pool.current_open_count() <= fd_limit,
        "Final open count {} exceeded limit {}",
        pool.current_open_count(),
        fd_limit
    );
}

#[test]
fn test_fd_pool_mass_partitions_scale_bounded() {
    let dir = tempdir().unwrap();
    // 64 descriptors shared across 250 partitions
    let fd_limit = 64;
    let pool = Arc::new(FdPool::new(fd_limit));

    let partition_count = 250;
    let mut partitions = Vec::with_capacity(partition_count);

    for p in 0..partition_count {
        let topic = format!("topic-{}", p % 10);
        let mut log = PartitionLog::open_or_create_with_pool(
            dir.path(),
            &topic,
            p as u32,
            1024 * 1024,
            pool.clone(),
        )
        .expect("Must open partition without exceeding file limit");

        // Write an initial record
        log.append(None, Bytes::from(format!("initial-data-for-part-{}", p)))
            .unwrap();
        // Seal active segment to emulate an idle partition
        log.seal_active_segment();
        partitions.push(log);
    }

    // Total partitions created is 250, but open files in pool must stay <= fd_limit
    assert!(
        pool.current_open_count() <= fd_limit,
        "Open count {} after creating 250 partitions exceeded pool limit {}",
        pool.current_open_count(),
        fd_limit
    );

    // Perform concurrent cross-partition reads and writes across 10 threads
    let parts_arc = Arc::new(std::sync::RwLock::new(partitions));
    let mut workers = Vec::new();

    for t in 0..10 {
        let parts_clone = Arc::clone(&parts_arc);
        let pool_clone = Arc::clone(&pool);
        workers.push(std::thread::spawn(move || {
            for step in 0..30 {
                let part_idx = (t * 25 + step) % partition_count;
                {
                    let mut guard = parts_clone.write().unwrap();
                    let part = &mut guard[part_idx];
                    let rec = part
                        .append(None, Bytes::from(format!("append-worker-{}-step-{}", t, step)))
                        .unwrap();
                    assert!(rec.offset >= 1);
                    part.seal_active_segment();
                }

                // Verify read back
                {
                    let guard = parts_clone.read().unwrap();
                    let part = &guard[part_idx];
                    let records = part.read(0, 1024).unwrap();
                    assert!(!records.is_empty());
                }

                assert!(
                    pool_clone.current_open_count() <= fd_limit,
                    "FD count {} exceeded limit {}",
                    pool_clone.current_open_count(),
                    fd_limit
                );
            }
        }));
    }

    for w in workers {
        w.join().unwrap();
    }

    assert!(pool.current_open_count() <= fd_limit);
}

#[test]
fn test_fd_pool_150_interleaved_edge_cases_and_pruning() {
    let dir = tempdir().unwrap();
    let fd_limit = 12;
    let pool = Arc::new(FdPool::new(fd_limit));

    let mut log = PartitionLog::open_or_create_with_pool(
        dir.path(),
        "edge-cases",
        0,
        400, // triggers rolls
        pool.clone(),
    )
    .unwrap();

    // Run 150 edge-case operations: writes, rolls, proof generation, cold reads, retention prunes
    for op in 0..150 {
        match op % 5 {
            0 => {
                // Write standard record
                log.append(
                    Some(Bytes::from(format!("key-{}", op))),
                    Bytes::from(format!("val-{}", op)),
                )
                .unwrap();
            }
            1 => {
                // Force segment rollover
                log.roll_segment().unwrap();
            }
            2 => {
                // Generate MMR inclusion proof for early offset (exercises reading sealed evicted segment)
                let proof_target = (op / 10).min(log.next_offset().saturating_sub(1));
                if let Some(proof) = log.generate_inclusion_proof(proof_target) {
                    let expected_root = log.segment_mmr_root_for_offset(proof_target).unwrap();
                    assert!(proof.verify(&expected_root, &proof.leaf_hash));
                }
            }
            3 => {
                // Cold page-cache drop read
                let target = (op % 15).min(log.next_offset().saturating_sub(1));
                let _ = log.read_raw_record_bytes(target, 1024);
            }
            4 => {
                // Retention prune if log has grown
                if log.segments.len() > 5 {
                    let _ = log.prune_retention(1000000, None, Some(1500));
                }
            }
            _ => unreachable!(),
        }

        assert!(
            pool.current_open_count() <= fd_limit,
            "Edge case op {} caused open count {} to exceed limit {}",
            op,
            pool.current_open_count(),
            fd_limit
        );
    }
}
