use bytes::Bytes;
use std::sync::Arc;
use std::thread;
use vortex_core::{compute_genesis_hash, compute_record_hash, verify_record_integrity, Record};

#[test]
fn test_blake3_tree_hashing_over_150_edge_cases() {
    let prev_hash = compute_genesis_hash("test-topic", 0);

    // 1. Diverse payload sizes spanning chunk boundaries, powers of 2, and offsets
    let sizes = [
        0, 1, 2, 3, 7, 15, 16, 31, 32, 63, 64, 65, 127, 128, 255, 256,
        511, 512, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 4097, 8192,
        16384, 32768, 65535, 65536, 65537, 131072, 262144, 524288, 1048576,
    ];

    // 2. Key variations
    let key_variants: [Option<&[u8]>; 5] = [
        None,
        Some(b""),
        Some(b"k"),
        Some(b"standard-tenant-uuid-429810"),
        Some(b"very-long-composite-routing-key-with-unicode-\xf0\x9f\x94\xa5-entropy-pad-000000000000000000000000"),
    ];

    // 3. Offsets and timestamps
    let offsets: [u64; 3] = [0, 42, 18_446_744_073_709_551_614];
    let timestamps: [u64; 2] = [0, 1_730_000_000_000];

    let mut total_cases = 0;

    for &size in &sizes {
        let payload = vec![(size % 251) as u8; size];
        for &key in &key_variants {
            for &offset in &offsets {
                for &ts in &timestamps {
                    total_cases += 1;

                    // Compute hash via core function
                    let digest = compute_record_hash(&prev_hash, offset, ts, key, &payload);

                    // Verification must succeed
                    assert!(
                        verify_record_integrity(&prev_hash, &digest, offset, ts, key, &payload),
                        "Integrity verification failed for case #{} (size={}, key_len={:?}, offset={})",
                        total_cases,
                        size,
                        key.map(|k| k.len()),
                        offset
                    );

                    // Corrupt 1 byte in payload (if size > 0) and verify that integrity check rejects
                    if size > 0 {
                        let mut corrupted = payload.clone();
                        corrupted[size / 2] ^= 0x01;
                        assert!(
                            !verify_record_integrity(&prev_hash, &digest, offset, ts, key, &corrupted),
                            "Tamper detection failed to catch bit-flip for case #{} (size={})",
                            total_cases,
                            size
                        );
                    }
                }
            }
        }
    }

    println!("Successfully verified {} distinct parameter & edge cases!", total_cases);
    assert!(total_cases >= 150, "Expected at least 150 edge cases, tested {}", total_cases);
}

#[test]
fn test_parallel_multi_threaded_tree_hashing_concurrency() {
    let prev_hash = compute_genesis_hash("concurrent-topic", 0);
    let payload_size = 512 * 1024; // 512 KB per record
    let num_threads = 16;
    let records_per_thread = 10;

    let payload = Arc::new(vec![0xCC; payload_size]);
    let mut handles = Vec::new();

    for t in 0..num_threads {
        let p = Arc::clone(&payload);
        let handle = thread::spawn(move || {
            let mut thread_hashes = Vec::with_capacity(records_per_thread);
            for r in 0..records_per_thread {
                let offset = (t * 1000 + r) as u64;
                let rec = Record::new(
                    prev_hash,
                    offset,
                    Some(Bytes::from(format!("worker-{}", t))),
                    Bytes::copy_from_slice(&p),
                );
                thread_hashes.push(rec.record_hash);
            }
            thread_hashes
        });
        handles.push(handle);
    }

    let mut all_hashes = Vec::new();
    for h in handles {
        let hashes = h.join().expect("Worker thread must not panic");
        all_hashes.extend(hashes);
    }

    assert_eq!(all_hashes.len(), num_threads * records_per_thread);
    // Ensure all hashes are unique because offsets differ
    let mut deduped = all_hashes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), all_hashes.len(), "All computed hashes must be unique across offsets");
}
