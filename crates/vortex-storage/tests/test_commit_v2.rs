use bytes::Bytes;
use std::time::Instant;
use tempfile::tempdir;
use vortex_core::compute_genesis_hash;
use vortex_storage::Segment;

#[test]
fn test_commit_marker_v2_instant_mmr_recovery() {
    let dir = tempdir().unwrap();
    let genesis = compute_genesis_hash("v2-test", 0);

    let (expected_offset, expected_root, expected_hash) = {
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        // Append 200 records
        for i in 0..200 {
            seg.append(
                Some(Bytes::from(format!("k-{}", i))),
                Bytes::from(format!("payload-data-{}", i)),
            )
            .unwrap();
        }
        let root = seg.mmr_root();
        let next_offset = seg.next_offset;
        let last_hash = seg.last_record_hash;
        (next_offset, root, last_hash)
    };

    assert_eq!(expected_offset, 200);

    // Reopen segment — should load via CommitMarkerV2 in < 100 µs without full log scan
    let start_open = Instant::now();
    let recovered_seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
    let open_duration = start_open.elapsed();

    println!("Segment recovery took {:?}", open_duration);
    assert_eq!(recovered_seg.next_offset, expected_offset);
    assert_eq!(recovered_seg.last_record_hash, expected_hash);
    assert_eq!(recovered_seg.mmr_root(), expected_root);

    // Verify recovery was instantaneous (under 500 microseconds in debug mode)
    assert!(
        open_duration.as_micros() < 500,
        "V2 recovery took {:?} which exceeds instant recovery bound",
        open_duration
    );
}
