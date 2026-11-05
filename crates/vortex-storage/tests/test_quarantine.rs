use bytes::Bytes;
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use tempfile::tempdir;
use vortex_storage::PartitionLog;

#[test]
fn test_segment_quarantine_historical_bit_rot() {
    let dir = tempdir().unwrap();
    let topic = "quarantine-test";

    // 1. Create partition log with small segments (10 KB) to produce multiple historical segments
    {
        let mut log = PartitionLog::open_or_create(dir.path(), topic, 0, 10 * 1024).unwrap();
        // Append 60 records
        for i in 0..60 {
            log.append(
                Some(Bytes::from(format!("k-{}", i))),
                Bytes::from(format!("payload-data-line-{}", i)),
            )
            .unwrap();
        }
        assert!(log.segments.len() >= 3, "Expected at least 3 segments");
    }

    // 2. Intentionally inject physical bit-rot into the middle historical segment (segment 1)
    let partition_dir = dir.path().join(topic).join(format!("partition-{}", 0));
    let mut vtx_files: Vec<_> = std::fs::read_dir(&partition_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "vtx"))
        .collect();
    vtx_files.sort();
    assert!(vtx_files.len() >= 3, "Expected at least 3 segments, found {}", vtx_files.len());

    let historical_seg_path = &vtx_files[1];
    println!("Injecting bit-rot into historical segment: {:?}", historical_seg_path);

    // Corrupt data bytes inside historical segment (beyond 64KB header)
    let file = OpenOptions::new().write(true).open(historical_seg_path).unwrap();
    #[cfg(unix)]
    {
        file.write_all_at(&[0xDE, 0xAD, 0xBE, 0xEF], 65536 + 10).unwrap();
    }
    drop(file);

    // Also remove or tamper .commit marker so recovery is forced to encounter bit-rot
    let commit_path = historical_seg_path.with_file_name(format!(
        "{}.commit",
        historical_seg_path.file_name().unwrap().to_str().unwrap()
    ));
    if commit_path.exists() {
        let _ = std::fs::remove_file(commit_path);
    }

    // 3. Reopening PartitionLog MUST NOT crash! It must quarantine the corrupted segment and open successfully.
    let mut recovered_log = PartitionLog::open_or_create(dir.path(), topic, 0, 10 * 1024)
        .expect("Broker must survive historical segment bit-rot");

    // Quarantine directory must exist with the quarantined file
    let quarantine_dir = partition_dir.join(".quarantine");
    assert!(quarantine_dir.exists(), "Quarantine directory must be created");
    let quarantined_files: Vec<_> = std::fs::read_dir(&quarantine_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!quarantined_files.is_empty(), "Corrupted segment must be moved to quarantine");

    // Active writes must continue working
    let new_rec = recovered_log
        .append(Some(Bytes::from("new_key")), Bytes::from("new_live_data"))
        .expect("Active writes must proceed");
    assert!(new_rec.offset > 0);
}
