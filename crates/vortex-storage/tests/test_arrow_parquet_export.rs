use std::io::Cursor;
use bytes::Bytes;
use tempfile::tempdir;
use vortex_storage::arrow_parquet::{
    export_partition_arrow_ipc, export_partition_parquet, ArrowColumnarBatch,
    ARROW_CONTINUATION_TOKEN, COL_MMR_ROOT, COL_OFFSET, COL_PAYLOAD, COL_RECORD_HASH,
    COL_TIMESTAMP, PARQUET_MAGIC,
};
use vortex_storage::partition::{PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

#[test]
fn test_arrow_columnar_batch_in_memory() {
    let mut batch = ArrowColumnarBatch::new();
    assert_eq!(batch.num_rows, 0);

    for i in 0..100 {
        let hash = [i as u8; 32];
        let root = [(i + 1) as u8; 32];
        let payload = format!("payload-data-{}", i).into_bytes();
        batch.push_record(i as u64, 1_700_000_000 + i as u64, hash, root, &payload);
    }

    assert_eq!(batch.num_rows, 100);
    assert_eq!(batch.offsets.len(), 100);
    assert_eq!(batch.timestamps.len(), 100);
    assert_eq!(batch.record_hashes.len(), 100);
    assert_eq!(batch.mmr_roots.len(), 100);
    assert_eq!(batch.payload_offsets.len(), 101);

    // Test Arrow IPC write
    let mut arrow_buf = Vec::new();
    let written_arrow = batch.write_arrow_ipc(&mut arrow_buf).expect("write arrow ipc");
    assert_eq!(written_arrow, arrow_buf.len());
    assert!(written_arrow > 0);

    // Verify Arrow IPC format
    // 1. Starts with continuation token 0xFFFFFFFF
    let first_token = u32::from_le_bytes(arrow_buf[0..4].try_into().unwrap());
    assert_eq!(first_token, ARROW_CONTINUATION_TOKEN);

    // 2. Contains schema fields
    let arrow_str = String::from_utf8_lossy(&arrow_buf);
    assert!(arrow_str.contains(COL_OFFSET));
    assert!(arrow_str.contains(COL_TIMESTAMP));
    assert!(arrow_str.contains(COL_RECORD_HASH));
    assert!(arrow_str.contains(COL_MMR_ROOT));
    assert!(arrow_str.contains(COL_PAYLOAD));

    // 3. Ends with EOS marker (0xFFFFFFFF followed by 0x00000000)
    let end_idx = arrow_buf.len();
    let eos_token = u32::from_le_bytes(arrow_buf[end_idx - 8..end_idx - 4].try_into().unwrap());
    let eos_len = i32::from_le_bytes(arrow_buf[end_idx - 4..end_idx].try_into().unwrap());
    assert_eq!(eos_token, ARROW_CONTINUATION_TOKEN);
    assert_eq!(eos_len, 0);

    // Test Parquet write
    let latest_root = [0x42u8; 32];
    let mut parquet_buf = Vec::new();
    let written_parquet = batch
        .write_parquet(&mut parquet_buf, &latest_root)
        .expect("write parquet");
    assert_eq!(written_parquet, parquet_buf.len());

    // Verify Parquet format
    // 1. Header is PAR1
    assert_eq!(&parquet_buf[0..4], PARQUET_MAGIC);

    // 2. Trailer is PAR1
    let p_len = parquet_buf.len();
    assert_eq!(&parquet_buf[p_len - 4..p_len], PARQUET_MAGIC);

    // 3. Footer length is valid
    let footer_len = u32::from_le_bytes(parquet_buf[p_len - 8..p_len - 4].try_into().unwrap()) as usize;
    assert!(footer_len > 0);
    assert!(footer_len < p_len - 8);

    // 4. Metadata includes MMR root
    let parquet_str = String::from_utf8_lossy(&parquet_buf);
    assert!(parquet_str.contains("vortex.mmr_root"));
    assert!(parquet_str.contains(COL_OFFSET));
}

#[test]
fn test_partition_log_arrow_and_parquet_export() {
    let dir = tempdir().unwrap();
    let mut part = PartitionLog::open_or_create(dir.path(), "analytics_export", 0, DEFAULT_MAX_SEGMENT_BYTES)
        .expect("create partition");

    // Append 500 records
    for i in 0..500 {
        let payload = Bytes::from(format!("{{\"event_id\":{},\"metric\":\"cpu_load\",\"val\":{}.5}}", i, i % 100));
        part.append(None, payload).expect("append");
    }

    // Export Arrow IPC via PartitionLog helper
    let mut arrow_out = Cursor::new(Vec::new());
    let arrow_stats = part.export_arrow_ipc(&mut arrow_out).expect("export arrow");
    assert_eq!(arrow_stats.total_records, 500);
    assert_eq!(arrow_stats.schema_fields, 5);
    assert!(arrow_stats.total_bytes_written > 0);

    // Export Parquet via PartitionLog helper
    let mut parquet_out = Cursor::new(Vec::new());
    let parquet_stats = part.export_parquet(&mut parquet_out).expect("export parquet");
    assert_eq!(parquet_stats.total_records, 500);
    assert_eq!(parquet_stats.row_groups, 1);
    assert!(!parquet_stats.mmr_root_hex.is_empty());
    assert!(parquet_stats.total_bytes_written > 0);

    let parquet_bytes = parquet_out.into_inner();
    assert_eq!(&parquet_bytes[0..4], PARQUET_MAGIC);
    let p_len = parquet_bytes.len();
    assert_eq!(&parquet_bytes[p_len - 4..p_len], PARQUET_MAGIC);
}

#[test]
fn test_empty_partition_export() {
    let dir = tempdir().unwrap();
    let part = PartitionLog::open_or_create(dir.path(), "empty_export", 0, DEFAULT_MAX_SEGMENT_BYTES)
        .expect("create partition");

    let mut arrow_out = Vec::new();
    let stats = export_partition_arrow_ipc(&part, &mut arrow_out).expect("export empty arrow");
    assert_eq!(stats.total_records, 0);

    let mut parquet_out = Vec::new();
    let p_stats = export_partition_parquet(&part, &mut parquet_out).expect("export empty parquet");
    assert_eq!(p_stats.total_records, 0);
    assert_eq!(p_stats.row_groups, 0);
    assert_eq!(&parquet_out[0..4], PARQUET_MAGIC);
    let p_len = parquet_out.len();
    assert_eq!(&parquet_out[p_len - 4..p_len], PARQUET_MAGIC);
}

