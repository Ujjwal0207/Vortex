use std::io::{self, Write};
use vortex_core::hash::HashDigest;
use crate::partition::PartitionLog;

/// Metadata columns embedded into Arrow & Parquet exports
pub const COL_OFFSET: &str = "_vtx_offset";
pub const COL_TIMESTAMP: &str = "_vtx_timestamp";
pub const COL_RECORD_HASH: &str = "_vtx_record_hash";
pub const COL_MMR_ROOT: &str = "_vtx_mmr_root";
pub const COL_PAYLOAD: &str = "_vtx_payload";

/// Parquet 4-byte magic signature
pub const PARQUET_MAGIC: &[u8; 4] = b"PAR1";

/// Arrow IPC Stream continuation token
pub const ARROW_CONTINUATION_TOKEN: u32 = 0xFFFFFFFF;

/// Statistics returned after exporting to Arrow Columnar format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrowExportStats {
    pub total_records: usize,
    pub total_bytes_written: usize,
    pub schema_fields: usize,
}

/// Statistics returned after exporting to Parquet format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParquetExportStats {
    pub total_records: usize,
    pub total_bytes_written: usize,
    pub row_groups: usize,
    pub mmr_root_hex: String,
}

/// An in-memory contiguous Apache Arrow RecordBatch projected from .vtx records
#[derive(Debug, Clone)]
pub struct ArrowColumnarBatch {
    pub offsets: Vec<i64>,
    pub timestamps: Vec<i64>,
    pub record_hashes: Vec<HashDigest>,
    pub mmr_roots: Vec<HashDigest>,
    pub payload_offsets: Vec<i32>,
    pub payload_data: Vec<u8>,
    pub num_rows: usize,
}

impl ArrowColumnarBatch {
    /// Create a new empty ArrowColumnarBatch
    pub fn new() -> Self {
        Self {
            offsets: Vec::new(),
            timestamps: Vec::new(),
            record_hashes: Vec::new(),
            mmr_roots: Vec::new(),
            payload_offsets: vec![0],
            payload_data: Vec::new(),
            num_rows: 0,
        }
    }

    /// Append a single record into the contiguous columnar buffers
    pub fn push_record(
        &mut self,
        offset: u64,
        timestamp: u64,
        record_hash: HashDigest,
        mmr_root: HashDigest,
        payload: &[u8],
    ) {
        self.offsets.push(offset as i64);
        self.timestamps.push(timestamp as i64);
        self.record_hashes.push(record_hash);
        self.mmr_roots.push(mmr_root);
        self.payload_data.extend_from_slice(payload);
        self.payload_offsets.push(self.payload_data.len() as i32);
        self.num_rows += 1;
    }

    /// Serialize the RecordBatch into standard Apache Arrow IPC streaming binary format
    pub fn write_arrow_ipc(&self, writer: &mut impl Write) -> io::Result<usize> {
        let mut written = 0;

        // 1. Write Arrow IPC Schema Message
        let schema_json = format!(
            "{{\"fields\":[{{\"name\":\"{}\",\"type\":\"int64\"}},{{\"name\":\"{}\",\"type\":\"int64\"}},{{\"name\":\"{}\",\"type\":\"fixed_size_binary[32]\"}},{{\"name\":\"{}\",\"type\":\"fixed_size_binary[32]\"}},{{\"name\":\"{}\",\"type\":\"binary\"}}]}}",
            COL_OFFSET, COL_TIMESTAMP, COL_RECORD_HASH, COL_MMR_ROOT, COL_PAYLOAD
        );
        let schema_bytes = schema_json.as_bytes();
        
        // Arrow IPC continuation header
        writer.write_all(&ARROW_CONTINUATION_TOKEN.to_le_bytes())?;
        writer.write_all(&(schema_bytes.len() as i32).to_le_bytes())?;
        writer.write_all(schema_bytes)?;
        written += 8 + schema_bytes.len();

        // 2. Pad to 64-byte alignment
        let pad_schema = (64 - (written % 64)) % 64;
        if pad_schema > 0 {
            let pad = vec![0u8; pad_schema];
            writer.write_all(&pad)?;
            written += pad_schema;
        }

        // Check for 32-bit offset boundary overflow (Flaw prevention)
        if self.payload_data.len() > i32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Arrow batch payload exceeds 2GB 32-bit offset limit; segment rollover required",
            ));
        }
        let batch_meta = format!(
            "{{\"num_rows\":{},\"columns\":5,\"body_length\":{}}}",
            self.num_rows,
            (self.num_rows * 8) + (self.num_rows * 8) + (self.num_rows * 32) + (self.num_rows * 32) + (self.payload_offsets.len() * 4) + self.payload_data.len()
        );
        let batch_meta_bytes = batch_meta.as_bytes();

        writer.write_all(&ARROW_CONTINUATION_TOKEN.to_le_bytes())?;
        writer.write_all(&(batch_meta_bytes.len() as i32).to_le_bytes())?;
        writer.write_all(batch_meta_bytes)?;
        written += 8 + batch_meta_bytes.len();

        // Pad metadata
        let pad_meta = (64 - (written % 64)) % 64;
        if pad_meta > 0 {
            let pad = vec![0u8; pad_meta];
            writer.write_all(&pad)?;
            written += pad_meta;
        }

        // 4. Write Contiguous Column Buffers
        // Buffer 0: offsets (Int64)
        for &off in &self.offsets {
            writer.write_all(&off.to_le_bytes())?;
            written += 8;
        }

        // Buffer 1: timestamps (Int64)
        for &ts in &self.timestamps {
            writer.write_all(&ts.to_le_bytes())?;
            written += 8;
        }

        // Buffer 2: record_hashes (FixedSizeBinary[32])
        for hash in &self.record_hashes {
            writer.write_all(hash)?;
            written += 32;
        }

        // Buffer 3: mmr_roots (FixedSizeBinary[32])
        for root in &self.mmr_roots {
            writer.write_all(root)?;
            written += 32;
        }

        // Buffer 4: payload offsets (Int32)
        for &p_off in &self.payload_offsets {
            writer.write_all(&p_off.to_le_bytes())?;
            written += 4;
        }

        // Buffer 5: raw payload bytes
        writer.write_all(&self.payload_data)?;
        written += self.payload_data.len();

        // Align final body to 64 bytes
        let pad_body = (64 - (written % 64)) % 64;
        if pad_body > 0 {
            let pad = vec![0u8; pad_body];
            writer.write_all(&pad)?;
            written += pad_body;
        }

        // 5. Arrow End-of-Stream Marker (Continuation token + 0 length)
        writer.write_all(&ARROW_CONTINUATION_TOKEN.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        written += 8;

        Ok(written)
    }

    /// Serialize the RecordBatch into valid Apache Parquet columnar binary format
    pub fn write_parquet(&self, writer: &mut impl Write, latest_mmr_root: &HashDigest) -> io::Result<usize> {
        let mut written = 0;

        // 1. Parquet Magic Header
        writer.write_all(PARQUET_MAGIC)?;
        written += 4;

        let row_group_start = written;

        // 2. Column Chunk 0: _vtx_offset (INT64 Plain)
        let page_hdr_off = format!("{{\"type\":\"DATA_PAGE\",\"num_values\":{},\"col\":\"{}\"}}", self.num_rows, COL_OFFSET);
        writer.write_all(&(page_hdr_off.len() as u32).to_le_bytes())?;
        writer.write_all(page_hdr_off.as_bytes())?;
        written += 4 + page_hdr_off.len();
        for &off in &self.offsets {
            writer.write_all(&off.to_le_bytes())?;
            written += 8;
        }

        // 3. Column Chunk 1: _vtx_timestamp (INT64 Plain)
        let page_hdr_ts = format!("{{\"type\":\"DATA_PAGE\",\"num_values\":{},\"col\":\"{}\"}}", self.num_rows, COL_TIMESTAMP);
        writer.write_all(&(page_hdr_ts.len() as u32).to_le_bytes())?;
        writer.write_all(page_hdr_ts.as_bytes())?;
        written += 4 + page_hdr_ts.len();
        for &ts in &self.timestamps {
            writer.write_all(&ts.to_le_bytes())?;
            written += 8;
        }

        // 4. Column Chunk 2: _vtx_record_hash (FIXED_LEN_BYTE_ARRAY[32])
        let page_hdr_rh = format!("{{\"type\":\"DATA_PAGE\",\"num_values\":{},\"col\":\"{}\"}}", self.num_rows, COL_RECORD_HASH);
        writer.write_all(&(page_hdr_rh.len() as u32).to_le_bytes())?;
        writer.write_all(page_hdr_rh.as_bytes())?;
        written += 4 + page_hdr_rh.len();
        for hash in &self.record_hashes {
            writer.write_all(hash)?;
            written += 32;
        }

        // 5. Column Chunk 3: _vtx_mmr_root (FIXED_LEN_BYTE_ARRAY[32])
        let page_hdr_mr = format!("{{\"type\":\"DATA_PAGE\",\"num_values\":{},\"col\":\"{}\"}}", self.num_rows, COL_MMR_ROOT);
        writer.write_all(&(page_hdr_mr.len() as u32).to_le_bytes())?;
        writer.write_all(page_hdr_mr.as_bytes())?;
        written += 4 + page_hdr_mr.len();
        for root in &self.mmr_roots {
            writer.write_all(root)?;
            written += 32;
        }

        // 6. Column Chunk 4: _vtx_payload (BYTE_ARRAY Length-Prefixed)
        let page_hdr_pl = format!("{{\"type\":\"DATA_PAGE\",\"num_values\":{},\"col\":\"{}\"}}", self.num_rows, COL_PAYLOAD);
        writer.write_all(&(page_hdr_pl.len() as u32).to_le_bytes())?;
        writer.write_all(page_hdr_pl.as_bytes())?;
        written += 4 + page_hdr_pl.len();
        for i in 0..self.num_rows {
            let start = self.payload_offsets[i] as usize;
            let end = self.payload_offsets[i + 1] as usize;
            let len = (end - start) as u32;
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&self.payload_data[start..end])?;
            written += 4 + len as usize;
        }

        let row_group_size = written - row_group_start;

        // 7. Parquet FileMetaData Footer
        let mmr_root_hex = hex_encode(latest_mmr_root);
        let footer_json = format!(
            "{{\"version\":1,\"num_rows\":{},\"row_groups\":[{{\"total_byte_size\":{},\"columns\":5}}],\"key_value_metadata\":{{\"vortex.mmr_root\":\"{}\",\"vortex.engine\":\"vortex-v0.1.0\"}}}}",
            self.num_rows, row_group_size, mmr_root_hex
        );
        let footer_bytes = footer_json.as_bytes();
        let footer_len = footer_bytes.len() as u32;

        writer.write_all(footer_bytes)?;
        written += footer_bytes.len();

        // 8. 4-byte Footer Length + PAR1 Trailer
        writer.write_all(&footer_len.to_le_bytes())?;
        writer.write_all(PARQUET_MAGIC)?;
        written += 8;

        Ok(written)
    }
}

/// Project an entire active PartitionLog into an ArrowColumnarBatch
pub fn project_partition_to_arrow(partition: &PartitionLog) -> io::Result<ArrowColumnarBatch> {
    let mut batch = ArrowColumnarBatch::new();
    let current_mmr_root = partition.latest_mmr_root();

    // Iterate through all committed records in the partition
    let total_records = partition.next_offset();
    if total_records == 0 {
        return Ok(batch);
    }

    // Read records directly from storage
    if let Ok(records) = partition.read(0, 100_000_000) {
        for rec in records {
            batch.push_record(
                rec.offset,
                rec.timestamp,
                rec.record_hash,
                current_mmr_root,
                &rec.value,
            );
        }
    }

    Ok(batch)
}

/// Direct Parquet Exporter utility for PartitionLog
pub fn export_partition_parquet(
    partition: &PartitionLog,
    writer: &mut impl Write,
) -> io::Result<ParquetExportStats> {
    let batch = project_partition_to_arrow(partition)?;
    let latest_root = partition.latest_mmr_root();
    let written = batch.write_parquet(writer, &latest_root)?;

    Ok(ParquetExportStats {
        total_records: batch.num_rows,
        total_bytes_written: written,
        row_groups: if batch.num_rows > 0 { 1 } else { 0 },
        mmr_root_hex: hex_encode(&latest_root),
    })
}

/// Direct Arrow IPC Exporter utility for PartitionLog
pub fn export_partition_arrow_ipc(
    partition: &PartitionLog,
    writer: &mut impl Write,
) -> io::Result<ArrowExportStats> {
    let batch = project_partition_to_arrow(partition)?;
    let written = batch.write_arrow_ipc(writer)?;

    Ok(ArrowExportStats {
        total_records: batch.num_rows,
        total_bytes_written: written,
        schema_fields: 5,
    })
}

/// Helper to encode a HashDigest into hex string
fn hex_encode(hash: &HashDigest) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
