use bytes::Buf;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use vortex_core::{
    error::Result,
    hash::{compute_record_hash, HashDigest},
    record::RECORD_HEADER_SIZE,
    VortexError,
};

use crate::partition::PartitionLog;
use crate::segment::{Segment, HEADER_INDEX_REGION_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubReport {
    pub records_scanned: u64,
    pub bytes_scanned: u64,
    pub corrupted_crc_count: u64,
    pub broken_hash_chain_count: u64,
    pub healthy: bool,
    pub scan_duration_ms: u64,
    pub details: Vec<String>,
}

pub struct Scrubber;

impl Scrubber {
    /// Autonomously scrubs a single .vtx segment file, verifying CRC32 framing
    /// and the complete continuous Blake3 SIMD cryptographic hash chain against silent bit-rot.
    pub fn scrub_segment(segment: &mut Segment) -> Result<ScrubReport> {
        let start = Instant::now();
        let mut report = ScrubReport {
            records_scanned: 0,
            bytes_scanned: 0,
            corrupted_crc_count: 0,
            broken_hash_chain_count: 0,
            healthy: true,
            scan_duration_ms: 0,
            details: Vec::new(),
        };

        let file_len = segment
            .file
            .metadata()
            .map_err(|e| VortexError::Io(e.to_string()))?
            .len();

        if file_len <= HEADER_INDEX_REGION_SIZE {
            report.scan_duration_ms = start.elapsed().as_millis() as u64;
            return Ok(report);
        }

        segment
            .file
            .seek(SeekFrom::Start(HEADER_INDEX_REGION_SIZE))
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut curr_pos = HEADER_INDEX_REGION_SIZE;
        let mut expected_prev_hash: HashDigest = segment.genesis_hash;

        while curr_pos < file_len {
            // Read 4-byte total_len
            let mut len_buf = [0u8; 4];
            if let Err(e) = segment.file.read_exact(&mut len_buf) {
                report.details.push(format!("Truncated record at pos {}: {}", curr_pos, e));
                report.healthy = false;
                break;
            }

            let total_len = u32::from_be_bytes(len_buf) as u64;
            if total_len < 4 + RECORD_HEADER_SIZE as u64 || curr_pos + 4 + total_len > file_len {
                report.details.push(format!(
                    "Invalid record length {} at physical pos {}",
                    total_len, curr_pos
                ));
                report.corrupted_crc_count += 1;
                report.healthy = false;
                break;
            }

            // Read the record body (crc32 + payload)
            let mut body_buf = vec![0u8; total_len as usize];
            if let Err(e) = segment.file.read_exact(&mut body_buf) {
                report.details.push(format!("Read error at pos {}: {}", curr_pos, e));
                report.healthy = false;
                break;
            }

            // Decode and verify CRC32
            let mut slice = &body_buf[..];
            let actual_crc = slice.get_u32();
            let payload = slice;

            let mut hasher = crc32fast::Hasher::new();
            hasher.update(payload);
            let expected_crc = hasher.finalize();

            if actual_crc != expected_crc {
                report.corrupted_crc_count += 1;
                report.healthy = false;
                report.details.push(format!(
                    "CRC32 mismatch at pos {}: expected {:#010x}, found {:#010x}",
                    curr_pos, expected_crc, actual_crc
                ));
            }

            // Decode record fields
            let mut record_slice = payload;
            let offset = record_slice.get_u64();
            let timestamp = record_slice.get_u64();

            let mut prev_hash = [0u8; 32];
            record_slice.copy_to_slice(&mut prev_hash);

            let mut record_hash = [0u8; 32];
            record_slice.copy_to_slice(&mut record_hash);

            let key_len = record_slice.get_i32();
            let key = if key_len >= 0 {
                let k = record_slice.copy_to_bytes(key_len as usize);
                Some(k)
            } else {
                None
            };

            let val_len = record_slice.get_u32() as usize;
            let value = record_slice.copy_to_bytes(val_len);

            // Verify Blake3 hash chain
            if prev_hash != expected_prev_hash {
                report.broken_hash_chain_count += 1;
                report.healthy = false;
                report.details.push(format!(
                    "Blake3 chain break at offset {}: expected prev_hash {:?}, found {:?}",
                    offset, expected_prev_hash, prev_hash
                ));
            }

            let computed_hash = compute_record_hash(
                &prev_hash,
                offset,
                timestamp,
                key.as_deref(),
                &value,
            );

            if computed_hash != record_hash {
                report.broken_hash_chain_count += 1;
                report.healthy = false;
                report.details.push(format!(
                    "Blake3 record tamper detected at offset {}: computed {:?}, recorded {:?}",
                    offset, computed_hash, record_hash
                ));
            }

            expected_prev_hash = record_hash;
            report.records_scanned += 1;
            report.bytes_scanned += 4 + total_len;
            curr_pos += 4 + total_len;
        }

        report.scan_duration_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Autonomously scrubs all segments of a partition log.
    pub fn scrub_partition(partition: &mut PartitionLog) -> Result<ScrubReport> {
        let start = Instant::now();
        let mut aggregated = ScrubReport {
            records_scanned: 0,
            bytes_scanned: 0,
            corrupted_crc_count: 0,
            broken_hash_chain_count: 0,
            healthy: true,
            scan_duration_ms: 0,
            details: Vec::new(),
        };

        for segment in &mut partition.segments {
            let seg_report = Self::scrub_segment(segment)?;
            aggregated.records_scanned += seg_report.records_scanned;
            aggregated.bytes_scanned += seg_report.bytes_scanned;
            aggregated.corrupted_crc_count += seg_report.corrupted_crc_count;
            aggregated.broken_hash_chain_count += seg_report.broken_hash_chain_count;
            if !seg_report.healthy {
                aggregated.healthy = false;
                aggregated.details.extend(seg_report.details);
            }
        }

        aggregated.scan_duration_ms = start.elapsed().as_millis() as u64;
        Ok(aggregated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tempfile::tempdir;

    #[test]
    fn test_scrubber_healthy_and_tampered_segment() {
        let dir = tempdir().unwrap();
        let genesis = [0u8; 32];
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();

        // Append 10 healthy records
        for i in 0..10 {
            seg.append(None, Bytes::from(format!("Message-{}", i))).unwrap();
        }

        // 1. Scrub healthy segment
        let report = Scrubber::scrub_segment(&mut seg).unwrap();
        assert!(report.healthy);
        assert_eq!(report.records_scanned, 10);
        assert_eq!(report.corrupted_crc_count, 0);
        assert_eq!(report.broken_hash_chain_count, 0);

        // 2. Inject intentional bit-rot (tamper with a byte in record 2)
        use std::io::Write;
        seg.file.seek(SeekFrom::Start(HEADER_INDEX_REGION_SIZE + 15)).unwrap();
        seg.file.write_all(&[0xFF]).unwrap();
        seg.file.flush().unwrap();

        // 3. Scrub corrupted segment: must flag corruption
        let corrupt_report = Scrubber::scrub_segment(&mut seg).unwrap();
        assert!(!corrupt_report.healthy);
        assert!(corrupt_report.corrupted_crc_count > 0 || corrupt_report.broken_hash_chain_count > 0);
    }
}
