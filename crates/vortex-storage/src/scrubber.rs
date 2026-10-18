#[cfg(unix)]
use std::os::unix::fs::FileExt;
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
    /// Uses positional reads (`read_exact_at`) without mutating file pointers, allowing
    /// autonomous background scrubbing without locking out active readers.
    pub fn scrub_segment(segment: &Segment) -> Result<ScrubReport> {
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

        let mut curr_pos = HEADER_INDEX_REGION_SIZE;
        let mut expected_prev_hash: HashDigest = segment.genesis_hash;
        let mut body_buf = Vec::new();

        while curr_pos < file_len {
            // Read 4-byte total_len via positional read
            let mut len_buf = [0u8; 4];
            if let Err(e) = segment.file.read_exact_at(&mut len_buf, curr_pos) {
                report.details.push(format!("Truncated record at pos {}: {}", curr_pos, e));
                report.healthy = false;
                break;
            }

            let total_len = u32::from_be_bytes(len_buf) as u64;
            if total_len < (RECORD_HEADER_SIZE - 4) as u64
                || curr_pos.checked_add(4 + total_len).map_or(true, |end| end > file_len)
            {
                report.details.push(format!(
                    "Invalid record length {} at physical pos {}",
                    total_len, curr_pos
                ));
                report.corrupted_crc_count += 1;
                report.healthy = false;
                break;
            }

            // Read the record body (crc32 + payload) via positional read
            let Ok(body_len) = usize::try_from(total_len) else {
                report.details.push(format!("Record at pos {} is too large for this platform", curr_pos));
                report.healthy = false;
                break;
            };
            body_buf.resize(body_len, 0);
            if let Err(e) = segment.file.read_exact_at(&mut body_buf, curr_pos + 4) {
                report.details.push(format!("Read error at pos {}: {}", curr_pos, e));
                report.healthy = false;
                break;
            }

            // Decode and verify CRC32 without allocating a new payload per record.
            let actual_crc = u32::from_be_bytes(body_buf[0..4].try_into().unwrap());
            let payload = &body_buf[4..];

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

            let parsed = match parse_record_payload(payload) {
                Ok(parsed) => parsed,
                Err(message) => {
                    report.details.push(format!("Invalid record at pos {}: {}", curr_pos, message));
                    report.healthy = false;
                    break;
                }
            };

            // Verify Blake3 hash chain
            if parsed.prev_hash != expected_prev_hash {
                report.broken_hash_chain_count += 1;
                report.healthy = false;
                report.details.push(format!(
                    "Blake3 chain break at offset {}: expected prev_hash {:?}, found {:?}",
                    parsed.offset, expected_prev_hash, parsed.prev_hash
                ));
            }

            let computed_hash = compute_record_hash(
                &parsed.prev_hash,
                parsed.offset,
                parsed.timestamp,
                parsed.key,
                parsed.value,
            );

            if computed_hash != parsed.record_hash {
                report.broken_hash_chain_count += 1;
                report.healthy = false;
                report.details.push(format!(
                    "Blake3 record tamper detected at offset {}: computed {:?}, recorded {:?}",
                    parsed.offset, computed_hash, parsed.record_hash
                ));
            }

            expected_prev_hash = parsed.record_hash;
            report.records_scanned += 1;
            report.bytes_scanned += 4 + total_len;
            curr_pos += 4 + total_len;
        }

        report.scan_duration_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Autonomously scrubs all segments of a partition log without taking exclusive write locks.
    pub fn scrub_partition(partition: &PartitionLog) -> Result<ScrubReport> {
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

        for segment in &partition.segments {
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

struct ParsedRecord<'a> {
    offset: u64,
    timestamp: u64,
    prev_hash: HashDigest,
    record_hash: HashDigest,
    key: Option<&'a [u8]>,
    value: &'a [u8],
}

fn parse_record_payload(payload: &[u8]) -> std::result::Result<ParsedRecord<'_>, &'static str> {
    const FIXED_PREFIX: usize = 8 + 8 + 32 + 32 + 4;
    if payload.len() < FIXED_PREFIX + 4 {
        return Err("payload is shorter than the record header");
    }

    let offset = u64::from_be_bytes(payload[0..8].try_into().unwrap());
    let timestamp = u64::from_be_bytes(payload[8..16].try_into().unwrap());
    let prev_hash: HashDigest = payload[16..48].try_into().unwrap();
    let record_hash: HashDigest = payload[48..80].try_into().unwrap();
    let key_len = i32::from_be_bytes(payload[80..84].try_into().unwrap());
    if key_len < -1 {
        return Err("invalid negative key length");
    }

    let (key, value_len_pos) = if key_len == -1 {
        (None, 84)
    } else {
        let key_len = key_len as usize;
        let key_end = 84usize.checked_add(key_len).ok_or("key length overflow")?;
        if key_end.checked_add(4).map_or(true, |end| end > payload.len()) {
            return Err("key extends beyond the record payload");
        }
        (Some(&payload[84..key_end]), key_end)
    };

    let value_len = u32::from_be_bytes(payload[value_len_pos..value_len_pos + 4].try_into().unwrap()) as usize;
    let value_start = value_len_pos + 4;
    if value_start.checked_add(value_len) != Some(payload.len()) {
        return Err("value length does not match the remaining payload");
    }

    Ok(ParsedRecord {
        offset,
        timestamp,
        prev_hash,
        record_hash,
        key,
        value: &payload[value_start..],
    })
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
        let report = Scrubber::scrub_segment(&seg).unwrap();
        assert!(report.healthy);
        assert_eq!(report.records_scanned, 10);
        assert_eq!(report.corrupted_crc_count, 0);
        assert_eq!(report.broken_hash_chain_count, 0);

        // 2. Inject intentional bit-rot (tamper with a byte in record 2)
        #[cfg(unix)]
        seg.file.write_all_at(&[0xFF], HEADER_INDEX_REGION_SIZE + 15).unwrap();
        let _ = seg.file.sync_data();

        // 3. Scrub corrupted segment: must flag corruption
        let corrupt_report = Scrubber::scrub_segment(&seg).unwrap();
        assert!(!corrupt_report.healthy);
        assert!(corrupt_report.corrupted_crc_count > 0 || corrupt_report.broken_hash_chain_count > 0);
    }
}
