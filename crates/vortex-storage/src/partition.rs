use bytes::Bytes;
use std::fs;
use std::path::{Path, PathBuf};

use vortex_core::{
    compute_genesis_hash, error::Result, record::Record, HashDigest, VortexError,
};

use crate::segment::Segment;

pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

pub struct PartitionLog {
    pub topic: String,
    pub partition_id: u32,
    pub dir: PathBuf,
    pub max_segment_bytes: u64,
    pub segments: Vec<Segment>,
}

impl PartitionLog {
    /// Opens an existing partition directory or initializes a new partition log.
    pub fn open_or_create(
        base_dir: &Path,
        topic: &str,
        partition_id: u32,
        max_segment_bytes: u64,
    ) -> Result<Self> {
        let dir = base_dir.join(topic).join(format!("partition-{}", partition_id));
        fs::create_dir_all(&dir).map_err(|e| VortexError::Io(e.to_string()))?;

        let mut segment_files: Vec<PathBuf> = fs::read_dir(&dir)
            .map_err(|e| VortexError::Io(e.to_string()))?
            .filter_map(|entry| entry.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("vtx"))
            .collect();

        segment_files.sort();

        let mut segments = Vec::new();

        if segment_files.is_empty() {
            // New partition: initialize with deterministic genesis root
            let genesis = compute_genesis_hash(topic, partition_id);
            let active = Segment::open_or_create(&dir, 0, genesis)?;
            segments.push(active);
        } else {
            // Load existing segments in sequence
            let mut last_hash: Option<HashDigest> = None;

            for file_path in segment_files {
                let filename = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("0");
                let base_offset: u64 = filename.parse().unwrap_or(0);

                let genesis = last_hash.unwrap_or_else(|| compute_genesis_hash(topic, partition_id));
                let seg = Segment::open_or_create(&dir, base_offset, genesis)?;
                last_hash = Some(seg.last_record_hash);
                segments.push(seg);
            }
        }

        Ok(Self {
            topic: topic.to_string(),
            partition_id,
            dir,
            max_segment_bytes,
            segments,
        })
    }

    /// Appends a new event to the partition. If the active segment exceeds `max_segment_bytes`,
    /// rolls to a new segment with seamless cryptographic chain continuity.
    pub fn append(&mut self, key: Option<Bytes>, value: Bytes) -> Result<Record> {
        let should_roll = {
            let active = self.active_segment();
            active.size() >= self.max_segment_bytes
        };

        if should_roll {
            self.roll_segment()?;
        }

        let active = self.active_segment_mut();
        active.append(key, value)
    }

    /// Explicitly rolls the active segment, creating a new segment that inherits
    /// the cryptographic tail hash of the current active segment.
    pub fn roll_segment(&mut self) -> Result<()> {
        let active = self.active_segment_mut();
        active.flush()?;

        let next_base_offset = active.next_offset;
        let predecessor_tail_hash = active.last_record_hash;

        let new_segment = Segment::open_or_create(&self.dir, next_base_offset, predecessor_tail_hash)?;
        self.segments.push(new_segment);

        Ok(())
    }

    /// Reads records starting from `start_offset` across segments up to `max_bytes`.
    pub fn read(&mut self, start_offset: u64, max_bytes: usize) -> Result<Vec<Record>> {
        if self.segments.is_empty() {
            return Ok(Vec::new());
        }

        let first_offset = self.segments[0].base_offset;
        let next_offset = self.next_offset();

        if start_offset < first_offset || start_offset >= next_offset {
            return Ok(Vec::new());
        }

        // Find starting segment using binary search
        let seg_idx = match self
            .segments
            .binary_search_by_key(&start_offset, |s| s.base_offset)
        {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };

        let mut records = Vec::new();
        let mut curr_offset = start_offset;
        let mut bytes_accumulated = 0;

        for seg in &mut self.segments[seg_idx..] {
            if bytes_accumulated >= max_bytes {
                break;
            }

            let batch = seg.read(curr_offset, max_bytes - bytes_accumulated)?;
            if batch.is_empty() {
                continue;
            }

            for rec in batch {
                bytes_accumulated += rec.value.len() + 96;
                curr_offset = rec.offset + 1;
                records.push(rec);
                if bytes_accumulated >= max_bytes {
                    break;
                }
            }
        }

        Ok(records)
    }

    /// Flushes the active segment to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.active_segment_mut().flush()
    }

    /// Returns the next offset that will be assigned to an incoming message.
    pub fn next_offset(&self) -> u64 {
        self.active_segment().next_offset
    }

    /// Returns a reference to the current active segment.
    pub fn active_segment(&self) -> &Segment {
        self.segments.last().expect("Partition must have at least one segment")
    }

    /// Returns a mutable reference to the current active segment.
    pub fn active_segment_mut(&mut self) -> &mut Segment {
        self.segments.last_mut().expect("Partition must have at least one segment")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_partition_append_segment_rolling_and_cross_segment_reads() {
        let dir = tempdir().unwrap();

        // Small max segment size (1000 bytes) to force rapid segment rolling
        let mut log = PartitionLog::open_or_create(dir.path(), "orders", 0, 1000).unwrap();

        assert_eq!(log.segments.len(), 1);

        // Append 50 records
        for i in 0..50 {
            let key = Some(Bytes::from(format!("k-{}", i)));
            let val = Bytes::from(format!("val-{:010}", i));
            log.append(key, val).unwrap();
        }

        log.flush().unwrap();

        // Multiple segments must have rolled
        assert!(
            log.segments.len() > 1,
            "Partition should have rolled into multiple segments, had {}",
            log.segments.len()
        );

        // Read across all segments from offset 0 to 50
        let all_records = log.read(0, 1024 * 1024).unwrap();
        assert_eq!(all_records.len(), 50);

        // Verify uninterrupted cryptographic hash chain across segment boundaries!
        for i in 1..50 {
            assert_eq!(
                all_records[i].prev_hash, all_records[i - 1].record_hash,
                "Hash chain must be unbroken across segment rolling boundary at offset {}",
                i
            );
        }
    }
}
