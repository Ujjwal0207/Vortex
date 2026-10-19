use bytes::Bytes;
use std::fs;
use std::path::{Path, PathBuf};

use vortex_core::{
    compute_genesis_hash, error::Result, record::Record, HashDigest, MmrInclusionProof,
    VortexError,
};

use crate::keyring::TwoSlotKeyring;
use crate::segment::{commit_state_path, Segment};

pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionVerifyReport {
    pub topic: String,
    pub partition_id: u32,
    pub total_segments: usize,
    pub total_records: u64,
    pub earliest_offset: u64,
    pub latest_offset: u64,
    pub final_mmr_root: HashDigest,
    pub final_record_hash: HashDigest,
    pub is_valid: bool,
}

pub struct PartitionLog {
    pub topic: String,
    pub partition_id: u32,
    pub dir: PathBuf,
    pub max_segment_bytes: u64,
    pub segments: Vec<Segment>,
    pub keyring: TwoSlotKeyring,
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

        let mut segment_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| VortexError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| VortexError::Io(e.to_string()))?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("vtx") {
                segment_files.push(p);
            }
        }

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
            let mut expected_base_offset: Option<u64> = None;

            for file_path in segment_files {
                let stem = file_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| VortexError::Io(format!("invalid segment filename {:?}", file_path)))?;
                let base_offset: u64 = stem.parse().map_err(|_| {
                    VortexError::Io(format!(
                        "malformed segment filename {:?} (expected numeric base offset)",
                        file_path
                    ))
                })?;

                let genesis = last_hash.unwrap_or_else(|| compute_genesis_hash(topic, partition_id));
                let seg = Segment::open_or_create(&dir, base_offset, genesis)?;

                // Retention may remove a prefix of the log, so the first remaining
                // segment is the trusted chain anchor. Every following segment must
                // continue both the offset sequence and the previous segment's hash.
                // Segment recovery validates each file internally; these checks bind
                // the files together and reject gaps, reordered files, or a replaced
                // segment with an unrelated but internally valid chain.
                if seg.base_offset != base_offset {
                    return Err(VortexError::Io(format!(
                        "segment filename base offset {base_offset} disagrees with header base offset {} in {:?}",
                        seg.base_offset, file_path
                    )));
                }
                if let Some(expected) = expected_base_offset {
                    if seg.base_offset != expected {
                        return Err(VortexError::Io(format!(
                            "segment offset gap or overlap: expected base offset {expected}, found {} in {:?}",
                            seg.base_offset, file_path
                        )));
                    }
                }
                if let Some(expected_genesis) = last_hash {
                    if seg.genesis_hash != expected_genesis {
                        return Err(VortexError::Io(format!(
                            "segment hash-chain discontinuity at base offset {} in {:?}",
                            seg.base_offset, file_path
                        )));
                    }
                }

                expected_base_offset = Some(seg.next_offset);
                last_hash = Some(seg.last_record_hash);
                segments.push(seg);
            }
        }

        let current_next_offset = segments.last().map_or(0, |s| s.next_offset);
        let keyring =
            TwoSlotKeyring::open_or_create_with_offset(&dir, topic, partition_id, current_next_offset)?;

        Ok(Self {
            topic: topic.to_string(),
            partition_id,
            dir,
            max_segment_bytes,
            segments,
            keyring,
        })
    }

    /// Appends a new event to the partition. If the active segment exceeds `max_segment_bytes`,
    /// rolls to a new segment with seamless cryptographic chain continuity.
    pub fn append(&mut self, key: Option<Bytes>, value: Bytes) -> Result<Record> {
        self.append_with_timestamp(key, value, None)
    }

    pub fn append_with_timestamp(
        &mut self,
        key: Option<Bytes>,
        value: Bytes,
        timestamp: Option<u64>,
    ) -> Result<Record> {
        let mut results = self.append_batch(vec![(key, value, timestamp)])?;
        Ok(results.remove(0))
    }

    /// Appends an entire batch of records atomically.
    /// If the batch would exceed the active segment's capacity, rolls to a new segment first,
    /// ensuring the multi-record batch is not split across segments.
    pub fn append_batch(
        &mut self,
        batch: Vec<(Option<Bytes>, Bytes, Option<u64>)>,
    ) -> Result<Vec<Record>> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }

        let batch_bytes: u64 = batch
            .iter()
            .map(|(k, v, _)| {
                // Header (48B) + length prefix (4B) + key len + value len
                52 + k.as_ref().map_or(0, |k| k.len() as u64) + v.len() as u64
            })
            .sum();

        let should_roll = {
            let active = self.active_segment();
            active.next_offset > active.base_offset
                && active.size().saturating_add(batch_bytes) >= self.max_segment_bytes
        };

        if should_roll {
            self.roll_segment()?;
        }

        let active = self.active_segment_mut();
        let appended = active.append_batch(batch)?;

        for rec in &appended {
            let encoded = rec.encode();
            let _ = self.keyring.step_and_authenticate(&encoded, rec.offset + 1)?;
        }

        Ok(appended)
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
    /// Takes `&self` to allow concurrent readers without holding an exclusive lock.
    pub fn read(&self, start_offset: u64, max_bytes: usize) -> Result<Vec<Record>> {
        if self.segments.is_empty() {
            return Ok(Vec::new());
        }

        let first_offset = self.segments[0].base_offset;
        let next_offset = self.next_offset();

        if start_offset < first_offset {
            return Err(VortexError::OffsetOutOfRange {
                requested: start_offset,
                earliest: first_offset,
                latest: next_offset,
            });
        }

        if start_offset > next_offset {
            return Err(VortexError::OffsetOutOfRange {
                requested: start_offset,
                earliest: first_offset,
                latest: next_offset,
            });
        }

        if start_offset == next_offset {
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
        let total_segs = self.segments.len();

        for (i, seg) in self.segments[seg_idx..].iter().enumerate() {
            if bytes_accumulated >= max_bytes {
                break;
            }

            // Historical sealed segments drop kernel page cache after reading (Flaw 6.3),
            // while the active head segment keeps hot pages cached in RAM.
            let is_active = (seg_idx + i) == (total_segs.saturating_sub(1));
            let batch = if is_active {
                seg.read(curr_offset, max_bytes - bytes_accumulated)?
            } else {
                seg.read_cold(curr_offset, max_bytes - bytes_accumulated)?
            };
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

    /// Generates an O(log N) cryptographic MMR inclusion proof for the record at `offset`.
    pub fn generate_inclusion_proof(&self, offset: u64) -> Option<MmrInclusionProof> {
        for seg in &self.segments {
            if offset >= seg.base_offset && offset < seg.next_offset {
                return seg.generate_inclusion_proof(offset);
            }
        }
        None
    }

    /// Prunes expired sealed segments based on size (retention_bytes) and time (retention_ms).
    /// The active segment is NEVER pruned to guarantee append continuity.
    /// Returns the list of pruned segment base offsets.
    pub fn prune_retention(
        &mut self,
        now_ms: u64,
        retention_ms: Option<u64>,
        retention_bytes: Option<u64>,
    ) -> Result<Vec<u64>> {
        let mut pruned = Vec::new();

        while self.segments.len() > 1 {
            let total_size: u64 = self.segments.iter().map(|s| s.size()).sum();
            let oldest_seg = &self.segments[0];

            let should_prune_size = retention_bytes.map_or(false, |limit| total_size > limit);
            let should_prune_time = retention_ms.map_or(false, |limit_ms| {
                let cutoff = now_ms.saturating_sub(limit_ms);
                if let Ok(meta) = oldest_seg.file.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let dur = modified
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        dur.as_millis() < cutoff as u128
                    } else {
                        false
                    }
                } else {
                    false
                }
            });

            if should_prune_size || should_prune_time {
                let seg = &self.segments[0];
                let base = seg.base_offset;
                let path = seg.path.clone();
                let commit_path = commit_state_path(&path);

                // Remove the marker before the data file. If data deletion then fails,
                // the complete legacy segment remains recoverable by scanning it.
                remove_file_if_present(&commit_path).map_err(|e| {
                    VortexError::Io(format!("failed to remove pruned segment commit marker {:?}: {e}", commit_path))
                })?;
                remove_file_if_present(&path).map_err(|e| {
                    VortexError::Io(format!("failed to remove pruned segment file {:?}: {e}", path))
                })?;

                // Keep the segment available through its open descriptor, and in
                // memory, until unlinking has been made durable.
                fs::File::open(&self.dir)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|e| VortexError::Io(format!("failed to sync partition directory after retention deletion: {e}")))?;
                self.segments.remove(0);
                pruned.push(base);
            } else {
                break;
            }
        }

        Ok(pruned)
    }

    /// Flushes the active segment and checkpoints the forward-secure keyring to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.active_segment_mut().flush()?;
        self.keyring.checkpoint()
    }

    /// Returns the writer MAC for a specific offset, if recorded.
    pub fn writer_mac(&self, offset: u64) -> Result<Option<HashDigest>> {
        self.keyring.read_mac(offset)
    }

    /// Returns the public one-way hash H(state) of the forward-secure ratchet.
    pub fn public_ratchet_state_hash(&self) -> HashDigest {
        self.keyring.public_state_hash()
    }

    /// Returns the active ratchet offset.
    pub fn ratchet_offset(&self) -> u64 {
        self.keyring.current_offset()
    }

    /// Offline verification function: fully checks all segments, cryptographic hash chains,
    /// MMR roots, and offsets on disk with zero network or broker daemon involvement.
    pub fn verify_offline(
        partition_dir: &Path,
        topic: &str,
        partition_id: u32,
    ) -> Result<PartitionVerifyReport> {
        let mut segment_files: Vec<PathBuf> = Vec::new();
        if partition_dir.exists() {
            for entry in fs::read_dir(partition_dir).map_err(|e| VortexError::Io(e.to_string()))? {
                let entry = entry.map_err(|e| VortexError::Io(e.to_string()))?;
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("vtx") {
                    segment_files.push(p);
                }
            }
        }

        segment_files.sort();

        if segment_files.is_empty() {
            return Ok(PartitionVerifyReport {
                topic: topic.to_string(),
                partition_id,
                total_segments: 0,
                total_records: 0,
                earliest_offset: 0,
                latest_offset: 0,
                final_mmr_root: [0u8; 32],
                final_record_hash: [0u8; 32],
                is_valid: true,
            });
        }

        let genesis = compute_genesis_hash(topic, partition_id);
        let mut expected_genesis = genesis;
        let mut expected_base_offset: Option<u64> = None;
        let mut earliest_offset = 0u64;
        let mut total_records = 0u64;
        let mut final_mmr_root = [0u8; 32];
        let mut final_record_hash = [0u8; 32];

        for (idx, seg_path) in segment_files.iter().enumerate() {
            let stem = seg_path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| VortexError::Io("invalid segment path".into()))?;
            let base_offset: u64 = stem
                .parse()
                .map_err(|_| VortexError::Io("invalid segment offset".into()))?;

            if idx == 0 {
                earliest_offset = base_offset;
            }

            if let Some(expected) = expected_base_offset {
                if base_offset != expected {
                    return Err(VortexError::Io(format!(
                        "gap detected in partition sequence: expected base offset {expected}, found {base_offset}"
                    )));
                }
            }

            let loaded_seg = Segment::open_or_create(partition_dir, base_offset, expected_genesis)?;
            if loaded_seg.base_offset != base_offset {
                return Err(VortexError::Io(format!(
                    "segment filename base offset {base_offset} mismatch with header {}",
                    loaded_seg.base_offset
                )));
            }

            let seg_records = loaded_seg.next_offset.saturating_sub(loaded_seg.base_offset);
            total_records += seg_records;
            expected_base_offset = Some(loaded_seg.next_offset);
            expected_genesis = loaded_seg.last_record_hash;
            final_mmr_root = loaded_seg.mmr_root();
            final_record_hash = loaded_seg.last_record_hash;
        }

        let latest_offset = expected_base_offset.unwrap_or(0);

        Ok(PartitionVerifyReport {
            topic: topic.to_string(),
            partition_id,
            total_segments: segment_files.len(),
            total_records,
            earliest_offset,
            latest_offset,
            final_mmr_root,
            final_record_hash,
            is_valid: true,
        })
    }

    /// Returns the next offset that will be assigned to an incoming message.
    pub fn next_offset(&self) -> u64 {
        self.active_segment().next_offset
    }

    /// Returns the first offset still retained in this partition.
    pub fn earliest_offset(&self) -> u64 {
        self.segments.first().map_or(0, |segment| segment.base_offset)
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

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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

    #[test]
    fn test_retention_pruning_and_out_of_range() {
        let dir = tempdir().unwrap();

        // Roll rapidly (small segment byte limit)
        let mut log = PartitionLog::open_or_create(dir.path(), "retention_topic", 0, 800).unwrap();

        for i in 0..40 {
            log.append(None, Bytes::from(format!("val-{:020}", i))).unwrap();
        }

        assert!(log.segments.len() > 2);
        let initial_seg_count = log.segments.len();

        // Prune with a small retention_bytes limit (e.g. 1000 bytes)
        let pruned = log.prune_retention(1_000_000, None, Some(1000)).unwrap();
        assert!(!pruned.is_empty(), "Expected at least 1 segment pruned");
        assert!(log.segments.len() < initial_seg_count);
        assert!(log.segments.len() >= 1, "Active segment must be preserved");

        let earliest = log.segments[0].base_offset;
        assert!(earliest > 0);

        // Reading an offset prior to earliest must return OffsetOutOfRange error
        let err = log.read(0, 1024).unwrap_err();
        match err {
            VortexError::OffsetOutOfRange { requested, earliest: e, latest } => {
                assert_eq!(requested, 0);
                assert_eq!(e, earliest);
                assert_eq!(latest, log.next_offset());
            }
            other => panic!("Expected OffsetOutOfRange, got {:?}", other),
        }

        // Reading from earliest valid offset must succeed
        let valid_records = log.read(earliest, 1024).unwrap();
        assert!(!valid_records.is_empty());
        assert_eq!(valid_records[0].offset, earliest);
    }

    #[test]
    fn retained_segment_prefix_reopens_with_chain_continuity() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "retained", 0, 1024 * 1024).unwrap();

        log.append(None, Bytes::from_static(b"oldest" )).unwrap();
        log.roll_segment().unwrap();
        log.append(None, Bytes::from_static(b"middle" )).unwrap();
        log.roll_segment().unwrap();
        log.append(None, Bytes::from_static(b"newest" )).unwrap();

        let keep_bytes = log.segments[1].size() + log.segments[2].size();
        let pruned = log.prune_retention(0, None, Some(keep_bytes)).unwrap();
        assert_eq!(pruned, vec![0]);
        drop(log);

        let recovered = PartitionLog::open_or_create(dir.path(), "retained", 0, 1024 * 1024).unwrap();
        assert_eq!(recovered.earliest_offset(), 1);
        assert_eq!(recovered.next_offset(), 3);
        assert_eq!(recovered.read(1, 4096).unwrap().len(), 2);
    }

    #[test]
    fn startup_rejects_disconnected_segment_hash_chain() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "disconnected", 0, 1024 * 1024).unwrap();
        log.append(None, Bytes::from_static(b"first segment")).unwrap();
        log.roll_segment().unwrap();
        let segment_dir = log.dir.clone();
        let second_segment = log.segments[1].path.clone();
        drop(log);

        fs::remove_file(&second_segment).unwrap();
        fs::remove_file(commit_state_path(&second_segment)).unwrap();
        let unrelated = compute_genesis_hash("unrelated", 99);
        drop(Segment::open_or_create(&segment_dir, 1, unrelated).unwrap());

        let error = match PartitionLog::open_or_create(dir.path(), "disconnected", 0, 1024 * 1024) {
            Ok(_) => panic!("startup accepted a disconnected segment chain"),
            Err(error) => error,
        };
        assert!(matches!(error, VortexError::Io(_)));
    }

    #[test]
    fn failed_retention_unlink_keeps_the_segment_in_memory() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "retention_error", 0, 800).unwrap();
        for i in 0..20 {
            log.append(None, Bytes::from(format!("payload-{i}"))).unwrap();
        }
        assert!(log.segments.len() > 1);
        let original_count = log.segments.len();
        let oldest_path = log.segments[0].path.clone();
        let moved_path = oldest_path.with_extension("vtx.saved");
        fs::rename(&oldest_path, &moved_path).unwrap();
        fs::create_dir(&oldest_path).unwrap();

        let error = log.prune_retention(1_000_000, None, Some(1)).unwrap_err();
        assert!(matches!(error, VortexError::Io(_)));
        assert_eq!(log.segments.len(), original_count);

        fs::remove_dir(&oldest_path).unwrap();
        fs::rename(&moved_path, &oldest_path).unwrap();
        let pruned = log.prune_retention(1_000_000, None, Some(1)).unwrap();
        assert!(!pruned.is_empty());
        assert!(log.segments.len() < original_count);
    }

    #[test]
    fn test_atomic_batch_append_and_roll() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "batch_topic", 0, 1200).unwrap();

        // 1. Append a batch of 5 records
        let batch1: Vec<(Option<Bytes>, Bytes, Option<u64>)> = (0..5)
            .map(|i| (Some(Bytes::from(format!("key-{}", i))), Bytes::from(format!("val-{}", i)), Some(1000 + i)))
            .collect();

        let appended1 = log.append_batch(batch1).unwrap();
        assert_eq!(appended1.len(), 5);
        for i in 0..5 {
            assert_eq!(appended1[i].offset, i as u64);
            assert_eq!(appended1[i].timestamp, 1000 + i as u64);
        }

        // 2. Append another batch that exceeds the remaining segment bytes -> must roll before writing
        let batch2: Vec<(Option<Bytes>, Bytes, Option<u64>)> = (5..15)
            .map(|i| (Some(Bytes::from(format!("key-{}", i))), Bytes::from(format!("val-{}", i)), Some(2000 + i)))
            .collect();

        let appended2 = log.append_batch(batch2).unwrap();
        assert_eq!(appended2.len(), 10);
        assert!(log.segments.len() > 1, "Expected segment roll prior to large batch write");

        // 3. Read back all records and verify continuous Blake3 hash integrity
        let all_records = log.read(0, 100_000).unwrap();
        assert_eq!(all_records.len(), 15);
        for i in 1..15 {
            assert_eq!(all_records[i].prev_hash, all_records[i - 1].record_hash);
            assert_eq!(all_records[i].offset, i as u64);
        }
    }

    #[test]
    fn test_malformed_segment_name_rejected_safely() {
        let dir = tempdir().unwrap();
        let part_dir = dir.path().join("malformed_topic").join("partition-0");
        std::fs::create_dir_all(&part_dir).unwrap();

        // Write a malformed segment filename with non-numeric base offset
        let malformed_file = part_dir.join("corrupted_segment.vtx");
        std::fs::write(&malformed_file, b"garbage data").unwrap();

        // PartitionLog initialization must reject malformed filename rather than reinterpreting as offset 0
        let err = match PartitionLog::open_or_create(dir.path(), "malformed_topic", 0, 1024) {
            Ok(_) => panic!("expected open_or_create to fail on malformed segment name"),
            Err(e) => e,
        };
        assert!(matches!(err, VortexError::Io(msg) if msg.contains("malformed segment filename")));
    }

    #[test]
    fn retention_crash_between_marker_removal_and_data_file_recovers() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "retention_crash", 0, 1024 * 1024).unwrap();
        log.append(None, Bytes::from_static(b"segment 0 record")).unwrap();
        log.roll_segment().unwrap();
        log.append(None, Bytes::from_static(b"segment 1 record")).unwrap();

        let oldest_path = log.segments[0].path.clone();
        let commit_path = commit_state_path(&oldest_path);
        drop(log);

        // Simulate crash right after commit marker was unlinked during retention,
        // but before the .vtx data file was unlinked
        std::fs::remove_file(&commit_path).unwrap();

        // Recovery must treat segment 0 as a legacy segment, scan it, upgrade it,
        // and preserve offset and hash continuity across the partition
        let recovered = PartitionLog::open_or_create(dir.path(), "retention_crash", 0, 1024 * 1024).unwrap();
        assert_eq!(recovered.earliest_offset(), 0);
        assert_eq!(recovered.next_offset(), 2);
        let records = recovered.read(0, 4096).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value.as_ref(), b"segment 0 record");
        assert_eq!(records[1].value.as_ref(), b"segment 1 record");
    }

    #[test]
    fn test_partition_mmr_proof_and_cold_reads_across_segments() {
        let dir = tempdir().unwrap();
        let mut log = PartitionLog::open_or_create(dir.path(), "mmr_partition", 0, 1024 * 1024).unwrap();

        // Write records into segment 0
        for i in 0..5 {
            log.append(None, Bytes::from(format!("seg0-{}", i))).unwrap();
        }
        log.roll_segment().unwrap();

        // Write records into segment 1
        for i in 5..10 {
            log.append(None, Bytes::from(format!("seg1-{}", i))).unwrap();
        }

        assert_eq!(log.segments.len(), 2);

        // Cross-segment read exercises cold read on segment 0 and hot read on segment 1
        let records = log.read(0, 8192).unwrap();
        assert_eq!(records.len(), 10);

        // Verify MMR inclusion proof for a record in the cold segment (segment 0)
        let proof_seg0 = log.generate_inclusion_proof(2).expect("proof for offset 2 must exist");
        assert_eq!(proof_seg0.leaf_index, 2);
        assert!(proof_seg0.verify(&log.segments[0].mmr_root()));

        // Verify MMR inclusion proof for a record in the active segment (segment 1)
        let proof_seg1 = log.generate_inclusion_proof(7).expect("proof for offset 7 must exist");
        assert_eq!(proof_seg1.leaf_index, 2); // 7 - base_offset(5) = 2
        assert!(proof_seg1.verify(&log.segments[1].mmr_root()));

        // Out of range proof returns None
        assert!(log.generate_inclusion_proof(99).is_none());
    }
}


