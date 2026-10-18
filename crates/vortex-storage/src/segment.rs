use bytes::{Buf, BufMut, Bytes, BytesMut};
use memmap2::{Mmap, MmapOptions};
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use vortex_core::{error::Result, record::{Record, RECORD_HEADER_SIZE}, HashDigest, VortexError};

/// 64 KB pre-allocated header and sparse index region.
pub const HEADER_INDEX_REGION_SIZE: u64 = 65_536;
pub const SEGMENT_MAGIC: u32 = 0x56545831; // "VTX1"
pub const SEGMENT_VERSION: u8 = 1;
pub const INDEX_ENTRY_SIZE: usize = 16;
pub const MAX_INDEX_ENTRIES: usize = (HEADER_INDEX_REGION_SIZE as usize - 256) / INDEX_ENTRY_SIZE;
const COMMIT_STATE_MAGIC: u32 = 0x5654_5843; // "VTXC"
const COMMIT_STATE_VERSION: u8 = 1;
const COMMIT_STATE_SIZE: usize = 60;

/// Sparse index checkpoint interval in bytes (record one index entry every 64 KB of data).
pub const SPARSE_INDEX_INTERVAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    pub relative_offset: u32,
    pub physical_position: u64,
    pub timestamp_delta: u32,
}

pub struct Segment {
    pub base_offset: u64,
    pub next_offset: u64,
    pub genesis_hash: HashDigest,
    pub last_record_hash: HashDigest,
    pub path: PathBuf,
    pub file: File,
    pub mmap: Option<Mmap>,
    pub index_entries: Vec<IndexEntry>,
    pub current_data_position: u64,
    pub bytes_since_last_index: u64,
    commit_path: PathBuf,
    poisoned: bool,
}

impl Segment {
    /// Opens an existing segment or creates a new `.vtx` segment.
    pub fn open_or_create(dir: &Path, base_offset: u64, genesis_hash: HashDigest) -> Result<Self> {
        let filename = format!("{:020}.vtx", base_offset);
        let path = dir.join(filename);
        let file_exists = path.exists();

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        if !file_exists || file.metadata().map_err(|e| VortexError::Io(e.to_string()))?.len() == 0 {
            // Initialize new segment header
            file.set_len(HEADER_INDEX_REGION_SIZE)
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut header = BytesMut::with_capacity(256);
            header.put_u32(SEGMENT_MAGIC);
            header.put_u8(SEGMENT_VERSION);
            header.put_u16(0); // flags
            header.put_u64(base_offset);
            header.put_slice(&genesis_hash);
            header.put_u64(0); // created_at placeholder

            // Pad the header to the fixed 256-byte metadata block. The on-disk
            // index count lives in its final four bytes (offset 252).
            while header.len() < 256 {
                header.put_u8(0);
            }

            file.write_all_at(&header, 0)
                .map_err(|e| VortexError::Io(e.to_string()))?;
            file.sync_data()
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let commit_path = commit_state_path(&path);
            publish_commit_state(
                &path,
                &commit_path,
                HEADER_INDEX_REGION_SIZE,
                base_offset,
                genesis_hash,
            )?;

            Ok(Self {
                base_offset,
                next_offset: base_offset,
                genesis_hash,
                last_record_hash: genesis_hash,
                path,
                file,
                mmap: None,
                index_entries: Vec::new(),
                current_data_position: HEADER_INDEX_REGION_SIZE,
                bytes_since_last_index: 0,
                commit_path,
                poisoned: false,
            })
        } else {
            // Recover and validate existing segment
            Self::recover_existing(path, file)
        }
    }

    fn recover_existing(path: PathBuf, file: File) -> Result<Self> {
        let mut header_buf = [0u8; 256];
        file.read_exact_at(&mut header_buf, 0)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut reader = &header_buf[..];
        let magic = reader.get_u32();
        if magic != SEGMENT_MAGIC {
            return Err(VortexError::InvalidMagic {
                expected: SEGMENT_MAGIC,
                actual: magic,
            });
        }

        let _version = reader.get_u8();
        let _flags = reader.get_u16();
        let base_offset = reader.get_u64();

        let mut genesis_hash = [0u8; 32];
        reader.copy_to_slice(&mut genesis_hash);

        let _created_at = reader.get_u64();
        let _reserved = reader.get_u32();
        // The fixed header index is intentionally treated as a cache. Rebuild it
        // from validated records so checkpoints beyond its 4,080-entry capacity
        // survive restart, and so a torn or stale index cannot direct reads wrongly.
        let _stored_index_count = u32::from_be_bytes(header_buf[252..256].try_into().unwrap());

        // A sidecar records the durable end of the last complete append batch. Bytes
        // beyond that boundary are an uncommitted tail and are discarded on recovery.
        // Segments written before this marker existed are scanned once and upgraded.
        let file_len = file
            .metadata()
            .map_err(|e| VortexError::Io(e.to_string()))?
            .len();

        if file_len < HEADER_INDEX_REGION_SIZE {
            return Err(VortexError::Io(format!(
                "segment is shorter than its {}-byte header: {}",
                HEADER_INDEX_REGION_SIZE,
                path.display()
            )));
        }

        let commit_path = commit_state_path(&path);
        let commit_state = read_commit_state(&commit_path)?;
        let scan_end = match commit_state {
            Some(state) => {
                if state.end_position < HEADER_INDEX_REGION_SIZE || state.end_position > file_len {
                    return Err(VortexError::Io(format!(
                        "segment commit boundary {} is outside the data file (length {file_len})",
                        state.end_position
                    )));
                }
                if file_len > state.end_position {
                    file.set_len(state.end_position)
                        .and_then(|_| file.sync_data())
                        .map_err(|e| VortexError::Io(format!("failed to discard uncommitted segment tail: {e}")))?;
                }
                state.end_position
            }
            None => file_len,
        };

        let mut curr_pos = HEADER_INDEX_REGION_SIZE;
        let mut next_offset = base_offset;
        let mut last_hash = genesis_hash;
        let mut index_entries = Vec::new();
        let mut last_indexed_pos = HEADER_INDEX_REGION_SIZE;

        while curr_pos < scan_end {
            if scan_end - curr_pos < 4 {
                if commit_state.is_some() {
                    return Err(VortexError::Io(format!(
                        "commit marker ends inside a record length at byte {curr_pos}"
                    )));
                }
                file.set_len(curr_pos)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
                file.sync_data().map_err(|e| VortexError::Io(e.to_string()))?;
                break;
            }
            let mut len_buf = [0u8; 4];
            if file.read_exact_at(&mut len_buf, curr_pos).is_err() {
                return Err(VortexError::Io(format!("cannot read record length at byte {curr_pos}")));
            }
            let total_len = u32::from_be_bytes(len_buf) as u64;
            if total_len < (RECORD_HEADER_SIZE - 4) as u64 {
                return Err(VortexError::Io(format!(
                    "invalid record length {total_len} at byte {curr_pos}"
                )));
            }

            let record_end = curr_pos
                .checked_add(4)
                .and_then(|p| p.checked_add(total_len))
                .ok_or_else(|| VortexError::Io("record end offset overflow".into()))?;
            if record_end > scan_end {
                if commit_state.is_some() {
                    return Err(VortexError::Io(format!(
                        "commit marker ends inside a record at byte {curr_pos}"
                    )));
                }
                // Legacy segments have no batch boundary marker. Discard a physically
                // incomplete final record, then establish a marker at the valid prefix.
                file.set_len(curr_pos)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
                file.sync_data().map_err(|e| VortexError::Io(e.to_string()))?;
                break;
            }

            let record_size = usize::try_from(4 + total_len)
                .map_err(|_| VortexError::Io("record is too large for this platform".into()))?;
            let mut record_raw = vec![0u8; record_size];
            file.read_exact_at(&mut record_raw, curr_pos)
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut slice = &record_raw[..];
            let rec = Record::decode(&mut slice)?;
            if rec.offset != next_offset || rec.prev_hash != last_hash {
                return Err(VortexError::CryptographicLineageBroken {
                    offset: rec.offset,
                    expected: format!("{} at offset {}", hex_hash(&last_hash), next_offset),
                    actual: format!("{} at offset {}", hex_hash(&rec.prev_hash), rec.offset),
                });
            }

            if index_entries.is_empty()
                || curr_pos.saturating_sub(last_indexed_pos) >= SPARSE_INDEX_INTERVAL_BYTES
            {
                let relative_offset = rec.offset.checked_sub(base_offset)
                    .and_then(|offset| u32::try_from(offset).ok())
                    .ok_or_else(|| VortexError::Io("segment offset exceeds sparse-index format".into()))?;
                index_entries.push(IndexEntry {
                    relative_offset,
                    physical_position: curr_pos,
                    timestamp_delta: 0,
                });
                last_indexed_pos = curr_pos;
            }

            next_offset = next_offset.checked_add(1)
                .ok_or_else(|| VortexError::Io("segment offset overflow".into()))?;
            last_hash = rec.record_hash;
            curr_pos = record_end;
        }

        if let Some(state) = commit_state {
            if state.next_offset != next_offset || state.last_record_hash != last_hash {
                return Err(VortexError::Io(format!(
                    "segment commit marker disagrees with validated records in {}",
                    path.display()
                )));
            }
        } else {
            publish_commit_state(&path, &commit_path, curr_pos, next_offset, last_hash)?;
        }

        let bytes_since_last_index = curr_pos.saturating_sub(last_indexed_pos);

        let mmap = unsafe { MmapOptions::new().map(&file).ok() };

        let segment = Self {
            base_offset,
            next_offset,
            genesis_hash,
            last_record_hash: last_hash,
            path,
            file,
            mmap,
            index_entries,
            current_data_position: curr_pos,
            bytes_since_last_index,
            commit_path,
            poisoned: false,
        };
        for (i, entry) in segment.index_entries.iter().take(MAX_INDEX_ENTRIES).enumerate() {
            let _ = segment.write_index_entry(entry, i);
        }
        Ok(segment)
    }

    /// Appends a new payload to the segment using atomic positional I/O.
    pub fn append(&mut self, key: Option<Bytes>, value: Bytes) -> Result<Record> {
        self.append_with_timestamp(key, value, None)
    }

    /// Appends a payload while preserving an optional producer-supplied timestamp.
    pub fn append_with_timestamp(
        &mut self,
        key: Option<Bytes>,
        value: Bytes,
        timestamp: Option<u64>,
    ) -> Result<Record> {
        let mut results = self.append_batch(vec![(key, value, timestamp)])?;
        Ok(results.remove(0))
    }

    /// Appends a batch and advances a durable commit marker only after the data is synced.
    /// Invariants:
    /// - Stages all records, hashes, and offsets in memory before touching disk.
    /// - Writes and syncs all encoded records before publishing the new boundary.
    /// - Recovery truncates any data beyond the last atomically published boundary.
    /// - A failure while publishing the boundary poisons this segment until restart,
    ///   because a rename followed by a directory-sync failure has an uncertain outcome.
    pub fn append_batch(
        &mut self,
        batch: Vec<(Option<Bytes>, Bytes, Option<u64>)>,
    ) -> Result<Vec<Record>> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        if self.poisoned {
            return Err(VortexError::Io("segment is poisoned after an uncertain commit; restart required".into()));
        }

        let mut curr_offset = self.next_offset;
        let mut curr_hash = self.last_record_hash;
        let mut curr_pos = self.current_data_position;
        let mut bytes_since_last_index = self.bytes_since_last_index;

        let mut staged_records = Vec::with_capacity(batch.len());
        let mut staged_encoded = Vec::with_capacity(batch.len());
        let mut total_encoded_len: u64 = 0;
        let mut new_index_entries = Vec::new();

        for (key, value, timestamp) in batch {
            let record = match timestamp {
                Some(ts) => Record::new_with_timestamp(curr_hash, curr_offset, key, value, ts),
                None => Record::new(curr_hash, curr_offset, key, value),
            };
            let encoded = record.encode();
            let encoded_len = encoded.len() as u64;

            // Check if sparse index entry should be recorded
            if bytes_since_last_index >= SPARSE_INDEX_INTERVAL_BYTES
                || (self.index_entries.is_empty() && new_index_entries.is_empty())
            {
                let relative_offset = curr_offset
                    .checked_sub(self.base_offset)
                    .and_then(|off| u32::try_from(off).ok())
                    .ok_or_else(|| VortexError::Io("relative offset exceeds sparse index format".into()))?;
                let entry = IndexEntry {
                    relative_offset,
                    physical_position: curr_pos,
                    timestamp_delta: 0,
                };
                new_index_entries.push(entry);
                bytes_since_last_index = 0;
            }

            curr_offset = curr_offset
                .checked_add(1)
                .ok_or_else(|| VortexError::Io("segment offset overflow".into()))?;
            curr_pos = curr_pos
                .checked_add(encoded_len)
                .ok_or_else(|| VortexError::Io("segment physical position overflow".into()))?;
            bytes_since_last_index = bytes_since_last_index.saturating_add(encoded_len);
            total_encoded_len = total_encoded_len
                .checked_add(encoded_len)
                .ok_or_else(|| VortexError::Io("batch payload byte length overflow".into()))?;
            curr_hash = record.record_hash;

            staged_encoded.push(encoded);
            staged_records.push(record);
        }

        // Pack all encoded records into a single contiguous buffer
        let mut buffer = BytesMut::with_capacity(total_encoded_len as usize);
        for enc in staged_encoded {
            buffer.extend_from_slice(&enc);
        }

        let old_position = self.current_data_position;
        if let Err(error) = self.file.write_all_at(&buffer, old_position)
            .and_then(|_| self.file.sync_data())
        {
            if let Err(rollback) = self.file.set_len(old_position).and_then(|_| self.file.sync_data()) {
                self.poisoned = true;
                return Err(VortexError::Io(format!(
                    "segment batch write failed ({error}); rollback failed ({rollback}); restart required"
                )));
            }
            return Err(VortexError::Io(error.to_string()));
        }

        if let Err(error) = publish_commit_state(
            &self.path,
            &self.commit_path,
            curr_pos,
            curr_offset,
            curr_hash,
        ) {
            self.poisoned = true;
            return Err(VortexError::Io(format!(
                "segment batch data was written but commit publication is uncertain ({error}); restart required"
            )));
        }

        // Write new index entries to Region A header on disk up to MAX_INDEX_ENTRIES
        let current_index_count = self.index_entries.len();
        for (i, entry) in new_index_entries.iter().enumerate() {
            let target_idx = current_index_count + i;
            if target_idx < MAX_INDEX_ENTRIES {
                // The index is a rebuildable cache. A cache write failure must not
                // turn a durably committed batch into an apparent failed append.
                let _ = self.write_index_entry(entry, target_idx);
            }
        }

        // Now that physical disk write succeeded, commit in-memory state
        self.index_entries.extend(new_index_entries);
        self.current_data_position = curr_pos;
        self.bytes_since_last_index = bytes_since_last_index;
        self.last_record_hash = curr_hash;
        self.next_offset = curr_offset;
        self.mmap = None;

        Ok(staged_records)
    }

    fn write_index_entry(&self, entry: &IndexEntry, entry_idx: usize) -> Result<()> {
        let entry_pos = 256 + (entry_idx * INDEX_ENTRY_SIZE) as u64;

        let mut buf = [0u8; 16];
        let mut writer = &mut buf[..];
        writer.put_u32(entry.relative_offset);
        writer.put_u64(entry.physical_position);
        writer.put_u32(entry.timestamp_delta);

        self.file
            .write_all_at(&buf, entry_pos)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        // Update index count in header at offset 252
        self.file
            .write_all_at(&(entry_idx as u32 + 1).to_be_bytes(), 252)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        Ok(())
    }

    /// Flushes uncommitted file buffers to disk (`fdatasync`).
    pub fn flush(&mut self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|e| VortexError::Io(e.to_string()))
    }

    /// Reads records starting from the given offset up to `max_bytes`.
    /// Operates purely with positional reads (`read_exact_at`), taking `&self` to allow
    /// unlimited concurrent readers without mutex contention (Flaw 2.1).
    pub fn read(&self, start_offset: u64, max_bytes: usize) -> Result<Vec<Record>> {
        if start_offset < self.base_offset || start_offset >= self.next_offset {
            return Ok(Vec::new());
        }

        // Find nearest starting file position via binary search in sparse index
        let start_pos = self.find_file_position(start_offset);

        let mut records = Vec::new();
        let mut bytes_read = 0;
        let mut curr_pos = start_pos;

        while curr_pos < self.current_data_position && bytes_read < max_bytes {
            let mut len_buf = [0u8; 4];
            if self.file.read_exact_at(&mut len_buf, curr_pos).is_err() {
                break;
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;
            let full_record_len = 4 + total_len;

            let mut raw_record = vec![0u8; full_record_len];
            self.file
                .read_exact_at(&mut raw_record, curr_pos)
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut slice = &raw_record[..];
            let rec = Record::decode(&mut slice)?;

            if rec.offset >= start_offset {
                bytes_read += full_record_len;
                records.push(rec);
            }

            curr_pos += full_record_len as u64;
        }

        Ok(records)
    }

    /// Performs binary search over the sparse index to locate the closest physical file offset.
    fn find_file_position(&self, target_offset: u64) -> u64 {
        if self.index_entries.is_empty() {
            return HEADER_INDEX_REGION_SIZE;
        }

        let rel_target = (target_offset - self.base_offset) as u32;

        match self
            .index_entries
            .binary_search_by_key(&rel_target, |e| e.relative_offset)
        {
            Ok(idx) => self.index_entries[idx].physical_position,
            Err(idx) => {
                if idx == 0 {
                    HEADER_INDEX_REGION_SIZE
                } else {
                    self.index_entries[idx - 1].physical_position
                }
            }
        }
    }

    /// Returns total file size in bytes.
    pub fn size(&self) -> u64 {
        self.current_data_position
    }
}

#[derive(Clone, Copy)]
struct CommitState {
    end_position: u64,
    next_offset: u64,
    last_record_hash: HashDigest,
}

pub(crate) fn commit_state_path(segment_path: &Path) -> PathBuf {
    let name = segment_path.file_name().expect("segment path has a filename");
    let mut sidecar_name = name.to_os_string();
    sidecar_name.push(".commit");
    segment_path.with_file_name(sidecar_name)
}

fn read_commit_state(path: &Path) -> Result<Option<CommitState>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(VortexError::Io(format!("failed to open segment commit marker: {error}"))),
    };
    let length = file.metadata().map_err(|e| VortexError::Io(e.to_string()))?.len();
    if length != COMMIT_STATE_SIZE as u64 {
        return Err(VortexError::Io(format!("invalid segment commit marker length {length}")));
    }
    let mut bytes = [0u8; COMMIT_STATE_SIZE];
    std::io::Read::read_exact(&mut file, &mut bytes)
        .map_err(|e| VortexError::Io(format!("failed to read segment commit marker: {e}")))?;
    let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let version = bytes[4];
    let expected_crc = u32::from_be_bytes(bytes[56..60].try_into().unwrap());
    if magic != COMMIT_STATE_MAGIC
        || version != COMMIT_STATE_VERSION
        || crc32fast::hash(&bytes[..56]) != expected_crc
    {
        return Err(VortexError::Io("invalid or corrupt segment commit marker".into()));
    }
    let end_position = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let next_offset = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let mut last_record_hash = [0u8; 32];
    last_record_hash.copy_from_slice(&bytes[24..56]);
    Ok(Some(CommitState { end_position, next_offset, last_record_hash }))
}

fn publish_commit_state(
    segment_path: &Path,
    commit_path: &Path,
    end_position: u64,
    next_offset: u64,
    last_record_hash: HashDigest,
) -> Result<()> {
    let mut bytes = [0u8; COMMIT_STATE_SIZE];
    bytes[0..4].copy_from_slice(&COMMIT_STATE_MAGIC.to_be_bytes());
    bytes[4] = COMMIT_STATE_VERSION;
    bytes[8..16].copy_from_slice(&end_position.to_be_bytes());
    bytes[16..24].copy_from_slice(&next_offset.to_be_bytes());
    bytes[24..56].copy_from_slice(&last_record_hash);
    let checksum = crc32fast::hash(&bytes[..56]);
    bytes[56..60].copy_from_slice(&checksum.to_be_bytes());

    let name = commit_path.file_name().expect("commit marker path has a filename");
    let mut temp_name = name.to_os_string();
    temp_name.push(".tmp");
    let temp_path = commit_path.with_file_name(temp_name);
    let mut temp = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp_path)
        .map_err(|e| VortexError::Io(format!("failed to create segment commit marker: {e}")))?;
    std::io::Write::write_all(&mut temp, &bytes)
        .and_then(|_| temp.sync_all())
        .map_err(|e| VortexError::Io(format!("failed to persist segment commit marker: {e}")))?;
    drop(temp);
    std::fs::rename(&temp_path, commit_path)
        .map_err(|e| VortexError::Io(format!("failed to publish segment commit marker: {e}")))?;

    let parent = segment_path.parent().ok_or_else(|| VortexError::Io("segment has no parent directory".into()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| VortexError::Io(format!("failed to sync segment directory after commit: {e}")))
}

fn hex_hash(hash: &HashDigest) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vortex_core::compute_genesis_hash;

    #[test]
    fn test_segment_create_append_read_recover() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("telemetry", 0);

        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).expect("Segment created");
        assert_eq!(seg.next_offset, 0);

        // Append 10 records
        for i in 0..10 {
            let val = Bytes::from(format!("payload-item-{}", i));
            let rec = seg.append(None, val).expect("Append succeeded");
            assert_eq!(rec.offset, i as u64);
        }

        assert_eq!(seg.next_offset, 10);
        seg.flush().unwrap();

        // Read records from offset 5
        let read_back = seg.read(5, 1024 * 1024).expect("Read succeeded");
        assert_eq!(read_back.len(), 5);
        assert_eq!(read_back[0].offset, 5);
        assert_eq!(read_back[4].offset, 9);

        // Verify cryptographic hash continuity
        assert_eq!(read_back[1].prev_hash, read_back[0].record_hash);

        // Treat the on-disk index as a rebuildable cache: even a missing count
        // must be reconstructed from the validated data region on restart.
        seg.file.write_all_at(&0u32.to_be_bytes(), 252).unwrap();

        // Close and recover existing segment
        drop(seg);

        let recovered =
            Segment::open_or_create(dir.path(), 0, genesis).expect("Segment recovered successfully");
        assert_eq!(recovered.next_offset, 10);
        assert_eq!(recovered.base_offset, 0);
        assert_eq!(recovered.index_entries[0].relative_offset, 0);
        assert_eq!(recovered.read(5, 1024 * 1024).unwrap().len(), 5);
        let mut stored_count = [0u8; 4];
        recovered.file.read_exact_at(&mut stored_count, 252).unwrap();
        assert_eq!(u32::from_be_bytes(stored_count), 1);
    }

    #[test]
    fn test_segment_torn_tail_write_recovery() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("torn-test", 0);

        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).expect("Segment created");
        for i in 0..5 {
            let val = Bytes::from(format!("record-{i}"));
            seg.append(None, val).unwrap();
        }
        seg.flush().unwrap();
        assert_eq!(seg.next_offset, 5);
        let valid_size = seg.size();

        // Simulate a power-loss torn write at the tail by appending garbage bytes
        let mut torn_data = vec![0u8; 120];
        // Total len declared as 116 bytes
        torn_data[0..4].copy_from_slice(&116u32.to_be_bytes());
        // Deliberately wrong CRC / corrupted body
        torn_data[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        seg.file.write_all_at(&torn_data, valid_size).unwrap();
        drop(seg);

        // Reopen segment: recovery must detect torn tail write, truncate it to valid_size,
        // and resume cleanly at next_offset = 5
        let mut recovered = Segment::open_or_create(dir.path(), 0, genesis).expect("Recovery must succeed");
        assert_eq!(recovered.next_offset, 5);
        assert_eq!(recovered.size(), valid_size);

        // Can append record 5 without issue
        let new_rec = recovered.append(None, Bytes::from_static(b"record-5-after-crash")).unwrap();
        assert_eq!(new_rec.offset, 5);
        assert_eq!(recovered.next_offset, 6);
    }

    #[test]
    fn recovery_discards_a_complete_but_uncommitted_batch_tail() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("uncommitted-batch", 0);
        let seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        let committed_end = seg.size();

        let first = Record::new(seg.last_record_hash, seg.next_offset, None, Bytes::from_static(b"one"));
        let second = Record::new(first.record_hash, first.offset + 1, None, Bytes::from_static(b"two"));
        let mut uncommitted = BytesMut::from(first.encode().as_ref());
        uncommitted.extend_from_slice(second.encode().as_ref());
        seg.file.write_all_at(&uncommitted, committed_end).unwrap();
        seg.file.sync_data().unwrap();
        drop(seg);

        let recovered = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        assert_eq!(recovered.next_offset, 0);
        assert_eq!(recovered.size(), committed_end);
        assert!(recovered.read(0, 1024).unwrap().is_empty());
    }

    #[test]
    fn legacy_segment_is_scanned_and_upgraded_to_commit_marker() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("legacy-segment", 0);
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        seg.append(None, Bytes::from_static(b"legacy record")).unwrap();
        let segment_path = seg.path.clone();
        drop(seg);

        std::fs::remove_file(commit_state_path(&segment_path)).unwrap();
        let recovered = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        assert_eq!(recovered.next_offset, 1);
        assert!(commit_state_path(&segment_path).exists());
    }

    #[test]
    fn marker_publish_failure_poisons_segment_and_recovers_to_previous_commit() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("poison-test", 0);
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        seg.append(None, Bytes::from_static(b"committed-batch-1")).unwrap();
        let valid_size = seg.size();
        let valid_offset = seg.next_offset;

        // Block commit publication by creating a directory where .commit.tmp would be written
        let commit_tmp = seg.commit_path.with_file_name(format!(
            "{}.tmp",
            seg.commit_path.file_name().unwrap().to_str().unwrap()
        ));
        std::fs::create_dir(&commit_tmp).unwrap();

        // Attempting to append must fail and poison the segment
        let err = seg.append(None, Bytes::from_static(b"uncommitted-batch-2")).unwrap_err();
        assert!(matches!(err, VortexError::Io(_)));

        // Subsequent append must fail immediately due to poisoning
        let err2 = seg.append(None, Bytes::from_static(b"uncommitted-batch-3")).unwrap_err();
        assert!(matches!(err2, VortexError::Io(_)));
        assert!(err2.to_string().contains("poisoned"));

        // Clean up blocking directory and restart
        std::fs::remove_dir(&commit_tmp).unwrap();
        drop(seg);

        // Reopening the segment must recover to the last valid commit
        let recovered = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        assert_eq!(recovered.next_offset, valid_offset);
        assert_eq!(recovered.size(), valid_size);
        let records = recovered.read(0, 1024).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value.as_ref(), b"committed-batch-1");
    }

    #[test]
    fn corrupted_commit_marker_fails_recovery() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("corrupt-marker-test", 0);
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        seg.append(None, Bytes::from_static(b"data")).unwrap();
        let commit_path = seg.commit_path.clone();
        drop(seg);

        // Corrupt the magic in the commit marker
        let mut bytes = std::fs::read(&commit_path).unwrap();
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        std::fs::write(&commit_path, &bytes).unwrap();

        let err = match Segment::open_or_create(dir.path(), 0, genesis) {
            Ok(_) => panic!("recovery accepted corrupted commit marker"),
            Err(e) => e,
        };
        assert!(matches!(err, VortexError::Io(_)));
    }

    #[test]
    fn legacy_segment_with_torn_tail_is_truncated_and_upgraded() {
        let dir = tempdir().unwrap();
        let genesis = compute_genesis_hash("legacy-torn-tail", 0);
        let mut seg = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        seg.append(None, Bytes::from_static(b"valid-record-1")).unwrap();
        seg.append(None, Bytes::from_static(b"valid-record-2")).unwrap();
        let valid_size = seg.size();
        let segment_path = seg.path.clone();
        drop(seg);

        // Make it a legacy segment by removing .commit
        std::fs::remove_file(commit_state_path(&segment_path)).unwrap();

        // Simulate a power-loss crash by writing an incomplete record tail
        let file = OpenOptions::new().write(true).open(&segment_path).unwrap();
        let torn_len = 100u32;
        file.write_all_at(&torn_len.to_be_bytes(), valid_size).unwrap();
        file.write_all_at(&[0xAA, 0xBB, 0xCC], valid_size + 4).unwrap();
        drop(file);

        // Recovery of legacy segment must detect incomplete tail, truncate to valid_size,
        // establish a durable .commit marker, and recover offset = 2
        let recovered = Segment::open_or_create(dir.path(), 0, genesis).unwrap();
        assert_eq!(recovered.next_offset, 2);
        assert_eq!(recovered.size(), valid_size);
        assert!(commit_state_path(&segment_path).exists());
        let records = recovered.read(0, 1024).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value.as_ref(), b"valid-record-1");
        assert_eq!(records[1].value.as_ref(), b"valid-record-2");
    }
}
