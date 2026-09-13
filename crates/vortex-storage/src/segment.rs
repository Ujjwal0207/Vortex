use bytes::{Buf, BufMut, Bytes, BytesMut};
use memmap2::{Mmap, MmapOptions};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vortex_core::{error::Result, record::Record, HashDigest, VortexError};

/// 64 KB pre-allocated header and sparse index region.
pub const HEADER_INDEX_REGION_SIZE: u64 = 65_536;
pub const SEGMENT_MAGIC: u32 = 0x56545831; // "VTX1"
pub const SEGMENT_VERSION: u8 = 1;
pub const INDEX_ENTRY_SIZE: usize = 16;
pub const MAX_INDEX_ENTRIES: usize = (HEADER_INDEX_REGION_SIZE as usize - 256) / INDEX_ENTRY_SIZE;

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
}

impl Segment {
    /// Opens an existing segment or creates a new `.vtx` segment.
    pub fn open_or_create(dir: &Path, base_offset: u64, genesis_hash: HashDigest) -> Result<Self> {
        let filename = format!("{:020}.vtx", base_offset);
        let path = dir.join(filename);
        let file_exists = path.exists();

        let mut file = OpenOptions::new()
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
            header.put_u32(0); // index_count

            // Pad header up to 256 bytes
            while header.len() < 256 {
                header.put_u8(0);
            }

            file.seek(SeekFrom::Start(0))
                .map_err(|e| VortexError::Io(e.to_string()))?;
            file.write_all(&header)
                .map_err(|e| VortexError::Io(e.to_string()))?;
            file.flush()
                .map_err(|e| VortexError::Io(e.to_string()))?;

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
            })
        } else {
            // Recover and validate existing segment
            Self::recover_existing(path, file)
        }
    }

    fn recover_existing(path: PathBuf, mut file: File) -> Result<Self> {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut header_buf = [0u8; 256];
        file.read_exact(&mut header_buf)
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
        let index_count = reader.get_u32() as usize;

        // Read sparse index entries
        file.seek(SeekFrom::Start(256))
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut index_entries = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            let mut entry_buf = [0u8; 16];
            file.read_exact(&mut entry_buf)
                .map_err(|e| VortexError::Io(e.to_string()))?;
            let mut r = &entry_buf[..];
            index_entries.push(IndexEntry {
                relative_offset: r.get_u32(),
                physical_position: r.get_u64(),
                timestamp_delta: r.get_u32(),
            });
        }

        // Validate data region and recover next_offset & last_record_hash
        let file_len = file
            .metadata()
            .map_err(|e| VortexError::Io(e.to_string()))?
            .len();

        let mut curr_pos = HEADER_INDEX_REGION_SIZE;
        let mut next_offset = base_offset;
        let mut last_hash = genesis_hash;

        while curr_pos + 8 <= file_len {
            file.seek(SeekFrom::Start(curr_pos))
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let total_len = u32::from_be_bytes(len_buf) as u64;

            if curr_pos + 4 + total_len > file_len {
                // Incomplete write found at tail (e.g. power-loss crash). Truncate to last valid boundary!
                file.set_len(curr_pos)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
                break;
            }

            // Read and decode record to verify CRC and Blake3
            file.seek(SeekFrom::Start(curr_pos))
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut record_raw = vec![0u8; 4 + total_len as usize];
            file.read_exact(&mut record_raw)
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut slice = &record_raw[..];
            match Record::decode(&mut slice) {
                Ok(rec) => {
                    next_offset = rec.offset + 1;
                    last_hash = rec.record_hash;
                    curr_pos += 4 + total_len;
                }
                Err(_) => {
                    // Corrupted record found at tail, truncate safely
                    file.set_len(curr_pos)
                        .map_err(|e| VortexError::Io(e.to_string()))?;
                    break;
                }
            }
        }

        let mmap = unsafe { MmapOptions::new().map(&file).ok() };

        Ok(Self {
            base_offset,
            next_offset,
            genesis_hash,
            last_record_hash: last_hash,
            path,
            file,
            mmap,
            index_entries,
            current_data_position: curr_pos,
            bytes_since_last_index: 0,
        })
    }

    /// Appends a new payload to the segment, computing Blake3 hash, writing sparse index if needed,
    /// and returning the committed record.
    pub fn append(&mut self, key: Option<Bytes>, value: Bytes) -> Result<Record> {
        let offset = self.next_offset;
        let record = Record::new(self.last_record_hash, offset, key, value);
        let encoded = record.encode();
        let encoded_len = encoded.len() as u64;

        // Check if an index entry should be written
        if self.bytes_since_last_index >= SPARSE_INDEX_INTERVAL_BYTES
            || self.index_entries.is_empty()
        {
            if self.index_entries.len() < MAX_INDEX_ENTRIES {
                let entry = IndexEntry {
                    relative_offset: (offset - self.base_offset) as u32,
                    physical_position: self.current_data_position,
                    timestamp_delta: 0,
                };
                self.write_index_entry(&entry)?;
                self.index_entries.push(entry);
                self.bytes_since_last_index = 0;
            }
        }

        // Append to data region
        self.file
            .seek(SeekFrom::Start(self.current_data_position))
            .map_err(|e| VortexError::Io(e.to_string()))?;
        self.file
            .write_all(&encoded)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        self.current_data_position += encoded_len;
        self.bytes_since_last_index += encoded_len;
        self.last_record_hash = record.record_hash;
        self.next_offset += 1;

        // Invalidate mmap on write
        self.mmap = None;

        Ok(record)
    }

    fn write_index_entry(&mut self, entry: &IndexEntry) -> Result<()> {
        let entry_idx = self.index_entries.len();
        let entry_pos = 256 + (entry_idx * INDEX_ENTRY_SIZE) as u64;

        self.file
            .seek(SeekFrom::Start(entry_pos))
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut buf = [0u8; 16];
        let mut writer = &mut buf[..];
        writer.put_u32(entry.relative_offset);
        writer.put_u64(entry.physical_position);
        writer.put_u32(entry.timestamp_delta);

        self.file
            .write_all(&buf)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        // Update index count in header
        self.file
            .seek(SeekFrom::Start(256 - 4))
            .map_err(|e| VortexError::Io(e.to_string()))?;
        self.file
            .write_all(&(self.index_entries.len() as u32 + 1).to_be_bytes())
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
    pub fn read(&mut self, start_offset: u64, max_bytes: usize) -> Result<Vec<Record>> {
        if start_offset < self.base_offset || start_offset >= self.next_offset {
            return Ok(Vec::new());
        }

        // Find nearest starting file position via binary search in sparse index
        let start_pos = self.find_file_position(start_offset);

        // Read sequentially from start_pos until start_offset is reached and up to max_bytes
        self.file
            .seek(SeekFrom::Start(start_pos))
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let mut records = Vec::new();
        let mut bytes_read = 0;
        let mut curr_pos = start_pos;

        while curr_pos < self.current_data_position && bytes_read < max_bytes {
            let mut len_buf = [0u8; 4];
            if self.file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;
            let full_record_len = 4 + total_len;

            self.file
                .seek(SeekFrom::Start(curr_pos))
                .map_err(|e| VortexError::Io(e.to_string()))?;

            let mut raw_record = vec![0u8; full_record_len];
            self.file
                .read_exact(&mut raw_record)
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

        // Close and recover existing segment
        drop(seg);

        let recovered =
            Segment::open_or_create(dir.path(), 0, genesis).expect("Segment recovered successfully");
        assert_eq!(recovered.next_offset, 10);
        assert_eq!(recovered.base_offset, 0);
    }
}
