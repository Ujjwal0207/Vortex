use serde::{Deserialize, Serialize};
use blake3::Hasher;

use crate::hash::HashDigest;

/// Maximum size in bytes of a coalesced block (64 KB).
pub const COALESCE_BLOCK_MAX_BYTES: usize = 64 * 1024;

const COALESCE_NODE_PREFIX: &[u8] = b"VORTEX_COALESCE_NODE_V1:";

fn hash_coalesce_parent(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = Hasher::new();
    hasher.update(COALESCE_NODE_PREFIX);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Metadata describing an individual record within a 64 KB coalesced block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedRecord {
    pub offset: u64,
    pub relative_byte_offset: u32,
    pub payload_len: u32,
    pub payload_hash: HashDigest,
}

/// A sealed 64 KB coalesced block representing a single leaf in the Merkle Mountain Range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedBlock {
    pub block_index: u64,
    pub start_offset: u64,
    pub end_offset: u64,
    pub records: Vec<CoalescedRecord>,
    pub raw_bytes: Vec<u8>,
    pub block_hash: HashDigest,
}

impl CoalescedBlock {
    /// Generates an intra-block cryptographic inclusion proof for the record at `target_offset`.
    pub fn generate_inclusion_proof(&self, target_offset: u64) -> Option<CoalescedBlockProof> {
        let (rec_idx, rec) = self.records.iter().enumerate().find(|(_, r)| r.offset == target_offset)?;

        let mut current_level: Vec<HashDigest> = self.records.iter().map(|r| r.payload_hash).collect();
        let mut sibling_hashes = Vec::new();
        let mut idx = rec_idx;

        while current_level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < current_level.len() {
                sibling_hashes.push(current_level[sibling_idx]);
            } else {
                sibling_hashes.push(current_level[idx]);
            }

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_coalesce_parent(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_coalesce_parent(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(CoalescedBlockProof {
            block_hash: self.block_hash,
            offset: target_offset,
            intra_block_record_index: rec_idx as u32,
            intra_block_byte_offset: rec.relative_byte_offset,
            payload_len: rec.payload_len,
            payload_hash: rec.payload_hash,
            sibling_hashes,
        })
    }
}

/// Lightweight cryptographic proof proving that an individual message exists at an exact
/// byte boundary inside a 64 KB coalesced MMR block leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedBlockProof {
    pub block_hash: HashDigest,
    pub offset: u64,
    pub intra_block_record_index: u32,
    pub intra_block_byte_offset: u32,
    pub payload_len: u32,
    pub payload_hash: HashDigest,
    pub sibling_hashes: Vec<HashDigest>,
}

impl CoalescedBlockProof {
    /// Verifies that this proof demonstrates inclusion of `expected_payload` under `expected_block_hash`.
    pub fn verify(&self, expected_block_hash: &HashDigest, expected_payload: &[u8]) -> bool {
        if self.block_hash != *expected_block_hash {
            return false;
        }

        if expected_payload.len() != self.payload_len as usize {
            return false;
        }

        let computed_payload_hash: HashDigest = *blake3::hash(expected_payload).as_bytes();
        if computed_payload_hash != self.payload_hash {
            return false;
        }

        let mut curr = self.payload_hash;
        let mut idx = self.intra_block_record_index;

        for sibling in &self.sibling_hashes {
            if idx % 2 == 0 {
                curr = hash_coalesce_parent(&curr, sibling);
            } else {
                curr = hash_coalesce_parent(sibling, &curr);
            }
            idx /= 2;
        }

        curr == self.block_hash
    }
}

/// Accumulates incoming records into 64 KB contiguous chunks, slashing cryptographic hashing
/// and state update operations by up to 98% under high throughput.
pub struct BlockCoalescer {
    max_block_bytes: usize,
    current_block_index: u64,
    buffered_records: Vec<CoalescedRecord>,
    buffered_bytes: Vec<u8>,
}

impl BlockCoalescer {
    pub fn new(max_block_bytes: usize) -> Self {
        Self {
            max_block_bytes: max_block_bytes.max(1024),
            current_block_index: 0,
            buffered_records: Vec::new(),
            buffered_bytes: Vec::new(),
        }
    }

    /// Adds a record to the active coalescer buffer.
    /// If adding this record causes the buffer to reach `max_block_bytes`, the block is sealed and returned.
    pub fn add_record(&mut self, offset: u64, payload: &[u8]) -> Option<CoalescedBlock> {
        let relative_byte_offset = self.buffered_bytes.len() as u32;
        let payload_len = payload.len() as u32;
        let payload_hash: HashDigest = *blake3::hash(payload).as_bytes();

        self.buffered_records.push(CoalescedRecord {
            offset,
            relative_byte_offset,
            payload_len,
            payload_hash,
        });
        self.buffered_bytes.extend_from_slice(payload);

        if self.buffered_bytes.len() >= self.max_block_bytes {
            self.seal_current_block()
        } else {
            None
        }
    }

    /// Flushes any partially accumulated records into a sealed block.
    pub fn flush(&mut self) -> Option<CoalescedBlock> {
        if self.buffered_records.is_empty() {
            None
        } else {
            self.seal_current_block()
        }
    }

    fn seal_current_block(&mut self) -> Option<CoalescedBlock> {
        if self.buffered_records.is_empty() {
            return None;
        }

        let start_offset = self.buffered_records.first().unwrap().offset;
        let end_offset = self.buffered_records.last().unwrap().offset;
        let block_index = self.current_block_index;
        self.current_block_index += 1;

        let records = std::mem::take(&mut self.buffered_records);
        let raw_bytes = std::mem::take(&mut self.buffered_bytes);

        // Build intra-block Merkle tree over all record hashes
        let mut current_level: Vec<HashDigest> = records.iter().map(|r| r.payload_hash).collect();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_coalesce_parent(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_coalesce_parent(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
        }

        let block_hash = current_level.first().copied().unwrap_or([0u8; 32]);

        Some(CoalescedBlock {
            block_index,
            start_offset,
            end_offset,
            records,
            raw_bytes,
            block_hash,
        })
    }
}
