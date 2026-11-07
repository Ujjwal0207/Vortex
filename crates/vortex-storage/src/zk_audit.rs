use vortex_core::error::{Result, VortexError};
use vortex_core::hash::HashDigest;
use vortex_core::zkp::{ZkBatchAuditProof, ZkBatchProver, ZkBatchVerifier};

use crate::partition::PartitionLog;

/// Phase 15: Succinct ZK-SNARK batch audit engine.
///
/// Enables zero-knowledge batch audit proofs of $K$ partition records in constant 256 bytes,
/// verifying complete sequentiality and MMR root commitment with **zero data leakage**.
pub struct ZkAuditEngine;

impl ZkAuditEngine {
    /// Generates a constant 256-byte ZK-SNARK batch audit proof for `count` records
    /// beginning at `start_offset`.
    pub fn generate_batch_proof(
        partition: &PartitionLog,
        start_offset: u64,
        count: u32,
    ) -> Result<ZkBatchAuditProof> {
        if count == 0 {
            return Err(VortexError::InvalidRecordFormat(
                "Cannot generate ZK batch proof with count 0".to_string(),
            ));
        }

        let next_offset = partition.next_offset();
        let requested_end = start_offset
            .checked_add(count as u64)
            .ok_or_else(|| VortexError::Io("Offset overflow in batch proof".to_string()))?;

        if requested_end > next_offset {
            return Err(VortexError::OffsetOutOfBounds {
                requested: requested_end,
                base_offset: start_offset,
                next_offset,
            });
        }

        // Read records across the partition
        let records = partition.read(start_offset, 64 * 1024 * 1024)?;
        let batch_records: Vec<_> = records
            .into_iter()
            .take(count as usize)
            .collect();

        if batch_records.len() != count as usize {
            return Err(VortexError::OffsetOutOfBounds {
                requested: start_offset + (batch_records.len() as u64),
                base_offset: start_offset,
                next_offset,
            });
        }

        let tuples: Vec<(u64, HashDigest, HashDigest)> = batch_records
            .iter()
            .map(|r| (r.offset, r.prev_hash, r.record_hash))
            .collect();

        let mmr_root = partition.active_mmr_root();
        ZkBatchProver::prove_batch(&mmr_root, start_offset, &tuples)
    }

    /// Verifies a constant 256-byte ZK batch audit proof in sub-5ms against `trusted_mmr_root`.
    pub fn verify_batch_proof(
        proof: &ZkBatchAuditProof,
        trusted_mmr_root: &HashDigest,
    ) -> Result<bool> {
        ZkBatchVerifier::verify(proof, trusted_mmr_root)
    }
}

