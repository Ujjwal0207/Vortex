use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use vortex_core::{
    HashDigest, MmrConsistencyProof, Result, SignedCheckpoint, VortexError, WitnessCountersignature,
};

/// Persistent state tracked by an independent witness to ensure monotonic log continuity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessState {
    pub witness_pubkey: [u8; 32],
    pub last_checkpoint_seq: u64,
    pub last_tree_size: u64,
    pub last_mmr_root: HashDigest,
}

/// Independent Witness that verifies consistency proofs before countersigning checkpoints.
/// Modeled directly after RFC 9162 (Certificate Transparency v2) and transparency-dev/witness.
pub struct IndependentWitness {
    pub witness_key: SigningKey,
    pub state_path: PathBuf,
    pub reel_path: PathBuf,
    pub state: WitnessState,
}

impl IndependentWitness {
    pub fn open_or_create(
        witness_key: SigningKey,
        state_path: PathBuf,
        reel_path: PathBuf,
    ) -> Result<Self> {
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VortexError::Io(e.to_string()))?;
        }
        if let Some(parent) = reel_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VortexError::Io(e.to_string()))?;
        }

        let pubkey = witness_key.verifying_key().to_bytes();

        let state = if state_path.exists() {
            let mut file = File::open(&state_path).map_err(|e| VortexError::Io(e.to_string()))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| VortexError::Io(e.to_string()))?;
            serde_json::from_str(&contents)
                .map_err(|e| VortexError::InvalidRecordFormat(format!("Invalid witness state: {}", e)))?
        } else {
            WitnessState {
                witness_pubkey: pubkey,
                last_checkpoint_seq: 0,
                last_tree_size: 0,
                last_mmr_root: [0u8; 32],
            }
        };

        Ok(Self {
            witness_key,
            state_path,
            reel_path,
            state,
        })
    }

    pub fn witness_pubkey(&self) -> [u8; 32] {
        self.state.witness_pubkey
    }

    fn persist_state(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.state)
            .map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?;
        let mut file = File::create(&self.state_path).map_err(|e| VortexError::Io(e.to_string()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| VortexError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| VortexError::Io(e.to_string()))?;
        Ok(())
    }

    fn append_reel(&self, countersig: &WitnessCountersignature) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.reel_path)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let line = serde_json::to_string(countersig)
            .map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?;
        writeln!(file, "{}", line).map_err(|e| VortexError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| VortexError::Io(e.to_string()))?;
        Ok(())
    }

    /// Verifies a new checkpoint against prior witness state using an MMR consistency proof.
    /// If valid, updates local witness state and emits a countersignature to reel.wit.
    pub fn verify_and_countersign(
        &mut self,
        checkpoint: &SignedCheckpoint,
        consistency_proof: Option<&MmrConsistencyProof>,
    ) -> Result<WitnessCountersignature> {
        // 1. Verify gateway signature
        if !checkpoint.verify() {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Checkpoint seq {} signature is INVALID",
                    checkpoint.checkpoint_seq
                ),
            });
        }

        // 2. Check for tree truncation (equivocation attempt)
        if checkpoint.tree_size < self.state.last_tree_size {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "CRITICAL EQUIVOCATION: New checkpoint tree size ({}) is smaller than witness state ({})",
                    checkpoint.tree_size, self.state.last_tree_size
                ),
            });
        }

        let prior_tree_size = self.state.last_tree_size;
        let prior_mmr_root = self.state.last_mmr_root;

        // 3. Genesis checkpoint (first observation)
        if self.state.last_tree_size == 0 {
            let countersig = WitnessCountersignature::sign(
                checkpoint.checkpoint_seq,
                checkpoint.tree_size,
                checkpoint.mmr_root,
                0,
                [0u8; 32],
                &self.witness_key,
            );

            self.state.last_checkpoint_seq = checkpoint.checkpoint_seq;
            self.state.last_tree_size = checkpoint.tree_size;
            self.state.last_mmr_root = checkpoint.mmr_root;

            self.persist_state()?;
            self.append_reel(&countersig)?;
            return Ok(countersig);
        }

        // 4. Same tree size (must have identical root)
        if checkpoint.tree_size == self.state.last_tree_size {
            if checkpoint.mmr_root != self.state.last_mmr_root {
                return Err(VortexError::SecurityViolation {
                    reason: format!(
                        "CRITICAL EQUIVOCATION: Split-view detected! Identical tree size ({}) with different MMR roots",
                        checkpoint.tree_size
                    ),
                });
            }

            // Already verified, generate fresh countersignature for this checkpoint sequence
            let countersig = WitnessCountersignature::sign(
                checkpoint.checkpoint_seq,
                checkpoint.tree_size,
                checkpoint.mmr_root,
                prior_tree_size,
                prior_mmr_root,
                &self.witness_key,
            );
            self.append_reel(&countersig)?;
            return Ok(countersig);
        }

        // 5. Tree size grew: Must verify consistency proof
        let proof = consistency_proof.ok_or_else(|| {
            VortexError::SecurityViolation {
                reason: format!(
                    "Consistency proof required to advance tree from {} to {}",
                    prior_tree_size, checkpoint.tree_size
                ),
            }
        })?;

        if !proof.verify(&prior_mmr_root, &checkpoint.mmr_root) {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "CONSISTENCY PROOF FAILED: Tree size {} is not a valid append-only extension of tree size {}",
                    checkpoint.tree_size, prior_tree_size
                ),
            });
        }

        // 6. Verification successful: countersign, update state, and emit to reel.wit
        let countersig = WitnessCountersignature::sign(
            checkpoint.checkpoint_seq,
            checkpoint.tree_size,
            checkpoint.mmr_root,
            prior_tree_size,
            prior_mmr_root,
            &self.witness_key,
        );

        self.state.last_checkpoint_seq = checkpoint.checkpoint_seq;
        self.state.last_tree_size = checkpoint.tree_size;
        self.state.last_mmr_root = checkpoint.mmr_root;

        self.persist_state()?;
        self.append_reel(&countersig)?;

        Ok(countersig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vortex_core::{generate_signing_key, MerkleMountainRange};

    #[test]
    fn test_witness_monotonic_countersignature_and_equivocation_detection() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("witness_state.json");
        let reel_path = dir.path().join("reel.wit");

        let wit_key = generate_signing_key();
        let gw_key = generate_signing_key();

        let mut witness = IndependentWitness::open_or_create(wit_key, state_path.clone(), reel_path.clone()).unwrap();

        // 1. Genesis checkpoint with 5 leaves
        let mut mmr = MerkleMountainRange::new();
        for i in 0..5 {
            mmr.append([i as u8 + 1; 32]);
        }
        let root5 = mmr.root();
        let ckpt1 = SignedCheckpoint::sign(0, 5, root5, &gw_key);

        let countersig1 = witness.verify_and_countersign(&ckpt1, None).unwrap();
        assert!(countersig1.verify());
        assert_eq!(witness.state.last_tree_size, 5);
        assert_eq!(witness.state.last_mmr_root, root5);

        // 2. Extend tree to 10 leaves and verify consistency proof
        for i in 5..10 {
            mmr.append([i as u8 + 1; 32]);
        }
        let root10 = mmr.root();
        let proof = mmr.generate_consistency_proof(5).unwrap();
        let ckpt2 = SignedCheckpoint::sign(1, 10, root10, &gw_key);

        let countersig2 = witness.verify_and_countersign(&ckpt2, Some(&proof)).unwrap();
        assert!(countersig2.verify());
        assert_eq!(witness.state.last_tree_size, 10);
        assert_eq!(witness.state.last_mmr_root, root10);

        // 3. Negative test: Equivocation / truncation attack (trying to rewind tree size to 8)
        let ckpt_rewind = SignedCheckpoint::sign(2, 8, [99u8; 32], &gw_key);
        assert!(witness.verify_and_countersign(&ckpt_rewind, None).is_err());

        // 4. Negative test: Invalid consistency proof / tampered root
        let ckpt_tampered = SignedCheckpoint::sign(3, 15, [88u8; 32], &gw_key);
        assert!(witness.verify_and_countersign(&ckpt_tampered, Some(&proof)).is_err());

        // 5. Verify witness state survives reopening from disk
        let wit_key2 = generate_signing_key();
        let reopened_witness = IndependentWitness::open_or_create(wit_key2, state_path, reel_path).unwrap();
        assert_eq!(reopened_witness.state.last_tree_size, 10);
        assert_eq!(reopened_witness.state.last_mmr_root, root10);
    }
}
