use crate::hash::HashDigest;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

const MMR_NODE_PREFIX: &[u8] = b"VORTEX_MMR_NODE_V1:";
const MMR_BAG_PREFIX: &[u8] = b"VORTEX_MMR_BAGGED_ROOT_V1:";

/// Hashes two sibling nodes into a parent node with strict domain separation.
pub fn hash_parent(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = Hasher::new();
    hasher.update(MMR_NODE_PREFIX);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Computes the bagged root across all active peak roots.
pub fn bag_peaks(peaks: &[HashDigest]) -> HashDigest {
    if peaks.is_empty() {
        return [0u8; 32];
    }
    if peaks.len() == 1 {
        return peaks[0];
    }
    let mut hasher = Hasher::new();
    hasher.update(MMR_BAG_PREFIX);
    for peak in peaks {
        hasher.update(peak);
    }
    *hasher.finalize().as_bytes()
}

/// A complete binary tree representing a single mountain peak in the MMR.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MmrPeak {
    size: usize,
    /// levels[0] = leaves, levels[height] = [root]
    levels: Vec<Vec<HashDigest>>,
}

impl MmrPeak {
    fn new_leaf(hash: HashDigest) -> Self {
        Self {
            size: 1,
            levels: vec![vec![hash]],
        }
    }

    fn root(&self) -> HashDigest {
        *self.levels.last().and_then(|lvl| lvl.first()).unwrap_or(&[0u8; 32])
    }

    fn merge(left: Self, right: Self) -> Self {
        assert_eq!(left.size, right.size, "Merged peaks must have identical leaf counts");
        let height = left.levels.len();
        let mut new_levels = Vec::with_capacity(height + 1);

        for h in 0..height {
            let mut combined = Vec::with_capacity(left.levels[h].len() + right.levels[h].len());
            combined.extend_from_slice(&left.levels[h]);
            combined.extend_from_slice(&right.levels[h]);
            new_levels.push(combined);
        }

        let parent = hash_parent(&left.root(), &right.root());
        new_levels.push(vec![parent]);

        Self {
            size: left.size * 2,
            levels: new_levels,
        }
    }
}

/// Compact inclusion proof for an individual record in the MMR.
/// Compact inclusion proof for an individual record in the MMR.
/// Total size is bounded by O(log N) hashes (~320-480 bytes for millions of records).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrInclusionProof {
    /// Global leaf index across the MMR (0..count-1)
    pub leaf_index: u64,
    /// Offset of the leaf within its containing mountain peak tree
    pub leaf_offset_in_peak: u64,
    pub leaf_hash: HashDigest,
    /// Sibling hashes from leaf to peak root
    pub sibling_hashes: Vec<HashDigest>,
    /// Index of the peak containing this leaf
    pub peak_index: usize,
    /// All MMR peaks at the time the proof was generated
    pub peaks: Vec<HashDigest>,
}

impl MmrInclusionProof {
    /// Verifies that this proof demonstrates inclusion of a specific record
    /// under the given expected MMR root.
    ///
    /// `expected_root` is the MMR bagged-peaks root the caller trusts.
    /// `expected_leaf_hash` is the Blake3 hash of the record the caller wants
    /// to confirm is present at `self.leaf_index`. The proof carries its own
    /// `leaf_hash` internally; this parameter ensures the caller's record
    /// actually matches what the proof covers, preventing proof substitution.
    pub fn verify(&self, expected_root: &HashDigest, expected_leaf_hash: &HashDigest) -> bool {
        // Bind the proof to the caller's record — reject proofs for a different leaf
        if self.leaf_hash != *expected_leaf_hash {
            return false;
        }

        if self.peak_index >= self.peaks.len() {
            return false;
        }

        // Reconstruct the peak root from the leaf hash and sibling path
        let mut curr = self.leaf_hash;
        let mut offset = self.leaf_offset_in_peak;

        // Leaf offset inside its peak
        for &sibling in &self.sibling_hashes {
            if (offset & 1) == 0 {
                // Current node is left child
                curr = hash_parent(&curr, &sibling);
            } else {
                // Current node is right child
                curr = hash_parent(&sibling, &curr);
            }
            offset >>= 1;
        }

        // The reconstructed root must match the claimed peak
        if curr != self.peaks[self.peak_index] {
            return false;
        }

        // The bagged root across all peaks must match expected_root
        bag_peaks(&self.peaks) == *expected_root
    }
}

/// Compact consistency proof showing that an MMR with `new_size` is an append-only extension
/// of an earlier MMR with `old_size` (RFC 9162 / transparency-dev witness design).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub old_peaks: Vec<HashDigest>,
    pub new_peaks: Vec<HashDigest>,
    pub peak_proofs: Vec<PeakConsistencyProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeakConsistencyProof {
    pub old_peak_index: usize,
    pub new_peak_index: usize,
    pub old_peak_height: usize,
    pub offset_at_height: usize,
    pub sibling_hashes: Vec<HashDigest>,
}

impl MmrConsistencyProof {
    /// Verifies that the new MMR root is a consistent, append-only extension of the old MMR root.
    pub fn verify(&self, expected_old_root: &HashDigest, expected_new_root: &HashDigest) -> bool {
        if self.old_size > self.new_size {
            return false;
        }

        if self.old_size == self.new_size {
            return self.old_peaks == self.new_peaks
                && bag_peaks(&self.old_peaks) == *expected_old_root
                && bag_peaks(&self.new_peaks) == *expected_new_root;
        }

        if bag_peaks(&self.old_peaks) != *expected_old_root {
            return false;
        }

        if bag_peaks(&self.new_peaks) != *expected_new_root {
            return false;
        }

        if self.old_size == 0 {
            return self.old_peaks.is_empty() && self.peak_proofs.is_empty();
        }

        if self.peak_proofs.len() != self.old_peaks.len() {
            return false;
        }

        for (i, proof) in self.peak_proofs.iter().enumerate() {
            if proof.old_peak_index != i || proof.new_peak_index >= self.new_peaks.len() {
                return false;
            }

            let mut curr = self.old_peaks[i];
            let mut offset = proof.offset_at_height;

            for &sibling in &proof.sibling_hashes {
                if (offset & 1) == 0 {
                    curr = hash_parent(&curr, &sibling);
                } else {
                    curr = hash_parent(&sibling, &curr);
                }
                offset >>= 1;
            }

            if curr != self.new_peaks[proof.new_peak_index] {
                return false;
            }
        }

        true
    }
}

/// Append-only Merkle Mountain Range (MMR) ledger for high-performance,
/// O(log N) cryptographic inclusion proofs of streaming records.
#[derive(Debug, Clone, Default)]
pub struct MerkleMountainRange {
    peaks: Vec<MmrPeak>,
    leaf_count: u64,
}

impl MerkleMountainRange {
    /// Creates a new empty MMR.
    pub fn new() -> Self {
        Self {
            peaks: Vec::new(),
            leaf_count: 0,
        }
    }

    /// Total number of leaves committed to the MMR.
    pub fn count(&self) -> u64 {
        self.leaf_count
    }

    /// Returns the current bagged root digest of the entire MMR.
    pub fn root(&self) -> HashDigest {
        let peak_hashes: Vec<HashDigest> = self.peaks.iter().map(|p| p.root()).collect();
        bag_peaks(&peak_hashes)
    }

    /// Returns list of all individual active peak roots.
    pub fn peaks(&self) -> Vec<HashDigest> {
        self.peaks.iter().map(|p| p.root()).collect()
    }

    /// Appends a new record hash to the MMR.
    pub fn append(&mut self, record_hash: HashDigest) {
        let mut new_peak = MmrPeak::new_leaf(record_hash);

        while let Some(last) = self.peaks.last() {
            if last.size == new_peak.size {
                let prev = self.peaks.pop().unwrap();
                new_peak = MmrPeak::merge(prev, new_peak);
            } else {
                break;
            }
        }

        self.peaks.push(new_peak);
        self.leaf_count += 1;
    }

    /// Generates a compact O(log N) inclusion proof for the leaf at `leaf_index`.
    pub fn generate_proof(&self, leaf_index: u64) -> Option<MmrInclusionProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let mut remaining = leaf_index;
        let mut target_peak_idx = None;

        for (idx, peak) in self.peaks.iter().enumerate() {
            if remaining < peak.size as u64 {
                target_peak_idx = Some((idx, remaining));
                break;
            }
            remaining -= peak.size as u64;
        }

        let (peak_idx, offset_in_peak) = target_peak_idx?;
        let peak = &self.peaks[peak_idx];

        let mut sibling_hashes = Vec::with_capacity(peak.levels.len() - 1);
        let mut curr_idx = offset_in_peak as usize;

        for h in 0..(peak.levels.len() - 1) {
            let sibling_idx = curr_idx ^ 1;
            sibling_hashes.push(peak.levels[h][sibling_idx]);
            curr_idx /= 2;
        }

        let leaf_hash = peak.levels[0][offset_in_peak as usize];
        let peak_hashes = self.peaks();

        Some(MmrInclusionProof {
            leaf_index,
            leaf_offset_in_peak: offset_in_peak,
            leaf_hash,
            sibling_hashes,
            peak_index: peak_idx,
            peaks: peak_hashes,
        })
    }

    /// Generates an O(log N) consistency proof showing that the current MMR of size `self.leaf_count`
    /// is an unbroken append-only extension of an earlier MMR of size `old_size` (RFC 9162 / transparency-dev witness design).
    pub fn generate_consistency_proof(&self, old_size: u64) -> Option<MmrConsistencyProof> {
        if old_size > self.leaf_count {
            return None;
        }

        let new_peaks = self.peaks();

        if old_size == 0 {
            return Some(MmrConsistencyProof {
                old_size: 0,
                new_size: self.leaf_count,
                old_peaks: Vec::new(),
                new_peaks,
                peak_proofs: Vec::new(),
            });
        }

        if old_size == self.leaf_count {
            return Some(MmrConsistencyProof {
                old_size,
                new_size: self.leaf_count,
                old_peaks: new_peaks.clone(),
                new_peaks,
                peak_proofs: Vec::new(),
            });
        }

        // Decompose old_size into peak sizes (powers of 2 in descending order)
        let mut old_peak_sizes = Vec::new();
        let mut rem = old_size;
        while rem > 0 {
            let p = 1u64 << (63 - rem.leading_zeros());
            old_peak_sizes.push(p);
            rem -= p;
        }

        let mut old_peaks = Vec::with_capacity(old_peak_sizes.len());
        let mut peak_proofs = Vec::with_capacity(old_peak_sizes.len());

        let mut old_leaf_cursor = 0u64;

        for (old_peak_idx, &p_size) in old_peak_sizes.iter().enumerate() {
            let height = p_size.trailing_zeros() as usize;

            // Find which new_peak contains old_leaf_cursor
            let mut new_peak_base = 0u64;
            let mut found_new_peak = None;

            for (new_idx, new_p) in self.peaks.iter().enumerate() {
                let new_size = new_p.size as u64;
                if old_leaf_cursor >= new_peak_base && old_leaf_cursor + p_size <= new_peak_base + new_size {
                    found_new_peak = Some((new_idx, new_p, new_peak_base));
                    break;
                }
                new_peak_base += new_size;
            }

            let (new_peak_idx, new_peak, base) = found_new_peak?;

            let offset_at_height = ((old_leaf_cursor - base) >> height) as usize;
            let old_peak_hash = new_peak.levels[height][offset_at_height];
            old_peaks.push(old_peak_hash);

            let new_height = new_peak.levels.len() - 1;
            let mut sibling_hashes = Vec::with_capacity(new_height.saturating_sub(height));
            let mut curr_offset = offset_at_height;

            for l in height..new_height {
                let sibling_idx = curr_offset ^ 1;
                sibling_hashes.push(new_peak.levels[l][sibling_idx]);
                curr_offset >>= 1;
            }

            peak_proofs.push(PeakConsistencyProof {
                old_peak_index: old_peak_idx,
                new_peak_index: new_peak_idx,
                old_peak_height: height,
                offset_at_height,
                sibling_hashes,
            });

            old_leaf_cursor += p_size;
        }

        Some(MmrConsistencyProof {
            old_size,
            new_size: self.leaf_count,
            old_peaks,
            new_peaks,
            peak_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_empty_and_single_leaf() {
        let mut mmr = MerkleMountainRange::new();
        assert_eq!(mmr.count(), 0);
        assert_eq!(mmr.root(), [0u8; 32]);
        assert!(mmr.generate_proof(0).is_none());

        let h0 = [1u8; 32];
        mmr.append(h0);
        assert_eq!(mmr.count(), 1);
        assert_eq!(mmr.root(), h0);

        let proof = mmr.generate_proof(0).expect("proof must exist for leaf 0");
        assert_eq!(proof.leaf_hash, h0);
        assert_eq!(proof.sibling_hashes.len(), 0);
        assert!(proof.verify(&mmr.root(), &h0));

        // Negative test: proof must NOT verify against a different leaf hash
        let different_leaf = [99u8; 32];
        assert!(!proof.verify(&mmr.root(), &different_leaf), "proof must bind to caller's leaf hash");
    }

    #[test]
    fn test_mmr_logarithmic_proof_and_tamper_detection() {
        let mut mmr = MerkleMountainRange::new();
        let total_leaves = 1000u64;

        let mut leaf_hashes = Vec::with_capacity(total_leaves as usize);
        for i in 0..total_leaves {
            let mut hasher = Hasher::new();
            hasher.update(&i.to_be_bytes());
            let h = *hasher.finalize().as_bytes();
            mmr.append(h);
            leaf_hashes.push(h);
        }

        assert_eq!(mmr.count(), total_leaves);
        let root = mmr.root();

        // Check inclusion proofs for multiple leaves (beginning, middle, end)
        for &leaf_idx in &[0, 1, 7, 63, 64, 500, 999] {
            let expected_leaf = leaf_hashes[leaf_idx as usize];
            let proof = mmr.generate_proof(leaf_idx).expect("proof must exist");
            assert!(
                proof.sibling_hashes.len() <= 10,
                "proof depth must be logarithmic O(log N)"
            );
            assert!(proof.verify(&root, &expected_leaf), "valid proof must verify against root and leaf");

            // Negative test: proof verification fails if caller expects a different record
            let wrong_leaf = [0xEEu8; 32];
            assert!(!proof.verify(&root, &wrong_leaf), "must fail when caller supplies wrong leaf");

            // Tampering: corrupted leaf hash in proof fails
            let mut tampered_proof = proof.clone();
            tampered_proof.leaf_hash[0] ^= 0xFF;
            assert!(!tampered_proof.verify(&root, &expected_leaf));

            // Tampering: corrupted sibling fails
            if !proof.sibling_hashes.is_empty() {
                let mut tampered_sibling = proof.clone();
                tampered_sibling.sibling_hashes[0][0] ^= 0xFF;
                assert!(!tampered_sibling.verify(&root, &expected_leaf));
            }

            // Tampering: wrong root fails
            let mut bad_root = root;
            bad_root[0] ^= 0xFF;
            assert!(!proof.verify(&bad_root, &expected_leaf));
        }
    }

    #[test]
    fn test_mmr_consistency_proof_and_monotonicity() {
        let mut mmr = MerkleMountainRange::new();
        let mut roots = Vec::new();

        // Build MMR step by step, saving roots at various checkpoints
        let checkpoints = [0, 1, 3, 4, 7, 15, 16, 50, 100];
        let mut check_idx = 0;

        if checkpoints[check_idx] == 0 {
            roots.push((0, mmr.root()));
            check_idx += 1;
        }

        for i in 0..100u64 {
            let mut hasher = Hasher::new();
            hasher.update(&i.to_be_bytes());
            mmr.append(*hasher.finalize().as_bytes());

            let current_count = i + 1;
            if check_idx < checkpoints.len() && checkpoints[check_idx] == current_count {
                roots.push((current_count, mmr.root()));
                check_idx += 1;
            }
        }

        // Verify pairwise consistency proofs across all checkpoint pairs (old_size <= 100)
        for &(old_size, old_root) in &roots {
            let proof = mmr.generate_consistency_proof(old_size).expect("proof must generate");
            assert_eq!(proof.old_size, old_size);
            assert_eq!(proof.new_size, 100);
            assert!(
                proof.verify(&old_root, &mmr.root()),
                "consistency proof from {old_size} to 100 must verify"
            );

            // Negative test: verify against tampered old root fails
            let mut bad_old_root = old_root;
            bad_old_root[0] ^= 0xFF;
            assert!(!proof.verify(&bad_old_root, &mmr.root()));

            // Negative test: verify against tampered new root fails
            let mut bad_new_root = mmr.root();
            bad_new_root[0] ^= 0xFF;
            assert!(!proof.verify(&old_root, &bad_new_root));
        }

        // Negative test: requesting consistency proof for future size fails
        assert!(mmr.generate_consistency_proof(101).is_none());
    }
}
