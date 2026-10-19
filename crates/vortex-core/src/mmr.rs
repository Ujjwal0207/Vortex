use crate::hash::HashDigest;
use blake3::Hasher;

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
/// Total size is bounded by O(log N) hashes (~320-480 bytes for millions of records).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Verifies that this proof demonstrates inclusion under the given expected MMR root.
    pub fn verify(&self, expected_root: &HashDigest) -> bool {
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
        assert!(proof.verify(&mmr.root()));
    }

    #[test]
    fn test_mmr_logarithmic_proof_and_tamper_detection() {
        let mut mmr = MerkleMountainRange::new();
        let total_leaves = 1000u64;

        for i in 0..total_leaves {
            let mut hasher = Hasher::new();
            hasher.update(&i.to_be_bytes());
            mmr.append(*hasher.finalize().as_bytes());
        }

        assert_eq!(mmr.count(), total_leaves);
        let root = mmr.root();

        // Check inclusion proofs for multiple leaves (beginning, middle, end)
        for &leaf_idx in &[0, 1, 7, 63, 64, 500, 999] {
            let proof = mmr.generate_proof(leaf_idx).expect("proof must exist");
            assert!(
                proof.sibling_hashes.len() <= 10,
                "proof depth must be logarithmic O(log N)"
            );
            assert!(proof.verify(&root), "valid proof must verify against root");

            // Tampering: corrupted leaf hash fails
            let mut tampered_proof = proof.clone();
            tampered_proof.leaf_hash[0] ^= 0xFF;
            assert!(!tampered_proof.verify(&root));

            // Tampering: corrupted sibling fails
            if !proof.sibling_hashes.is_empty() {
                let mut tampered_sibling = proof.clone();
                tampered_sibling.sibling_hashes[0][0] ^= 0xFF;
                assert!(!tampered_sibling.verify(&root));
            }

            // Tampering: wrong root fails
            let mut bad_root = root;
            bad_root[0] ^= 0xFF;
            assert!(!proof.verify(&bad_root));
        }
    }
}
