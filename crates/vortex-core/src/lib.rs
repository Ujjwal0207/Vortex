pub mod blind_index;
pub mod error;
pub mod evidence;
pub mod hash;
pub mod mmr;
pub mod ore;
pub mod ratchet;
pub mod record;
pub mod shred;
pub mod spsc;
pub mod tx;
pub mod zkp;

pub use blind_index::BlindIndexer;
pub use error::{Result, VortexError};
pub use evidence::{
    compute_commitment, generate_signing_key, verify_signature, ActionEvidenceRecord,
    ActionRequest, ActionVerdict, CausalActionRequest, ExecutorReceipt, GatewayReceipt, PolicyDecision, SignedCheckpoint,
    WitnessCountersignature, SignatureBytes, Signer, SigningKey,
};
pub use hash::{compute_genesis_hash, compute_record_hash, verify_record_integrity, HashDigest};
pub use mmr::{MerkleMountainRange, MmrConsistencyProof, MmrInclusionProof, PeakConsistencyProof};
pub use ore::{OreRangeQuery, OreTag, OrderRevealingIndexer};
pub use ratchet::{constant_time_eq_32, ForwardSecureRatchet, KeyringSlot, KEYRING_SLOT_SIZE};
pub use record::{Record, TopicMode, RECORD_HEADER_SIZE};
pub use shred::EntityKeyRegistry;
pub use spsc::SpscRingBuffer;
pub use tx::{IsolationLevel, TransactionCoordinator, CONTROL_TXN_ABORT, CONTROL_TXN_COMMIT};
pub use zkp::{
    ZkBatchAuditProof, ZkBatchProver, ZkBatchPublicInputs, ZkBatchVerifier,
    ZK_SNARK_PROOF_BYTES_LEN,
};

