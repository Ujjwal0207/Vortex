use crate::hash::HashDigest;
pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// 64-byte Ed25519 signature wrapper with hex serialization.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureBytes(pub [u8; 64]);

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignatureBytes({})", self.to_hex())
    }
}

impl std::ops::Deref for SignatureBytes {
    type Target = [u8; 64];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 64]> for SignatureBytes {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<SignatureBytes> for [u8; 64] {
    fn from(sig: SignatureBytes) -> Self {
        sig.0
    }
}

impl SignatureBytes {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(s: &str) -> std::result::Result<Self, String> {
        let clean = s.trim();
        if clean.len() != 128 {
            return Err(format!("expected 128 hex chars for signature, got {}", clean.len()));
        }
        let mut bytes = [0u8; 64];
        for i in 0..64 {
            bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex char at byte {}: {e}", i))?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Computes a Blake3 cryptographic commitment (hash) of arbitrary data.
/// Used for arguments and executor results to guarantee integrity without leaking plaintext.
pub fn compute_commitment(data: &[u8]) -> HashDigest {
    *blake3::hash(data).as_bytes()
}

/// Helper to generate a random 32-byte Ed25519 secret key from OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("CSPRNG failure during key generation");
    SigningKey::from_bytes(&seed)
}

/// Verifies an Ed25519 signature over an arbitrary byte message.
pub fn verify_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// Stage 1: Request Commitment
/// Recorded when an agent attempts a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRequest {
    pub action_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub args_commitment: HashDigest,
    pub timestamp_ns: u64,
}

impl ActionRequest {
    pub fn new(agent_id: String, tool_name: String, action_id: String, args: &[u8]) -> Self {
        let args_commitment = compute_commitment(args);
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            action_id,
            agent_id,
            tool_name,
            args_commitment,
            timestamp_ns,
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-stage1-request-v1");
        hasher.update(self.action_id.as_bytes());
        hasher.update(self.agent_id.as_bytes());
        hasher.update(self.tool_name.as_bytes());
        hasher.update(&self.args_commitment);
        hasher.update(&self.timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }
}

/// Stage 2: Policy Decision
/// Evaluated and committed by the gateway before action execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action_id: String,
    pub policy_version: String,
    pub allowed: bool,
    pub reason: String,
    pub timestamp_ns: u64,
}

impl PolicyDecision {
    pub fn new(action_id: String, policy_version: String, allowed: bool, reason: String) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            action_id,
            policy_version,
            allowed,
            reason,
            timestamp_ns,
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-stage2-policy-v1");
        hasher.update(self.action_id.as_bytes());
        hasher.update(self.policy_version.as_bytes());
        hasher.update(&[if self.allowed { 1u8 } else { 0u8 }]);
        hasher.update(self.reason.as_bytes());
        hasher.update(&self.timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }
}

/// Gateway Receipt returned to the calling agent upon policy evaluation & log commit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayReceipt {
    pub action_id: String,
    pub sequence_number: u64,
    pub args_commitment: HashDigest,
    pub policy_allowed: bool,
    pub gateway_pubkey: [u8; 32],
    pub signature: SignatureBytes,
    pub timestamp_ns: u64,
}

impl GatewayReceipt {
    pub fn signing_bytes(
        action_id: &str,
        sequence_number: u64,
        args_commitment: &HashDigest,
        policy_allowed: bool,
        timestamp_ns: u64,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-gateway-receipt-v1");
        hasher.update(action_id.as_bytes());
        hasher.update(&sequence_number.to_be_bytes());
        hasher.update(args_commitment);
        hasher.update(&[if policy_allowed { 1u8 } else { 0u8 }]);
        hasher.update(&timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn sign(
        action_id: String,
        sequence_number: u64,
        args_commitment: HashDigest,
        policy_allowed: bool,
        signing_key: &SigningKey,
    ) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let msg = Self::signing_bytes(&action_id, sequence_number, &args_commitment, policy_allowed, timestamp_ns);
        let sig = signing_key.sign(&msg);

        Self {
            action_id,
            sequence_number,
            args_commitment,
            policy_allowed,
            gateway_pubkey: signing_key.verifying_key().to_bytes(),
            signature: SignatureBytes(sig.to_bytes()),
            timestamp_ns,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(
            &self.action_id,
            self.sequence_number,
            &self.args_commitment,
            self.policy_allowed,
            self.timestamp_ns,
        );
        verify_signature(&self.gateway_pubkey, &msg, &self.signature)
    }
}

/// Stage 3: Executor Receipt
/// Signed directly by the tool executor (not just the gateway asserting what happened).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorReceipt {
    pub action_id: String,
    pub sequence_number: u64,
    pub result_commitment: HashDigest,
    pub success: bool,
    pub executor_pubkey: [u8; 32],
    pub signature: SignatureBytes,
    pub timestamp_ns: u64,
}

impl ExecutorReceipt {
    pub fn signing_bytes(
        action_id: &str,
        sequence_number: u64,
        result_commitment: &HashDigest,
        success: bool,
        timestamp_ns: u64,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-stage3-executor-receipt-v1");
        hasher.update(action_id.as_bytes());
        hasher.update(&sequence_number.to_be_bytes());
        hasher.update(result_commitment);
        hasher.update(&[if success { 1u8 } else { 0u8 }]);
        hasher.update(&timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn sign(
        action_id: String,
        sequence_number: u64,
        result: &[u8],
        success: bool,
        signing_key: &SigningKey,
    ) -> Self {
        let result_commitment = compute_commitment(result);
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let msg = Self::signing_bytes(&action_id, sequence_number, &result_commitment, success, timestamp_ns);
        let sig = signing_key.sign(&msg);

        Self {
            action_id,
            sequence_number,
            result_commitment,
            success,
            executor_pubkey: signing_key.verifying_key().to_bytes(),
            signature: SignatureBytes(sig.to_bytes()),
            timestamp_ns,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(
            &self.action_id,
            self.sequence_number,
            &self.result_commitment,
            self.success,
            self.timestamp_ns,
        );
        verify_signature(&self.executor_pubkey, &msg, &self.signature)
    }
}

/// Stage 4: Signed Checkpoint
/// Emitted by the gateway, covering tree size and MMR root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub checkpoint_seq: u64,
    pub tree_size: u64,
    pub mmr_root: HashDigest,
    pub gateway_pubkey: [u8; 32],
    pub signature: SignatureBytes,
    pub timestamp_ns: u64,
}

impl SignedCheckpoint {
    pub fn signing_bytes(checkpoint_seq: u64, tree_size: u64, mmr_root: &HashDigest, timestamp_ns: u64) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-stage4-checkpoint-v1");
        hasher.update(&checkpoint_seq.to_be_bytes());
        hasher.update(&tree_size.to_be_bytes());
        hasher.update(mmr_root);
        hasher.update(&timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn sign(checkpoint_seq: u64, tree_size: u64, mmr_root: HashDigest, signing_key: &SigningKey) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let msg = Self::signing_bytes(checkpoint_seq, tree_size, &mmr_root, timestamp_ns);
        let sig = signing_key.sign(&msg);

        Self {
            checkpoint_seq,
            tree_size,
            mmr_root,
            gateway_pubkey: signing_key.verifying_key().to_bytes(),
            signature: SignatureBytes(sig.to_bytes()),
            timestamp_ns,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(self.checkpoint_seq, self.tree_size, &self.mmr_root, self.timestamp_ns);
        verify_signature(&self.gateway_pubkey, &msg, &self.signature)
    }
}

/// Stage 5: Witness Countersignature
/// Issued only after independent verification of MMR consistency from prior state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessCountersignature {
    pub checkpoint_seq: u64,
    pub tree_size: u64,
    pub mmr_root: HashDigest,
    pub prior_tree_size: u64,
    pub prior_mmr_root: HashDigest,
    pub witness_pubkey: [u8; 32],
    pub signature: SignatureBytes,
    pub timestamp_ns: u64,
}

impl WitnessCountersignature {
    pub fn signing_bytes(
        checkpoint_seq: u64,
        tree_size: u64,
        mmr_root: &HashDigest,
        prior_tree_size: u64,
        prior_mmr_root: &HashDigest,
        timestamp_ns: u64,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-stage5-witness-countersignature-v1");
        hasher.update(&checkpoint_seq.to_be_bytes());
        hasher.update(&tree_size.to_be_bytes());
        hasher.update(mmr_root);
        hasher.update(&prior_tree_size.to_be_bytes());
        hasher.update(prior_mmr_root);
        hasher.update(&timestamp_ns.to_be_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn sign(
        checkpoint_seq: u64,
        tree_size: u64,
        mmr_root: HashDigest,
        prior_tree_size: u64,
        prior_mmr_root: HashDigest,
        signing_key: &SigningKey,
    ) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let msg = Self::signing_bytes(
            checkpoint_seq,
            tree_size,
            &mmr_root,
            prior_tree_size,
            &prior_mmr_root,
            timestamp_ns,
        );
        let sig = signing_key.sign(&msg);

        Self {
            checkpoint_seq,
            tree_size,
            mmr_root,
            prior_tree_size,
            prior_mmr_root,
            witness_pubkey: signing_key.verifying_key().to_bytes(),
            signature: SignatureBytes(sig.to_bytes()),
            timestamp_ns,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(
            self.checkpoint_seq,
            self.tree_size,
            &self.mmr_root,
            self.prior_tree_size,
            &self.prior_mmr_root,
            self.timestamp_ns,
        );
        verify_signature(&self.witness_pubkey, &msg, &self.signature)
    }
}

/// Action evidence payload stored within the partition log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionEvidenceRecord {
    Request(ActionRequest),
    Policy(PolicyDecision),
    Executor(ExecutorReceipt),
    Checkpoint(SignedCheckpoint),
}

/// Verification verdict for a given action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionVerdict {
    /// All 5 stages are present, signatures valid, no sequence gaps up to the witnessed checkpoint.
    Verified {
        action_id: String,
        agent_id: String,
        tool_name: String,
        sequence_number: u64,
        witness_checkpoint_seq: u64,
    },
    /// Policy denied the action; signed evidence of denial is present.
    Rejected {
        action_id: String,
        agent_id: String,
        tool_name: String,
        policy_version: String,
        reason: String,
    },
    /// One or more stages are missing (e.g. request with no executor receipt, or orphaned receipt).
    /// MUST NOT be reported as success.
    Incomplete {
        action_id: String,
        missing_stages: Vec<String>,
        details: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_signing_and_verification_roundtrip() {
        let gw_key = generate_signing_key();
        let exec_key = generate_signing_key();
        let wit_key = generate_signing_key();

        let action_id = "act-9901".to_string();
        let req = ActionRequest::new(
            "agent-01".to_string(),
            "transfer_funds".to_string(),
            action_id.clone(),
            b"{\"amount\": 1000}",
        );
        assert_eq!(req.args_commitment, compute_commitment(b"{\"amount\": 1000}"));

        // Stage 1 & 2 Gateway Receipt
        let gw_receipt = GatewayReceipt::sign(action_id.clone(), 42, req.args_commitment, true, &gw_key);
        assert!(gw_receipt.verify());

        // Tamper test on gateway receipt
        let mut tampered_gw_receipt = gw_receipt.clone();
        tampered_gw_receipt.policy_allowed = false;
        assert!(!tampered_gw_receipt.verify());

        // Stage 3 Executor Receipt
        let exec_receipt = ExecutorReceipt::sign(
            action_id.clone(),
            42,
            b"{\"tx_hash\": \"0xabc123\"}",
            true,
            &exec_key,
        );
        assert!(exec_receipt.verify());

        // Tamper test on executor receipt
        let mut tampered_exec = exec_receipt.clone();
        tampered_exec.success = false;
        assert!(!tampered_exec.verify());

        // Stage 4 Checkpoint
        let root = [7u8; 32];
        let checkpoint = SignedCheckpoint::sign(1, 100, root, &gw_key);
        assert!(checkpoint.verify());

        // Stage 5 Witness Countersignature
        let prior_root = [6u8; 32];
        let wit_countersig = WitnessCountersignature::sign(1, 100, root, 50, prior_root, &wit_key);
        assert!(wit_countersig.verify());

        // Tamper test on witness countersignature
        let mut tampered_wit = wit_countersig.clone();
        tampered_wit.tree_size = 101;
        assert!(!tampered_wit.verify());
    }

    #[test]
    fn test_action_evidence_record_serde_json_roundtrip() {
        let req = ActionRequest::new(
            "agent-01".to_string(),
            "read_file".to_string(),
            "act-123".to_string(),
            b"/etc/hosts",
        );
        let record = ActionEvidenceRecord::Request(req);
        let serialized = serde_json::to_vec(&record).unwrap();
        let deserialized: ActionEvidenceRecord = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(record, deserialized);
    }
}
