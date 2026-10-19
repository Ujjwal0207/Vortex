use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use vortex_core::{
    ActionEvidenceRecord, ActionRequest, ExecutorReceipt, GatewayReceipt,
    MmrConsistencyProof, PolicyDecision, Result, SignedCheckpoint, VortexError,
};

use crate::partition::{AppendResult, PartitionLog};

/// Pluggable policy engine for tool-call authorization.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(&self, agent_id: &str, tool_name: &str, raw_args: &[u8]) -> PolicyDecision;
}

/// A default rule-based policy engine allowing/blocking tools.
pub struct SimplePolicyEngine {
    pub policy_version: String,
    pub blocked_tools: Vec<String>,
}

impl SimplePolicyEngine {
    pub fn new(policy_version: &str, blocked_tools: Vec<String>) -> Self {
        Self {
            policy_version: policy_version.to_string(),
            blocked_tools,
        }
    }
}

impl PolicyEngine for SimplePolicyEngine {
    fn evaluate(&self, _agent_id: &str, tool_name: &str, _raw_args: &[u8]) -> PolicyDecision {
        let action_id = format!("act-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        if self.blocked_tools.iter().any(|b| b == tool_name) {
            PolicyDecision::new(
                action_id,
                self.policy_version.clone(),
                false,
                format!("Tool '{}' is blocked by security policy", tool_name),
            )
        } else {
            PolicyDecision::new(
                action_id,
                self.policy_version.clone(),
                true,
                "Policy allowed execution".to_string(),
            )
        }
    }
}

/// Gateway write path managing agent action logging, policy enforcement,
/// receipts emission, and signed checkpoint generation.
pub struct ActionGateway {
    pub partition: PartitionLog,
    pub gateway_key: SigningKey,
    pub policy_engine: Box<dyn PolicyEngine>,
    pub receipts_path: PathBuf,
    pub checkpoints_path: PathBuf,
    pub checkpoint_seq: u64,
}

impl ActionGateway {
    pub fn new(
        partition: PartitionLog,
        gateway_key: SigningKey,
        policy_engine: Box<dyn PolicyEngine>,
        receipts_path: PathBuf,
        checkpoints_path: PathBuf,
    ) -> Self {
        Self {
            partition,
            gateway_key,
            policy_engine,
            receipts_path,
            checkpoints_path,
            checkpoint_seq: 0,
        }
    }

    pub fn gateway_pubkey(&self) -> [u8; 32] {
        self.gateway_key.verifying_key().to_bytes()
    }

    /// Appends a receipt to the receipts.jsonl file.
    fn append_receipt_json<T: serde::Serialize>(&self, record: &T) -> Result<()> {
        if let Some(parent) = self.receipts_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VortexError::Io(e.to_string()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.receipts_path)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let line = serde_json::to_string(record).map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?;
        writeln!(file, "{}", line).map_err(|e| VortexError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| VortexError::Io(e.to_string()))?;
        Ok(())
    }

    /// Appends a checkpoint to the checkpoints.jsonl file.
    fn append_checkpoint_json(&self, checkpoint: &SignedCheckpoint) -> Result<()> {
        if let Some(parent) = self.checkpoints_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VortexError::Io(e.to_string()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.checkpoints_path)
            .map_err(|e| VortexError::Io(e.to_string()))?;

        let line = serde_json::to_string(checkpoint).map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?;
        writeln!(file, "{}", line).map_err(|e| VortexError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| VortexError::Io(e.to_string()))?;
        Ok(())
    }

    /// Evaluates policy for an incoming agent request, writes both the request commitment
    /// and policy decision to the immutable hash-chained log, and emits a signed GatewayReceipt.
    pub fn record_action_request(
        &mut self,
        agent_id: &str,
        tool_name: &str,
        action_id: &str,
        raw_args: &[u8],
    ) -> Result<(GatewayReceipt, PolicyDecision)> {
        let req = ActionRequest::new(
            agent_id.to_string(),
            tool_name.to_string(),
            action_id.to_string(),
            raw_args,
        );

        let mut policy = self.policy_engine.evaluate(agent_id, tool_name, raw_args);
        policy.action_id = action_id.to_string();

        // 1. Stage 1: Commit Request to append-only log
        let req_entry = ActionEvidenceRecord::Request(req.clone());
        let req_bytes = Bytes::from(serde_json::to_vec(&req_entry).map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?);
        let req_append = self.partition.append_authenticated(Some(Bytes::from(action_id.as_bytes().to_vec())), req_bytes)?;

        // 2. Stage 2: Commit Policy Decision to append-only log
        let policy_entry = ActionEvidenceRecord::Policy(policy.clone());
        let policy_bytes = Bytes::from(serde_json::to_vec(&policy_entry).map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?);
        self.partition.append_authenticated(Some(Bytes::from(action_id.as_bytes().to_vec())), policy_bytes)?;

        // 3. Issue signed GatewayReceipt
        let receipt = GatewayReceipt::sign(
            action_id.to_string(),
            req_append.record.offset,
            req.args_commitment,
            policy.allowed,
            &self.gateway_key,
        );

        // 4. Save to receipts.jsonl
        self.append_receipt_json(&receipt)?;

        Ok((receipt, policy))
    }

    /// Ingests a signed ExecutorReceipt from the tool executor, verifies its cryptographic
    /// signature, and appends it to the immutable hash-chained log.
    pub fn record_executor_receipt(&mut self, receipt: ExecutorReceipt) -> Result<AppendResult> {
        if !receipt.verify() {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Executor receipt for action '{}' has an invalid signature",
                    receipt.action_id
                ),
            });
        }

        // Commit Executor Receipt to log
        let exec_entry = ActionEvidenceRecord::Executor(receipt.clone());
        let exec_bytes = Bytes::from(serde_json::to_vec(&exec_entry).map_err(|e| VortexError::InvalidRecordFormat(e.to_string()))?);
        let append_res = self.partition.append_authenticated(
            Some(Bytes::from(receipt.action_id.as_bytes().to_vec())),
            exec_bytes,
        )?;

        // Save to receipts.jsonl
        self.append_receipt_json(&receipt)?;

        Ok(append_res)
    }

    /// Emits a signed checkpoint covering the current MMR tree size and root.
    pub fn emit_checkpoint(&mut self) -> Result<SignedCheckpoint> {
        let tree_size = self.partition.active_tree_size();
        let mmr_root = self.partition.active_mmr_root();

        let checkpoint = SignedCheckpoint::sign(
            self.checkpoint_seq,
            tree_size,
            mmr_root,
            &self.gateway_key,
        );

        self.checkpoint_seq += 1;

        // Save to checkpoints.jsonl
        self.append_checkpoint_json(&checkpoint)?;

        Ok(checkpoint)
    }

    /// Exposes MMR consistency proof generation for witnesses.
    pub fn get_consistency_proof(&self, old_size: u64) -> Result<MmrConsistencyProof> {
        self.partition
            .generate_consistency_proof(old_size)
            .ok_or_else(|| {
                VortexError::Io(format!(
                    "Unable to generate consistency proof from size {} to current size {}",
                    old_size,
                    self.partition.active_tree_size()
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vortex_core::generate_signing_key;

    #[test]
    fn test_gateway_lifecycle_and_executor_receipt_ingest() {
        let dir = tempdir().unwrap();
        let part_dir = dir.path().join("storage");
        let partition = PartitionLog::open_or_create(&part_dir, "agent-audit", 0, 1024 * 1024).unwrap();

        let gw_key = generate_signing_key();
        let exec_key = generate_signing_key();

        let receipts_path = dir.path().join("receipts.jsonl");
        let checkpoints_path = dir.path().join("checkpoints.jsonl");

        let policy = SimplePolicyEngine::new("v1.0", vec!["rm_rf".to_string()]);
        let mut gateway = ActionGateway::new(
            partition,
            gw_key,
            Box::new(policy),
            receipts_path.clone(),
            checkpoints_path.clone(),
        );

        // 1. Allowed tool request
        let (rcpt1, pol1) = gateway
            .record_action_request("agent-alice", "create_file", "act-001", b"{\"path\": \"test.txt\"}")
            .unwrap();
        assert!(pol1.allowed);
        assert!(rcpt1.verify());
        assert_eq!(rcpt1.action_id, "act-001");

        // 2. Tool execution by executor
        let exec_rcpt = ExecutorReceipt::sign(
            "act-001".to_string(),
            rcpt1.sequence_number,
            b"{\"bytes_written\": 120}",
            true,
            &exec_key,
        );
        let append_res = gateway.record_executor_receipt(exec_rcpt).unwrap();
        assert!(append_res.record.offset > rcpt1.sequence_number);

        // 3. Blocked tool request
        let (rcpt2, pol2) = gateway
            .record_action_request("agent-alice", "rm_rf", "act-002", b"{\"path\": \"/\"}")
            .unwrap();
        assert!(!pol2.allowed);
        assert!(rcpt2.verify());
        assert!(!rcpt2.policy_allowed);

        // 4. Emit checkpoint
        let ckpt = gateway.emit_checkpoint().unwrap();
        assert!(ckpt.verify());
        assert_eq!(ckpt.checkpoint_seq, 0);
        assert!(ckpt.tree_size > 0);

        // 5. Negative test: Executor receipt with invalid signature must be rejected
        let mut forged_exec = ExecutorReceipt::sign(
            "act-003".to_string(),
            99,
            b"result",
            true,
            &exec_key,
        );
        forged_exec.success = false; // tampered payload without re-signing
        assert!(gateway.record_executor_receipt(forged_exec).is_err());
    }
}
