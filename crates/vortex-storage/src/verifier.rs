use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use vortex_core::{
    ActionEvidenceRecord, ActionRequest, ActionVerdict, ExecutorReceipt, GatewayReceipt,
    PolicyDecision, Result, VortexError, WitnessCountersignature,
};

use crate::partition::PartitionLog;

/// Detailed summary report emitted by the offline verifier.
#[derive(Debug, Clone)]
pub struct EvidenceVerificationReport {
    pub topic: String,
    pub partition_id: u32,
    pub total_actions: usize,
    pub verified_count: usize,
    pub rejected_count: usize,
    pub incomplete_count: usize,
    pub verdicts: Vec<ActionVerdict>,
    pub log_integrity_valid: bool,
    pub ratchet_macs_valid: bool,
    pub witness_checkpoints_valid: bool,
    pub witnessed_tree_size: u64,
    pub gateway_pubkey: [u8; 32],
    pub witness_pubkey: [u8; 32],
}

impl EvidenceVerificationReport {
    pub fn print_summary(&self) {
        println!("===============================================================================");
        println!("               VORTEX OFFLINE EVIDENCE AUDIT REPORT");
        println!("===============================================================================");
        println!("Topic/Partition:      {}:{}", self.topic, self.partition_id);
        println!("Gateway Trust Root:   0x{}", hex::encode(self.gateway_pubkey));
        println!("Witness Trust Root:   0x{}", hex::encode(self.witness_pubkey));
        println!("Hash Chain Integrity: {}", if self.log_integrity_valid { "✅ VALID (Blake3 + CRC32)" } else { "❌ CORRUPTED" });
        println!("Forward Secrecy MACs: {}", if self.ratchet_macs_valid { "✅ VERIFIED (Ratchet replayed)" } else { "❌ FAILED" });
        println!("Witness Countersigns: {}", if self.witness_checkpoints_valid { "✅ MONOTONIC & SIGNED" } else { "❌ INVALID" });
        println!("Witnessed Tree Size:  {} entries", self.witnessed_tree_size);
        println!("-------------------------------------------------------------------------------");
        println!("ACTION VERDICTS ({} total):", self.total_actions);
        println!("  ✅ Verified:   {}", self.verified_count);
        println!("  ❌ Rejected:   {}", self.rejected_count);
        println!("  ⚠️ Incomplete: {}", self.incomplete_count);
        println!("-------------------------------------------------------------------------------");
        for v in &self.verdicts {
            match v {
                ActionVerdict::Verified { action_id, agent_id, tool_name, sequence_number, witness_checkpoint_seq } => {
                    println!("  [✅ VERIFIED] Action: {:<12} | Agent: {:<12} | Tool: {:<15} | Seq: {:<4} | WitCkpt: {}",
                             action_id, agent_id, tool_name, sequence_number, witness_checkpoint_seq);
                }
                ActionVerdict::Rejected { action_id, agent_id, tool_name, policy_version, reason } => {
                    println!("  [❌ REJECTED] Action: {:<12} | Agent: {:<12} | Tool: {:<15} | Policy: {} | Reason: {}",
                             action_id, agent_id, tool_name, policy_version, reason);
                }
                ActionVerdict::Incomplete { action_id, missing_stages, details } => {
                    println!("  [⚠️ INCOMPLETE] Action: {:<10} | Missing: {:?} | Details: {}",
                             action_id, missing_stages, details);
                }
            }
        }
        println!("===============================================================================");
    }
}

/// Offline Verifier that inspects the partition log, receipts, and witness reel without requiring
/// any active service or network connection.
pub struct OfflineVerifier;

impl OfflineVerifier {
    /// Conducts a comprehensive, zero-trust cryptographic audit across:
    /// 1. The append-only hash chain and ratchet MACs in the partition log.
    /// 2. The gateway and executor signatures in `receipts.jsonl`.
    /// 3. The independent witness countersignatures in `reel.wit`.
    pub fn verify(
        base_dir: &Path,
        topic: &str,
        partition_id: u32,
        genesis_seed: Option<[u8; 32]>,
        receipts_path: &Path,
        witness_reel_path: &Path,
        trusted_gateway_pubkey: [u8; 32],
        trusted_witness_pubkey: [u8; 32],
    ) -> Result<EvidenceVerificationReport> {
        // 1. Verify partition log hash-chain and forward-secure MACs
        let part_dir = base_dir.join(topic).join(format!("partition-{}", partition_id));
        let log_report = PartitionLog::verify_offline_with_seed(&part_dir, topic, partition_id, genesis_seed.as_ref())?;

        // 2. Open partition to read all records
        let log = PartitionLog::open_or_create(base_dir, topic, partition_id, 1024 * 1024 * 1024)?;

        // Read all records across segments
        let records = if log.next_offset() > 0 {
            log.read(0, 1024 * 1024 * 1024)?
        } else {
            Vec::new()
        };

        let mut requests: HashMap<String, ActionRequest> = HashMap::new();
        let mut policies: HashMap<String, PolicyDecision> = HashMap::new();
        let mut executors: HashMap<String, ExecutorReceipt> = HashMap::new();

        for rec in records {
            // Attempt to parse evidence JSON from record value
            if let Ok(entry) = serde_json::from_slice::<ActionEvidenceRecord>(&rec.value) {
                match entry {
                    ActionEvidenceRecord::Request(req) => {
                        requests.insert(req.action_id.clone(), req);
                    }
                    ActionEvidenceRecord::Policy(pol) => {
                        policies.insert(pol.action_id.clone(), pol);
                    }
                    ActionEvidenceRecord::Executor(exec) => {
                        executors.insert(exec.action_id.clone(), exec);
                    }
                    ActionEvidenceRecord::Checkpoint(_) => {}
                }
            }
        }

        // 3. Ingest and verify receipts.jsonl
        let mut gateway_receipts: HashMap<String, GatewayReceipt> = HashMap::new();
        if receipts_path.exists() {
            let file = File::open(receipts_path).map_err(|e| VortexError::Io(e.to_string()))?;
            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                let line = line_res.map_err(|e| VortexError::Io(e.to_string()))?;
                let clean = line.trim();
                if clean.is_empty() {
                    continue;
                }

                if let Ok(gw_receipt) = serde_json::from_str::<GatewayReceipt>(clean) {
                    if gw_receipt.gateway_pubkey == trusted_gateway_pubkey && gw_receipt.verify() {
                        gateway_receipts.insert(gw_receipt.action_id.clone(), gw_receipt);
                    }
                } else if let Ok(exec_receipt) = serde_json::from_str::<ExecutorReceipt>(clean) {
                    if exec_receipt.verify() {
                        executors.insert(exec_receipt.action_id.clone(), exec_receipt);
                    }
                }
            }
        }

        // 4. Ingest and verify witness reel (reel.wit)
        let mut witness_countersignatures: Vec<WitnessCountersignature> = Vec::new();
        let mut witness_checkpoints_valid = true;
        let mut max_witnessed_tree_size = 0u64;

        if witness_reel_path.exists() {
            let file = File::open(witness_reel_path).map_err(|e| VortexError::Io(e.to_string()))?;
            let reader = BufReader::new(file);
            let mut last_seq = None;
            let mut last_size = 0u64;

            for line_res in reader.lines() {
                let line = line_res.map_err(|e| VortexError::Io(e.to_string()))?;
                let clean = line.trim();
                if clean.is_empty() {
                    continue;
                }

                if let Ok(countersig) = serde_json::from_str::<WitnessCountersignature>(clean) {
                    if countersig.witness_pubkey != trusted_witness_pubkey || !countersig.verify() {
                        witness_checkpoints_valid = false;
                        continue;
                    }

                    if let Some(prev) = last_seq {
                        if countersig.checkpoint_seq <= prev {
                            witness_checkpoints_valid = false;
                        }
                    }
                    if countersig.tree_size < last_size {
                        witness_checkpoints_valid = false;
                    }

                    last_seq = Some(countersig.checkpoint_seq);
                    last_size = countersig.tree_size;
                    max_witnessed_tree_size = max_witnessed_tree_size.max(countersig.tree_size);
                    witness_countersignatures.push(countersig);
                }
            }
        } else {
            witness_checkpoints_valid = false;
        }

        // 5. Evaluate verdicts for each observed action
        let mut all_action_ids: Vec<String> = requests.keys().cloned().collect();
        // Also include actions only present in receipts
        for act in gateway_receipts.keys() {
            if !all_action_ids.contains(act) {
                all_action_ids.push(act.clone());
            }
        }
        all_action_ids.sort();

        let mut verdicts = Vec::new();
        let mut verified_count = 0;
        let mut rejected_count = 0;
        let mut incomplete_count = 0;

        for action_id in all_action_ids {
            let req = requests.get(&action_id);
            let pol = policies.get(&action_id);
            let gw_rcpt = gateway_receipts.get(&action_id);
            let exec_rcpt = executors.get(&action_id);

            // Check if Request exists
            let Some(req) = req else {
                verdicts.push(ActionVerdict::Incomplete {
                    action_id: action_id.clone(),
                    missing_stages: vec!["Stage 1: ActionRequest".to_string()],
                    details: "Request commitment absent from log".to_string(),
                });
                incomplete_count += 1;
                continue;
            };

            // Check Policy
            let Some(pol) = pol else {
                verdicts.push(ActionVerdict::Incomplete {
                    action_id: action_id.clone(),
                    missing_stages: vec!["Stage 2: PolicyDecision".to_string()],
                    details: "Policy decision absent from log".to_string(),
                });
                incomplete_count += 1;
                continue;
            };

            // Stage 2 check: Was the action rejected by policy?
            if !pol.allowed {
                verdicts.push(ActionVerdict::Rejected {
                    action_id: action_id.clone(),
                    agent_id: req.agent_id.clone(),
                    tool_name: req.tool_name.clone(),
                    policy_version: pol.policy_version.clone(),
                    reason: pol.reason.clone(),
                });
                rejected_count += 1;
                continue;
            }

            // For allowed actions, check GatewayReceipt
            let Some(gw_rcpt) = gw_rcpt else {
                verdicts.push(ActionVerdict::Incomplete {
                    action_id: action_id.clone(),
                    missing_stages: vec!["GatewayReceipt".to_string()],
                    details: "No signed gateway receipt found".to_string(),
                });
                incomplete_count += 1;
                continue;
            };

            // Stage 3 check: ExecutorReceipt
            let Some(_exec_rcpt) = exec_rcpt else {
                verdicts.push(ActionVerdict::Incomplete {
                    action_id: action_id.clone(),
                    missing_stages: vec!["Stage 3: ExecutorReceipt".to_string()],
                    details: "Tool call has no signed executor receipt (unfulfilled or severed)".to_string(),
                });
                incomplete_count += 1;
                continue;
            };

            // Stage 4 & 5 check: Is action offset witnessed?
            let is_witnessed = witness_countersignatures.iter().find(|w| w.tree_size > gw_rcpt.sequence_number);
            let Some(wit_ckpt) = is_witnessed else {
                verdicts.push(ActionVerdict::Incomplete {
                    action_id: action_id.clone(),
                    missing_stages: vec!["Stage 5: WitnessCountersignature".to_string()],
                    details: format!("Sequence {} is beyond highest witnessed tree size {}", gw_rcpt.sequence_number, max_witnessed_tree_size),
                });
                incomplete_count += 1;
                continue;
            };

            // All 5 stages present and verified!
            verdicts.push(ActionVerdict::Verified {
                action_id: action_id.clone(),
                agent_id: req.agent_id.clone(),
                tool_name: req.tool_name.clone(),
                sequence_number: gw_rcpt.sequence_number,
                witness_checkpoint_seq: wit_ckpt.checkpoint_seq,
            });
            verified_count += 1;
        }

        Ok(EvidenceVerificationReport {
            topic: topic.to_string(),
            partition_id,
            total_actions: verdicts.len(),
            verified_count,
            rejected_count,
            incomplete_count,
            verdicts,
            log_integrity_valid: log_report.is_valid,
            ratchet_macs_valid: log_report.macs_verified,
            witness_checkpoints_valid,
            witnessed_tree_size: max_witnessed_tree_size,
            gateway_pubkey: trusted_gateway_pubkey,
            witness_pubkey: trusted_witness_pubkey,
        })
    }
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vortex_core::generate_signing_key;
    use crate::gateway::{ActionGateway, SimplePolicyEngine};
    use crate::witness::IndependentWitness;

    #[test]
    fn test_full_offline_verification_pipeline_with_all_verdicts() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path().join("data");
        let receipts_path = dir.path().join("receipts.jsonl");
        let checkpoints_path = dir.path().join("checkpoints.jsonl");
        let witness_state_path = dir.path().join("witness_state.json");
        let witness_reel_path = dir.path().join("reel.wit");

        let gw_key = generate_signing_key();
        let gw_pubkey = gw_key.verifying_key().to_bytes();

        let exec_key = generate_signing_key();
        let wit_key = generate_signing_key();
        let wit_pubkey = wit_key.verifying_key().to_bytes();

        let genesis_seed = [42u8; 32];
        let partition = PartitionLog::open_or_create_with_seed(&base_dir, "agent-ops", 0, 1024 * 1024, genesis_seed).unwrap();
        let policy = SimplePolicyEngine::new("v1.0", vec!["delete_database".to_string()]);

        let mut gateway = ActionGateway::new(
            partition,
            gw_key,
            Box::new(policy),
            receipts_path.clone(),
            checkpoints_path.clone(),
        );

        let mut witness = IndependentWitness::open_or_create(
            wit_key,
            witness_state_path,
            witness_reel_path.clone(),
        ).unwrap();

        // Action 1: Allowed and completed by executor -> should be ✅ VERIFIED
        let (rcpt1, pol1) = gateway
            .record_action_request("trader-agent", "buy_asset", "act-101", b"{\"ticker\": \"BTC\", \"qty\": 1}")
            .unwrap();
        assert!(pol1.allowed);

        let exec_rcpt1 = ExecutorReceipt::sign(
            "act-101".to_string(),
            rcpt1.sequence_number,
            b"{\"order_id\": 998811}",
            true,
            &exec_key,
        );
        gateway.record_executor_receipt(exec_rcpt1).unwrap();

        // Action 2: Rejected by policy -> should be ❌ REJECTED
        let (_rcpt2, pol2) = gateway
            .record_action_request("bad-agent", "delete_database", "act-102", b"{\"target\": \"prod\"}")
            .unwrap();
        assert!(!pol2.allowed);

        // Action 3: Allowed, but executor NEVER completed it -> should be ⚠️ INCOMPLETE
        let (_rcpt3, pol3) = gateway
            .record_action_request("slow-agent", "fetch_remote", "act-103", b"{\"url\": \"http://hang.org\"}")
            .unwrap();
        assert!(pol3.allowed);

        // Emit checkpoint covering the actions so far
        let ckpt = gateway.emit_checkpoint().unwrap();

        // Witness verifies checkpoint & countersigns into reel.wit
        witness.verify_and_countersign(&ckpt, None).unwrap();

        // Run OfflineVerifier with the genesis seed to replay forward-secure ratchet
        let report = OfflineVerifier::verify(
            &base_dir,
            "agent-ops",
            0,
            Some(genesis_seed),
            &receipts_path,
            &witness_reel_path,
            gw_pubkey,
            wit_pubkey,
        ).unwrap();

        report.print_summary();

        assert_eq!(report.total_actions, 3);
        assert_eq!(report.verified_count, 1);
        assert_eq!(report.rejected_count, 1);
        assert_eq!(report.incomplete_count, 1);
        assert!(report.log_integrity_valid);
        assert!(report.ratchet_macs_valid);
        assert!(report.witness_checkpoints_valid);
    }
}
