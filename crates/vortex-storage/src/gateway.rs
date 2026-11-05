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
    pub enable_ddl_guard: bool,
    pub enable_ssrf_guard: bool,
    pub enable_path_traversal_guard: bool,
}

impl SimplePolicyEngine {
    pub fn new(policy_version: &str, blocked_tools: Vec<String>) -> Self {
        Self {
            policy_version: policy_version.to_string(),
            blocked_tools,
            enable_ddl_guard: true,
            enable_ssrf_guard: true,
            enable_path_traversal_guard: true,
        }
    }
}

impl PolicyEngine for SimplePolicyEngine {
    fn evaluate(&self, _agent_id: &str, tool_name: &str, raw_args: &[u8]) -> PolicyDecision {
        let action_id = format!(
            "act-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // 1. Tool name blocklist
        if self.blocked_tools.iter().any(|b| b == tool_name) {
            return PolicyDecision::new(
                action_id,
                self.policy_version.clone(),
                false,
                format!("Tool '{}' is blocked by security policy", tool_name),
            );
        }

        let args_str = String::from_utf8_lossy(raw_args);
        let upper_args = args_str.to_uppercase();

        // 2. Semantic AST Taint: Destructive SQL DDL & privilege escalation blocker
        if self.enable_ddl_guard {
            const DESTRUCTIVE_KEYWORDS: &[&str] = &[
                "DROP TABLE",
                "DROP DATABASE",
                "DROP SCHEMA",
                "TRUNCATE TABLE",
                "TRUNCATE ",
                "ALTER TABLE",
                "GRANT ",
                "REVOKE ",
                ";--",
                "; --",
            ];

            for kw in DESTRUCTIVE_KEYWORDS {
                if upper_args.contains(kw) {
                    return PolicyDecision::new(
                        action_id,
                        self.policy_version.clone(),
                        false,
                        format!(
                            "Semantic AST taint: Destructive DDL / privilege escalation keyword '{}' blocked",
                            kw
                        ),
                    );
                }
            }
        }

        // 3. SSRF barrier: Block AWS/GCP/Alibaba cloud metadata, private IPs, and local loopbacks
        if self.enable_ssrf_guard {
            const SSRF_PATTERNS: &[&str] = &[
                "169.254.169.254",          // AWS / GCP / Azure metadata endpoint
                "metadata.google.internal", // GCP metadata DNS
                "100.100.100.200",          // Alibaba Cloud metadata endpoint
                "localhost",
                "127.0.0.1",
                "::1",
                "file://",                  // Local file protocol scheme
            ];

            for pattern in SSRF_PATTERNS {
                if upper_args.contains(&pattern.to_uppercase()) {
                    return PolicyDecision::new(
                        action_id,
                        self.policy_version.clone(),
                        false,
                        format!("SSRF barrier: Restricted endpoint or scheme '{}' blocked", pattern),
                    );
                }
            }

            // Private RFC 1918 subnets: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
            if upper_args.contains("://10.")
                || upper_args.contains("://192.168.")
                || (16..=31).any(|octet| upper_args.contains(&format!("://172.{}.", octet)))
            {
                return PolicyDecision::new(
                    action_id,
                    self.policy_version.clone(),
                    false,
                    "SSRF barrier: Private RFC 1918 subnet access blocked".to_string(),
                );
            }
        }

        // 4. Path traversal protection for file tools
        if self.enable_path_traversal_guard {
            const TRAVERSAL_PATTERNS: &[&str] = &[
                "../",
                "..\\",
                "/etc/passwd",
                "/etc/shadow",
                "/.ssh/",
                "/proc/self/",
            ];

            for pattern in TRAVERSAL_PATTERNS {
                if upper_args.contains(&pattern.to_uppercase()) {
                    return PolicyDecision::new(
                        action_id,
                        self.policy_version.clone(),
                        false,
                        format!("Path traversal barrier: Suspicious pattern '{}' blocked", pattern),
                    );
                }
            }
        }

        PolicyDecision::new(
            action_id,
            self.policy_version.clone(),
            true,
            "Policy allowed execution".to_string(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct AgentBudgetConfig {
    pub max_ops_per_second: u32,
    pub max_burst_ops: u32,
    pub total_gas_limit: Option<u64>,
}

impl Default for AgentBudgetConfig {
    fn default() -> Self {
        Self {
            max_ops_per_second: 50,
            max_burst_ops: 100,
            total_gas_limit: Some(1_000_000),
        }
    }
}

pub struct AgentBudgetGovernor {
    pub default_config: AgentBudgetConfig,
    agent_states: std::sync::Mutex<std::collections::HashMap<String, AgentBudgetState>>,
}

struct AgentBudgetState {
    tokens: f64,
    last_update_ns: u64,
    consumed_gas: u64,
    config: AgentBudgetConfig,
}

impl Default for AgentBudgetGovernor {
    fn default() -> Self {
        Self::new(AgentBudgetConfig::default())
    }
}

impl AgentBudgetGovernor {
    pub fn new(default_config: AgentBudgetConfig) -> Self {
        Self {
            default_config,
            agent_states: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn set_agent_config(&mut self, agent_id: &str, config: AgentBudgetConfig) {
        let mut states = self.agent_states.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let burst = config.max_burst_ops as f64;
        states.insert(
            agent_id.to_string(),
            AgentBudgetState {
                tokens: burst,
                last_update_ns: now,
                consumed_gas: 0,
                config,
            },
        );
    }

    pub fn consume(&mut self, agent_id: &str, gas_cost: u64) -> Result<()> {
        let mut states = self.agent_states.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let default_cfg = self.default_config.clone();
        let state = states.entry(agent_id.to_string()).or_insert_with(|| {
            let burst = default_cfg.max_burst_ops as f64;
            AgentBudgetState {
                tokens: burst,
                last_update_ns: now,
                consumed_gas: 0,
                config: default_cfg,
            }
        });

        // 1. Replenish tokens based on elapsed time
        let elapsed_sec = (now.saturating_sub(state.last_update_ns) as f64) / 1_000_000_000.0;
        state.last_update_ns = now;
        state.tokens = (state.tokens + elapsed_sec * (state.config.max_ops_per_second as f64))
            .min(state.config.max_burst_ops as f64);

        // 2. Check rate limit tokens
        if state.tokens < 1.0 {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Rate limit exceeded for agent '{}': rate ceiling {} ops/s",
                    agent_id, state.config.max_ops_per_second
                ),
            });
        }

        // 3. Check cumulative gas limit
        if let Some(limit) = state.config.total_gas_limit {
            if state.consumed_gas.saturating_add(gas_cost) > limit {
                return Err(VortexError::SecurityViolation {
                    reason: format!(
                        "Gas budget exhausted for agent '{}': limit {}, attempted {}",
                        agent_id, limit, state.consumed_gas + gas_cost
                    ),
                });
            }
        }

        state.tokens -= 1.0;
        state.consumed_gas += gas_cost;
        Ok(())
    }
}

/// Gateway write path managing agent action logging, policy enforcement,
/// receipts emission, and signed checkpoint generation.
pub struct ActionGateway {
    pub partition: PartitionLog,
    pub gateway_key: SigningKey,
    pub policy_engine: Box<dyn PolicyEngine>,
    pub budget_governor: AgentBudgetGovernor,
    pub receipts_path: PathBuf,
    pub checkpoints_path: PathBuf,
    pub checkpoint_seq: u64,
    pub last_seen_seqs: std::collections::HashMap<String, u64>,
    pub seen_action_ids: std::collections::HashSet<String>,
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
            budget_governor: AgentBudgetGovernor::default(),
            receipts_path,
            checkpoints_path,
            checkpoint_seq: 0,
            last_seen_seqs: std::collections::HashMap::new(),
            seen_action_ids: std::collections::HashSet::new(),
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
    /// Replay protection: Rejects duplicate action_ids.
    pub fn record_action_request(
        &mut self,
        agent_id: &str,
        tool_name: &str,
        action_id: &str,
        raw_args: &[u8],
    ) -> Result<(GatewayReceipt, PolicyDecision)> {
        if self.seen_action_ids.contains(action_id) {
            return Err(VortexError::SecurityViolation {
                reason: format!("Replay attack detected: action_id '{}' already processed", action_id),
            });
        }
        self.seen_action_ids.insert(action_id.to_string());
        self.record_action_request_internal(agent_id, tool_name, action_id, raw_args)
    }

    /// Records an agent action with monotonic sequence verification and optional deadline fencing.
    /// Rejects out-of-order dispatches, replays, and expired intents.
    pub fn record_action_request_with_seq(
        &mut self,
        agent_id: &str,
        tool_name: &str,
        action_id: &str,
        raw_args: &[u8],
        agent_seq: u64,
        deadline_utc_ns: Option<u64>,
    ) -> Result<(GatewayReceipt, PolicyDecision)> {
        if self.seen_action_ids.contains(action_id) {
            return Err(VortexError::SecurityViolation {
                reason: format!("Replay attack detected: action_id '{}' already processed", action_id),
            });
        }

        if let Some(&last_seq) = self.last_seen_seqs.get(agent_id) {
            if agent_seq <= last_seq {
                return Err(VortexError::SecurityViolation {
                    reason: format!(
                        "Agent sequence violation for '{}': incoming seq {} <= last seen seq {}",
                        agent_id, agent_seq, last_seq
                    ),
                });
            }
        }

        if let Some(deadline) = deadline_utc_ns {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            if now > deadline {
                return Err(VortexError::SecurityViolation {
                    reason: format!("Action expired: current time {} > deadline {}", now, deadline),
                });
            }
        }

        self.last_seen_seqs.insert(agent_id.to_string(), agent_seq);
        self.seen_action_ids.insert(action_id.to_string());
        self.record_action_request_internal(agent_id, tool_name, action_id, raw_args)
    }

    fn record_action_request_internal(
        &mut self,
        agent_id: &str,
        tool_name: &str,
        action_id: &str,
        raw_args: &[u8],
    ) -> Result<(GatewayReceipt, PolicyDecision)> {
        // Enforce rate limiter and gas budget governor
        let gas_cost = (raw_args.len() as u64).max(10);
        self.budget_governor.consume(agent_id, gas_cost)?;

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
