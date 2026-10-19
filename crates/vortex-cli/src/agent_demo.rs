use std::fs;
use std::path::Path;

use vortex_core::{generate_signing_key, ExecutorReceipt};
use vortex_storage::{
    ActionGateway, IndependentWitness, OfflineVerifier, PartitionLog, SimplePolicyEngine,
};

pub fn run_agent_evidence_demo(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n===============================================================================");
    println!("        VORTEX AUTONOMOUS ACTION VERIFIABLE EVIDENCE PIPELINE DEMO");
    println!("===============================================================================\n");

    let base_dir = output_dir.join("vortex_data");
    let receipts_path = output_dir.join("receipts.jsonl");
    let checkpoints_path = output_dir.join("checkpoints.jsonl");
    let witness_state_path = output_dir.join("witness_state.json");
    let witness_reel_path = output_dir.join("reel.wit");
    let court_bundle_dir = output_dir.join("court_bundle");

    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(&base_dir)?;

    // 1. Generate cryptographic keys
    println!("🔑 1. Initializing Cryptographic Identities & Escrowed Genesis Seed...");
    let mut genesis_seed = [0u8; 32];
    getrandom::getrandom(&mut genesis_seed).map_err(|e| format!("CSPRNG error: {e}"))?;

    let gw_key = generate_signing_key();
    let gw_pubkey = gw_key.verifying_key().to_bytes();
    println!("   • Gateway Ed25519 Pubkey: 0x{}", hex::encode(gw_pubkey));

    let exec_key = generate_signing_key();
    let exec_pubkey = exec_key.verifying_key().to_bytes();
    println!("   • Executor Ed25519 Pubkey: 0x{}", hex::encode(exec_pubkey));

    let wit_key = generate_signing_key();
    let wit_pubkey = wit_key.verifying_key().to_bytes();
    println!("   • Witness Ed25519 Pubkey: 0x{}", hex::encode(wit_pubkey));

    // 2. Initialize Gateway with Policy Engine
    println!("\n🛡️ 2. Starting Agent-Action Gateway with Security Policy (Sentinel v1.0)...");
    let partition = PartitionLog::open_or_create_with_seed(
        &base_dir,
        "agent-audit",
        0,
        1024 * 1024,
        genesis_seed,
    )?;

    let blocked_tools = vec![
        "delete_production_database".to_string(),
        "exfiltrate_keys".to_string(),
    ];
    let policy = SimplePolicyEngine::new("sentinel-v1.0", blocked_tools);

    let mut gateway = ActionGateway::new(
        partition,
        gw_key,
        Box::new(policy),
        receipts_path.clone(),
        checkpoints_path.clone(),
    );

    // 3. Initialize Independent Witness
    println!("\n👁️ 3. Initializing Independent Witness (RFC 9162 Monotonic Ledger)...");
    let mut witness = IndependentWitness::open_or_create(
        wit_key,
        witness_state_path,
        witness_reel_path.clone(),
    )?;

    // 4. Simulate 10 Agent Actions
    println!("\n⚡ 4. Routing 10 Autonomous Agent Tool Calls through Gateway Boundary...");

    struct SimulatedAction {
        action_id: &'static str,
        agent_id: &'static str,
        tool_name: &'static str,
        args: &'static [u8],
        executor_result: Option<&'static [u8]>,
    }

    let actions = vec![
        SimulatedAction {
            action_id: "act-001",
            agent_id: "finance-agent",
            tool_name: "transfer_funds",
            args: b"{\"recipient\": \"treasury\", \"amount_usd\": 50000}",
            executor_result: Some(b"{\"status\": \"executed\", \"tx_hash\": \"0x8f2d...\"}"),
        },
        SimulatedAction {
            action_id: "act-002",
            agent_id: "rogue-agent",
            tool_name: "delete_production_database",
            args: b"{\"database\": \"customers_prod\", \"force\": true}",
            executor_result: None, // Will be blocked by policy
        },
        SimulatedAction {
            action_id: "act-003",
            agent_id: "k8s-operator",
            tool_name: "deploy_container",
            args: b"{\"image\": \"vortex-broker:v2\", \"replicas\": 3}",
            executor_result: Some(b"{\"deployment_id\": \"d-8812\", \"status\": \"healthy\"}"),
        },
        SimulatedAction {
            action_id: "act-004",
            agent_id: "data-pipeline",
            tool_name: "ingest_telemetry",
            args: b"{\"stream\": \"sensor_feed\", \"records\": 10000}",
            executor_result: Some(b"{\"accepted\": 10000, \"dropped\": 0}"),
        },
        SimulatedAction {
            action_id: "act-005",
            agent_id: "untrusted-plugin",
            tool_name: "exfiltrate_keys",
            args: b"{\"dest\": \"https://pastebin.com/raw\"}",
            executor_result: None, // Will be blocked by policy
        },
        SimulatedAction {
            action_id: "act-006",
            agent_id: "secops-bot",
            tool_name: "rotate_tls_cert",
            args: b"{\"domain\": \"api.vortex.internal\"}",
            executor_result: Some(b"{\"fingerprint\": \"sha256:d9a4...\", \"valid_days\": 90}"),
        },
        SimulatedAction {
            action_id: "act-007",
            agent_id: "flaky-agent",
            tool_name: "call_external_webhook",
            args: b"{\"url\": \"https://slow-external-service.com/hook\"}",
            executor_result: None, // Unfulfilled tool call: Executor timed out / crashed!
        },
        SimulatedAction {
            action_id: "act-008",
            agent_id: "storage-janitor",
            tool_name: "prune_temp_files",
            args: b"{\"older_than\": \"7d\", \"dir\": \"/tmp/scratch\"}",
            executor_result: Some(b"{\"reclaimed_bytes\": 4294967296}"),
        },
        SimulatedAction {
            action_id: "act-009",
            agent_id: "analytics-agent",
            tool_name: "build_daily_report",
            args: b"{\"date\": \"2026-10-19\", \"format\": \"pdf\"}",
            executor_result: Some(b"{\"report_id\": \"rep-994\", \"pages\": 14}"),
        },
        SimulatedAction {
            action_id: "act-010",
            agent_id: "monitor-agent",
            tool_name: "assert_latency_sla",
            args: b"{\"sla_ms\": 5.0, \"window\": \"1h\"}",
            executor_result: Some(b"{\"p99_latency_ms\": 2.14, \"sla_met\": true}"),
        },
    ];

    for (idx, sim) in actions.iter().enumerate() {
        print!("   [{:>2}/10] Action {:<7} | Agent: {:<15} | Tool: {:<27} -> ", idx + 1, sim.action_id, sim.agent_id, sim.tool_name);
        let (gw_receipt, pol_decision) = gateway.record_action_request(
            sim.agent_id,
            sim.tool_name,
            sim.action_id,
            sim.args,
        )?;

        if pol_decision.allowed {
            if let Some(res_bytes) = sim.executor_result {
                let exec_receipt = ExecutorReceipt::sign(
                    sim.action_id.to_string(),
                    gw_receipt.sequence_number,
                    res_bytes,
                    true,
                    &exec_key,
                );
                gateway.record_executor_receipt(exec_receipt)?;
                println!("Allowed & Executed (Seq {}) ✅", gw_receipt.sequence_number);
            } else {
                println!("Allowed, but Tool Severed/Timed Out (Seq {}) ⚠️", gw_receipt.sequence_number);
            }
        } else {
            println!("BLOCKED by Sentinel Policy ❌");
        }

        // Emit intermediate checkpoint at action 5
        if idx == 4 {
            let intermediate_ckpt = gateway.emit_checkpoint()?;
            witness.verify_and_countersign(&intermediate_ckpt, None)?;
        }
    }

    // 5. Final checkpoint & Witness verification with consistency proof
    println!("\n🏛️ 5. Emitting Final Gateway Checkpoint & Performing Witness Consistency Audit...");
    let final_ckpt = gateway.emit_checkpoint()?;
    println!("   • Gateway Checkpoint: seq={}, tree_size={}, mmr_root=0x{}",
             final_ckpt.checkpoint_seq, final_ckpt.tree_size, &hex::encode(final_ckpt.mmr_root)[..16]);

    let consistency_proof = gateway.get_consistency_proof(witness.state.last_tree_size)?;
    println!("   • Generated MMR Consistency Proof: old_size={}, new_size={}, peak_proofs={}",
             consistency_proof.old_size, consistency_proof.new_size, consistency_proof.peak_proofs.len());

    let witness_countersig = witness.verify_and_countersign(&final_ckpt, Some(&consistency_proof))?;
    println!("   • Independent Witness VERIFIED consistency and countersigned into reel.wit ✅");
    println!("   • Witness Countersignature: 0x{}...", &witness_countersig.signature.to_hex()[..24]);

    // 6. Run Offline Verifier
    println!("\n🔍 6. Executing Zero-Trust Offline Verifier (No Daemons, No Network)...");
    let report = OfflineVerifier::verify(
        &base_dir,
        "agent-audit",
        0,
        Some(genesis_seed),
        &receipts_path,
        &witness_reel_path,
        gw_pubkey,
        wit_pubkey,
    )?;

    report.print_summary();

    // 7. Package Court Bundle
    println!("📦 7. Packaging Offline Court Bundle into '{:?}'...", court_bundle_dir);
    fs::create_dir_all(&court_bundle_dir)?;

    // Copy partition directory
    let part_source = base_dir.join("agent-audit").join("partition-0");
    let part_dest = court_bundle_dir.join("agent-audit").join("partition-0");
    fs::create_dir_all(&part_dest)?;
    for entry in fs::read_dir(&part_source)? {
        let entry = entry?;
        fs::copy(entry.path(), part_dest.join(entry.file_name()))?;
    }

    // Copy receipts.jsonl and reel.wit
    fs::copy(&receipts_path, court_bundle_dir.join("receipts.jsonl"))?;
    fs::copy(&witness_reel_path, court_bundle_dir.join("reel.wit"))?;

    // Create pubkeys.toml
    let pubkeys_content = format!(
        "# Vortex Trusted Public Keys and Verification Parameters\n\
         [gateway]\n\
         pubkey = \"{}\"\n\
         algorithm = \"Ed25519\"\n\n\
         [witness]\n\
         pubkey = \"{}\"\n\
         algorithm = \"Ed25519\"\n\n\
         [escrow]\n\
         genesis_seed = \"{}\"\n",
        hex::encode(gw_pubkey),
        hex::encode(wit_pubkey),
        hex::encode(genesis_seed),
    );
    fs::write(court_bundle_dir.join("pubkeys.toml"), pubkeys_content)?;

    // Create AUDIT_README.md
    let readme_content = format!(
        "# Vortex Verifiable Evidence Court Bundle\n\n\
         ## Cryptographic Trust Boundary\n\
         This bundle contains offline-auditable evidence for autonomous AI agent actions.\n\n\
         - **Gateway Pubkey:** `{}`\n\
         - **Witness Pubkey:** `{}`\n\
         - **Topic / Partition:** `agent-audit:0`\n\n\
         ## Stated Guarantees\n\
         - **What is proven:** Every action routed through the gateway is recorded in an immutable Blake3 hash chain and committed to an MMR.\n\
         - **Completeness:** The monotonic sequence number and independent witness countersignatures prove that no intermediate action was silently deleted or truncated.\n\
         - **What is NOT proven:** Actions that bypassed the gateway entirely are invisible.\n\
         - **Non-repudiation:** The tool executor signed its own result commitment; the gateway cannot fabricate executor outcomes.\n\n\
         ## How to Verify Offline\n\
         ```bash\n\
         vortex-cli verify-evidence \\\n\
           --data-dir ./court_bundle \\\n\
           --receipts ./court_bundle/receipts.jsonl \\\n\
           --witness-reel ./court_bundle/reel.wit \\\n\
           --pubkeys ./court_bundle/pubkeys.toml\n\
         ```\n",
        hex::encode(gw_pubkey),
        hex::encode(wit_pubkey),
    );
    fs::write(court_bundle_dir.join("README.md"), readme_content)?;

    println!("   • Court bundle successfully exported with partition log, receipts, witness reel, pubkeys, and README.md ✅");
    println!("\n✨ Pipeline Demo Completed with 100% cryptographic integrity verified.\n");

    Ok(())
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
