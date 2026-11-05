use vortex_core::{ActionEvidenceRecord, CausalActionRequest, HashDigest};

#[test]
fn test_causal_dag_multi_parent_lineage_and_tamper_proofing() {
    // 1. Planner Agent issues initial research task
    let root_action = CausalActionRequest::new(
        "planner-agent".to_string(),
        "plan_architecture".to_string(),
        "act-root-001".to_string(),
        vec![], // Root has no parents
        b"{\"objective\": \"Build high-performance streaming engine\"}",
    );
    let root_hash = root_action.compute_causal_node_hash();

    // 2. Three parallel subagents spawned by planner:
    // Subagent 1: Storage engine researcher
    let subagent1_action = CausalActionRequest::new(
        "subagent-storage".to_string(),
        "benchmark_nvme_fsync".to_string(),
        "act-sub-001".to_string(),
        vec![root_hash], // Depends on planner root
        b"{\"benchmark\": \"NVMe 11ms physical flush delay\"}",
    );
    let sub1_hash = subagent1_action.compute_causal_node_hash();

    // Subagent 2: Crypto hashing researcher
    let subagent2_action = CausalActionRequest::new(
        "subagent-crypto".to_string(),
        "profile_simd_blake3".to_string(),
        "act-sub-002".to_string(),
        vec![root_hash], // Depends on planner root
        b"{\"algorithm\": \"Blake3 SIMD multi-threaded tree hashing\"}",
    );
    let sub2_hash = subagent2_action.compute_causal_node_hash();

    // Subagent 3: Guardrail researcher
    let subagent3_action = CausalActionRequest::new(
        "subagent-guard".to_string(),
        "scan_adversarial_tokens".to_string(),
        "act-sub-003".to_string(),
        vec![root_hash], // Depends on planner root
        b"{\"tokens\": \"ChatML prompt injection barriers\"}",
    );
    let sub3_hash = subagent3_action.compute_causal_node_hash();

    // 3. Synthesis Agent aggregates results from ALL THREE subagents (Multi-Parent Causal Merge)
    let synthesis_action = CausalActionRequest::new(
        "synthesis-agent".to_string(),
        "merge_architecture_spec".to_string(),
        "act-synth-001".to_string(),
        vec![sub1_hash, sub2_hash, sub3_hash], // 3 causal parent dependencies!
        b"{\"verdict\": \"Architecture locked and verified\"}",
    );
    let synth_hash = synthesis_action.compute_causal_node_hash();

    assert_eq!(synthesis_action.parent_action_hashes.len(), 3);
    assert_ne!(synth_hash, [0u8; 32]);
    assert_ne!(synth_hash, root_hash);

    // 4. Mathematical Tamper Proof: Corrupting ANY single parent hash MUST change the node hash
    let mut tampered_parents = vec![sub1_hash, sub2_hash, sub3_hash];
    tampered_parents[1][0] ^= 0xFF; // Invert byte in subagent 2's hash

    let tampered_synthesis = CausalActionRequest::new(
        "synthesis-agent".to_string(),
        "merge_architecture_spec".to_string(),
        "act-synth-001".to_string(),
        tampered_parents,
        b"{\"verdict\": \"Architecture locked and verified\"}",
    );
    let tampered_hash = tampered_synthesis.compute_causal_node_hash();

    assert_ne!(
        synth_hash, tampered_hash,
        "Tampering with an upstream subagent parent must invalidate the synthesis causal hash"
    );

    // 5. Serde JSON serialization & deserialization roundtrip
    let record = ActionEvidenceRecord::CausalRequest(synthesis_action.clone());
    let serialized = serde_json::to_vec(&record).unwrap();
    let deserialized: ActionEvidenceRecord = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn test_causal_dag_matrix_120_topologies() {
    let mut current_parents: Vec<HashDigest> = Vec::new();

    // Test DAG progression across 120 chained multi-agent transitions
    for step in 0..120 {
        let action = CausalActionRequest::new(
            format!("agent-worker-{:03}", step % 10),
            format!("tool_step_{}", step),
            format!("act-step-{:04}", step),
            current_parents.clone(),
            format!("{{\"step\": {}}}", step).as_bytes(),
        );

        let node_hash = action.compute_causal_node_hash();
        assert_ne!(node_hash, [0u8; 32]);

        // Next step takes the latest 2-3 hashes as parents
        current_parents.push(node_hash);
        if current_parents.len() > 3 {
            current_parents.remove(0);
        }
    }
}
