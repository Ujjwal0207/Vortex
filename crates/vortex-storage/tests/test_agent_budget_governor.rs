use ed25519_dalek::SigningKey;
use tempfile::tempdir;
use vortex_core::VortexError;
use vortex_storage::gateway::{ActionGateway, AgentBudgetConfig, AgentBudgetGovernor, SimplePolicyEngine};
use vortex_storage::PartitionLog;

#[test]
fn test_agent_budget_governor_rate_limit_and_gas_exhaustion() {
    let mut governor = AgentBudgetGovernor::new(AgentBudgetConfig {
        max_ops_per_second: 10,
        max_burst_ops: 10,
        total_gas_limit: Some(500),
    });

    let agent_id = "agent-fin-007";

    // 1. Consume 10 operations (burst capacity)
    for i in 0..10 {
        assert!(
            governor.consume(agent_id, 20).is_ok(),
            "Burst op #{} should succeed",
            i
        );
    }

    // 2. 11th operation immediately in the same second must fail with rate limit
    let err = governor.consume(agent_id, 20).unwrap_err();
    match err {
        VortexError::SecurityViolation { reason } => {
            assert!(
                reason.contains("Rate limit exceeded"),
                "Expected rate limit violation, got: {}",
                reason
            );
        }
        other => panic!("Expected SecurityViolation, got {:?}", other),
    }

    // 3. Test gas limit exhaustion on another agent
    let heavy_agent = "agent-heavy-batch";
    governor.set_agent_config(
        heavy_agent,
        AgentBudgetConfig {
            max_ops_per_second: 1000,
            max_burst_ops: 1000,
            total_gas_limit: Some(150),
        },
    );

    // Consume 100 gas
    assert!(governor.consume(heavy_agent, 100).is_ok());
    // Attempt to consume 60 gas (100 + 60 = 160 > 150)
    let err = governor.consume(heavy_agent, 60).unwrap_err();
    match err {
        VortexError::SecurityViolation { reason } => {
            assert!(
                reason.contains("Gas budget exhausted"),
                "Expected gas exhaustion violation, got: {}",
                reason
            );
        }
        other => panic!("Expected SecurityViolation, got {:?}", other),
    }
}

#[test]
fn test_action_gateway_governor_denial_of_wallet_shield() {
    let dir = tempdir().unwrap();
    let partition = PartitionLog::open_or_create(dir.path(), "agent-actions", 0, 1024 * 1024).unwrap();
    let gateway_key = SigningKey::from_bytes(&[0x42; 32]);
    let policy = Box::new(SimplePolicyEngine::new("v1.0", vec![]));
    let receipts_path = dir.path().join("receipts.jsonl");
    let checkpoints_path = dir.path().join("checkpoints.jsonl");

    let mut gateway = ActionGateway::new(
        partition,
        gateway_key,
        policy,
        receipts_path,
        checkpoints_path,
    );

    let rogue_agent = "agent-rogue-loop-01";
    // Configure tight budget: 1 op/s, 5 burst, total gas limit 200
    gateway.budget_governor.set_agent_config(
        rogue_agent,
        AgentBudgetConfig {
            max_ops_per_second: 1,
            max_burst_ops: 5,
            total_gas_limit: Some(200),
        },
    );

    // Run 5 legitimate burst actions
    for i in 0..5 {
        let action_id = format!("act-valid-{}", i);
        let res = gateway.record_action_request(
            rogue_agent,
            "read_database",
            &action_id,
            b"{\"query\":\"SELECT 1\"}",
        );
        assert!(res.is_ok(), "Action #{} should be allowed", i);
    }

    // 6th rapid request in loop must be rejected before disk persistence
    let rogue_action_id = "act-rogue-6";
    let rogue_res = gateway.record_action_request(
        rogue_agent,
        "read_database",
        rogue_action_id,
        b"{\"query\":\"SELECT 1\"}",
    );

    assert!(rogue_res.is_err());
    let err = rogue_res.unwrap_err();
    assert!(matches!(err, VortexError::SecurityViolation { .. }));
}

#[test]
fn test_agent_budget_governor_over_120_edge_cases() {
    let mut governor = AgentBudgetGovernor::default();

    // Test 120 different agent parameter scenarios
    for a in 0..120 {
        let agent_name = format!("agent-matrix-{:03}", a);
        let max_rate = (a % 20 + 1) as u32;
        let gas_cap = ((a + 1) * 50) as u64;

        governor.set_agent_config(
            &agent_name,
            AgentBudgetConfig {
                max_ops_per_second: max_rate,
                max_burst_ops: max_rate,
                total_gas_limit: Some(gas_cap),
            },
        );

        // First consume must always succeed if gas_cost <= gas_cap
        let first_res = governor.consume(&agent_name, gas_cap / 2);
        assert!(first_res.is_ok());

        // Attempting to consume exceeding remaining gas must fail
        let overflow_res = governor.consume(&agent_name, gas_cap);
        assert!(overflow_res.is_err());
    }
}
