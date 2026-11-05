use tempfile::tempdir;
use vortex_core::generate_signing_key;
use vortex_storage::gateway::{ActionGateway, SimplePolicyEngine};
use vortex_storage::PartitionLog;

#[test]
fn test_gateway_ast_taint_and_ssrf_blocking() {
    let dir = tempdir().unwrap();
    let part_dir = dir.path().join("storage");
    let partition = PartitionLog::open_or_create(&part_dir, "agent-policy-test", 0, 1024 * 1024).unwrap();
    let gw_key = generate_signing_key();
    let receipts_path = dir.path().join("receipts.jsonl");
    let checkpoints_path = dir.path().join("checkpoints.jsonl");

    let policy = SimplePolicyEngine::new("v2.0", vec!["dangerous_exec".to_string()]);
    let mut gateway = ActionGateway::new(
        partition,
        gw_key,
        Box::new(policy),
        receipts_path,
        checkpoints_path,
    );

    // 1. Normal allowed query
    let (rcpt1, pol1) = gateway
        .record_action_request(
            "finance-agent",
            "sql_query",
            "act-safe-001",
            b"SELECT * FROM invoices WHERE amount > 1000",
        )
        .unwrap();
    assert!(pol1.allowed);
    assert!(rcpt1.policy_allowed);

    // 2. Destructive SQL DDL attempt: DROP TABLE
    let (rcpt_ddl, pol_ddl) = gateway
        .record_action_request(
            "finance-agent",
            "sql_query",
            "act-malicious-001",
            b"SELECT 1; DROP TABLE audit_log; --",
        )
        .unwrap();
    assert!(!pol_ddl.allowed);
    assert!(!rcpt_ddl.policy_allowed);
    assert!(pol_ddl.reason.contains("Semantic AST taint"));

    // 3. Destructive SQL TRUNCATE attempt
    let (rcpt_trunc, pol_trunc) = gateway
        .record_action_request(
            "finance-agent",
            "sql_query",
            "act-malicious-002",
            b"TRUNCATE TABLE balances",
        )
        .unwrap();
    assert!(!pol_trunc.allowed);
    assert!(!rcpt_trunc.policy_allowed);

    // 4. SSRF attack on AWS IAM metadata endpoint (169.254.169.254)
    let (rcpt_ssrf, pol_ssrf) = gateway
        .record_action_request(
            "web-scraper-agent",
            "http_fetch",
            "act-ssrf-001",
            b"{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
        )
        .unwrap();
    assert!(!pol_ssrf.allowed);
    assert!(!rcpt_ssrf.policy_allowed);
    assert!(pol_ssrf.reason.contains("SSRF barrier"));

    // 5. SSRF attack on GCP metadata endpoint (metadata.google.internal)
    let (rcpt_gcp, pol_gcp) = gateway
        .record_action_request(
            "web-scraper-agent",
            "http_fetch",
            "act-ssrf-002",
            b"{\"url\": \"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\"}",
        )
        .unwrap();
    assert!(!pol_gcp.allowed);
    assert!(!rcpt_gcp.policy_allowed);
    assert!(pol_gcp.reason.contains("SSRF barrier"));

    // 6. SSRF attack targeting internal private subnet (RFC 1918)
    let (rcpt_priv, pol_priv) = gateway
        .record_action_request(
            "web-scraper-agent",
            "http_fetch",
            "act-ssrf-003",
            b"{\"url\": \"http://192.168.1.100:8080/admin/delete\"}",
        )
        .unwrap();
    assert!(!pol_priv.allowed);
    assert!(!rcpt_priv.policy_allowed);
    assert!(pol_priv.reason.contains("RFC 1918"));

    // 7. Path traversal attack
    let (rcpt_trav, pol_trav) = gateway
        .record_action_request(
            "file-agent",
            "read_file",
            "act-trav-001",
            b"{\"path\": \"../../../../etc/passwd\"}",
        )
        .unwrap();
    assert!(!pol_trav.allowed);
    assert!(!rcpt_trav.policy_allowed);
    assert!(pol_trav.reason.contains("Path traversal"));
}

#[test]
fn test_gateway_anti_replay_and_monotonic_sequence_ledger() {
    let dir = tempdir().unwrap();
    let part_dir = dir.path().join("storage");
    let partition = PartitionLog::open_or_create(&part_dir, "agent-replay-test", 0, 1024 * 1024).unwrap();
    let gw_key = generate_signing_key();
    let receipts_path = dir.path().join("receipts.jsonl");
    let checkpoints_path = dir.path().join("checkpoints.jsonl");

    let policy = SimplePolicyEngine::new("v2.0", vec![]);
    let mut gateway = ActionGateway::new(
        partition,
        gw_key,
        Box::new(policy),
        receipts_path,
        checkpoints_path,
    );

    // 1. Initial valid request with seq = 100
    let res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-100",
        b"{\"symbol\": \"BTC\", \"qty\": 1}",
        100,
        None,
    );
    assert!(res.is_ok());

    // 2. Replay attack with identical action_id must fail
    let replay_res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-100",
        b"{\"symbol\": \"BTC\", \"qty\": 1}",
        101,
        None,
    );
    assert!(replay_res.is_err());
    let err_msg = replay_res.err().unwrap().to_string();
    assert!(err_msg.contains("Replay attack detected"));

    // 3. Stale sequence number (seq = 99 <= 100) must fail
    let stale_seq_res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-101",
        b"{\"symbol\": \"ETH\", \"qty\": 5}",
        99,
        None,
    );
    assert!(stale_seq_res.is_err());
    let err_msg = stale_seq_res.err().unwrap().to_string();
    assert!(err_msg.contains("Agent sequence violation"));

    // 4. Equal sequence number (seq = 100 <= 100) must fail
    let dup_seq_res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-102",
        b"{\"symbol\": \"SOL\", \"qty\": 20}",
        100,
        None,
    );
    assert!(dup_seq_res.is_err());

    // 5. Monotonic advancement (seq = 101 > 100) must succeed
    let forward_res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-103",
        b"{\"symbol\": \"SOL\", \"qty\": 20}",
        101,
        None,
    );
    assert!(forward_res.is_ok());

    // 6. Expired intent with deadline in the past must fail
    let past_deadline = 1_000_000_000u64; // Jan 1970
    let expired_res = gateway.record_action_request_with_seq(
        "autonomous-trader-01",
        "place_order",
        "action-trade-104",
        b"{\"symbol\": \"AVAX\", \"qty\": 50}",
        102,
        Some(past_deadline),
    );
    assert!(expired_res.is_err());
    let err_msg = expired_res.err().unwrap().to_string();
    assert!(err_msg.contains("Action expired"));
}

