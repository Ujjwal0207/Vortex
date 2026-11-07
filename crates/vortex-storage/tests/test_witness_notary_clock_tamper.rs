use tempfile::tempdir;
use vortex_core::evidence::generate_signing_key;
use vortex_storage::witness_notary::{WitnessNotaryEngine, WitnessNotaryPulse};

#[test]
fn test_witness_notary_normal_flow_and_reel_audit() {
    let dir = tempdir().unwrap();
    let reel_path = dir.path().join("reel.wit");

    // 3 independent witness nodes (Google, Cloudflare, Dedicated Notary)
    let w1 = generate_signing_key();
    let w2 = generate_signing_key();
    let w3 = generate_signing_key();

    let witness_keys = vec![w1.clone(), w2.clone(), w3.clone()];
    let witness_pubkeys = vec![
        w1.verifying_key().to_bytes(),
        w2.verifying_key().to_bytes(),
        w3.verifying_key().to_bytes(),
    ];

    let mut engine = WitnessNotaryEngine::new(&reel_path, witness_pubkeys.clone())
        .expect("init notary engine");

    let pulse = WitnessNotaryPulse {
        epoch: 1,
        offset: 1000,
        mmr_root: [55u8; 32],
        host_timestamp: 1_700_000_000,
    };

    // External Roughtime witness timestamps agreeing with host clock (e.g. within 1 second)
    let witness_timestamps = vec![1_700_000_000, 1_700_000_001, 1_700_000_000];

    let records = engine.notarize_and_append(&pulse, &witness_keys, &witness_timestamps)
        .expect("notarize and append");

    assert_eq!(records.len(), 3);
    assert!(reel_path.exists());

    // Verify notary reel integrity offline
    let verified_count = WitnessNotaryEngine::verify_reel(&reel_path, &witness_pubkeys)
        .expect("verify reel");
    assert_eq!(verified_count, 3);
}

#[test]
fn test_witness_notary_detects_clock_rollback_attack() {
    let dir = tempdir().unwrap();
    let reel_path = dir.path().join("reel.wit");

    let w1 = generate_signing_key();
    let witness_keys = vec![w1.clone()];
    let witness_pubkeys = vec![w1.verifying_key().to_bytes()];

    let mut engine = WitnessNotaryEngine::new(&reel_path, witness_pubkeys)
        .expect("init notary engine");

    // Pulse at time T = 1,700,000,000
    let pulse1 = WitnessNotaryPulse {
        epoch: 1,
        offset: 1000,
        mmr_root: [1u8; 32],
        host_timestamp: 1_700_000_000,
    };
    engine.notarize_and_append(&pulse1, &witness_keys, &[1_700_000_000]).unwrap();

    // Attacker with root privileges sets system clock BACKWARDS to T = 1,600,000,000 (100 million seconds in the past)
    let rollback_pulse = WitnessNotaryPulse {
        epoch: 1,
        offset: 2000,
        mmr_root: [2u8; 32],
        host_timestamp: 1_600_000_000, // MALICIOUS CLOCK ROLLBACK
    };

    let result = engine.notarize_and_append(&rollback_pulse, &witness_keys, &[1_700_001_000]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Clock rollback"));
}

#[test]
fn test_witness_notary_detects_future_clock_skew_tamper() {
    let dir = tempdir().unwrap();
    let reel_path = dir.path().join("reel.wit");

    let w1 = generate_signing_key();
    let witness_keys = vec![w1.clone()];
    let witness_pubkeys = vec![w1.verifying_key().to_bytes()];

    let mut engine = WitnessNotaryEngine::new(&reel_path, witness_pubkeys)
        .expect("init notary engine");

    // Attacker sets clock 3 days into the future
    let future_pulse = WitnessNotaryPulse {
        epoch: 1,
        offset: 1000,
        mmr_root: [3u8; 32],
        host_timestamp: 1_700_259_200, // +3 days
    };

    // Roughtime witnesses provide true network time 1,700,000,000
    let true_witness_time = vec![1_700_000_000];

    let result = engine.notarize_and_append(&future_pulse, &witness_keys, &true_witness_time);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Clock drift/tampering detected"));
}

