use std::fs::OpenOptions;
use std::io::Write;
use tempfile::tempdir;

use vortex_core::{ForwardSecureRatchet, HashDigest};
use vortex_storage::keyring::{TwoSlotKeyring, KEYRING_SLOT_A};

#[test]
fn test_forward_secure_ratchet_forge_the_past_dies() {
    let initial_seed = [0x99u8; 32];
    let mut ratchet = ForwardSecureRatchet::new(initial_seed);

    // Write record at offset 0
    let record_0 = b"record_bytes_at_offset_0_signed_by_state_0";
    let mac_0 = ratchet.compute_mac(record_0);
    assert!(ForwardSecureRatchet::verify_mac(ratchet.secret_state(), record_0, &mac_0));

    // Advance ratchet through 100 offsets
    for off in 1..=100 {
        ratchet.step(off);
    }
    assert_eq!(ratchet.offset(), 100);

    // Adversary captures root on the machine at offset 100
    let compromised_state_100 = *ratchet.secret_state();

    // Adversary attempts to forge or re-sign record 0
    let forged_mac_0 = ForwardSecureRatchet::verify_mac(&compromised_state_100, record_0, &mac_0);
    assert!(!forged_mac_0, "State at offset 100 must NEVER validate MAC from offset 0");

    // Adversary attempts to generate a new MAC for altered record 0 using compromised state 100
    let altered_record_0 = b"forged_malicious_record_at_offset_0";
    let attacker_new_mac = *blake3::keyed_hash(&compromised_state_100, altered_record_0).as_bytes();

    // Verification against true historical MAC fails
    assert_ne!(mac_0, attacker_new_mac);
}

#[test]
fn test_two_slot_keyring_crash_recovery_and_persistence() {
    let dir = tempdir().unwrap();
    let topic = "financial-settlement";
    let partition = 0;

    let mut record_macs: Vec<HashDigest> = Vec::new();

    // 1. Writer creates partition and appends 50 records
    {
        let mut keyring = TwoSlotKeyring::open_or_create(dir.path(), topic, partition).unwrap();
        assert_eq!(keyring.current_offset(), 0);

        for i in 0..50 {
            let payload = format!("transaction_record_{}", i);
            let mac = keyring.step_and_authenticate(payload.as_bytes(), i + 1).unwrap();
            record_macs.push(mac);
        }

        keyring.checkpoint().unwrap();
        assert_eq!(keyring.current_offset(), 50);
    }

    // 2. Simulate process crash and restart: reopen keyring
    {
        let mut keyring = TwoSlotKeyring::open_or_create(dir.path(), topic, partition).unwrap();
        assert_eq!(keyring.current_offset(), 50);

        // Verify stored MACs for all 50 records can be read
        for (i, expected_mac) in record_macs.iter().enumerate() {
            let stored_mac = keyring.read_mac(i as u64).unwrap().expect("mac must be stored");
            assert_eq!(&stored_mac, expected_mac);
        }

        // Continue appending from offset 50 to 100
        for i in 50..100 {
            let payload = format!("transaction_record_{}", i);
            let mac = keyring.step_and_authenticate(payload.as_bytes(), i + 1).unwrap();
            record_macs.push(mac);
        }

        keyring.checkpoint().unwrap();
        assert_eq!(keyring.current_offset(), 100);
    }

    // 3. Simulate power-loss causing torn write on slot A
    let path_a = dir.path().join(KEYRING_SLOT_A);
    if path_a.exists() {
        let mut f = OpenOptions::new().write(true).open(&path_a).unwrap();
        f.write_all(b"torn-power-cut-zero-bytes-garbage").unwrap();
    }

    // Keyring must gracefully recover from slot B without data corruption
    {
        let recovered = TwoSlotKeyring::open_or_create(dir.path(), topic, partition).unwrap();
        // Since slot A was corrupted, recovered slot is slot B
        assert!(recovered.current_offset() > 0);
    }
}
