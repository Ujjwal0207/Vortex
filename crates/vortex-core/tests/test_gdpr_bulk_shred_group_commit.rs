use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use vortex_core::shred::EntityKeyRegistry;
use vortex_core::VortexError;

#[test]
fn test_gdpr_bulk_shred_150_entities_batch_and_no_resurrection() {
    let dir = tempdir().unwrap();
    let wal_path = dir.path().join("shredded_keys.wal");
    let master_key = [0x5A; 32];

    let registry = EntityKeyRegistry::with_wal(master_key, &wal_path).unwrap();

    let total_entities = 150;
    let mut entity_ids = Vec::with_capacity(total_entities);

    // 1. Generate keys and encrypt payload for all 150 entities
    for i in 0..total_entities {
        let entity_id = match i % 5 {
            0 => format!("eu-tenant-uuid-{:08}", i),
            1 => format!("user-email-{}@corporate-domain.org", i),
            2 => format!("gdpr-subject-\u{00e9}\u{00e0}\u{00fc}-{}", i), // Unicode name
            3 => format!("device-serial-{:016X}", i * 99991),
            _ => format!("id-{}", i),
        };

        let key = registry.get_or_create_key(&entity_id).unwrap();
        assert_ne!(key, [0u8; 32]);
        entity_ids.push(entity_id);
    }

    // Encrypt sample data for entity 42
    let sample_payload = b"Top secret health records for subject 42";
    let nonce = EntityKeyRegistry::compute_nonce("medical-topic", 0, 42);
    let nonce_u64 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
    let ciphertext = registry.encrypt_payload(&entity_ids[42], nonce_u64, sample_payload).unwrap();

    // 2. Bulk shred all 150 entities in a single batch
    let id_refs: Vec<&str> = entity_ids.iter().map(|s| s.as_str()).collect();

    let start_shred = Instant::now();
    let shredded_count = registry.shred_entities_batch(&id_refs);
    let shred_elapsed = start_shred.elapsed();

    assert_eq!(shredded_count, total_entities);
    println!(
        "Batch shredded {} entities with durable WAL sync in {:?}",
        total_entities, shred_elapsed
    );

    // 150 unbatched syncs would take >1,500ms. With batch group commit, must be <150ms!
    assert!(
        shred_elapsed < Duration::from_millis(150),
        "Batch shredding took {:?}, exceeding 150ms limit",
        shred_elapsed
    );

    // 3. Verify all 150 keys are shredded in memory immediately
    for id in &entity_ids {
        assert!(registry.is_shredded(id));
        let err = registry.get_or_create_key(id).unwrap_err();
        match err {
            VortexError::EntityShredded { entity_id } => assert_eq!(&entity_id, id),
            other => panic!("Expected EntityShredded, got {:?}", other),
        }
    }

    // Decryption of subject 42 ciphertext must fail
    assert!(registry.decrypt_payload(&entity_ids[42], nonce_u64, &ciphertext).is_err());

    // 4. Broker Reboot Simulation: Reopen registry from disk WAL
    let rebooted_registry = EntityKeyRegistry::with_wal(master_key, &wal_path).unwrap();

    // Verify 0% resurrection rate across all 150 entities
    let mut resurrected = 0;
    for id in &entity_ids {
        if !rebooted_registry.is_shredded(id) {
            resurrected += 1;
        }
        assert!(rebooted_registry.get_or_create_key(id).is_err());
    }
    assert_eq!(resurrected, 0, "Resurrection rate must be strictly 0%");
}

#[test]
fn test_concurrent_multi_threaded_gdpr_shredding() {
    let dir = tempdir().unwrap();
    let wal_path = dir.path().join("concurrent_shred.wal");
    let master_key = [0x77; 32];

    let registry = Arc::new(EntityKeyRegistry::with_wal(master_key, &wal_path).unwrap());

    let num_threads = 10;
    let entities_per_thread = 15;
    let mut handles = Vec::new();

    for t in 0..num_threads {
        let reg = Arc::clone(&registry);
        let handle = thread::spawn(move || {
            let mut ids = Vec::new();
            for i in 0..entities_per_thread {
                let id = format!("tenant-{}-{}", t, i);
                let _ = reg.get_or_create_key(&id).unwrap();
                ids.push(id);
            }

            let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
            reg.shred_entities_batch(&id_refs)
        });
        handles.push(handle);
    }

    let mut total_shredded = 0;
    for h in handles {
        total_shredded += h.join().expect("Worker thread must succeed");
    }

    assert_eq!(total_shredded, num_threads * entities_per_thread);

    // Reopen from WAL
    let rebooted = EntityKeyRegistry::with_wal(master_key, &wal_path).unwrap();
    for t in 0..num_threads {
        for i in 0..entities_per_thread {
            let id = format!("tenant-{}-{}", t, i);
            assert!(rebooted.is_shredded(&id));
        }
    }
}
