use bytes::Bytes;
use std::ffi::CString;
use std::time::Instant;
use tempfile::tempdir;
use vortex::*;
use vortex_core::{
    compute_genesis_hash, generate_signing_key, verify_signature, BlindIndexer,
    EntityKeyRegistry, ExecutorReceipt, ForwardSecureRatchet, MerkleMountainRange, Record,
    SignatureBytes, Signer,
};
use vortex_storage::{
    ActionGateway, IndependentWitness, OfflineVerifier, PartitionLog, SimplePolicyEngine,
};

fn main() {
    println!("================================================================================");
    println!("              VORTEX COMPREHENSIVE PERFORMANCE BENCHMARK SUITE                  ");
    println!("================================================================================");

    // =========================================================================
    // 1. Pure CPU Cryptographic & Zero-Knowledge Microbenchmarks
    // =========================================================================
    println!("\n[1] Core Cryptographic & Zero-Knowledge Primitives (Pure CPU):");

    // (A) Record Blake3 linear hash chaining
    let key = Some(Bytes::from_static(b"entity_user_42"));
    let val = Bytes::from_static(b"{\"action\":\"transfer\",\"amount\":500.00,\"currency\":\"USD\"}");
    let prev_hash = compute_genesis_hash("bench-topic", 0);
    let n_records = 50_000u64;
    let start = Instant::now();
    let mut h = prev_hash;
    for i in 0..n_records {
        let rec = Record::new(h, i, key.clone(), val.clone());
        h = rec.record_hash;
    }
    let dur_record = start.elapsed();
    let us_per_record = dur_record.as_micros() as f64 / n_records as f64;
    let rec_per_sec = n_records as f64 / dur_record.as_secs_f64();
    println!(
        "  • Blake3 Hash Chaining & Lineage : {:>6.3} µs / record ({:>9.0} rec/sec)",
        us_per_record, rec_per_sec
    );

    // (B) Forward-Secure Ratchet MAC & Step
    let n_ratchet = 50_000u64;
    let mut ratchet = ForwardSecureRatchet::new([42u8; 32]);
    let dummy_raw = vec![7u8; 128];
    let start = Instant::now();
    for i in 0..n_ratchet {
        let _mac = ratchet.compute_mac(&dummy_raw);
        ratchet.step(i);
    }
    let dur_ratchet = start.elapsed();
    let us_per_ratchet = dur_ratchet.as_micros() as f64 / n_ratchet as f64;
    let ratchet_per_sec = n_ratchet as f64 / dur_ratchet.as_secs_f64();
    println!(
        "  • Forward-Secure Ratchet Step+MAC: {:>6.3} µs / record ({:>9.0} rec/sec)",
        us_per_ratchet, ratchet_per_sec
    );
    println!(
        "    ↳ Total Ingress Crypto Overhead: {:>6.3} µs / record",
        us_per_record + us_per_ratchet
    );

    // (C) Incremental Merkle Mountain Range (MMR)
    let n_mmr = 20_000u64;
    let mut mmr = MerkleMountainRange::new();
    let start = Instant::now();
    for i in 0..n_mmr {
        let leaf_hash = blake3::hash(&i.to_le_bytes());
        mmr.append(*leaf_hash.as_bytes());
    }
    let dur_mmr = start.elapsed();
    let us_per_mmr = dur_mmr.as_micros() as f64 / n_mmr as f64;
    let mmr_per_sec = n_mmr as f64 / dur_mmr.as_secs_f64();
    println!(
        "  • Incremental MMR Leaf Insertion : {:>6.3} µs / leaf   ({:>9.0} leaves/sec)",
        us_per_mmr, mmr_per_sec
    );

    // (D) MMR O(log N) Inclusion Proof Generation & Verification
    let n_proofs = 2_000usize;
    let root = mmr.root();
    let start = Instant::now();
    for i in 0..n_proofs {
        let leaf_idx = ((i * 7) as u64) % n_mmr;
        let proof = mmr.generate_proof(leaf_idx).unwrap();
        assert!(proof.verify(&root, &proof.leaf_hash));
    }
    let dur_proofs = start.elapsed();
    let us_per_proof = dur_proofs.as_micros() as f64 / n_proofs as f64;
    let proofs_per_sec = n_proofs as f64 / dur_proofs.as_secs_f64();
    println!(
        "  • MMR Proof Gen + Verify (O(logN): {:>6.3} µs / proof  ({:>9.0} proofs/sec)",
        us_per_proof, proofs_per_sec
    );

    // (E) Zero-Knowledge Blind Index Search
    let n_blind = 20_000usize;
    let salt = [99u8; 32];
    let start = Instant::now();
    for i in 0..n_blind {
        let tag = BlindIndexer::compute_tag(&salt, &format!("account-id-{}", i));
        let _ = tag[0];
    }
    let dur_blind = start.elapsed();
    let us_per_blind = dur_blind.as_micros() as f64 / n_blind as f64;
    let blind_per_sec = n_blind as f64 / dur_blind.as_secs_f64();
    println!(
        "  • Blind Index Tag Generation     : {:>6.3} µs / tag    ({:>9.0} tags/sec)",
        us_per_blind, blind_per_sec
    );

    // (F) Ephemeral Key Shredder (Right-to-be-Forgotten)
    let n_shred = 5_000usize;
    let registry = EntityKeyRegistry::new([123u8; 32]);
    let plaintext = b"Sensitive diagnostic patient record: PII confidential";
    let start = Instant::now();
    for i in 0..n_shred {
        let entity = format!("user-{}", i);
        let ciphertext = registry.encrypt_payload(&entity, i as u64, plaintext).unwrap();
        let decrypted = registry.decrypt_payload(&entity, i as u64, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
        registry.shred_entity(&entity);
    }
    let dur_shred = start.elapsed();
    let us_per_shred = dur_shred.as_micros() as f64 / n_shred as f64;
    let shred_per_sec = n_shred as f64 / dur_shred.as_secs_f64();
    println!(
        "  • Key Shredding (Encrypt+Wipe)   : {:>6.3} µs / entity ({:>9.0} ops/sec)",
        us_per_shred, shred_per_sec
    );

    // (G) Ed25519 Signatures (Sign & Verify)
    let n_sig = 2_000usize;
    let keypair = generate_signing_key();
    let pubkey = keypair.verifying_key().to_bytes();
    let msg = b"Vortex action authorization verification payload v1.0";
    let start_sign = Instant::now();
    let mut sigs = Vec::with_capacity(n_sig);
    for _ in 0..n_sig {
        let sig = keypair.sign(msg);
        sigs.push(SignatureBytes(sig.to_bytes()));
    }
    let dur_sign = start_sign.elapsed();
    let us_per_sign = dur_sign.as_micros() as f64 / n_sig as f64;

    let start_ver = Instant::now();
    for sig in &sigs {
        assert!(verify_signature(&pubkey, msg, sig));
    }
    let dur_ver = start_ver.elapsed();
    let us_per_ver = dur_ver.as_micros() as f64 / n_sig as f64;
    println!(
        "  • Ed25519 Sign Latency           : {:>6.3} µs / sign   ({:>9.0} signs/sec)",
        us_per_sign, n_sig as f64 / dur_sign.as_secs_f64()
    );
    println!(
        "  • Ed25519 Verify Latency         : {:>6.3} µs / verify ({:>9.0} verifs/sec)",
        us_per_ver, n_sig as f64 / dur_ver.as_secs_f64()
    );

    // =========================================================================
    // 2. High-Throughput In-Process Storage Engine (libvortex C-ABI)
    // =========================================================================
    println!("\n[2] In-Process Storage Engine Performance (libvortex C-ABI):");

    let temp_dir = tempdir().unwrap();
    let base_dir = temp_dir.path().to_str().unwrap();
    let base_dir_c = CString::new(base_dir).unwrap();
    let topic_c = CString::new("bench-topic").unwrap();

    let handle = unsafe {
        vtx_open(base_dir_c.as_ptr(), topic_c.as_ptr(), 0, 64 * 1024 * 1024)
    };
    assert!(!handle.is_null());

    let batch_size = 500;
    let num_batches = 20; // 10,000 records
    let keys_str: Vec<String> = (0..batch_size).map(|j| format!("key-{:06}", j)).collect();
    let vals_str: Vec<String> = (0..batch_size).map(|j| format!("val-{:06}", j)).collect();
    let key_ptrs: Vec<*const u8> = keys_str.iter().map(|k| k.as_ptr()).collect();
    let key_lens: Vec<usize> = keys_str.iter().map(|k| k.len()).collect();
    let val_ptrs: Vec<*const u8> = vals_str.iter().map(|v| v.as_ptr()).collect();
    let val_lens: Vec<usize> = vals_str.iter().map(|v| v.len()).collect();

    let mut start_off = 0u64;
    let mut end_off = 0u64;
    let mut rec_hash = [0u8; 32];
    let mut root_hash = [0u8; 32];

    let start = Instant::now();
    for _ in 0..num_batches {
        unsafe {
            vtx_append_batch(
                handle,
                key_ptrs.as_ptr(),
                key_lens.as_ptr(),
                val_ptrs.as_ptr(),
                val_lens.as_ptr(),
                batch_size,
                &mut start_off,
                &mut end_off,
                rec_hash.as_mut_ptr(),
                root_hash.as_mut_ptr(),
            );
        }
    }
    let dur_batch = start.elapsed();
    let total_recs = (batch_size * num_batches) as f64;
    let total_bytes = total_recs * (10.0 + 10.0 + 96.0); // key + val + record framing
    let mb_per_sec = (total_bytes / (1024.0 * 1024.0)) / dur_batch.as_secs_f64();
    println!(
        "  • Batched Sequential Append      : {:>6.2} ms for 10k records ({:>5.1} µs/rec, {:>7.0} rec/sec, {:>6.2} MB/s)",
        dur_batch.as_secs_f64() * 1000.0,
        (dur_batch.as_micros() as f64) / total_recs,
        total_recs / dur_batch.as_secs_f64(),
        mb_per_sec
    );

    // Flush and close handle
    unsafe {
        vtx_flush(handle);
        vtx_close(handle);
    }

    // Offline Verification Scan via C-ABI
    let part_dir_str = temp_dir.path().join("bench-topic").join("partition-0");
    let part_dir_c = CString::new(part_dir_str.to_str().unwrap()).unwrap();
    let mut out_verified = 0u64;
    let mut out_mmr = [0u8; 32];
    let mut out_h = [0u8; 32];

    let start_scan = Instant::now();
    let verify_status = unsafe {
        vtx_verify_partition(
            part_dir_c.as_ptr(),
            topic_c.as_ptr(),
            0,
            &mut out_verified,
            out_mmr.as_mut_ptr(),
            out_h.as_mut_ptr(),
        )
    };
    let dur_scan = start_scan.elapsed();
    assert_eq!(verify_status, 1);
    assert_eq!(out_verified, 10_000);
    println!(
        "  • Offline Verification Scan (CRC32+Blake3+MMR): {:>6.2} ms ({:>7.0} rec/sec)",
        dur_scan.as_secs_f64() * 1000.0,
        10_000.0 / dur_scan.as_secs_f64()
    );

    // Single commit durability with APFS fsync (calibrated to 20 samples to protect SSD)
    let temp_dir_single = tempdir().unwrap();
    let base_single_c = CString::new(temp_dir_single.path().to_str().unwrap()).unwrap();
    let handle_single = unsafe {
        vtx_open(base_single_c.as_ptr(), topic_c.as_ptr(), 0, 64 * 1024 * 1024)
    };
    let single_count = 20;
    let start_single = Instant::now();
    let mut mac = [0u8; 32];
    for i in 0..single_count {
        let k = format!("k-{}", i);
        let v = format!("v-{}", i);
        unsafe {
            vtx_append(
                handle_single,
                k.as_ptr(),
                k.len(),
                v.as_ptr(),
                v.len(),
                &mut end_off,
                rec_hash.as_mut_ptr(),
                root_hash.as_mut_ptr(),
                mac.as_mut_ptr(),
            );
        }
    }
    let dur_single = start_single.elapsed();
    unsafe {
        vtx_close(handle_single);
    }
    println!(
        "  • Physical Single-Commit Sync    : {:>6.2} ms / commit (APFS fsync + .commit fence)",
        (dur_single.as_secs_f64() * 1000.0) / single_count as f64
    );

    // =========================================================================
    // 3. Verifiable Autonomous Evidence & Witness Pipeline
    // =========================================================================
    println!("\n[3] Verifiable Autonomous Evidence & Witness Pipeline:");

    let evidence_dir = tempdir().unwrap();
    let evidence_base = evidence_dir.path().join("ledger");
    let receipts_path = evidence_dir.path().join("receipts.jsonl");
    let checkpoints_path = evidence_dir.path().join("checkpoints.jsonl");
    let witness_state_path = evidence_dir.path().join("witness_state.json");
    let witness_reel_path = evidence_dir.path().join("reel.wit");

    let mut genesis_seed = [0u8; 32];
    genesis_seed.copy_from_slice(&blake3::hash(b"bench-genesis-seed").as_bytes()[..]);

    let partition = PartitionLog::open_or_create_with_seed(
        &evidence_base,
        "audit-stream",
        0,
        64 * 1024 * 1024,
        genesis_seed,
    )
    .unwrap();

    let gw_key = generate_signing_key();
    let gw_pubkey = gw_key.verifying_key().to_bytes();
    let exec_key = generate_signing_key();
    let _exec_pubkey = exec_key.verifying_key().to_bytes();
    let wit_key = generate_signing_key();
    let wit_pubkey = wit_key.verifying_key().to_bytes();

    let policy = Box::new(SimplePolicyEngine::new("sentinel-v1.0", vec!["delete_db".into()]));
    let mut gateway = ActionGateway::new(
        partition,
        gw_key,
        policy,
        receipts_path.clone(),
        checkpoints_path,
    );

    let mut witness = IndependentWitness::open_or_create(
        wit_key,
        witness_state_path,
        witness_reel_path.clone(),
    )
    .unwrap();

    let n_actions = 50usize;
    let start_actions = Instant::now();
    for i in 0..n_actions {
        let action_id = format!("act-{:05}", i);
        let raw_args = format!("{{\"destination\":\"vault_{}\",\"amount\":100}}", i);

        // Stage 1 & 2: Gateway records request + policy decision + issues GatewayReceipt
        let (_gw_receipt, _decision) = gateway
            .record_action_request("bench-agent", "send_funds", &action_id, raw_args.as_bytes())
            .unwrap();

        // Stage 3: Executor finishes and signs ExecutorReceipt
        let exec_receipt = ExecutorReceipt::sign(
            action_id,
            0,
            b"{\"status\":\"success\"}",
            true,
            &exec_key,
        );
        gateway.record_executor_receipt(exec_receipt).unwrap();
    }
    let dur_actions = start_actions.elapsed();
    let us_per_action = dur_actions.as_micros() as f64 / n_actions as f64;
    println!(
        "  • Gateway Action Ingestion Rate  : {:>6.2} ms for {} actions ({:>5.1} µs/action, {:>5.0} actions/sec)",
        dur_actions.as_secs_f64() * 1000.0,
        n_actions,
        us_per_action,
        n_actions as f64 / dur_actions.as_secs_f64()
    );

    // Witness Checkpoint & Countersign
    let start_ckpt = Instant::now();
    let checkpoint = gateway.emit_checkpoint().unwrap();
    let countersig = witness
        .verify_and_countersign(&checkpoint, None)
        .unwrap();
    let dur_ckpt = start_ckpt.elapsed();
    assert_eq!(countersig.checkpoint_seq, 0);
    println!(
        "  • Witness Checkpoint & Countersign: {:>6.2} ms (Tree size: {} records)",
        dur_ckpt.as_secs_f64() * 1000.0,
        checkpoint.tree_size
    );

    // Offline Verifier Audit across all artifacts
    let start_audit = Instant::now();
    let audit_report = OfflineVerifier::verify(
        &evidence_base,
        "audit-stream",
        0,
        Some(genesis_seed),
        &receipts_path,
        &witness_reel_path,
        gw_pubkey,
        wit_pubkey,
    )
    .unwrap();
    let dur_audit = start_audit.elapsed();

    assert!(audit_report.log_integrity_valid && audit_report.ratchet_macs_valid && audit_report.witness_checkpoints_valid);
    assert_eq!(audit_report.verified_count, n_actions);
    println!(
        "  • End-to-End Offline Court Audit : {:>6.2} ms (100% verified {}/{} actions, zero bit-rot)",
        dur_audit.as_secs_f64() * 1000.0,
        audit_report.verified_count,
        n_actions
    );

    println!("\n================================================================================");
    println!("                         ALL BENCHMARK TESTS PASSED                             ");
    println!("================================================================================");
}
