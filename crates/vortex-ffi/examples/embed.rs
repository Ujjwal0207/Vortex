use std::ffi::CString;
use std::time::Instant;
use tempfile::tempdir;

use vortex::*;

fn main() {
    println!("===============================================================================");
    println!(" Vortex 'libvortex' Embeddable Sealed Reel Demo (No Broker Process Required)");
    println!("===============================================================================\n");

    let temp_dir = tempdir().expect("failed to create temp dir");
    let base_dir = temp_dir.path().to_str().unwrap();
    let topic = "financial-ledger-audit";
    let partition_id = 0;

    let base_dir_c = CString::new(base_dir).unwrap();
    let topic_c = CString::new(topic).unwrap();

    println!("[1/6] Initializing sealed partition via libvortex C-ABI...");
    let handle = unsafe {
        vtx_open(
            base_dir_c.as_ptr(),
            topic_c.as_ptr(),
            partition_id,
            16 * 1024 * 1024, // 16 MB segment size
        )
    };
    assert!(!handle.is_null(), "vtx_open failed");
    println!("      ✓ Partition log handle opened successfully at: {}", base_dir);

    let total_records = 10_000;
    let single_records = 500;
    let batch_records = 9_500;
    println!("\n[2/6] Appending {} records in-process ({} single appends + {} batched appends)...",
             total_records, single_records, batch_records);

    let start_time = Instant::now();
    let mut last_offset = 0u64;
    let mut last_record_hash = [0u8; 32];
    let mut last_mmr_root = [0u8; 32];
    let mut last_writer_mac = [0u8; 32];

    // Single message appends
    for i in 0..single_records {
        let key = format!("tx-single-{:06}", i);
        let val = format!("{{\"action\":\"transfer\",\"amount\":{}.50,\"status\":\"SETTLED\"}}", i);

        let res = unsafe {
            vtx_append(
                handle,
                key.as_ptr(),
                key.len(),
                val.as_ptr(),
                val.len(),
                &mut last_offset,
                last_record_hash.as_mut_ptr(),
                last_mmr_root.as_mut_ptr(),
                last_writer_mac.as_mut_ptr(),
            )
        };
        assert_eq!(res, VTX_OK, "vtx_append failed at index {}", i);
    }

    // Batched appends in chunks of 500
    let chunk_size = 500;
    for chunk_start in (single_records..total_records).step_by(chunk_size) {
        let keys_str: Vec<String> = (0..chunk_size)
            .map(|j| format!("tx-batch-{:06}", chunk_start + j))
            .collect();
        let vals_str: Vec<String> = (0..chunk_size)
            .map(|j| format!("{{\"action\":\"batch_settle\",\"amount\":{}.00}}", chunk_start + j))
            .collect();

        let key_ptrs: Vec<*const u8> = keys_str.iter().map(|k| k.as_ptr()).collect();
        let key_lens: Vec<usize> = keys_str.iter().map(|k| k.len()).collect();
        let val_ptrs: Vec<*const u8> = vals_str.iter().map(|v| v.as_ptr()).collect();
        let val_lens: Vec<usize> = vals_str.iter().map(|v| v.len()).collect();

        let mut start_off = 0u64;
        let mut end_off = 0u64;

        let res = unsafe {
            vtx_append_batch(
                handle,
                key_ptrs.as_ptr(),
                key_lens.as_ptr(),
                val_ptrs.as_ptr(),
                val_lens.as_ptr(),
                chunk_size,
                &mut start_off,
                &mut end_off,
                last_record_hash.as_mut_ptr(),
                last_mmr_root.as_mut_ptr(),
            )
        };
        assert_eq!(res, VTX_OK, "vtx_append_batch failed");
        last_offset = end_off;
    }

    let elapsed = start_time.elapsed();
    let elapsed_micros = elapsed.as_micros() as f64;
    let avg_latency_us = elapsed_micros / total_records as f64;
    let records_per_sec = (total_records as f64) / elapsed.as_secs_f64();

    println!("      ✓ Appended {} records in {:.2?}", total_records, elapsed);
    println!("      ✓ Average in-process append latency: {:.2} µs / record", avg_latency_us);
    println!("      ✓ Throughput: {:.0} records / sec", records_per_sec);
    println!("      ✓ Final record offset: {}", last_offset);
    println!("      ✓ Final record Blake3 hash: {}", hex_fmt(&last_record_hash));
    println!("      ✓ Current MMR bagged root: {}", hex_fmt(&last_mmr_root));

    // Ratchet Public State Hash
    let mut public_ratchet_hash = [0u8; 32];
    unsafe {
        assert_eq!(vtx_ratchet_state_hash(handle, public_ratchet_hash.as_mut_ptr()), VTX_OK);
    }
    println!("      ✓ Forward-secure ratchet H(state): {}", hex_fmt(&public_ratchet_hash));

    // Generate O(log N) MMR proof for a specific record
    let target_offset = 5_000u64;
    println!("\n[3/6] Generating O(log N) MMR inclusion proof for record offset {}...", target_offset);
    let mut proof_buf = [0u8; 2048];
    let mut proof_len = 0usize;

    let res = unsafe {
        vtx_prove(
            handle,
            target_offset,
            proof_buf.as_mut_ptr(),
            proof_buf.len(),
            &mut proof_len,
        )
    };
    assert_eq!(res, VTX_OK, "vtx_prove failed");
    println!("      ✓ Compact inclusion proof generated: {} bytes", proof_len);

    // Verify proof
    println!("\n[4/6] Verifying inclusion proof against current MMR bagged root...");
    let valid = unsafe {
        vtx_verify_proof(last_mmr_root.as_ptr(), proof_buf.as_ptr(), proof_len)
    };
    assert_eq!(valid, 1, "MMR inclusion proof verification failed");
    println!("      ✓ Proof verification: VALID (record {} cryptographically bound to root)", target_offset);

    // Flush and Close
    println!("\n[5/6] Flushing and destroying in-memory partition handle (simulating process exit)...");
    unsafe {
        assert_eq!(vtx_flush(handle), VTX_OK);
        assert_eq!(vtx_close(handle), VTX_OK);
    }
    println!("      ✓ Partition handle closed. No broker, daemon, or background thread running.");

    // Offline Disk Verification
    println!("\n[6/6] Performing standalone offline disk verification on raw .vtx files...");
    let partition_dir = temp_dir.path().join(topic).join(format!("partition-{}", partition_id));
    let partition_dir_c = CString::new(partition_dir.to_str().unwrap()).unwrap();

    let mut verified_count = 0u64;
    let mut verified_root = [0u8; 32];
    let mut verified_hash = [0u8; 32];

    let verify_start = Instant::now();
    let audit_res = unsafe {
        vtx_verify_partition(
            partition_dir_c.as_ptr(),
            topic_c.as_ptr(),
            partition_id,
            &mut verified_count,
            verified_root.as_mut_ptr(),
            verified_hash.as_mut_ptr(),
        )
    };
    let audit_elapsed = verify_start.elapsed();

    assert_eq!(audit_res, 1, "Offline verification failed");
    assert_eq!(verified_count, total_records as u64);
    assert_eq!(verified_root, last_mmr_root);
    assert_eq!(verified_hash, last_record_hash);

    println!("      ✓ Audit result: 100% VALID");
    println!("      ✓ Records scanned & cryptographically verified: {}", verified_count);
    println!("      ✓ All CRC32 checksums: PASSED");
    println!("      ✓ Monotonic offset sequence: PASSED");
    println!("      ✓ Blake3 unbroken hash chain: PASSED");
    println!("      ✓ Recomputed MMR root match: PASSED ({})", hex_fmt(&verified_root));
    println!("      ✓ Total verification time: {:.2?}", audit_elapsed);

    println!("\n===============================================================================");
    println!(" Summary: Vortex proved tamper-evident sealed log properties with ZERO server.");
    println!("===============================================================================\n");
}

fn hex_fmt(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &hash[0..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push_str("...");
    s
}
