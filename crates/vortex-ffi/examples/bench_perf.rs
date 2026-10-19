use std::ffi::CString;
use std::time::Instant;
use tempfile::tempdir;
use vortex::*;
use vortex_core::{ForwardSecureRatchet, Record};
use bytes::Bytes;

fn main() {
    println!("=== Vortex Latency & Throughput Benchmark ===");

    // 1. Pure CPU Cryptographic Microbenchmarks
    println!("\n[1] Cryptographic Primitives Microbenchmark (100,000 iterations):");
    let key = Some(Bytes::from_static(b"user_123456789"));
    let val = Bytes::from_static(b"{\"action\":\"transfer\",\"amount\":250.75,\"currency\":\"USD\"}");
    let prev_hash = [1u8; 32];
    
    // Baseline: Record encode + Blake3 chain hash
    let start = Instant::now();
    let mut h = prev_hash;
    for i in 0..100_000 {
        let rec = Record::new(h, i, key.clone(), val.clone());
        h = rec.record_hash;
    }
    let dur_record = start.elapsed();
    let us_per_record = dur_record.as_micros() as f64 / 100_000.0;
    println!("  • Record Blake3 linear hash chaining: {:.3} µs / record ({:.0} rec/sec)", 
             us_per_record, 100_000.0 / dur_record.as_secs_f64());

    // Ratchet MAC calculation & step
    let mut ratchet = ForwardSecureRatchet::new([42u8; 32]);
    let dummy_raw = vec![7u8; 128];
    let start = Instant::now();
    for i in 0..100_000 {
        let _mac = ratchet.compute_mac(&dummy_raw);
        ratchet.step(i);
    }
    let dur_ratchet = start.elapsed();
    let us_per_ratchet = dur_ratchet.as_micros() as f64 / 100_000.0;
    println!("  • Forward-secure Ratchet MAC + step:   {:.3} µs / record ({:.0} rec/sec)", 
             us_per_ratchet, 100_000.0 / dur_ratchet.as_secs_f64());
    println!("  • Total crypto overhead (Blake3 + Ratchet MAC): {:.3} µs / record", 
             us_per_record + us_per_ratchet);

    // 2. In-Process Storage Benchmark (libvortex vs Server/Network)
    println!("\n[2] libvortex In-Process Append Breakdown:");

    let temp_dir = tempdir().unwrap();
    let base_dir = temp_dir.path().to_str().unwrap();
    let base_dir_c = CString::new(base_dir).unwrap();
    let topic_c = CString::new("bench-topic").unwrap();

    let handle = unsafe {
        vtx_open(base_dir_c.as_ptr(), topic_c.as_ptr(), 0, 64 * 1024 * 1024)
    };
    assert!(!handle.is_null());

    // (A) Batched appends (chunk size 500)
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
    println!("  • Batched (chunk 500) append: 10,000 records in {:.2?} ({:.1} µs / record, {:.0} rec/sec)",
             dur_batch, (dur_batch.as_micros() as f64) / total_recs, total_recs / dur_batch.as_secs_f64());

    // (B) Single fsynced appends (measuring physical APFS fsync cost)
    let single_count = 50;
    let start = Instant::now();
    let mut mac = [0u8; 32];
    for i in 0..single_count {
        let k = format!("k-{}", i);
        let v = format!("v-{}", i);
        unsafe {
            vtx_append(
                handle,
                k.as_ptr(), k.len(),
                v.as_ptr(), v.len(),
                &mut end_off,
                rec_hash.as_mut_ptr(),
                root_hash.as_mut_ptr(),
                mac.as_mut_ptr(),
            );
        }
    }
    let dur_single = start.elapsed();
    println!("  • Single durable appends (each with atomic commit + APFS fsync): {:.2?} for {} records ({:.2} ms / commit)",
             dur_single, single_count, (dur_single.as_millis() as f64) / single_count as f64);

    unsafe {
        vtx_close(handle);
    }

    println!("\nBenchmark complete.");
}
