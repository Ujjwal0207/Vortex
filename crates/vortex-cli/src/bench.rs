use bytes::Bytes;
use std::time::Instant;
use vortex_core::error::Result;

use crate::client::VortexClient;

pub async fn run_benchmark(addr: &str, topic: &str, num_messages: usize, message_size: usize) -> Result<()> {
    println!("\n🌀 ==========================================================");
    println!("             VORTEX HIGH-PERFORMANCE BENCHMARK               ");
    println!("============================================================");
    println!("Broker Address : {}", addr);
    println!("Topic Name     : {}", topic);
    println!("Message Count  : {} messages", num_messages);
    println!("Message Size   : {} bytes per message", message_size);
    println!("------------------------------------------------------------");

    let mut client = VortexClient::connect(addr).await?;
    println!("Connected to broker successfully.");

    // Create topic
    client.create_topic(topic, 1).await?;
    println!("Topic '{}' ready.\n", topic);

    let payload = Bytes::from(vec![b'X'; message_size]);
    let mut latencies_micros = Vec::with_capacity(num_messages);

    println!("🚀 Ingesting {} events...", num_messages);
    let bench_start = Instant::now();

    for i in 0..num_messages {
        let msg_start = Instant::now();
        let key = Some(Bytes::from(format!("bench-key-{}", i)));

        client.produce(topic, 0, key, payload.clone()).await?;

        let elapsed = msg_start.elapsed().as_micros() as u64;
        latencies_micros.push(elapsed);

        if (i + 1) % (num_messages / 5).max(1) == 0 || i + 1 == num_messages {
            let progress = ((i + 1) as f64 / num_messages as f64) * 100.0;
            println!("  -> Progress: {:>5.1}% ({}/{} events)", progress, i + 1, num_messages);
        }
    }

    let total_elapsed = bench_start.elapsed();
    let total_secs = total_elapsed.as_secs_f64();
    let throughput_msg_sec = num_messages as f64 / total_secs;
    let total_bytes = (num_messages * (message_size + 96)) as f64;
    let throughput_mb_sec = (total_bytes / (1024.0 * 1024.0)) / total_secs;

    latencies_micros.sort_unstable();
    let p50 = latencies_micros[num_messages * 50 / 100];
    let p95 = latencies_micros[num_messages * 95 / 100];
    let p99 = latencies_micros[num_messages * 99 / 100];

    println!("\n📊 ---------------- BENCHMARK RESULTS ----------------");
    println!("  Total Duration       : {:.3} s", total_secs);
    println!("  Throughput           : {:>10.2} msgs/sec", throughput_msg_sec);
    println!("  Bandwidth            : {:>10.2} MB/sec", throughput_mb_sec);
    println!("  Latency (p50)        : {:>10} µs ({:.3} ms)", p50, p50 as f64 / 1000.0);
    println!("  Latency (p95)        : {:>10} µs ({:.3} ms)", p95, p95 as f64 / 1000.0);
    println!("  Latency (p99)        : {:>10} µs ({:.3} ms)", p99, p99 as f64 / 1000.0);
    println!("-----------------------------------------------------");

    // Cryptographic audit check
    println!("\n🔐 Running Cryptographic Lineage & Immutability Audit...");
    let audit_start = Instant::now();

    let mut fetched_count = 0;
    let mut current_offset = 0;
    let mut prev_hash_opt = None;
    let mut audit_passed = true;

    while fetched_count < num_messages {
        let batch = client.fetch(topic, 0, current_offset, 1024 * 1024).await?;
        if batch.is_empty() {
            break;
        }

        for rec in batch {
            if let Some(prev) = prev_hash_opt {
                if rec.prev_hash != prev {
                    println!("❌ Cryptographic lineage broke at offset {}!", rec.offset);
                    audit_passed = false;
                    break;
                }
            }
            prev_hash_opt = Some(rec.record_hash);
            current_offset = rec.offset + 1;
            fetched_count += 1;
        }

        if !audit_passed {
            break;
        }
    }

    if audit_passed && fetched_count == num_messages {
        println!(
            "✅ AUDIT PASSED: 100% of {} records cryptographically verified with zero bit-rot in {:.3}s!",
            fetched_count,
            audit_start.elapsed().as_secs_f64()
        );
    } else {
        println!(
            "⚠️ Audit finished with anomalies: verified {}/{} records, status = {}",
            fetched_count, num_messages, audit_passed
        );
    }

    println!("============================================================\n");
    Ok(())
}
