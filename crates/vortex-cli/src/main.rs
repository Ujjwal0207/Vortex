use bytes::Bytes;
use clap::{Parser, Subcommand};

mod bench;
mod client;

use bench::run_benchmark;
use client::VortexClient;

#[derive(Parser, Debug)]
#[command(name = "vortex-cli", version = "0.1.0", about = "Vortex Command Line Interface & Benchmarking Tool")]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1:9092")]
    broker: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new topic with the given partition count
    CreateTopic {
        #[arg(short, long)]
        topic: String,

        #[arg(short, long, default_value_t = 1)]
        partitions: u32,
    },

    /// Produce an event to a topic
    Produce {
        #[arg(short, long)]
        topic: String,

        #[arg(short, long, default_value_t = 0)]
        partition: u32,

        #[arg(short, long)]
        key: Option<String>,

        #[arg(short, long)]
        message: String,
    },

    /// Consume events from a topic
    Consume {
        #[arg(short, long)]
        topic: String,

        #[arg(short, long, default_value_t = 0)]
        partition: u32,

        #[arg(short, long, default_value_t = 0)]
        from_offset: u64,

        #[arg(short, long, default_value_t = 100)]
        limit: usize,
    },

    /// Run an automated performance and cryptographic audit benchmark
    Bench {
        #[arg(short, long, default_value = "bench-stream")]
        topic: String,

        #[arg(short, long, default_value_t = 10_000)]
        messages: usize,

        #[arg(short, long, default_value_t = 256)]
        size: usize,
    },

    /// Proactively scrub .vtx storage segments for silent bit-rot and cryptographic chain breaks
    Scrub {
        #[arg(short, long, default_value = "./data")]
        data_dir: std::path::PathBuf,
    },

    /// Inspect a message payload for leaked secrets, API keys, or credit card PII
    PiiCheck {
        #[arg(short, long)]
        message: String,

        #[arg(short, long, default_value_t = true)]
        quarantine: bool,
    },

    /// Compute a zero-knowledge blind search tag for client-side encrypted streams
    BlindTag {
        #[arg(short, long, default_value = "vortex-default-salt")]
        salt: String,

        #[arg(short, long)]
        value: String,
    },

    /// Demonstrate sub-millisecond cryptographic key shredding (GDPR Right-to-be-Forgotten)
    ShredDemo {
        #[arg(short, long, default_value = "user-alice-42")]
        entity: String,

        #[arg(short, long, default_value = "Patient medical record: diagnosis=confidential")]
        payload: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateTopic { topic, partitions } => {
            let mut client = VortexClient::connect(&cli.broker).await?;
            client.create_topic(&topic, partitions).await?;
            println!("✅ Topic '{}' created with {} partition(s).", topic, partitions);
        }
        Commands::Produce {
            topic,
            partition,
            key,
            message,
        } => {
            let mut client = VortexClient::connect(&cli.broker).await?;
            let key_bytes = key.map(Bytes::from);
            let val_bytes = Bytes::from(message);

            let resp = client.produce(&topic, partition, key_bytes, val_bytes).await?;
            println!(
                "✅ Event produced successfully! Offset: {}, Timestamp: {}, Blake3: 0x{}",
                resp.offset,
                resp.timestamp,
                hex::encode(resp.record_hash)
            );
        }
        Commands::Consume {
            topic,
            partition,
            from_offset,
            limit,
        } => {
            let mut client = VortexClient::connect(&cli.broker).await?;
            let records = client
                .fetch(&topic, partition, from_offset, 1024 * 1024)
                .await?;

            println!("📥 Fetched {} record(s) from '{}:{}':\n", records.len(), topic, partition);
            for (idx, rec) in records.iter().take(limit).enumerate() {
                let key_str = rec
                    .key
                    .as_ref()
                    .map(|k| String::from_utf8_lossy(k).to_string())
                    .unwrap_or_else(|| "<none>".to_string());
                let val_str = String::from_utf8_lossy(&rec.value);

                println!(
                    "[{:>3}] Offset: {:<6} | Key: {:<12} | Hash: 0x{}... | Val: {}",
                    idx,
                    rec.offset,
                    key_str,
                    &hex::encode(rec.record_hash)[..12],
                    val_str
                );
            }
        }
        Commands::Bench {
            topic,
            messages,
            size,
        } => {
            run_benchmark(&cli.broker, &topic, messages, size).await?;
        }
        Commands::Scrub { data_dir } => {
            println!("🔍 Initializing Vortex Autonomous Scrubber on: {:?}", data_dir);
            if !data_dir.exists() {
                println!("⚠️ Directory {:?} does not exist yet. Run benchmarks or produce messages first.", data_dir);
                return Ok(());
            }

            let mut found_segments = 0;
            let mut total_records = 0;
            let mut any_corruption = false;

            fn visit_dirs(dir: &std::path::Path, vtx_files: &mut Vec<std::path::PathBuf>) {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            visit_dirs(&path, vtx_files);
                        } else if path.extension().and_then(|s| s.to_str()) == Some("vtx") {
                            vtx_files.push(path);
                        }
                    }
                }
            }

            let mut vtx_files = Vec::new();
            visit_dirs(&data_dir, &mut vtx_files);

            for vtx_path in vtx_files {
                let parent = vtx_path.parent().unwrap();
                let stem = vtx_path.file_stem().unwrap().to_str().unwrap();
                if let Ok(base_offset) = stem.parse::<u64>() {
                    found_segments += 1;
                    let genesis = [0u8; 32];
                    if let Ok(mut seg) = vortex_storage::Segment::open_or_create(parent, base_offset, genesis) {
                        let report = vortex_storage::Scrubber::scrub_segment(&mut seg)?;
                        total_records += report.records_scanned;
                        if report.healthy {
                            println!(
                                "  ✅ Segment {:?} | Scanned: {} records ({} bytes) in {} ms | Status: HEALTHY",
                                vtx_path.file_name().unwrap(),
                                report.records_scanned,
                                report.bytes_scanned,
                                report.scan_duration_ms
                            );
                        } else {
                            any_corruption = true;
                            println!(
                                "  ❌ Segment {:?} | Corrupted CRCs: {}, Broken Blake3 Links: {} | Status: CORRUPTED",
                                vtx_path.file_name().unwrap(),
                                report.corrupted_crc_count,
                                report.broken_hash_chain_count
                            );
                            for detail in report.details {
                                println!("     ⚠️ {}", detail);
                            }
                        }
                    }
                }
            }

            if found_segments == 0 {
                println!("ℹ️ No .vtx segment files found in {:?}.", data_dir);
            } else if !any_corruption {
                println!("\n🛡️ Scrub Complete: {} segment(s) verified, {} total records. Zero bit-rot detected.", found_segments, total_records);
            } else {
                println!("\n⚠️ Scrub Alert: Segment integrity violations detected! Review logs above.");
            }
        }
        Commands::PiiCheck { message, quarantine } => {
            println!("🛡️ Scanning payload for secrets & compliance PII...");
            let scanner = vortex_guard::PiiScanner::new();
            match scanner.scan(message.as_bytes(), quarantine) {
                vortex_guard::PiiAction::Allow => {
                    println!("✅ Status: CLEAN. No exposed credentials, private keys, or credit cards detected.");
                }
                vortex_guard::PiiAction::Mask(masked_bytes) => {
                    println!("⚠️ Status: REDACTED.");
                    println!("   Cleaned Payload: {}", String::from_utf8_lossy(&masked_bytes));
                }
                vortex_guard::PiiAction::Quarantine(reason) => {
                    println!("❌ Status: QUARANTINED (Ingress Policy Violation).");
                    println!("   Reason: {}", reason);
                }
            }
        }
        Commands::BlindTag { salt, value } => {
            let mut salt_bytes = [0u8; 32];
            let hash = blake3::hash(salt.as_bytes());
            salt_bytes.copy_from_slice(hash.as_bytes());

            let tag = vortex_core::BlindIndexer::compute_tag(&salt_bytes, &value);
            let tag_hex = vortex_core::BlindIndexer::to_hex(&tag);

            println!("🔐 Zero-Knowledge Blind Search Tag:");
            println!("   Input Value: \"{}\"", value);
            println!("   Salt Hash:   0x{}", &hex::encode(salt_bytes)[..16]);
            println!("   Blind Tag:   0x{}", tag_hex);
            println!("   Broker can index & route on this tag without decrypting plaintext.");
        }
        Commands::ShredDemo { entity, payload } => {
            println!("⚡ Cryptographic Shredding Ledger Demonstration (GDPR Right-to-be-Forgotten):");
            let master_key = [0x5au8; 32];
            let registry = vortex_core::EntityKeyRegistry::new(master_key);

            println!("   1. Generating derived 256-bit DEK for entity '{}'...", entity);
            let nonce = 1001u64;

            println!("   2. Encrypting payload with ChaCha20-Poly1305...");
            let ciphertext = registry.encrypt_payload(&entity, nonce, payload.as_bytes())?;
            println!("      Ciphertext ({} bytes): 0x{}...", ciphertext.len(), &hex::encode_bytes(&ciphertext)[..24]);

            println!("   3. Verifying decryption with active key...");
            let decrypted = registry.decrypt_payload(&entity, nonce, &ciphertext)?;
            println!("      Decrypted: \"{}\" ✅", String::from_utf8_lossy(&decrypted));

            println!("   4. Invoking GDPR shred_entity('{}')...", entity);
            registry.shred_entity(&entity);
            println!("      DEK zeroized from memory and marked shredded ✅");

            println!("   5. Attempting post-shred decryption of immutable log payload...");
            match registry.decrypt_payload(&entity, nonce, &ciphertext) {
                Ok(_) => panic!("Decryption should not succeed after shredding!"),
                Err(e) => {
                    println!("      Result: {} 🛡️", e);
                    println!("      The append-only log remains untouched and Blake3 hash chain intact,");
                    println!("      but the data payload is mathematically rendered irreversible white noise.");
                }
            }
        }
    }

    Ok(())
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn encode_bytes(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
