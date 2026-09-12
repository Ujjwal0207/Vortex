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
    }

    Ok(())
}

mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
