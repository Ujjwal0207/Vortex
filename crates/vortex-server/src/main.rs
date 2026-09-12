use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod connection;
mod engine;

use connection::handle_connection;
use engine::Engine;

#[derive(Parser, Debug)]
#[command(name = "vortex-server", version = "0.1.0", about = "Vortex Next-Gen Event Streaming Broker")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,

    #[arg(short, long, default_value_t = 9092)]
    port: u16,

    #[arg(short, long, default_value = "./data/vortex")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);

    info!("============================================================");
    info!("             🌀 VORTEX STREAMING BROKER v0.1.0               ");
    info!("   Self-Defending, Cryptographically Verifiable Event Engine");
    info!("============================================================");
    info!("Listening on: {}", addr);
    info!("Data directory: {}", args.data_dir.display());

    let engine = Arc::new(Engine::new(args.data_dir));
    let listener = TcpListener::bind(&addr).await?;

    loop {
        match listener.accept().await {
            Ok((socket, _remote_addr)) => {
                let engine_clone = Arc::clone(&engine);
                tokio::spawn(async move {
                    handle_connection(socket, engine_clone).await;
                });
            }
            Err(e) => {
                error!("Failed to accept incoming TCP connection: {}", e);
            }
        }
    }
}
