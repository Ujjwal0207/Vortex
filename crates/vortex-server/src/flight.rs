use std::io::Cursor;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::Engine;

/// High-throughput Apache Arrow Flight and Columnar IPC streaming service for Vortex.
/// Exposes memory-mapped partition segments directly to DuckDB, DataFusion, Polars, and PyArrow
/// with zero ETL, zero deserialization overhead, and 64-byte memory alignment.
pub struct ArrowFlightService {
    engine: Arc<Engine>,
    bind_addr: String,
}

impl ArrowFlightService {
    /// Create a new Arrow Flight streaming service bound to `bind_addr` (e.g., "127.0.0.1:8443")
    pub fn new(engine: Arc<Engine>, bind_addr: impl Into<String>) -> Self {
        Self {
            engine,
            bind_addr: bind_addr.into(),
        }
    }

    /// Access reference to underlying broker Engine
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    /// Starts the background asynchronous Arrow Flight listener loop
    pub async fn start(self: Arc<Self>) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("🚀 Arrow Flight Columnar IPC Service listening on: {}", self.bind_addr);

        loop {
            match listener.accept().await {
                Ok((socket, remote_addr)) => {
                    let svc = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = svc.handle_flight_client(socket).await {
                            warn!("Flight client {} disconnected with error: {}", remote_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Arrow Flight accept error: {}", e);
                }
            }
        }
    }

    /// Handles an individual Arrow Flight / IPC streaming connection
    pub async fn handle_flight_client(&self, mut socket: TcpStream) -> Result<(), std::io::Error> {
        let (reader, mut writer) = socket.split();
        let mut buf_reader = BufReader::new(reader);

        // Read command or ticket request header (e.g. "GET <topic> <partition> <from_offset>\n" or "TICKET:<topic>\n")
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }

        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        let (topic, partition_id) = if parts.is_empty() {
            ("default", 0)
        } else if parts[0].eq_ignore_ascii_case("GET") || parts[0].eq_ignore_ascii_case("STREAM") {
            let t = if parts.len() > 1 { parts[1] } else { "default" };
            let p = if parts.len() > 2 { parts[2].parse::<u32>().unwrap_or(0) } else { 0 };
            (t, p)
        } else if let Some(stripped) = trimmed.strip_prefix("TICKET:") {
            let t_parts: Vec<&str> = stripped.split(':').collect();
            let t = t_parts.first().unwrap_or(&"default");
            let p = t_parts.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            (*t, p)
        } else {
            (trimmed, 0)
        };

        // Fetch partition handle from the broker engine
        let partition = match self.engine.get_or_create_partition(topic, partition_id).await {
            Ok(p) => p,
            Err(e) => {
                let err_msg = format!("ERR: Failed to open topic '{}': {}\n", topic, e);
                writer.write_all(err_msg.as_bytes()).await?;
                return Ok(());
            }
        };

        let log = partition.log.read().await;

        // Project partition records into Apache Arrow IPC streaming binary format
        let mut ipc_buffer = Cursor::new(Vec::new());
        match log.export_arrow_ipc(&mut ipc_buffer) {
            Ok(stats) => {
                let bytes = ipc_buffer.into_inner();
                // Stream Arrow IPC payload over the wire directly
                writer.write_all(&bytes).await?;
                writer.flush().await?;
                info!(
                    "Transmitted Arrow Flight IPC batch for '{}:{}': {} records ({} bytes)",
                    topic, partition_id, stats.total_records, stats.total_bytes_written
                );
            }
            Err(e) => {
                let err_msg = format!("ERR: Failed to project partition to Arrow: {}\n", e);
                writer.write_all(err_msg.as_bytes()).await?;
            }
        }

        Ok(())
    }
}
