use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod bridge;
mod connection;
mod coordinator;
mod engine;

use connection::handle_connection;
use coordinator::ConsumerGroupCoordinator;
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

    let engine = Arc::new(Engine::new(args.data_dir.clone()));
    let coordinator = Arc::new(ConsumerGroupCoordinator::new(&args.data_dir, std::time::Duration::from_secs(30))?);
    let listener = TcpListener::bind(&addr).await?;

    loop {
        match listener.accept().await {
            Ok((socket, _remote_addr)) => {
                let engine_clone = Arc::clone(&engine);
                let coordinator_clone = Arc::clone(&coordinator);
                tokio::spawn(async move {
                    handle_connection(socket, engine_clone, coordinator_clone).await;
                });
            }
            Err(e) => {
                error!("Failed to accept incoming TCP connection: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use vortex_protocol::kafka::KafkaCodec;
    use vortex_protocol::{Frame, MessageType, ProduceRequest, ProduceResponse};

    #[tokio::test]
    async fn test_live_tcp_dual_protocol_multiplexing() {
        let tmp = tempdir().unwrap();
        let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));
        let coordinator = Arc::new(ConsumerGroupCoordinator::new(tmp.path(), std::time::Duration::from_secs(30)).unwrap());

        // Bind ephemeral loopback TCP port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Spawn server loop in background
        let eng_srv = Arc::clone(&engine);
        let coord_srv = Arc::clone(&coordinator);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    let e = Arc::clone(&eng_srv);
                    let c = Arc::clone(&coord_srv);
                    tokio::spawn(handle_connection(socket, e, c));
                }
            }
        });

        // -------------------------------------------------------------
        // CLIENT 1: Native Vortex Protocol Client (b"VTX0" Framing)
        // -------------------------------------------------------------
        let mut native_socket = TcpStream::connect(server_addr).await.unwrap();

        // Send native ProduceReq
        let produce_body = ProduceRequest {
            topic: "iot-stream".to_string(),
            partition: 0,
            key: Some(Bytes::from("device-101")),
            value: Bytes::from("speed: 120km/h"),
        }
        .encode(501);

        native_socket.write_all(&produce_body.encode()).await.unwrap();

        // Read native ProduceResp
        let mut native_buf = BytesMut::with_capacity(4096);
        let frame = loop {
            if let Ok(Some(f)) = Frame::decode(&mut native_buf) {
                break f;
            }
            native_socket.read_buf(&mut native_buf).await.unwrap();
        };

        assert_eq!(frame.req_id, 501);
        assert_eq!(frame.msg_type, MessageType::ProduceResp);
        let resp = ProduceResponse::decode(&mut frame.payload.clone()).unwrap();
        assert_eq!(resp.offset, 0);

        // -------------------------------------------------------------
        // CLIENT 2: Standard Kafka Wire Protocol Client (Port 9092)
        // -------------------------------------------------------------
        let mut kafka_socket = TcpStream::connect(server_addr).await.unwrap();

        // 1. Send Kafka ApiVersions Request (ApiKey 18, CorrelationId 777)
        let mut api_req = BytesMut::new();
        api_req.put_i16(18); // ApiVersions
        api_req.put_i16(1);  // v1
        api_req.put_i32(777); // CorrelationId
        KafkaCodec::put_string(&mut api_req, "confluent-python-client");

        let total_size = api_req.len() as i32;
        let mut raw_kafka = BytesMut::new();
        raw_kafka.put_i32(total_size);
        raw_kafka.put_slice(&api_req);

        kafka_socket.write_all(&raw_kafka).await.unwrap();

        // Read Kafka ApiVersions Response
        let mut k_resp_buf = BytesMut::with_capacity(4096);
        let k_frame = loop {
            if k_resp_buf.len() >= 4 {
                let size = u32::from_be_bytes([k_resp_buf[0], k_resp_buf[1], k_resp_buf[2], k_resp_buf[3]]) as usize;
                if k_resp_buf.len() >= 4 + size {
                    k_resp_buf.advance(4);
                    break k_resp_buf.split_to(size).freeze();
                }
            }
            kafka_socket.read_buf(&mut k_resp_buf).await.unwrap();
        };

        let mut r = &k_frame[..];
        assert_eq!(r.get_i32(), 777); // Matching correlation ID
        assert_eq!(r.get_i16(), 0);   // ErrorCode: NONE
        let api_count = r.get_i32();
        assert_eq!(api_count, 12);    // APIs currently advertised by the bridge.
    }
}
