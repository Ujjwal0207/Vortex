use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error};

use vortex_protocol::kafka::KafkaFrame;
use vortex_protocol::{Frame, VTX_MAGIC};

use crate::bridge::KafkaBridge;
use crate::coordinator::ConsumerGroupCoordinator;
use crate::engine::Engine;

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB max frame size

pub async fn handle_connection(
    socket: TcpStream,
    engine: Arc<Engine>,
    coordinator: Arc<ConsumerGroupCoordinator>,
) {
    let (mut reader, mut writer) = socket.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(128);

    // Dedicated background writer task: flushes serialized frames to the network
    // without blocking incoming request parsing (eliminating Head-of-Line write stalls, Flaw 4.2)
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if let Err(e) = writer.write_all(&bytes).await {
                debug!("Client write error: {}", e);
                break;
            }
        }
    });

    let mut buffer = BytesMut::with_capacity(64 * 1024);

    loop {
        // Enforce maximum buffer ceiling to prevent memory exhaustion DoS (Flaw 4.1)
        if buffer.len() > MAX_FRAME_SIZE {
            error!(
                "Inbound frame buffer exceeded limit ({} > {} bytes); closing connection",
                buffer.len(),
                MAX_FRAME_SIZE
            );
            break;
        }

        // Multiplex protocol based on magic bytes:
        // "VTX0" (0x56545830) indicates native Vortex binary framing;
        // any other prefix is processed via standard Kafka Wire Protocol (port 9092).
        let is_native = if buffer.len() >= 4 {
            u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) == VTX_MAGIC
        } else {
            false
        };

        if is_native {
            match Frame::decode(&mut buffer) {
                Ok(Some(frame)) => {
                    let response = engine.handle_frame(frame).await;
                    let encoded_response = response.encode();

                    if tx.send(encoded_response).await.is_err() {
                        break;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Protocol violation from client: {}, closing connection", e);
                    break;
                }
            }
        } else {
            match KafkaFrame::decode(&mut buffer) {
                Ok(Some(kafka_frame)) => {
                    let response_bytes = KafkaBridge::handle_frame(
                        kafka_frame,
                        Arc::clone(&engine),
                        Arc::clone(&coordinator),
                    )
                    .await;

                    if response_bytes.is_empty() {
                        // The bridge uses an empty result for unknown APIs and
                        // unsupported versions whose response schema is unknown.
                        break;
                    }

                    if tx.send(response_bytes).await.is_err() {
                        break;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Kafka protocol decode error: {}, closing connection", e);
                    break;
                }
            }
        }

        match reader.read_buf(&mut buffer).await {
            Ok(0) => {
                debug!("Client disconnected gracefully");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                error!("Socket read error: {}", e);
                break;
            }
        }
    }

    drop(tx);
    let _ = writer_task.await;
}
