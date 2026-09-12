use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error};

use vortex_protocol::Frame;

use crate::engine::Engine;

pub async fn handle_connection(mut socket: TcpStream, engine: Arc<Engine>) {
    let mut buffer = BytesMut::with_capacity(64 * 1024);

    loop {
        // Try decoding an existing frame in the buffer
        match Frame::decode(&mut buffer) {
            Ok(Some(frame)) => {
                let response = engine.handle_frame(frame).await;
                let encoded_response = response.encode();

                if let Err(e) = socket.write_all(&encoded_response).await {
                    error!("Failed to write frame to client: {}", e);
                    return;
                }
                continue;
            }
            Ok(None) => {
                // Incomplete frame, read more bytes from TCP socket
            }
            Err(e) => {
                error!("Protocol violation from client: {}, closing connection", e);
                return;
            }
        }

        match socket.read_buf(&mut buffer).await {
            Ok(0) => {
                debug!("Client disconnected gracefully");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                error!("Socket read error: {}", e);
                return;
            }
        }
    }
}
