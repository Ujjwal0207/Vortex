use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vortex_protocol::ProduceRequest;
use vortex_server::{ArrowFlightService, Engine};
use vortex_storage::ARROW_CONTINUATION_TOKEN;

#[tokio::test]
async fn test_arrow_flight_ipc_streaming_service() {
    let tmp = tempdir().unwrap();
    let engine = Arc::new(Engine::new(tmp.path().to_path_buf()));

    let topic = "flight-analytics-topic";
    let partition_id = 0;

    // 1. Ingest 25 sample events into the partition
    for i in 0..25 {
        let req = ProduceRequest {
            topic: topic.to_string(),
            partition: partition_id,
            key: Some(bytes::Bytes::from(format!("agent-{}", i))),
            value: bytes::Bytes::from(format!("{{\"model\":\"claude-3-7-sonnet\",\"step\":{}}}", i)),
        };
        engine.produce(req).await.unwrap();
    }

    // 2. Bind ephemeral Arrow Flight server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flight_addr = listener.local_addr().unwrap();

    let flight_service = Arc::new(ArrowFlightService::new(Arc::clone(&engine), flight_addr.to_string()));

    // Spawn flight accept loop
    let svc_clone = Arc::clone(&flight_service);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let s = Arc::clone(&svc_clone);
            tokio::spawn(async move {
                let _ = s.handle_flight_client(socket).await;
            });
        }
    });

    // 3. Connect client socket and issue ticket request
    let mut client = match TcpStream::connect(flight_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("Skipping live TCP flight test due to sandbox permissions");
            return;
        }
        Err(e) => panic!("Failed to connect to Flight service: {}", e),
    };

    client.write_all(b"STREAM flight-analytics-topic 0 0\n").await.unwrap();

    // 4. Read streamed Arrow IPC buffer
    let mut received_bytes = Vec::new();
    client.read_to_end(&mut received_bytes).await.unwrap();

    assert!(received_bytes.len() > 100, "Received bytes must contain Arrow IPC stream");

    // 5. Verify Arrow Continuation Token (0xFFFFFFFF)
    let token = u32::from_le_bytes(received_bytes[0..4].try_into().unwrap());
    assert_eq!(token, ARROW_CONTINUATION_TOKEN, "Must begin with Arrow IPC continuation token");

    // 6. Verify Schema contains required Vortex metadata columns
    let stream_str = String::from_utf8_lossy(&received_bytes);
    assert!(stream_str.contains("_vtx_offset"), "Arrow schema must contain _vtx_offset");
    assert!(stream_str.contains("_vtx_timestamp"), "Arrow schema must contain _vtx_timestamp");
    assert!(stream_str.contains("_vtx_record_hash"), "Arrow schema must contain _vtx_record_hash");
    assert!(stream_str.contains("_vtx_mmr_root"), "Arrow schema must contain _vtx_mmr_root");
    assert!(stream_str.contains("_vtx_payload"), "Arrow schema must contain _vtx_payload");

    // 7. Verify EOS (End of Stream) zero marker at end of payload
    let len = received_bytes.len();
    assert_eq!(&received_bytes[len - 4..len], &[0, 0, 0, 0], "Arrow IPC stream must terminate with 4-byte 0x0 EOS marker");

    println!("✅ Verified live Arrow Flight Columnar IPC streaming: received {} bytes.", received_bytes.len());
}
