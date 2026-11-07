use tempfile::tempdir;
use bytes::Bytes;
use vortex_core::record::Record;
use vortex_protocol::ProduceRequest;
use vortex_server::engine::Engine;

#[tokio::test]
async fn test_engine_zero_copy_locate_and_splice_end_to_end() {
    let dir = tempdir().unwrap();
    let engine = Engine::new(dir.path().to_path_buf());

    // Produce 25 records
    for i in 0..25 {
        let req = ProduceRequest {
            topic: "network.telemetry".to_string(),
            partition: 0,
            key: Some(Bytes::from(format!("node-{i}"))),
            value: Bytes::from(format!("packet-sample-{i}-content-padding")),
        };
        let resp = engine.produce(req).await.unwrap();
        assert_eq!(resp.offset, i as u64);
    }

    // 1. Verify locate_record_slice returns exact physical boundaries
    let slice_info = engine
        .locate_record_slice("network.telemetry", 0, 10, 1024 * 1024)
        .await
        .unwrap()
        .expect("Record slice must exist");

    assert!(slice_info.1 > 0, "file position must be positive");
    assert!(slice_info.2 > 0, "slice length must be positive");

    #[cfg(unix)]
    {
        // 2. Splice directly to a Unix domain socketpair
        let mut sock_fds = [0i32; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sock_fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair must be created");
        let read_fd = sock_fds[0];
        let write_fd = sock_fds[1];

        let spliced_bytes = engine
            .splice_records_to_fd("network.telemetry", 0, 10, 1024 * 1024, write_fd)
            .await
            .unwrap();
        assert_eq!(spliced_bytes, slice_info.2);

        unsafe { libc::close(write_fd) };

        // Read all spliced bytes from socket
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        unsafe { libc::close(read_fd) };

        assert_eq!(buf.len() as u64, spliced_bytes);

        // Verify decoded records match exactly starting from offset 10 to 24
        let mut reader = &buf[..];
        let mut decoded = Vec::new();
        while !reader.is_empty() {
            let rec = Record::decode(&mut reader).unwrap();
            decoded.push(rec);
        }

        assert_eq!(decoded.len(), 15);
        assert_eq!(decoded[0].offset, 10);
        assert_eq!(decoded[14].offset, 24);
        assert_eq!(decoded[0].key, Some(Bytes::from("node-10")));
    }
}

