use std::fs::OpenOptions;
use std::sync::Arc;
use bytes::Bytes;
use tempfile::tempdir;
use vortex_storage::batch_io::{SqpollConfig, SqpollSubmissionRing, BatchedWriteRequest, BatchedPositionalIo};

#[test]
fn test_sqpoll_ring_submission_and_flush() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("sqpoll_test.dat");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&file_path)
        .unwrap();
    let file = Arc::new(file);

    let config = SqpollConfig {
        queue_depth: 256,
        idle_timeout_ms: 10,
        force_sync: false,
    };

    let ring = SqpollSubmissionRing::new(config).expect("failed to init sqpoll ring");

    // Submit asynchronous positional writes
    ring.submit_write(file.clone(), 0, Bytes::from_static(b"HELLO_SQPOLL_"))
        .expect("write submit failed");
    ring.submit_write(file.clone(), 13, Bytes::from_static(b"KERNEL_SUBMISSION_RING"))
        .expect("write submit failed");

    // Flush ring completions
    ring.flush().expect("flush failed");

    let stats = ring.stats();
    assert_eq!(stats.submissions, 2);
    assert_eq!(stats.completions, 2);

    // Read back through BatchedPositionalIo
    let ranges = vec![(0, 13), (13, 22)];
    let buffers = BatchedPositionalIo::read_batch(&file, &ranges).expect("read failed");
    assert_eq!(&buffers[0], b"HELLO_SQPOLL_");
    assert_eq!(&buffers[1], b"KERNEL_SUBMISSION_RING");
}

#[test]
fn test_sqpoll_atomic_write_and_sync() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("sqpoll_sync_test.dat");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&file_path)
        .unwrap();
    let file = Arc::new(file);

    let config = SqpollConfig {
        queue_depth: 128,
        idle_timeout_ms: 5,
        force_sync: true,
    };

    let ring = SqpollSubmissionRing::new(config).expect("failed to init sqpoll ring");

    // Submit coalesced write + fsync operation
    ring.submit_write_and_sync(file.clone(), 0, Bytes::from_static(b"ATOMIC_FSYNC_COALESCED"))
        .expect("write_and_sync failed");

    ring.flush().expect("flush failed");

    let stats = ring.stats();
    assert_eq!(stats.submissions, 1);
    assert_eq!(stats.completions, 1);
    assert!(stats.fsyncs >= 1);

    // Read back and verify content
    let ranges = vec![(0, 22)];
    let buffers = BatchedPositionalIo::read_batch(&file, &ranges).expect("read failed");
    assert_eq!(&buffers[0], b"ATOMIC_FSYNC_COALESCED");
}

#[test]
fn test_sqpoll_batch_submission() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("sqpoll_batch.dat");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&file_path)
        .unwrap();
    let file = Arc::new(file);

    let ring = SqpollSubmissionRing::new(SqpollConfig::default()).expect("init ring");

    let batch = vec![
        BatchedWriteRequest {
            file_position: 0,
            data: Bytes::from_static(b"CHUNK_001_"),
        },
        BatchedWriteRequest {
            file_position: 10,
            data: Bytes::from_static(b"CHUNK_002_"),
        },
        BatchedWriteRequest {
            file_position: 20,
            data: Bytes::from_static(b"CHUNK_003"),
        },
    ];

    let bytes_submitted = ring.submit_batch(file.clone(), &batch, true).expect("submit batch");
    assert_eq!(bytes_submitted, 29);

    ring.flush().expect("flush failed");

    let stats = ring.stats();
    assert_eq!(stats.submissions, 1);
    assert_eq!(stats.completions, 1);
    assert_eq!(stats.fsyncs, 1);

    // Verify all 3 chunks in file
    let ranges = vec![(0, 29)];
    let buffers = BatchedPositionalIo::read_batch(&file, &ranges).expect("read failed");
    assert_eq!(&buffers[0], b"CHUNK_001_CHUNK_002_CHUNK_003");
}

