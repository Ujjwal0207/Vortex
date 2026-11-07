use tempfile::tempdir;
use bytes::Bytes;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use vortex_core::{compute_genesis_hash, record::Record};
use vortex_storage::partition::PartitionLog;
use vortex_storage::segment::{Segment, HEADER_INDEX_REGION_SIZE};

#[test]
fn test_segment_locate_record_slice_exact_byte_boundaries() {
    let dir = tempdir().unwrap();
    let genesis = compute_genesis_hash("test-slice", 0);
    let mut seg = Segment::open_or_create(dir.path(), 100, genesis).unwrap();

    for i in 0..20 {
        let key = Some(Bytes::from(format!("key-{i}")));
        let val = Bytes::from(format!("payload-content-{i}-with-extra-bytes"));
        seg.append(key, val).unwrap();
    }

    assert_eq!(seg.next_offset, 120);

    // 1. Locate entire range from offset 100
    let (pos, len) = seg.locate_record_slice(100, 1024 * 1024).unwrap().expect("Slice must exist");
    assert_eq!(pos, HEADER_INDEX_REGION_SIZE);
    assert!(len > 0);

    // Read exact slice directly from file at (pos, len)
    let file = seg.get_file().unwrap();
    let mut slice_bytes = vec![0u8; len as usize];
    #[cfg(unix)]
    file.read_exact_at(&mut slice_bytes, pos).unwrap();

    // Verify all 20 records decode with 100% cryptographic integrity
    let mut reader = &slice_bytes[..];
    let mut decoded_records = Vec::new();
    while !reader.is_empty() {
        let rec = Record::decode(&mut reader).unwrap();
        decoded_records.push(rec);
    }
    assert_eq!(decoded_records.len(), 20);
    assert_eq!(decoded_records[0].offset, 100);
    assert_eq!(decoded_records[19].offset, 119);

    // 2. Locate sub-range starting at offset 105
    let (sub_pos, sub_len) = seg.locate_record_slice(105, 1024 * 1024).unwrap().expect("Sub-slice must exist");
    assert!(sub_pos > pos);
    assert!(sub_len < len);

    let mut sub_slice = vec![0u8; sub_len as usize];
    #[cfg(unix)]
    file.read_exact_at(&mut sub_slice, sub_pos).unwrap();

    let mut sub_reader = &sub_slice[..];
    let first_rec = Record::decode(&mut sub_reader).unwrap();
    assert_eq!(first_rec.offset, 105);

    // 3. Out-of-bounds offset returns None
    assert!(seg.locate_record_slice(99, 1024).unwrap().is_none());
    assert!(seg.locate_record_slice(120, 1024).unwrap().is_none());
    assert!(seg.locate_record_slice(100, 0).unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn test_partition_splice_records_to_pipe_descriptor() {
    let dir = tempdir().unwrap();
    let mut partition = PartitionLog::open_or_create(dir.path(), "spliced-stream", 0, 64 * 1024 * 1024).unwrap();

    for i in 0..15 {
        let val = Bytes::from(format!("streamed-payload-item-{i}"));
        partition.append(None, val).unwrap();
    }

    assert_eq!(partition.next_offset(), 15);

    // Create a connected UNIX domain stream socketpair to receive spliced kernel page-cache bytes
    // (macOS sendfile(2) requires a stream socket descriptor for out_fd).
    let mut sock_fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sock_fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair creation must succeed");
    let read_fd = sock_fds[0];
    let write_fd = sock_fds[1];

    // Splice records starting at offset 3 directly to write_fd via kernel sendfile
    let spliced_bytes = partition.splice_records_to_fd(3, 1024 * 1024, write_fd).unwrap();
    assert!(spliced_bytes > 0, "Must have spliced bytes directly from page cache");

    // Close write_fd so reader encounters EOF
    unsafe { libc::close(write_fd) };

    // Read all bytes from read_fd
    let mut socket_data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if n <= 0 {
            break;
        }
        socket_data.extend_from_slice(&chunk[..n as usize]);
    }
    unsafe { libc::close(read_fd) };

    assert_eq!(socket_data.len() as u64, spliced_bytes);

    // Decode records from received socket data
    let mut reader = &socket_data[..];
    let mut decoded = Vec::new();
    while !reader.is_empty() {
        let rec = Record::decode(&mut reader).unwrap();
        decoded.push(rec);
    }

    assert_eq!(decoded.len(), 12); // records 3 through 14
    assert_eq!(decoded[0].offset, 3);
    assert_eq!(decoded[11].offset, 14);
    assert_eq!(decoded[0].value, Bytes::from("streamed-payload-item-3"));
}
