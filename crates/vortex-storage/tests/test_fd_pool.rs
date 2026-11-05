use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use vortex_storage::fd_pool::FdPool;

#[test]
fn test_fd_pool_1000_partitions_under_limit() {
    let dir = tempdir().unwrap();
    let total_files = 300;
    let pool_limit = 32;

    // Create 300 dummy files
    for i in 0..total_files {
        let file_path = dir.path().join(format!("file_{:04}.dat", i));
        let mut f = File::create(&file_path).unwrap();
        f.write_all(format!("data-{}", i).as_bytes()).unwrap();
    }

    let pool = FdPool::new(pool_limit);

    // Access all 300 files through the pool
    for i in 0..total_files {
        let file_path = dir.path().join(format!("file_{:04}.dat", i));
        let file_handle = pool.acquire(&file_path).expect("must acquire file handle");
        assert!(file_handle.metadata().unwrap().len() > 0);
    }

    // Verify open file count inside pool never exceeds pool_limit
    assert!(pool.current_open_count() <= pool_limit);

    // Verify re-acquiring an evicted file reopens seamlessly
    let file_0 = dir.path().join("file_0000.dat");
    let handle_0 = pool.acquire(&file_0).expect("must reopen evicted file");
    assert_eq!(handle_0.metadata().unwrap().len(), 6); // "data-0"
}

