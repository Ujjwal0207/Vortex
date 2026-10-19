use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use tempfile::tempdir;

use vortex::*;

#[test]
fn test_libvortex_offline_write_and_verify() {
    let dir = tempdir().unwrap();
    let base_dir_c = CString::new(dir.path().to_str().unwrap()).unwrap();
    let topic_c = CString::new("audit-reel").unwrap();

    // 1. Open partition and write 1,200 records with small segment size to force segment rolls
    let (final_mmr_root, final_record_hash) = unsafe {
        let handle = vtx_open(base_dir_c.as_ptr(), topic_c.as_ptr(), 0, 64 * 1024);
        assert!(!handle.is_null());

        let mut offset = 0u64;
        let mut rec_hash = [0u8; 32];
        let mut mmr_root = [0u8; 32];
        let mut mac = [0u8; 32];

        // 200 single appends
        for i in 0..200 {
            let key = format!("user-{:04}", i);
            let val = format!("{{\"action\":\"login\",\"ip\":\"10.0.0.{}\"}}", i % 250);
            let res = vtx_append(
                handle,
                key.as_ptr(),
                key.len(),
                val.as_ptr(),
                val.len(),
                &mut offset,
                rec_hash.as_mut_ptr(),
                mmr_root.as_mut_ptr(),
                mac.as_mut_ptr(),
            );
            assert_eq!(res, VTX_OK);
            assert_eq!(offset, i as u64);
        }

        // 1,000 batch appends in two chunks of 500
        for chunk in 0..2 {
            let start_id = 200 + chunk * 500;
            let keys_str: Vec<String> = (0..500).map(|j| format!("user-{:04}", start_id + j)).collect();
            let vals_str: Vec<String> = (0..500).map(|j| format!("{{\"action\":\"event\",\"id\":{}}}", start_id + j)).collect();

            let key_ptrs: Vec<*const u8> = keys_str.iter().map(|k| k.as_ptr()).collect();
            let key_lens: Vec<usize> = keys_str.iter().map(|k| k.len()).collect();
            let val_ptrs: Vec<*const u8> = vals_str.iter().map(|v| v.as_ptr()).collect();
            let val_lens: Vec<usize> = vals_str.iter().map(|v| v.len()).collect();

            let mut start_off = 0u64;
            let mut end_off = 0u64;

            let res = vtx_append_batch(
                handle,
                key_ptrs.as_ptr(),
                key_lens.as_ptr(),
                val_ptrs.as_ptr(),
                val_lens.as_ptr(),
                500,
                &mut start_off,
                &mut end_off,
                rec_hash.as_mut_ptr(),
                mmr_root.as_mut_ptr(),
            );
            assert_eq!(res, VTX_OK);
            assert_eq!(start_off, start_id as u64);
            assert_eq!(end_off, (start_id + 499) as u64);
        }

        // Close partition completely
        assert_eq!(vtx_flush(handle), VTX_OK);
        assert_eq!(vtx_close(handle), VTX_OK);

        (mmr_root, rec_hash)
    };

    // 2. Standalone Offline Verification with NO server running
    let partition_dir = dir.path().join("audit-reel").join("partition-0");
    let partition_dir_c = CString::new(partition_dir.to_str().unwrap()).unwrap();

    let mut verified_count = 0u64;
    let mut verified_root = [0u8; 32];
    let mut verified_hash = [0u8; 32];

    unsafe {
        let audit_res = vtx_verify_partition(
            partition_dir_c.as_ptr(),
            topic_c.as_ptr(),
            0,
            &mut verified_count,
            verified_root.as_mut_ptr(),
            verified_hash.as_mut_ptr(),
        );

        assert_eq!(audit_res, 1, "offline verification must pass for intact partition");
        assert_eq!(verified_count, 1200);
        assert_eq!(verified_root, final_mmr_root);
        assert_eq!(verified_hash, final_record_hash);
    }

    // 3. Test tamper detection: corrupt 1 byte in active segment data region
    let active_vtx = partition_dir.join("00000000000000000000.vtx");
    if active_vtx.exists() {
        let mut f = OpenOptions::new().read(true).write(true).open(&active_vtx).unwrap();
        f.seek(SeekFrom::Start(65536 + 10)).unwrap(); // Inside record payload
        let mut byte = [0u8; 1];
        byte[0] ^= 0x55;
        f.write_all(&byte).unwrap();
        f.sync_data().unwrap();

        // Verification must now fail!
        unsafe {
            let corrupt_res = vtx_verify_partition(
                partition_dir_c.as_ptr(),
                topic_c.as_ptr(),
                0,
                &mut verified_count,
                verified_root.as_mut_ptr(),
                verified_hash.as_mut_ptr(),
            );
            assert_ne!(corrupt_res, 1, "tampered file must be rejected by offline verification");
        }
    }
}
