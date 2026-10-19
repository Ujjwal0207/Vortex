use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Mutex;

use bytes::Bytes;
use vortex_core::MmrInclusionProof;
use vortex_storage::{PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

// ============================================================================
// Status and Error Codes
// ============================================================================

pub const VTX_OK: i32 = 0;
pub const VTX_ERR_NULL_PTR: i32 = -1;
pub const VTX_ERR_IO: i32 = -2;
pub const VTX_ERR_CORRUPTION: i32 = -3;
pub const VTX_ERR_OFFSET_OUT_OF_RANGE: i32 = -4;
pub const VTX_ERR_VERIFICATION_FAILED: i32 = -5;
pub const VTX_ERR_BUFFER_TOO_SMALL: i32 = -6;
pub const VTX_ERR_INVALID_ARG: i32 = -7;

thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = msg;
    });
}

// ============================================================================
// Opaque FFI Handle
// ============================================================================

pub struct VtxPartition {
    inner: Mutex<PartitionLog>,
}

// ============================================================================
// C-ABI Exports
// ============================================================================

/// Opens or creates a sealed partition log at `base_dir/topic/partition-id/`.
/// Returns an opaque pointer handle on success, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn vtx_open(
    base_dir: *const c_char,
    topic: *const c_char,
    partition_id: u32,
    max_segment_bytes: u64,
) -> *mut VtxPartition {
    if base_dir.is_null() || topic.is_null() {
        set_last_error("base_dir or topic pointer is null".into());
        return std::ptr::null_mut();
    }

    let base_dir_str = match CStr::from_ptr(base_dir).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in base_dir: {e}"));
            return std::ptr::null_mut();
        }
    };

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in topic: {e}"));
            return std::ptr::null_mut();
        }
    };

    let max_bytes = if max_segment_bytes == 0 {
        DEFAULT_MAX_SEGMENT_BYTES
    } else {
        max_segment_bytes
    };

    match PartitionLog::open_or_create(Path::new(base_dir_str), topic_str, partition_id, max_bytes) {
        Ok(log) => Box::into_raw(Box::new(VtxPartition {
            inner: Mutex::new(log),
        })),
        Err(e) => {
            set_last_error(format!("failed to open partition log: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Appends a single record to the partition log with forward-secure ratchet authentication.
///
/// Parameters:
/// - `handle`: valid open partition handle
/// - `key`: optional key buffer (NULL if keyless)
/// - `key_len`: length of key in bytes
/// - `val`: payload buffer (must not be NULL)
/// - `val_len`: length of payload in bytes
/// - `out_offset`: outputs the assigned 64-bit monotonic offset
/// - `out_record_hash`: outputs the 32-byte Blake3 record hash
/// - `out_mmr_root`: outputs the 32-byte current Merkle Mountain Range bagged root
/// - `out_writer_mac`: optional outputs the 32-byte writer MAC (can be NULL)
#[no_mangle]
pub unsafe extern "C" fn vtx_append(
    handle: *mut VtxPartition,
    key: *const u8,
    key_len: usize,
    val: *const u8,
    val_len: usize,
    out_offset: *mut u64,
    out_record_hash: *mut u8,
    out_mmr_root: *mut u8,
    out_writer_mac: *mut u8,
) -> i32 {
    if handle.is_null() {
        set_last_error("null handle provided to vtx_append".into());
        return VTX_ERR_NULL_PTR;
    }
    if val.is_null() && val_len > 0 {
        set_last_error("val pointer is null but val_len > 0".into());
        return VTX_ERR_NULL_PTR;
    }

    let key_bytes = if !key.is_null() && key_len > 0 {
        Some(Bytes::copy_from_slice(std::slice::from_raw_parts(key, key_len)))
    } else {
        None
    };

    let val_bytes = if val_len > 0 {
        Bytes::copy_from_slice(std::slice::from_raw_parts(val, val_len))
    } else {
        Bytes::new()
    };

    let partition = &*handle;
    let mut log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    match log.append(key_bytes, val_bytes) {
        Ok(rec) => {
            if !out_offset.is_null() {
                *out_offset = rec.offset;
            }
            if !out_record_hash.is_null() {
                std::ptr::copy_nonoverlapping(rec.record_hash.as_ptr(), out_record_hash, 32);
            }
            if !out_mmr_root.is_null() {
                let root = log.active_segment().mmr_root();
                std::ptr::copy_nonoverlapping(root.as_ptr(), out_mmr_root, 32);
            }
            if !out_writer_mac.is_null() {
                if let Ok(Some(mac)) = log.writer_mac(rec.offset) {
                    std::ptr::copy_nonoverlapping(mac.as_ptr(), out_writer_mac, 32);
                } else {
                    std::ptr::write_bytes(out_writer_mac, 0, 32);
                }
            }
            VTX_OK
        }
        Err(e) => {
            set_last_error(format!("append failed: {e}"));
            VTX_ERR_IO
        }
    }
}

/// Appends a batch of records atomically in a single durable write.
#[no_mangle]
pub unsafe extern "C" fn vtx_append_batch(
    handle: *mut VtxPartition,
    keys: *const *const u8,
    key_lens: *const usize,
    vals: *const *const u8,
    val_lens: *const usize,
    count: usize,
    out_start_offset: *mut u64,
    out_end_offset: *mut u64,
    out_final_record_hash: *mut u8,
    out_final_mmr_root: *mut u8,
) -> i32 {
    if handle.is_null() {
        set_last_error("null handle provided to vtx_append_batch".into());
        return VTX_ERR_NULL_PTR;
    }
    if count == 0 {
        return VTX_OK;
    }
    if vals.is_null() || val_lens.is_null() {
        set_last_error("null vals or val_lens provided to vtx_append_batch".into());
        return VTX_ERR_NULL_PTR;
    }

    let val_ptrs = std::slice::from_raw_parts(vals, count);
    let val_lens_slice = std::slice::from_raw_parts(val_lens, count);

    let key_ptrs = if !keys.is_null() && !key_lens.is_null() {
        Some((
            std::slice::from_raw_parts(keys, count),
            std::slice::from_raw_parts(key_lens, count),
        ))
    } else {
        None
    };

    let mut batch = Vec::with_capacity(count);
    for i in 0..count {
        let key_bytes = if let Some((k_ptrs, k_lens)) = key_ptrs {
            let k_ptr = k_ptrs[i];
            let k_len = k_lens[i];
            if !k_ptr.is_null() && k_len > 0 {
                Some(Bytes::copy_from_slice(std::slice::from_raw_parts(k_ptr, k_len)))
            } else {
                None
            }
        } else {
            None
        };

        let v_ptr = val_ptrs[i];
        let v_len = val_lens_slice[i];
        let val_bytes = if !v_ptr.is_null() && v_len > 0 {
            Bytes::copy_from_slice(std::slice::from_raw_parts(v_ptr, v_len))
        } else {
            Bytes::new()
        };

        batch.push((key_bytes, val_bytes, None));
    }

    let partition = &*handle;
    let mut log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    match log.append_batch(batch) {
        Ok(results) => {
            if let Some(first) = results.first() {
                if !out_start_offset.is_null() {
                    *out_start_offset = first.offset;
                }
            }
            if let Some(last) = results.last() {
                if !out_end_offset.is_null() {
                    *out_end_offset = last.offset;
                }
                if !out_final_record_hash.is_null() {
                    std::ptr::copy_nonoverlapping(last.record_hash.as_ptr(), out_final_record_hash, 32);
                }
            }
            if !out_final_mmr_root.is_null() {
                let root = log.active_segment().mmr_root();
                std::ptr::copy_nonoverlapping(root.as_ptr(), out_final_mmr_root, 32);
            }
            VTX_OK
        }
        Err(e) => {
            set_last_error(format!("batch append failed: {e}"));
            VTX_ERR_IO
        }
    }
}

/// Flushes pending file buffers and checkpoints the two-slot keyring to disk.
#[no_mangle]
pub unsafe extern "C" fn vtx_flush(handle: *mut VtxPartition) -> i32 {
    if handle.is_null() {
        set_last_error("null handle provided to vtx_flush".into());
        return VTX_ERR_NULL_PTR;
    }

    let partition = &*handle;
    let mut log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    match log.flush() {
        Ok(()) => VTX_OK,
        Err(e) => {
            set_last_error(format!("flush failed: {e}"));
            VTX_ERR_IO
        }
    }
}

/// Returns the next offset that will be assigned to an incoming message.
#[no_mangle]
pub unsafe extern "C" fn vtx_next_offset(handle: *mut VtxPartition, out_offset: *mut u64) -> i32 {
    if handle.is_null() || out_offset.is_null() {
        set_last_error("null pointer provided to vtx_next_offset".into());
        return VTX_ERR_NULL_PTR;
    }

    let partition = &*handle;
    let log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    *out_offset = log.next_offset();
    VTX_OK
}

/// Generates an O(log N) cryptographic Merkle Mountain Range inclusion proof for record at `offset`.
/// Serializes the proof into `out_buf` in format:
/// `[leaf_index: u64][peaks_count: u32][peaks: [32B...]][siblings_count: u32][siblings: [32B...]]`
#[no_mangle]
pub unsafe extern "C" fn vtx_prove(
    handle: *mut VtxPartition,
    offset: u64,
    out_buf: *mut u8,
    buf_len: usize,
    out_actual_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_actual_len.is_null() {
        set_last_error("null pointer provided to vtx_prove".into());
        return VTX_ERR_NULL_PTR;
    }

    let partition = &*handle;
    let log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    let proof = match log.generate_inclusion_proof(offset) {
        Some(p) => p,
        None => {
            set_last_error(format!("offset {offset} out of range or not found"));
            return VTX_ERR_OFFSET_OUT_OF_RANGE;
        }
    };

    let serialized = encode_proof(&proof);
    *out_actual_len = serialized.len();

    if out_buf.is_null() || buf_len < serialized.len() {
        return VTX_ERR_BUFFER_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(serialized.as_ptr(), out_buf, serialized.len());
    VTX_OK
}

/// Verifies an MMR inclusion proof against a known root and leaf hash.
/// Returns 1 if valid, 0 if invalid, or negative error code on malformed input.
#[no_mangle]
pub unsafe extern "C" fn vtx_verify_proof(
    root: *const u8,
    proof_bytes: *const u8,
    proof_len: usize,
) -> i32 {
    if root.is_null() || proof_bytes.is_null() {
        set_last_error("null pointer provided to vtx_verify_proof".into());
        return VTX_ERR_NULL_PTR;
    }

    let root_slice = std::slice::from_raw_parts(root, 32);
    let mut expected_root = [0u8; 32];
    expected_root.copy_from_slice(root_slice);

    let proof_slice = std::slice::from_raw_parts(proof_bytes, proof_len);
    let proof = match decode_proof(proof_slice) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("malformed proof format: {e}"));
            return VTX_ERR_INVALID_ARG;
        }
    };

    if proof.verify(&expected_root) {
        1
    } else {
        0
    }
}

/// Verifies an entire partition directory offline: validates record CRCs, sequential offsets,
/// cryptographic Blake3 hash chains, and Merkle Mountain Range roots with zero server process.
///
/// Returns 1 if completely verified, 0 if corrupt/invalid, or negative error code.
#[no_mangle]
pub unsafe extern "C" fn vtx_verify_partition(
    partition_dir: *const c_char,
    topic: *const c_char,
    partition_id: u32,
    out_records_verified: *mut u64,
    out_final_mmr_root: *mut u8,
    out_final_hash: *mut u8,
) -> i32 {
    if partition_dir.is_null() || topic.is_null() {
        set_last_error("null pointer provided to vtx_verify_partition".into());
        return VTX_ERR_NULL_PTR;
    }

    let dir_str = match CStr::from_ptr(partition_dir).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in partition_dir: {e}"));
            return VTX_ERR_INVALID_ARG;
        }
    };

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in topic: {e}"));
            return VTX_ERR_INVALID_ARG;
        }
    };

    match PartitionLog::verify_offline(Path::new(dir_str), topic_str, partition_id) {
        Ok(report) => {
            if !out_records_verified.is_null() {
                *out_records_verified = report.total_records;
            }
            if !out_final_mmr_root.is_null() {
                std::ptr::copy_nonoverlapping(report.final_mmr_root.as_ptr(), out_final_mmr_root, 32);
            }
            if !out_final_hash.is_null() {
                std::ptr::copy_nonoverlapping(report.final_record_hash.as_ptr(), out_final_hash, 32);
            }
            if report.is_valid {
                1
            } else {
                0
            }
        }
        Err(e) => {
            set_last_error(format!("verification error: {e}"));
            VTX_ERR_VERIFICATION_FAILED
        }
    }
}

/// Returns the public one-way hash H(state) of the forward-secure ratchet (32 bytes).
#[no_mangle]
pub unsafe extern "C" fn vtx_ratchet_state_hash(
    handle: *mut VtxPartition,
    out_state_hash: *mut u8,
) -> i32 {
    if handle.is_null() || out_state_hash.is_null() {
        set_last_error("null pointer provided to vtx_ratchet_state_hash".into());
        return VTX_ERR_NULL_PTR;
    }

    let partition = &*handle;
    let log = match partition.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("partition lock poisoned".into());
            return VTX_ERR_IO;
        }
    };

    let hash = log.public_ratchet_state_hash();
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_state_hash, 32);
    VTX_OK
}

/// Closes and frees the partition handle.
#[no_mangle]
pub unsafe extern "C" fn vtx_close(handle: *mut VtxPartition) -> i32 {
    if handle.is_null() {
        return VTX_OK;
    }
    let _ = Box::from_raw(handle);
    VTX_OK
}

/// Copies the last thread-local error message into `buf` up to `buf_len - 1` bytes, null-terminated.
#[no_mangle]
pub unsafe extern "C" fn vtx_last_error(buf: *mut c_char, buf_len: usize) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return VTX_ERR_INVALID_ARG;
    }

    LAST_ERROR.with(|err| {
        let s = err.borrow();
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(buf_len - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy_len);
        *buf.add(copy_len) = 0;
        copy_len as i32
    })
}

// ============================================================================
// Proof Binary Serialization Helpers
// ============================================================================

fn encode_proof(proof: &MmrInclusionProof) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&proof.leaf_index.to_be_bytes());
    buf.extend_from_slice(&proof.leaf_offset_in_peak.to_be_bytes());
    buf.extend_from_slice(&proof.leaf_hash);
    buf.extend_from_slice(&(proof.peak_index as u32).to_be_bytes());
    buf.extend_from_slice(&(proof.sibling_hashes.len() as u32).to_be_bytes());
    for sibling in &proof.sibling_hashes {
        buf.extend_from_slice(sibling);
    }
    buf.extend_from_slice(&(proof.peaks.len() as u32).to_be_bytes());
    for peak in &proof.peaks {
        buf.extend_from_slice(peak);
    }
    buf
}

fn decode_proof(buf: &[u8]) -> Result<MmrInclusionProof, &'static str> {
    if buf.len() < 8 + 8 + 32 + 4 + 4 + 4 {
        return Err("proof buffer too short");
    }

    let leaf_index = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let leaf_offset_in_peak = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&buf[16..48]);
    let peak_index = u32::from_be_bytes(buf[48..52].try_into().unwrap()) as usize;
    let siblings_count = u32::from_be_bytes(buf[52..56].try_into().unwrap()) as usize;

    let mut cursor = 56;
    let siblings_end = cursor + siblings_count * 32;
    if buf.len() < siblings_end + 4 {
        return Err("truncated siblings");
    }

    let mut sibling_hashes = Vec::with_capacity(siblings_count);
    for _ in 0..siblings_count {
        let mut s = [0u8; 32];
        s.copy_from_slice(&buf[cursor..cursor + 32]);
        sibling_hashes.push(s);
        cursor += 32;
    }

    let peaks_count = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;

    if buf.len() < cursor + peaks_count * 32 {
        return Err("truncated peaks");
    }

    let mut peaks = Vec::with_capacity(peaks_count);
    for _ in 0..peaks_count {
        let mut p = [0u8; 32];
        p.copy_from_slice(&buf[cursor..cursor + 32]);
        peaks.push(p);
        cursor += 32;
    }

    Ok(MmrInclusionProof {
        leaf_index,
        leaf_offset_in_peak,
        leaf_hash,
        sibling_hashes,
        peak_index,
        peaks,
    })
}

// ============================================================================
// Internal Tests for C-ABI Functionality
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use tempfile::tempdir;

    #[test]
    fn test_vtx_ffi_lifecycle_and_verification() {
        let dir = tempdir().unwrap();
        let base_dir_c = CString::new(dir.path().to_str().unwrap()).unwrap();
        let topic_c = CString::new("sensor-stream").unwrap();

        unsafe {
            let handle = vtx_open(base_dir_c.as_ptr(), topic_c.as_ptr(), 0, 1024 * 1024);
            assert!(!handle.is_null());

            let mut assigned_offset = 0u64;
            let mut record_hash = [0u8; 32];
            let mut mmr_root = [0u8; 32];
            let mut writer_mac = [0u8; 32];

            // Append 10 records
            for i in 0..10 {
                let key = format!("k-{}", i);
                let val = format!("telemetry-reading-{}", i);
                let res = vtx_append(
                    handle,
                    key.as_ptr(),
                    key.len(),
                    val.as_ptr(),
                    val.len(),
                    &mut assigned_offset,
                    record_hash.as_mut_ptr(),
                    mmr_root.as_mut_ptr(),
                    writer_mac.as_mut_ptr(),
                );
                assert_eq!(res, VTX_OK);
                assert_eq!(assigned_offset, i as u64);
                assert_ne!(record_hash, [0u8; 32]);
                assert_ne!(mmr_root, [0u8; 32]);
                assert_ne!(writer_mac, [0u8; 32]);
            }

            // Flush
            assert_eq!(vtx_flush(handle), VTX_OK);

            // Generate MMR inclusion proof for offset 5
            let mut proof_buf = [0u8; 1024];
            let mut proof_len = 0usize;
            let res = vtx_prove(handle, 5, proof_buf.as_mut_ptr(), proof_buf.len(), &mut proof_len);
            assert_eq!(res, VTX_OK);
            assert!(proof_len > 0);

            // Verify MMR proof offline with root
            let verify_res = vtx_verify_proof(mmr_root.as_ptr(), proof_buf.as_ptr(), proof_len);
            assert_eq!(verify_res, 1);

            // Check public ratchet state hash
            let mut state_hash = [0u8; 32];
            assert_eq!(vtx_ratchet_state_hash(handle, state_hash.as_mut_ptr()), VTX_OK);
            assert_ne!(state_hash, [0u8; 32]);

            // Close handle
            assert_eq!(vtx_close(handle), VTX_OK);

            // Offline partition verification
            let part_dir = dir.path().join("sensor-stream").join("partition-0");
            let part_dir_c = CString::new(part_dir.to_str().unwrap()).unwrap();
            let mut verified_count = 0u64;
            let mut final_root = [0u8; 32];
            let mut final_hash = [0u8; 32];

            let check_res = vtx_verify_partition(
                part_dir_c.as_ptr(),
                topic_c.as_ptr(),
                0,
                &mut verified_count,
                final_root.as_mut_ptr(),
                final_hash.as_mut_ptr(),
            );

            assert_eq!(check_res, 1);
            assert_eq!(verified_count, 10);
            assert_eq!(final_root, mmr_root);
            assert_eq!(final_hash, record_hash);
        }
    }
}
