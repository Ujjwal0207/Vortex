/**
 * @file vortex.h
 * @brief Vortex C-API: The SQLite of Sealed, Tamper-Evident Logs.
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef VORTEX_H
#define VORTEX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return and status error codes */
#define VTX_OK                         0
#define VTX_ERR_NULL_PTR              -1
#define VTX_ERR_IO                    -2
#define VTX_ERR_CORRUPTION            -3
#define VTX_ERR_OFFSET_OUT_OF_RANGE   -4
#define VTX_ERR_VERIFICATION_FAILED   -5
#define VTX_ERR_BUFFER_TOO_SMALL      -6
#define VTX_ERR_INVALID_ARG           -7

/** Opaque handle to an open partition log */
typedef struct VtxPartition VtxPartition;

/**
 * Opens or creates a sealed partition log at `base_dir/topic/partition-id/`.
 *
 * @param base_dir Directory root where topic data resides.
 * @param topic Topic identifier string.
 * @param partition_id Numeric partition index.
 * @param max_segment_bytes Maximum segment size before rolling (pass 0 for 64MB default).
 * @return Opaque partition pointer or NULL on error.
 */
VtxPartition* vtx_open(
    const char* base_dir,
    const char* topic,
    uint32_t partition_id,
    uint64_t max_segment_bytes
);

/**
 * Appends a record to the partition with forward-secure ratchet authentication.
 *
 * @param handle Valid open partition handle.
 * @param key Optional key buffer (can be NULL).
 * @param key_len Key length in bytes.
 * @param val Payload buffer (must not be NULL).
 * @param val_len Payload length in bytes.
 * @param out_offset Outputs the assigned 64-bit monotonic offset.
 * @param out_record_hash Outputs the 32-byte Blake3 record hash.
 * @param out_mmr_root Outputs the 32-byte Merkle Mountain Range bagged root.
 * @param out_writer_mac Optional output for 32-byte forward-secure writer MAC (can be NULL).
 * @return VTX_OK (0) on success, or negative error code.
 */
int32_t vtx_append(
    VtxPartition* handle,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* val,
    size_t val_len,
    uint64_t* out_offset,
    uint8_t* out_record_hash,
    uint8_t* out_mmr_root,
    uint8_t* out_writer_mac
);

/**
 * Appends a batch of records atomically in a single durable write.
 *
 * @param handle Valid open partition handle.
 * @param keys Array of key pointers (can be NULL if all records are keyless).
 * @param key_lens Array of key byte lengths.
 * @param vals Array of payload pointers (must not be NULL).
 * @param val_lens Array of payload byte lengths.
 * @param count Number of records in batch.
 * @param out_start_offset Optional output for first assigned offset.
 * @param out_end_offset Optional output for last assigned offset.
 * @param out_final_record_hash Optional output for final Blake3 record hash.
 * @param out_final_mmr_root Optional output for final MMR bagged root.
 * @return VTX_OK (0) on success, or negative error code.
 */
int32_t vtx_append_batch(
    VtxPartition* handle,
    const uint8_t* const* keys,
    const size_t* key_lens,
    const uint8_t* const* vals,
    const size_t* val_lens,
    size_t count,
    uint64_t* out_start_offset,
    uint64_t* out_end_offset,
    uint8_t* out_final_record_hash,
    uint8_t* out_final_mmr_root
);

/**
 * Flushes all pending writes and checkpoints the two-slot keyring to disk.
 */
int32_t vtx_flush(VtxPartition* handle);

/**
 * Returns the next offset that will be assigned to an incoming message.
 */
int32_t vtx_next_offset(VtxPartition* handle, uint64_t* out_offset);

/**
 * Generates an O(log N) cryptographic Merkle Mountain Range inclusion proof for `offset`.
 */
int32_t vtx_prove(
    VtxPartition* handle,
    uint64_t offset,
    uint8_t* out_buf,
    size_t buf_len,
    size_t* out_actual_len
);

/**
 * Verifies an MMR inclusion proof against a known root and leaf hash.
 *
 * @return 1 if valid, 0 if invalid, negative on format error.
 */
int32_t vtx_verify_proof(
    const uint8_t* root,
    const uint8_t* leaf_hash,
    const uint8_t* proof_bytes,
    size_t proof_len
);

/**
 * Verifies an entire partition directory offline on disk with zero running servers.
 *
 * @return 1 if completely verified, 0 if invalid, negative on error.
 */
int32_t vtx_verify_partition(
    const char* partition_dir,
    const char* topic,
    uint32_t partition_id,
    uint64_t* out_records_verified,
    uint8_t* out_final_mmr_root,
    uint8_t* out_final_hash
);

/**
 * Verifies an entire partition directory offline and cryptographically replays the forward-secure ratchet
 * using `genesis_seed` (32 bytes) to verify every stored writer MAC in partition.macs.
 *
 * @return 1 if completely verified, 0 if invalid, negative on error.
 */
int32_t vtx_verify_partition_with_seed(
    const char* partition_dir,
    const char* topic,
    uint32_t partition_id,
    const uint8_t* genesis_seed,
    uint64_t* out_records_verified,
    uint8_t* out_final_mmr_root,
    uint8_t* out_final_hash
);

/**
 * Returns the public one-way hash H(state) of the forward-secure ratchet (32 bytes).
 */
int32_t vtx_ratchet_state_hash(VtxPartition* handle, uint8_t* out_state_hash);

/**
 * Closes the partition handle and frees associated resources.
 */
int32_t vtx_close(VtxPartition* handle);

/**
 * Copies the last thread-local error message into `buf`.
 */
int32_t vtx_last_error(char* buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* VORTEX_H */
