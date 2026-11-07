use vortex_core::coalesce::{BlockCoalescer, COALESCE_BLOCK_MAX_BYTES};

#[test]
fn test_block_coalescing_64kb_boundary_and_proof() {
    let mut coalescer = BlockCoalescer::new(COALESCE_BLOCK_MAX_BYTES);

    // 500 small 128-byte IoT telemetry records
    let small_payload = vec![0xAB; 128];
    let mut sealed_blocks = Vec::new();

    for offset in 0..1000 {
        if let Some(block) = coalescer.add_record(offset, &small_payload) {
            sealed_blocks.push(block);
        }
    }
    if let Some(block) = coalescer.flush() {
        sealed_blocks.push(block);
    }

    // 1000 records * 128 bytes = 128,000 bytes. With 64 KB blocks, this produces exactly 2 full blocks
    assert_eq!(sealed_blocks.len(), 2);
    assert!(sealed_blocks[0].raw_bytes.len() <= COALESCE_BLOCK_MAX_BYTES);
    assert_eq!(sealed_blocks[0].records.len(), 512); // 512 * 128 = 65,536 bytes (64 KB)
    assert_eq!(sealed_blocks[1].records.len(), 488); // 488 * 128 = 62,464 bytes

    // Generate and verify individual record inclusion proof inside block 0
    let target_offset = 42;
    let proof = sealed_blocks[0].generate_inclusion_proof(target_offset)
        .expect("generate inclusion proof");

    assert_eq!(proof.offset, target_offset);
    assert_eq!(proof.intra_block_byte_offset, 42 * 128);
    assert_eq!(proof.payload_len, 128);

    // Verify proof
    let is_valid = proof.verify(&sealed_blocks[0].block_hash, &small_payload);
    assert!(is_valid);

    // Verify with corrupted payload fails
    let corrupted_payload = vec![0xFF; 128];
    assert!(!proof.verify(&sealed_blocks[0].block_hash, &corrupted_payload));
}

#[test]
fn test_block_coalescing_slashes_hashes_by_98_percent() {
    let mut coalescer = BlockCoalescer::new(64 * 1024);
    let payload = vec![0x55; 128]; // 128 byte records

    let mut blocks = Vec::new();
    let num_records = 512; // Exactly 1 block of 64 KB

    for i in 0..num_records {
        if let Some(b) = coalescer.add_record(i, &payload) {
            blocks.push(b);
        }
    }
    if let Some(b) = coalescer.flush() {
        blocks.push(b);
    }

    assert_eq!(blocks.len(), 1);
    // 512 messages resulted in only 1 block hash instead of 512 separate MMR updates!
    let hash_reduction_pct = ((num_records - blocks.len() as u64) as f64 / num_records as f64) * 100.0;
    println!("Hash operation reduction: {:.2}%", hash_reduction_pct);
    assert!(hash_reduction_pct > 99.0);
}
