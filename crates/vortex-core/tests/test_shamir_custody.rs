use vortex_core::shamir::ShamirSecretSharing;

#[test]
fn test_shamir_2_of_3_split_and_reconstruction() {
    let secret_dek: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    let shares = ShamirSecretSharing::split_secret(&secret_dek).expect("split secret");
    assert_eq!(shares.len(), 3);
    assert_eq!(shares[0].share_index, 1);
    assert_eq!(shares[1].share_index, 2);
    assert_eq!(shares[2].share_index, 3);

    // Each share by itself is pseudorandom and != original secret
    assert_ne!(shares[0].data, secret_dek);
    assert_ne!(shares[1].data, secret_dek);
    assert_ne!(shares[2].data, secret_dek);

    // Any 2 of 3 shares must reconstruct the exact secret
    // Combination 1: Share 1 + Share 2
    let recovered_1_2 = ShamirSecretSharing::reconstruct_secret(&[shares[0].clone(), shares[1].clone()])
        .expect("reconstruct 1 and 2");
    assert_eq!(recovered_1_2, secret_dek);

    // Combination 2: Share 2 + Share 3
    let recovered_2_3 = ShamirSecretSharing::reconstruct_secret(&[shares[1].clone(), shares[2].clone()])
        .expect("reconstruct 2 and 3");
    assert_eq!(recovered_2_3, secret_dek);

    // Combination 3: Share 1 + Share 3
    let recovered_1_3 = ShamirSecretSharing::reconstruct_secret(&[shares[0].clone(), shares[2].clone()])
        .expect("reconstruct 1 and 3");
    assert_eq!(recovered_1_3, secret_dek);

    // Insufficient shares (1 share only) must fail
    let insufficient = ShamirSecretSharing::reconstruct_secret(&[shares[0].clone()]);
    assert!(insufficient.is_err());

    // Duplicate shares must fail
    let duplicate = ShamirSecretSharing::reconstruct_secret(&[shares[0].clone(), shares[0].clone()]);
    assert!(duplicate.is_err());
}

#[test]
fn test_shamir_gdpr_provable_shredding() {
    let secret_dek: [u8; 32] = *blake3::hash(b"USER_DEK_CONFIDENTIAL_PII_1234").as_bytes();
    let shares = ShamirSecretSharing::split_secret(&secret_dek).expect("split secret");

    // Client device holds share 1, KMS holds share 2, IdP holds share 3
    let share_1 = shares[0].clone();
    let share_2 = shares[1].clone();
    let share_3 = shares[2].clone();

    // Normal access with share 1 + share 2
    let dek = ShamirSecretSharing::reconstruct_secret(&[
        share_1,
        share_2,
    ]).expect("decrypt");
    assert_eq!(dek, secret_dek);

    // GDPR Shred: User requests immediate key destruction -> Client destroys share 1 and share 2
    // Remaining share 3 is mathematically insufficient to reconstruct DEK
    let attempt = ShamirSecretSharing::reconstruct_secret(&[share_3]);
    assert!(attempt.is_err());
}
