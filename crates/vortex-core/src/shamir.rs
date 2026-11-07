use serde::{Deserialize, Serialize};

use crate::error::{Result, VortexError};

/// Multiplication in Galois Field $GF(2^8)$ with irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (0x11b).
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in $GF(2^8)$ using Fermat's Little Theorem: $a^{-1} = a^{254}$.
pub fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254;
    while exp > 0 {
        if (exp & 1) != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Division in $GF(2^8)$.
pub fn gf256_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        0
    } else {
        gf256_mul(a, gf256_inv(b))
    }
}

/// An individual threshold key share of a 32-byte secret (Data Encryption Key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShamirShare {
    /// Distinct evaluation point $x \in \{1, 2, 3\}$.
    pub share_index: u8,
    /// Evaluated polynomial bytes $P(x)$ for each of the 32 secret bytes.
    pub data: [u8; 32],
}

/// Phase 16: Shamir (2,3) Secret Sharing Engine for Client-Side Split-Knowledge DEK Custody.
///
/// Ensures the broker never possesses decryption keys in memory or on disk.
/// Any 2 of 3 shares can reconstruct the 32-byte DEK; any single share yields zero information.
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Splits a 32-byte secret into 3 threshold shares $(x=1, x=2, x=3)$ where any 2 reconstruct the secret.
    pub fn split_secret(secret: &[u8; 32]) -> Result<[ShamirShare; 3]> {
        let mut random_coeffs = [0u8; 32];
        getrandom::getrandom(&mut random_coeffs)
            .map_err(|e| VortexError::EncryptionError(format!("CSPRNG error generating Shamir polynomial: {e}")))?;

        let mut share1 = [0u8; 32];
        let mut share2 = [0u8; 32];
        let mut share3 = [0u8; 32];

        for i in 0..32 {
            let s = secret[i];
            let a = if random_coeffs[i] == 0 { 0x42 } else { random_coeffs[i] };

            // P(x) = s ^ (a * x)
            share1[i] = s ^ gf256_mul(a, 1);
            share2[i] = s ^ gf256_mul(a, 2);
            share3[i] = s ^ gf256_mul(a, 3);
        }

        Ok([
            ShamirShare { share_index: 1, data: share1 },
            ShamirShare { share_index: 2, data: share2 },
            ShamirShare { share_index: 3, data: share3 },
        ])
    }

    /// Reconstructs the 32-byte secret from any 2 distinct shares using Lagrange interpolation.
    pub fn reconstruct_secret(shares: &[ShamirShare]) -> Result<[u8; 32]> {
        if shares.len() < 2 {
            return Err(VortexError::SecurityViolation {
                reason: format!("Shamir reconstruction requires at least 2 shares, got {}", shares.len()),
            });
        }

        let s1 = &shares[0];
        let s2 = &shares[1];

        if s1.share_index == s2.share_index {
            return Err(VortexError::SecurityViolation {
                reason: format!("Duplicate Shamir share index {} provided", s1.share_index),
            });
        }

        if s1.share_index == 0 || s2.share_index == 0 {
            return Err(VortexError::SecurityViolation {
                reason: "Invalid Shamir share index 0".to_string(),
            });
        }

        let x1 = s1.share_index;
        let x2 = s2.share_index;
        let dx = x1 ^ x2; // x1 - x2 in GF(256)

        let mut secret = [0u8; 32];
        let l1 = gf256_div(x2, dx); // (0 - x2) / (x1 - x2)
        let l2 = gf256_div(x1, dx); // (0 - x1) / (x2 - x1)

        for i in 0..32 {
            let y1 = s1.data[i];
            let y2 = s2.data[i];
            secret[i] = gf256_mul(y1, l1) ^ gf256_mul(y2, l2);
        }

        Ok(secret)
    }
}

