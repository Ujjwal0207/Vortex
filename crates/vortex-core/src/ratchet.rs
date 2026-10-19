use crc32fast::Hasher as Crc32Hasher;
use crate::error::{Result, VortexError};
use crate::hash::HashDigest;

pub const RATCHET_DOMAIN_TAG: &[u8] = b"vtx-ratchet-v1.00";
pub const KEYRING_SLOT_MAGIC: u32 = 0x56545852; // "VTXR"
pub const KEYRING_SLOT_VERSION: u32 = 1;
pub const KEYRING_SLOT_SIZE: usize = 92;

/// A forward-secure cryptographic ratchet maintaining the writer's ephemeral secret state.
///
/// Under this ratchet, every record is authenticated with a keyed Blake3 MAC derived from
/// the current `state`. Once record $N$ is appended, the ratchet steps forward to $N+1$
/// via a one-way cryptographically secure derivation, and the previous secret state
/// is securely zeroized from memory.
///
/// Even if an adversary compromises root access to the machine at offset 10,000,
/// the forward secrecy of Blake3 prevents them from reversing the state to mint or forge
/// records from offset 50.
pub struct ForwardSecureRatchet {
    state: [u8; 32],
    offset: u64,
    sequence: u64,
}

impl Drop for ForwardSecureRatchet {
    fn drop(&mut self) {
        // Securely zeroize key material on drop
        self.state.fill(0);
    }
}

impl ForwardSecureRatchet {
    /// Initializes a new ratchet from an initial 32-byte secret seed at offset 0.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            offset: 0,
            sequence: 1,
        }
    }

    /// Restores a ratchet from a previously persisted slot state.
    pub fn from_state(state: [u8; 32], offset: u64, sequence: u64) -> Self {
        Self {
            state,
            offset,
            sequence,
        }
    }

    /// Generates a deterministic genesis seed for a partition from topic, partition id, and a salt.
    pub fn derive_genesis_seed(topic: &str, partition_id: u32, salt: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vortex-genesis-ratchet-v1");
        hasher.update(salt);
        hasher.update(topic.as_bytes());
        hasher.update(&partition_id.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Computes a forward-secure Message Authentication Code (MAC) for a raw record
    /// using the current ratchet state as the Blake3 symmetric key.
    pub fn compute_mac(&self, record_raw: &[u8]) -> HashDigest {
        *blake3::keyed_hash(&self.state, record_raw).as_bytes()
    }

    /// Advances the ratchet state to `next_offset` via a one-way keyed derivation,
    /// and securely zeroizes the old state in memory.
    pub fn step(&mut self, next_offset: u64) {
        let mut hasher = blake3::Hasher::new_keyed(&self.state);
        hasher.update(RATCHET_DOMAIN_TAG);
        hasher.update(&next_offset.to_be_bytes());
        let next_state = *hasher.finalize().as_bytes();

        // Zeroize old state in place before replacing
        self.state.fill(0);
        self.state = next_state;
        self.offset = next_offset;
        self.sequence = self.sequence.saturating_add(1);
    }

    /// Returns the public one-way hash of the current ratchet state: H(state).
    /// This can be publicly distributed or committed to Region A / witnesses
    /// to prove continuous advancement without leaking the private state itself.
    pub fn public_state_hash(&self) -> HashDigest {
        *blake3::hash(&self.state).as_bytes()
    }

    /// Returns the current offset associated with this ratchet state.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the monotonic persistence sequence counter.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the raw current secret state.
    pub fn secret_state(&self) -> &[u8; 32] {
        &self.state
    }

    /// Verifies a record's MAC against a supplied ratchet secret state in constant time.
    pub fn verify_mac(state: &[u8; 32], record_raw: &[u8], expected_mac: &HashDigest) -> bool {
        let calculated = blake3::keyed_hash(state, record_raw);
        constant_time_eq_32(calculated.as_bytes(), expected_mac)
    }
}

/// Constant-time 32-byte equality check to prevent timing side-channel attacks on MAC verification.
#[inline(always)]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// A serialized persistence slot representing a verified checkpoint of the ratchet state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringSlot {
    pub magic: u32,
    pub version: u32,
    pub sequence: u64,
    pub offset: u64,
    pub state: [u8; 32],
    pub state_hash: [u8; 32],
    pub crc32: u32,
}

impl KeyringSlot {
    /// Creates a new slot with computed public state hash and CRC32 checksum.
    pub fn new(sequence: u64, offset: u64, state: [u8; 32]) -> Self {
        let state_hash = *blake3::hash(&state).as_bytes();
        let mut slot = Self {
            magic: KEYRING_SLOT_MAGIC,
            version: KEYRING_SLOT_VERSION,
            sequence,
            offset,
            state,
            state_hash,
            crc32: 0,
        };
        slot.crc32 = slot.compute_crc32();
        slot
    }

    /// Computes the CRC32 checksum over the slot contents (excluding the checksum field itself).
    fn compute_crc32(&self) -> u32 {
        let mut crc = Crc32Hasher::new();
        crc.update(&self.magic.to_be_bytes());
        crc.update(&self.version.to_be_bytes());
        crc.update(&self.sequence.to_be_bytes());
        crc.update(&self.offset.to_be_bytes());
        crc.update(&self.state);
        crc.update(&self.state_hash);
        crc.finalize()
    }

    /// Encodes the slot into fixed 92-byte binary format.
    pub fn encode(&self) -> [u8; KEYRING_SLOT_SIZE] {
        let mut buf = [0u8; KEYRING_SLOT_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.version.to_be_bytes());
        buf[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        buf[16..24].copy_from_slice(&self.offset.to_be_bytes());
        buf[24..56].copy_from_slice(&self.state);
        buf[56..88].copy_from_slice(&self.state_hash);
        buf[88..92].copy_from_slice(&self.crc32.to_be_bytes());
        buf
    }

    /// Decodes and verifies a 92-byte binary slot.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYRING_SLOT_SIZE {
            return Err(VortexError::InvalidRecordFormat(format!(
                "invalid keyring slot length: expected {}, got {}",
                KEYRING_SLOT_SIZE,
                bytes.len()
            )));
        }

        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != KEYRING_SLOT_MAGIC {
            return Err(VortexError::InvalidMagic {
                expected: KEYRING_SLOT_MAGIC,
                actual: magic,
            });
        }

        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if version != KEYRING_SLOT_VERSION {
            return Err(VortexError::InvalidRecordFormat(format!(
                "unsupported keyring version: {}",
                version
            )));
        }

        let sequence = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let offset = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let mut state = [0u8; 32];
        state.copy_from_slice(&bytes[24..56]);
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(&bytes[56..88]);
        let actual_crc32 = u32::from_be_bytes(bytes[88..92].try_into().unwrap());

        // Validate public state hash
        let expected_hash = *blake3::hash(&state).as_bytes();
        if expected_hash != state_hash {
            return Err(VortexError::KeyringCorrupted {
                slot: "deserialization".into(),
                reason: "state hash mismatch against embedded state".into(),
            });
        }

        let slot = Self {
            magic,
            version,
            sequence,
            offset,
            state,
            state_hash,
            crc32: actual_crc32,
        };

        let calculated_crc = slot.compute_crc32();
        if calculated_crc != actual_crc32 {
            return Err(VortexError::KeyringCorrupted {
                slot: "deserialization".into(),
                reason: format!("CRC mismatch: expected {calculated_crc:#010x}, found {actual_crc32:#010x}"),
            });
        }

        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_progression_and_forward_secrecy() {
        let initial_seed = [42u8; 32];
        let mut ratchet = ForwardSecureRatchet::new(initial_seed);

        let record_1 = b"record payload at offset 0";
        let mac_1 = ratchet.compute_mac(record_1);

        // Verification with current state succeeds
        assert!(ForwardSecureRatchet::verify_mac(ratchet.secret_state(), record_1, &mac_1));

        // Advance to offset 1
        ratchet.step(1);
        assert_eq!(ratchet.offset(), 1);
        assert_eq!(ratchet.sequence(), 2);

        // State at offset 1 CANNOT forge MAC for record 1
        assert!(!ForwardSecureRatchet::verify_mac(ratchet.secret_state(), record_1, &mac_1));

        // Record 2 with new state
        let record_2 = b"record payload at offset 1";
        let mac_2 = ratchet.compute_mac(record_2);
        assert!(ForwardSecureRatchet::verify_mac(ratchet.secret_state(), record_2, &mac_2));
        assert_ne!(mac_1, mac_2);
    }

    #[test]
    fn test_keyring_slot_encoding_decoding() {
        let state = [77u8; 32];
        let slot = KeyringSlot::new(42, 100, state);
        let encoded = slot.encode();

        assert_eq!(encoded.len(), KEYRING_SLOT_SIZE);

        let decoded = KeyringSlot::decode(&encoded).expect("slot decoding must succeed");
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.offset, 100);
        assert_eq!(decoded.state, state);
        assert_eq!(decoded.crc32, slot.crc32);
    }

    #[test]
    fn test_corrupted_keyring_slot_rejected() {
        let state = [11u8; 32];
        let slot = KeyringSlot::new(1, 0, state);
        let mut encoded = slot.encode();

        // Corrupt one byte of the secret state
        encoded[30] ^= 0xff;

        let res = KeyringSlot::decode(&encoded);
        assert!(res.is_err());
    }
}
