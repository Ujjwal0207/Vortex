use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::{FileExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use vortex_core::{
    ForwardSecureRatchet, HashDigest, KeyringSlot, Result, VortexError,
    KEYRING_SLOT_SIZE,
};

pub const KEYRING_SLOT_A: &str = "partition.keyring.A";
pub const KEYRING_SLOT_B: &str = "partition.keyring.B";
pub const PARTITION_MACS_FILE: &str = "partition.macs";

enum ActiveSlot {
    SlotA,
    SlotB,
}

/// A durable, crash-resilient two-slot keyring maintaining the partition's forward-secure ratchet.
///
/// Under crash conditions or sudden power-cuts, one of the two slots (`keyring.A` or `keyring.B`)
/// is guaranteed to hold the last committed consistent state. The active writer alternates slots
/// and fsyncs before advancing, completely eliminating torn writes.
pub struct TwoSlotKeyring {
    _dir: PathBuf,
    path_a: PathBuf,
    path_b: PathBuf,
    macs_file: File,
    ratchet: ForwardSecureRatchet,
    active_slot: ActiveSlot,
}

impl TwoSlotKeyring {
    /// Opens an existing two-slot keyring in `partition_dir` or initializes a new one from genesis.
    pub fn open_or_create(partition_dir: &Path, topic: &str, partition_id: u32) -> Result<Self> {
        Self::open_or_create_with_offset(partition_dir, topic, partition_id, 0)
    }

    /// Opens an existing two-slot keyring in `partition_dir` or initializes a new one from genesis with `initial_offset`.
    pub fn open_or_create_with_offset(
        partition_dir: &Path,
        topic: &str,
        partition_id: u32,
        initial_offset: u64,
    ) -> Result<Self> {
        let path_a = partition_dir.join(KEYRING_SLOT_A);
        let path_b = partition_dir.join(KEYRING_SLOT_B);
        let macs_path = partition_dir.join(PARTITION_MACS_FILE);

        let macs_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&macs_path)
            .map_err(|e| VortexError::Io(format!("failed to open macs log: {e}")))?;

        #[cfg(unix)]
        {
            if let Ok(meta) = macs_file.metadata() {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = macs_file.set_permissions(perms);
            }
        }

        let slot_a = read_keyring_slot(&path_a)?;
        let slot_b = read_keyring_slot(&path_b)?;

        let (ratchet, active_slot) = match (slot_a, slot_b) {
            (Some(sa), Some(sb)) => {
                // Both slots valid: select the one with the higher sequence number
                if sa.sequence >= sb.sequence {
                    (
                        ForwardSecureRatchet::from_state(sa.state, sa.offset, sa.sequence),
                        ActiveSlot::SlotA,
                    )
                } else {
                    (
                        ForwardSecureRatchet::from_state(sb.state, sb.offset, sb.sequence),
                        ActiveSlot::SlotB,
                    )
                }
            }
            (Some(sa), None) => (
                ForwardSecureRatchet::from_state(sa.state, sa.offset, sa.sequence),
                ActiveSlot::SlotA,
            ),
            (None, Some(sb)) => (
                ForwardSecureRatchet::from_state(sb.state, sb.offset, sb.sequence),
                ActiveSlot::SlotB,
            ),
            (None, None) => {
                // Initialize slot A with deterministic genesis seed derived from partition identity
                let genesis_salt = b"VORTEX_KEYRING_GENESIS_SALT_V1.00";
                let genesis_seed =
                    ForwardSecureRatchet::derive_genesis_seed(topic, partition_id, genesis_salt);
                let mut ratchet = ForwardSecureRatchet::new(genesis_seed);
                if initial_offset > 0 {
                    ratchet.step(initial_offset);
                }
                let initial_slot =
                    KeyringSlot::new(ratchet.sequence(), ratchet.offset(), *ratchet.secret_state());

                write_slot_atomic(&path_a, &initial_slot)?;
                (ratchet, ActiveSlot::SlotA)
            }
        };

        Ok(Self {
            _dir: partition_dir.to_path_buf(),
            path_a,
            path_b,
            macs_file,
            ratchet,
            active_slot,
        })
    }

    /// Computes the writer MAC for a raw record using current ratchet state,
    /// advances the ratchet state to `next_offset`, and appends the MAC into the page cache.
    /// Checkpointing and physical disk fsync is decoupled and executed on batch boundary / flush.
    pub fn step_and_authenticate(&mut self, record_raw: &[u8], next_offset: u64) -> Result<HashDigest> {
        let mac = self.ratchet.compute_mac(record_raw);
        let current_offset = self.ratchet.offset();

        #[cfg(unix)]
        {
            self.macs_file
                .write_all_at(&mac, current_offset * 32)
                .map_err(|e| VortexError::Io(format!("failed to write mac: {e}")))?;
        }
        #[cfg(windows)]
        {
            self.macs_file
                .seek_write(&mac, current_offset * 32)
                .map_err(|e| VortexError::Io(format!("failed to write mac: {e}")))?;
        }

        self.ratchet.step(next_offset);
        Ok(mac)
    }

    /// Reads the stored writer MAC for a given offset, if present.
    pub fn read_mac(&self, offset: u64) -> Result<Option<HashDigest>> {
        let file_len = self
            .macs_file
            .metadata()
            .map_err(|e| VortexError::Io(e.to_string()))?
            .len();

        let byte_pos = offset * 32;
        if byte_pos + 32 > file_len {
            return Ok(None);
        }

        let mut mac = [0u8; 32];
        #[cfg(unix)]
        {
            self.macs_file
                .read_exact_at(&mut mac, byte_pos)
                .map_err(|e| VortexError::Io(format!("failed to read mac at offset {offset}: {e}")))?;
        }
        #[cfg(windows)]
        {
            self.macs_file
                .seek_read(&mut mac, byte_pos)
                .map_err(|e| VortexError::Io(format!("failed to read mac at offset {offset}: {e}")))?;
        }

        Ok(Some(mac))
    }

    /// Checkpoints the current ratchet state to the inactive slot and switches slots upon fsync.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.macs_file
            .sync_data()
            .map_err(|e| VortexError::Io(format!("failed to sync macs log: {e}")))?;

        let slot = KeyringSlot::new(
            self.ratchet.sequence(),
            self.ratchet.offset(),
            *self.ratchet.secret_state(),
        );

        match self.active_slot {
            ActiveSlot::SlotA => {
                write_slot_atomic(&self.path_b, &slot)?;
                self.active_slot = ActiveSlot::SlotB;
            }
            ActiveSlot::SlotB => {
                write_slot_atomic(&self.path_a, &slot)?;
                self.active_slot = ActiveSlot::SlotA;
            }
        }

        Ok(())
    }

    /// Returns the public one-way hash H(state) of the current ratchet state.
    pub fn public_state_hash(&self) -> HashDigest {
        self.ratchet.public_state_hash()
    }

    /// Returns current ratchet offset.
    pub fn current_offset(&self) -> u64 {
        self.ratchet.offset()
    }

    /// Returns monotonic ratchet sequence.
    pub fn sequence(&self) -> u64 {
        self.ratchet.sequence()
    }
}

/// Reads and verifies a keyring slot file, returning None if file is missing or corrupted.
fn read_keyring_slot(path: &Path) -> Result<Option<KeyringSlot>> {
    if !path.exists() {
        return Ok(None);
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(VortexError::Io(format!("cannot open slot {:?}: {e}", path))),
    };

    let mut buf = [0u8; KEYRING_SLOT_SIZE];
    if file.read_exact(&mut buf).is_err() {
        return Ok(None);
    }

    match KeyringSlot::decode(&buf) {
        Ok(slot) => Ok(Some(slot)),
        Err(_) => Ok(None), // Discard torn/corrupted slot
    }
}

/// Writes a keyring slot atomically with fsync and restricted 0600 file permissions.
fn write_slot_atomic(path: &Path, slot: &KeyringSlot) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| VortexError::Io(format!("failed to open slot file {:?}: {e}", path)))?;

    #[cfg(unix)]
    {
        if let Ok(meta) = file.metadata() {
            let mut perms = meta.permissions();
            perms.set_mode(0o600); // Read/write only for owner
            let _ = file.set_permissions(perms);
        }
    }

    let encoded = slot.encode();
    file.write_all(&encoded)
        .map_err(|e| VortexError::Io(format!("failed to write slot bytes: {e}")))?;

    file.sync_all()
        .map_err(|e| VortexError::Io(format!("failed to fsync keyring slot: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_two_slot_keyring_lifecycle_and_recovery() {
        let dir = tempdir().unwrap();
        let topic = "test-topic";
        let partition = 0;

        {
            let mut keyring = TwoSlotKeyring::open_or_create(dir.path(), topic, partition)
                .expect("keyring creation must succeed");

            assert_eq!(keyring.current_offset(), 0);
            assert_eq!(keyring.sequence(), 1);

            let record_1 = b"test record payload offset 0";
            let mac_1 = keyring.step_and_authenticate(record_1, 1).unwrap();
            assert_eq!(keyring.current_offset(), 1);
            assert_eq!(keyring.sequence(), 2);

            let read_mac_1 = keyring.read_mac(0).unwrap().expect("mac 0 must exist");
            assert_eq!(read_mac_1, mac_1);

            let record_2 = b"test record payload offset 1";
            let mac_2 = keyring.step_and_authenticate(record_2, 2).unwrap();
            assert_eq!(keyring.current_offset(), 2);
            assert_eq!(keyring.sequence(), 3);
            assert_ne!(mac_1, mac_2);

            keyring.checkpoint().expect("checkpoint must succeed");
        }

        // Reopen from disk (crash recovery simulation)
        {
            let keyring = TwoSlotKeyring::open_or_create(dir.path(), topic, partition)
                .expect("keyring recovery must succeed");

            assert_eq!(keyring.current_offset(), 2);
            assert_eq!(keyring.sequence(), 3);

            let read_mac_1 = keyring.read_mac(0).unwrap().expect("mac 0 must exist");
            let read_mac_2 = keyring.read_mac(1).unwrap().expect("mac 1 must exist");
            assert_ne!(read_mac_1, read_mac_2);
        }
    }

    #[test]
    fn test_corrupted_slot_failover() {
        let dir = tempdir().unwrap();
        let topic = "test-topic";
        let partition = 0;

        {
            let mut keyring = TwoSlotKeyring::open_or_create(dir.path(), topic, partition).unwrap();
            let _ = keyring.step_and_authenticate(b"rec0", 1).unwrap();
            keyring.checkpoint().unwrap(); // Checkpointed to slot B (offset 1, sequence 2)
            let _ = keyring.step_and_authenticate(b"rec1", 2).unwrap();
            keyring.checkpoint().unwrap(); // Checkpointed to slot A (offset 2, sequence 3)
        }

        // Corrupt slot A intentionally
        let path_a = dir.path().join(KEYRING_SLOT_A);
        if path_a.exists() {
            let mut f = OpenOptions::new().write(true).open(&path_a).unwrap();
            f.write_all(b"garbage-corruption").unwrap();
        }

        // Reopen: must cleanly recover from slot B (offset 1, sequence 2) rather than corrupted slot A!
        let recovered = TwoSlotKeyring::open_or_create(dir.path(), topic, partition).unwrap();
        assert_eq!(recovered.current_offset(), 1);
        assert_eq!(recovered.sequence(), 2);
    }
}
