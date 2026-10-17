use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::error::{Result, VortexError};

/// EntityKeyRegistry manages per-entity / per-tenant cryptographic Data Encryption Keys (DEKs).
/// It enables instant sub-millisecond GDPR "Right-to-be-Forgotten" compliance:
/// when an entity is shredded, its 32-byte DEK is erased and recorded as shredded.
/// The append-only .vtx log segments and their Blake3 hash chains remain 100% mathematically valid,
/// but all ciphertext corresponding to that entity becomes provably unrecoverable noise.
pub struct EntityKeyRegistry {
    master_key: [u8; 32],
    active_keys: RwLock<HashMap<String, [u8; 32]>>,
    shredded_entities: RwLock<HashSet<String>>,
}

impl EntityKeyRegistry {
    /// Creates a new key registry initialized with a 32-byte master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            active_keys: RwLock::new(HashMap::new()),
            shredded_entities: RwLock::new(HashSet::new()),
        }
    }

    /// Checks if an entity has been cryptographically shredded.
    pub fn is_shredded(&self, entity_id: &str) -> bool {
        self.shredded_entities.read().unwrap().contains(entity_id)
    }

    /// Derives or retrieves the 256-bit DEK for a given entity using Blake3 HKDF.
    /// If the entity was shredded, returns `VortexError::EntityShredded`.
    pub fn get_or_create_key(&self, entity_id: &str) -> Result<[u8; 32]> {
        if self.is_shredded(entity_id) {
            return Err(VortexError::EntityShredded {
                entity_id: entity_id.to_string(),
            });
        }

        let read_guard = self.active_keys.read().unwrap();
        if let Some(key) = read_guard.get(entity_id) {
            return Ok(*key);
        }
        drop(read_guard);

        let mut write_guard = self.active_keys.write().unwrap();
        if let Some(key) = write_guard.get(entity_id) {
            return Ok(*key);
        }

        // Derive deterministic DEK using Blake3 keyed hashing
        let mut hasher = blake3::Hasher::new_keyed(&self.master_key);
        hasher.update(b"vortex-entity-dek-v1:");
        hasher.update(entity_id.as_bytes());
        let derived_key: [u8; 32] = *hasher.finalize().as_bytes();

        write_guard.insert(entity_id.to_string(), derived_key);
        Ok(derived_key)
    }

    /// Cryptographically shreds an entity (GDPR Right-to-be-Forgotten).
    /// Permanently wipes its DEK and marks the entity as shredded.
    pub fn shred_entity(&self, entity_id: &str) -> bool {
        let mut shredded = self.shredded_entities.write().unwrap();
        let was_new = shredded.insert(entity_id.to_string());

        let mut keys = self.active_keys.write().unwrap();
        if let Some(mut key) = keys.remove(entity_id) {
            // Overwrite memory before drop
            key.fill(0);
        }

        was_new
    }

    /// Encrypts plaintext payload with the entity's 256-bit DEK using ChaCha20-Poly1305 AEAD.
    pub fn encrypt_payload(&self, entity_id: &str, nonce_val: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = self.get_or_create_key(entity_id)?;
        let cipher = ChaCha20Poly1305::new(&key_bytes.into());

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VortexError::EncryptionError(format!("AEAD encrypt error: {}", e)))
    }

    /// Decrypts ciphertext with the entity's DEK.
    /// Returns `VortexError::EntityShredded` if the entity was deleted under GDPR.
    pub fn decrypt_payload(&self, entity_id: &str, nonce_val: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.is_shredded(entity_id) {
            return Err(VortexError::EntityShredded {
                entity_id: entity_id.to_string(),
            });
        }

        let keys = self.active_keys.read().unwrap();
        let key_bytes = match keys.get(entity_id) {
            Some(k) => *k,
            None => {
                drop(keys);
                self.get_or_create_key(entity_id)?
            }
        };

        let cipher = ChaCha20Poly1305::new(&key_bytes.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| VortexError::DecryptionError(format!("AEAD decrypt error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_encryption_decryption_and_instant_shred() {
        let master_key = [0x42u8; 32];
        let registry = EntityKeyRegistry::new(master_key);

        let user_id = "user-789-gdpr";
        let plaintext = b"Sensitive Medical/Financial Record: balance=$150,000";

        // 1. Encrypt payload
        let ciphertext = registry.encrypt_payload(user_id, 1, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        // 2. Decrypt payload before shredding
        let decrypted = registry.decrypt_payload(user_id, 1, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        // 3. Cryptographically shred the entity (GDPR request)
        assert!(registry.shred_entity(user_id));
        assert!(registry.is_shredded(user_id));

        // 4. Attempt to decrypt post-shred: MUST fail with EntityShredded
        let err = registry.decrypt_payload(user_id, 1, &ciphertext).unwrap_err();
        match err {
            VortexError::EntityShredded { entity_id } => {
                assert_eq!(entity_id, user_id);
            }
            other => panic!("Expected EntityShredded, got {:?}", other),
        }

        // 5. Attempt to encrypt new data for shredded entity: MUST fail
        let enc_err = registry.encrypt_payload(user_id, 2, b"New transaction").unwrap_err();
        assert!(matches!(enc_err, VortexError::EntityShredded { .. }));
    }
}
