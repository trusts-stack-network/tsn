//! Mechanism de rotation automatique of keys SLH-DSA
//!
//! Implements a system de rotation periodic of keys post-quantiques for maintenir
//! the security to long terme. Based on the recommandations NIST SP 800-57 Part 1 Rev. 5
//! for the gestion of keys cryptographiques.
//!
//! ## Security
//!
//! La rotation of keys SLH-DSA is critique for the security post-quantique car :
//! - Limite l'exposition temporelle of keys privates
//! - Reduces l'impact d'une compromission possible
//! - Prepares the transition vers de nouveaux parameters if necessary
//!
//! ## References
//!
//! - NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard
//! - RFC 8391: XMSS: eXtended Merkle Signature Scheme

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    keys::{KeyPair, KeyError},
    pq::slh_dsa::{PublicKey as SlhPublicKey, SecretKey as SlhSecretKey, SlhDsaError},
    Address,
};

/// Default key validity duration (30 days).
pub const DEFAULT_KEY_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Transition period during which the old and new keys coexist (7 days).
pub const DEFAULT_TRANSITION_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Maximum number of simultaneously active keys
pub const MAX_ACTIVE_KEYS: usize = 3;

/// Identifiant unique d'une key in the system de rotation
pub type KeyId = u64;

/// State d'une key in the cycle de rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key in progress de generation
    Generating,
    /// Key active for signature
    Active,
    /// Key in transition (encore valid for verification)
    Transitioning,
    /// Key revoked (invalid)
    Revoked,
}

/// Metadata d'une key in the system de rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Identifiant unique de the key
    pub id: KeyId,
    /// State current de the key
    pub state: KeyState,
    /// Timestamp de creation (Unix epoch)
    pub created_at: u64,
    /// Timestamp d'activation (Unix epoch)
    pub activated_at: Option<u64>,
    /// Timestamp de revocation (Unix epoch)
    pub revoked_at: Option<u64>,
    /// Duration de vie configurede for this key
    pub lifetime: Duration,
    /// Address derived from this key
    pub address: Address,
    /// Hash de the key publique for identification rapide
    pub public_key_hash: [u8; 32],
}

impl KeyMetadata {
    /// Checks if the key is expired
    pub fn is_expired(&self, now: SystemTime) -> bool {
        if let Some(activated_at) = self.activated_at {
            let activated_time = UNIX_EPOCH + Duration::from_secs(activated_at);
            now.duration_since(activated_time)
                .map(|d| d > self.lifetime)
                .unwrap_or(true)
        } else {
            false
        }
    }

    /// Checks if the key is in period de transition
    pub fn is_in_transition(&self, now: SystemTime) -> bool {
        if let Some(activated_at) = self.activated_at {
            let activated_time = UNIX_EPOCH + Duration::from_secs(activated_at);
            let transition_start = activated_time + self.lifetime - DEFAULT_TRANSITION_PERIOD;
            now >= transition_start && !self.is_expired(now)
        } else {
            false
        }
    }
}

/// Key with ses metadata, protected par zeroize
#[derive(ZeroizeOnDrop)]
pub struct ManagedKey {
    /// Metadata publics
    pub metadata: KeyMetadata,
    /// Paire de keys (sera zeroized to the destruction)
    keypair: KeyPair,
}

impl ManagedKey {
    /// Creates a new key managed
    pub fn new(id: KeyId, lifetime: Duration) -> Result<Self, KeyRotationError> {
        let keypair = KeyPair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        // Calcul of the hash de the key publique for identification
        let public_key_bytes = keypair.public_key_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&public_key_bytes);
        let public_key_hash: [u8; 32] = hasher.finalize().into();

        let metadata = KeyMetadata {
            id,
            state: KeyState::Generating,
            created_at: now,
            activated_at: None,
            revoked_at: None,
            lifetime,
            address: keypair.address(),
            public_key_hash,
        };

        Ok(Self { metadata, keypair })
    }

    /// Read-only access to key pair
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Active the key
    pub fn activate(&mut self) -> Result<(), KeyRotationError> {
        if self.metadata.state != KeyState::Generating {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        self.metadata.state = KeyState::Active;
        self.metadata.activated_at = Some(now);

        Ok(())
    }

    /// Met the key in transition
    pub fn transition(&mut self) -> Result<(), KeyRotationError> {
        if self.metadata.state != KeyState::Active {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        self.metadata.state = KeyState::Transitioning;
        Ok(())
    }

    /// Revokes the key
    pub fn revoke(&mut self) -> Result<(), KeyRotationError> {
        if matches!(self.metadata.state, KeyState::Revoked) {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        self.metadata.state = KeyState::Revoked;
        self.metadata.revoked_at = Some(now);

        Ok(())
    }
}

/// Gestionnaire de rotation automatique of keys SLH-DSA
pub struct KeyRotationManager {
    /// Keys manageds indexed par ID
    keys: HashMap<KeyId, ManagedKey>,
    /// ID de the prochaine key to generate
    next_key_id: KeyId,
    /// Key currently active for signature
    active_key_id: Option<KeyId>,
    /// Configuration de duration de vie by default
    default_lifetime: Duration,
    /// Last verification de rotation
    last_rotation_check: SystemTime,
}

impl KeyRotationManager {
    /// Creates a new rotation manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: DEFAULT_KEY_LIFETIME,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Creates a manager with a duration de vie custom
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: lifetime,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Generates a new key
    pub fn generate_key(&mut self) -> Result<KeyId, KeyRotationError> {
        if self.keys.len() >= MAX_ACTIVE_KEYS {
            return Err(KeyRotationError::TooManyKeys);
        }

        let key_id = self.next_key_id;
        self.next_key_id += 1;

        let managed_key = ManagedKey::new(key_id, self.default_lifetime)?;
        self.keys.insert(key_id, managed_key);

        Ok(key_id)
    }

    /// Active a key for signature
    pub fn activate_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.activate()?;

        // Met l'ancienne key active in transition if elle exists
        if let Some(old_active_id) = self.active_key_id {
            if old_active_id != key_id {
                if let Some(old_key) = self.keys.get_mut(&old_active_id) {
                    let _ = old_key.transition();
                }
            }
        }

        self.active_key_id = Some(key_id);
        Ok(())
    }

    /// Gets the active key for signing
    pub fn active_key(&self) -> Option<&ManagedKey> {
        self.active_key_id
            .and_then(|id| self.keys.get(&id))
    }

    /// Gets a key by its ID
    pub fn get_key(&self, key_id: KeyId) -> Option<&ManagedKey> {
        self.keys.get(&key_id)
    }

    /// Liste all keys with leur state
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.keys.values().map(|k| &k.metadata).collect()
    }

    /// Revokes a key
    pub fn revoke_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.revoke()?;

        // Si it was the key active, on the disables
        if self.active_key_id == Some(key_id) {
            self.active_key_id = None;
        }

        Ok(())
    }

    /// Cleans up the keys revoked anciennes
    pub fn cleanup_revoked_keys(&mut self, retention_period: Duration) -> usize {
        let now = SystemTime::now();
        let mut to_remove = Vec::new();

        for (id, key) in &self.keys {
            if key.metadata.state == KeyState::Revoked {
                if let Some(revoked_at) = key.metadata.revoked_at {
                    let revoked_time = UNIX_EPOCH + Duration::from_secs(revoked_at);
                    if now.duration_since(revoked_time)
                        .map(|d| d > retention_period)
                        .unwrap_or(false)
                    {
                        to_remove.push(*id);
                    }
                }
            }
        }

        let removed_count = to_remove.len();
        for id in to_remove {
            self.keys.remove(&id);
        }

        removed_count
    }

    /// Checks if a rotation automatique is necessary
    pub fn check_rotation_needed(&mut self) -> Result<bool, KeyRotationError> {
        let now = SystemTime::now();
        self.last_rotation_check = now;

        if let Some(active_key) = self.active_key() {
            // Check if the key active is in period de transition
            if active_key.metadata.is_in_transition(now) {
                return Ok(true);
            }

            // Check if the key active is expired
            if active_key.metadata.is_expired(now) {
                return Ok(true);
            }
        } else {
            // No key active, rotation necessary
            return Ok(true);
        }

        Ok(false)
    }

    /// Performs a rotation automatique if necessary
    pub fn auto_rotate(&mut self) -> Result<Option<KeyId>, KeyRotationError> {
        if !self.check_rotation_needed()? {
            return Ok(None);
        }

        // Generates a new key
        let new_key_id = self.generate_key()?;

        // Active immediately the new key
        self.activate_key(new_key_id)?;

        Ok(Some(new_key_id))
    }

    /// Trouve a key par son hash de key publique
    pub fn find_key_by_public_hash(&self, public_key_hash: &[u8; 32]) -> Option<&ManagedKey> {
        self.keys.values()
            .find(|k| &k.metadata.public_key_hash == public_key_hash)
    }

    /// Checks if a key can be used for verification
    pub fn can_verify_with_key(&self, key_id: KeyId) -> bool {
        if let Some(key) = self.keys.get(&key_id) {
            matches!(key.metadata.state, KeyState::Active | KeyState::Transitioning)
        } else {
            false
        }
    }

    /// Gets the statistics of the gestionnaire
    pub fn stats(&self) -> KeyRotationStats {
        let mut stats = KeyRotationStats::default();

        for key in self.keys.values() {
            match key.metadata.state {
                KeyState::Generating => stats.generating += 1,
                KeyState::Active => stats.active += 1,
                KeyState::Transitioning => stats.transitioning += 1,
                KeyState::Revoked => stats.revoked += 1,
            }
        }

        stats.total = self.keys.len();
        stats
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistiques of the rotation manager
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyRotationStats {
    pub total: usize,
    pub generating: usize,
    pub active: usize,
    pub transitioning: usize,
    pub revoked: usize,
}

/// Errors of the system de rotation of keys
#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("Key non founde")]
    KeyNotFound,

    #[error("Transition d'state invalid")]
    InvalidStateTransition,

    #[error("Trop de keys active (maximum: {MAX_ACTIVE_KEYS})")]
    TooManyKeys,

    #[error("System time error")]
    TimeError,

    #[error("Error de generation de key: {0}")]
    KeyGenerationError(#[from] KeyError),

    #[error("SLH-DSA error: {0}")]
    SlhDsaError(#[from] SlhDsaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_key_generation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        assert_eq!(key_id, 1);
        assert!(manager.get_key(key_id).is_some());
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Generating);
    }

    #[test]
    fn test_key_activation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Active);
        assert!(key.metadata.activated_at.is_some());
        assert_eq!(manager.active_key_id, Some(key_id));
    }

    #[test]
    fn test_key_transition() {
        let mut manager = KeyRotationManager::new();
        let key_id1 = manager.generate_key().unwrap();
        let key_id2 = manager.generate_key().unwrap();
        
        manager.activate_key(key_id1).unwrap();
        manager.activate_key(key_id2).unwrap();
        
        // La first key must be in transition
        let key1 = manager.get_key(key_id1).unwrap();
        assert_eq!(key1.metadata.state, KeyState::Transitioning);
        
        // La seconde key must be active
        let key2 = manager.get_key(key_id2).unwrap();
        assert_eq!(key2.metadata.state, KeyState::Active);
        assert_eq!(manager.active_key_id, Some(key_id2));
    }

    #[test]
    fn test_key_revocation() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        manager.revoke_key(key_id).unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Revoked);
        assert!(key.metadata.revoked_at.is_some());
        assert_eq!(manager.active_key_id, None);
    }

    #[test]
    fn test_max_keys_limit() {
        let mut manager = KeyRotationManager::new();
        
        // Generates the maximum de keys
        for _ in 0..MAX_ACTIVE_KEYS {
            manager.generate_key().unwrap();
        }
        
        // La suivante must failsr
        assert!(matches!(
            manager.generate_key(),
            Err(KeyRotationError::TooManyKeys)
        ));
    }

    #[test]
    fn test_cleanup_revoked_keys() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        manager.activate_key(key_id).unwrap();
        manager.revoke_key(key_id).unwrap();
        
        // Cleanup immediate (retention = 0)
        let removed = manager.cleanup_revoked_keys(Duration::from_secs(0));
        assert_eq!(removed, 1);
        assert!(manager.get_key(key_id).is_none());
    }

    #[test]
    fn test_key_expiration() {
        let short_lifetime = Duration::from_millis(100);
        let mut manager = KeyRotationManager::with_lifetime(short_lifetime);
        
        let key_id = manager.generate_key().unwrap();
        manager.activate_key(key_id).unwrap();
        
        // Wait l'expiration
        thread::sleep(Duration::from_millis(150));
        
        let key = manager.get_key(key_id).unwrap();
        assert!(key.metadata.is_expired(SystemTime::now()));
        
        assert!(manager.check_rotation_needed().unwrap());
    }

    #[test]
    fn test_auto_rotation() {
        let short_lifetime = Duration::from_millis(100);
        let mut manager = KeyRotationManager::with_lifetime(short_lifetime);
        
        let key_id1 = manager.generate_key().unwrap();
        manager.activate_key(key_id1).unwrap();
        
        // Wait l'expiration
        thread::sleep(Duration::from_millis(150));
        
        // Rotation automatique
        let new_key_id = manager.auto_rotate().unwrap();
        assert!(new_key_id.is_some());
        
        let new_id = new_key_id.unwrap();
        assert_ne!(new_id, key_id1);
        assert_eq!(manager.active_key_id, Some(new_id));
        
        // L'ancienne key must be in transition
        let old_key = manager.get_key(key_id1).unwrap();
        assert_eq!(old_key.metadata.state, KeyState::Transitioning);
    }

    #[test]
    fn test_find_key_by_public_hash() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        let key = manager.get_key(key_id).unwrap();
        let public_hash = key.metadata.public_key_hash;
        
        let found_key = manager.find_key_by_public_hash(&public_hash);
        assert!(found_key.is_some());
        assert_eq!(found_key.unwrap().metadata.id, key_id);
    }

    #[test]
    fn test_verification_permissions() {
        let mut manager = KeyRotationManager::new();
        let key_id = manager.generate_key().unwrap();
        
        // Key in generation - pas de verification
        assert!(!manager.can_verify_with_key(key_id));
        
        // Key active - verification OK
        manager.activate_key(key_id).unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Key in transition - verification OK
        let key = manager.keys.get_mut(&key_id).unwrap();
        key.transition().unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Key revoked - pas de verification
        let key = manager.keys.get_mut(&key_id).unwrap();
        key.revoke().unwrap();
        assert!(!manager.can_verify_with_key(key_id));
    }

    #[test]
    fn test_stats() {
        let mut manager = KeyRotationManager::new();
        
        let key_id1 = manager.generate_key().unwrap();
        let key_id2 = manager.generate_key().unwrap();
        let key_id3 = manager.generate_key().unwrap();
        
        manager.activate_key(key_id1).unwrap();
        manager.activate_key(key_id2).unwrap(); // key_id1 passe en transition
        manager.revoke_key(key_id3).unwrap();
        
        let stats = manager.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.transitioning, 1);
        assert_eq!(stats.revoked, 1);
        assert_eq!(stats.generating, 0);
    }
}