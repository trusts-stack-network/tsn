//! Mecanisme de rotation automatique des keys SLH-DSA
//!
//! Implemente un system de rotation periodic des keys post-quantiques pour maintenir
//! la security a long terme. Base sur les recommandations NIST SP 800-57 Part 1 Rev. 5
//! pour la gestion des keys cryptographiques.
//!
//! ## Security
//!
//! La rotation des keys SLH-DSA est critique pour la security post-quantique car :
//! - Limite l'exposition temporelle des keys privates
//! - Reduit l'impact d'une compromission eventuelle
//! - Prepare la transition vers de nouveaux parameters if needed
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

/// Duration de validite by default d'une key (30 jours)
pub const DEFAULT_KEY_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Periode de transition pendant laquelle l'oldne et la nouvelle key coexistent (7 jours)
pub const DEFAULT_TRANSITION_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Nombre maximum de keys actives simultanement
pub const MAX_ACTIVE_KEYS: usize = 3;

/// Identifiant unique d'une key dans le system de rotation
pub type KeyId = u64;

/// State d'une key dans le cycle de rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key in progress de generation
    Generating,
    /// Key active pour signature
    Active,
    /// Key en transition (encore valide pour verification)
    Transitioning,
    /// Key revoquee (invalid)
    Revoked,
}

/// Metadata d'une key dans le system de rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Identifiant unique de la key
    pub id: KeyId,
    /// State current de la key
    pub state: KeyState,
    /// Timestamp de creation (Unix epoch)
    pub created_at: u64,
    /// Timestamp d'activation (Unix epoch)
    pub activated_at: Option<u64>,
    /// Timestamp de revocation (Unix epoch)
    pub revoked_at: Option<u64>,
    /// Duration de vie configuree pour cette key
    pub lifetime: Duration,
    /// Adresse derivee de cette key
    pub address: Address,
    /// Hash de la key publique pour identification rapide
    pub public_key_hash: [u8; 32],
}

impl KeyMetadata {
    /// Checks if la key est expiree
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

    /// Checks if la key est en period de transition
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

/// Key avec ses metadata, protegee par zeroize
#[derive(ZeroizeOnDrop)]
pub struct ManagedKey {
    /// Metadata publiques
    pub metadata: KeyMetadata,
    /// Paire de keys (sera zeroisee a la destruction)
    keypair: KeyPair,
}

impl ManagedKey {
    /// Creates a nouvelle key geree
    pub fn new(id: KeyId, lifetime: Duration) -> Result<Self, KeyRotationError> {
        let keypair = KeyPair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyRotationError::TimeError)?
            .as_secs();

        // Calcul du hash de la key publique pour identification
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

    /// Acces en lecture seule a la paire de keys
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Active la key
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

    /// Met la key en transition
    pub fn transition(&mut self) -> Result<(), KeyRotationError> {
        if self.metadata.state != KeyState::Active {
            return Err(KeyRotationError::InvalidStateTransition);
        }

        self.metadata.state = KeyState::Transitioning;
        Ok(())
    }

    /// Revoque la key
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

/// Gestionnaire de rotation automatique des keys SLH-DSA
pub struct KeyRotationManager {
    /// Keys gerees indexees par ID
    keys: HashMap<KeyId, ManagedKey>,
    /// ID de la prochaine key a generate
    next_key_id: KeyId,
    /// Key currentlement active pour signature
    active_key_id: Option<KeyId>,
    /// Configuration de duration de vie by default
    default_lifetime: Duration,
    /// Derniere verification de rotation
    last_rotation_check: SystemTime,
}

impl KeyRotationManager {
    /// Creates a nouveau manager de rotation
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: DEFAULT_KEY_LIFETIME,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Creates a manager avec une duration de vie personnalisee
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: 1,
            active_key_id: None,
            default_lifetime: lifetime,
            last_rotation_check: SystemTime::now(),
        }
    }

    /// Generates ae nouvelle key
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

    /// Active une key pour signature
    pub fn activate_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.activate()?;

        // Met l'oldne key active en transition si elle existe
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

    /// Gets the key active pour signature
    pub fn active_key(&self) -> Option<&ManagedKey> {
        self.active_key_id
            .and_then(|id| self.keys.get(&id))
    }

    /// Obtient une key par son ID
    pub fn get_key(&self, key_id: KeyId) -> Option<&ManagedKey> {
        self.keys.get(&key_id)
    }

    /// Liste toutes les keys avec leur state
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.keys.values().map(|k| &k.metadata).collect()
    }

    /// Revoque une key
    pub fn revoke_key(&mut self, key_id: KeyId) -> Result<(), KeyRotationError> {
        let key = self.keys.get_mut(&key_id)
            .ok_or(KeyRotationError::KeyNotFound)?;

        key.revoke()?;

        // Si c'etait la key active, on la desactive
        if self.active_key_id == Some(key_id) {
            self.active_key_id = None;
        }

        Ok(())
    }

    /// Cleans up the keys revoquees oldnes
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

    /// Checks if une rotation automatique est necessary
    pub fn check_rotation_needed(&mut self) -> Result<bool, KeyRotationError> {
        let now = SystemTime::now();
        self.last_rotation_check = now;

        if let Some(active_key) = self.active_key() {
            // Checks if la key active est en period de transition
            if active_key.metadata.is_in_transition(now) {
                return Ok(true);
            }

            // Checks if la key active est expiree
            if active_key.metadata.is_expired(now) {
                return Ok(true);
            }
        } else {
            // Aucune key active, rotation necessary
            return Ok(true);
        }

        Ok(false)
    }

    /// Performs ae rotation automatique if needed
    pub fn auto_rotate(&mut self) -> Result<Option<KeyId>, KeyRotationError> {
        if !self.check_rotation_needed()? {
            return Ok(None);
        }

        // Generates ae nouvelle key
        let new_key_id = self.generate_key()?;

        // Active immediatement la nouvelle key
        self.activate_key(new_key_id)?;

        Ok(Some(new_key_id))
    }

    /// Trouve une key par son hash de key publique
    pub fn find_key_by_public_hash(&self, public_key_hash: &[u8; 32]) -> Option<&ManagedKey> {
        self.keys.values()
            .find(|k| &k.metadata.public_key_hash == public_key_hash)
    }

    /// Checks if une key peut be utilisee pour verification
    pub fn can_verify_with_key(&self, key_id: KeyId) -> bool {
        if let Some(key) = self.keys.get(&key_id) {
            matches!(key.metadata.state, KeyState::Active | KeyState::Transitioning)
        } else {
            false
        }
    }

    /// Gets thes statistiques du manager
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

/// Statistiques du manager de rotation
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyRotationStats {
    pub total: usize,
    pub generating: usize,
    pub active: usize,
    pub transitioning: usize,
    pub revoked: usize,
}

/// Erreurs du system de rotation des keys
#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("Key non trouvee")]
    KeyNotFound,

    #[error("Transition d'state invalid")]
    InvalidStateTransition,

    #[error("Trop de keys actives (maximum: {MAX_ACTIVE_KEYS})")]
    TooManyKeys,

    #[error("Erreur de temps system")]
    TimeError,

    #[error("Erreur de generation de key: {0}")]
    KeyGenerationError(#[from] KeyError),

    #[error("Erreur SLH-DSA: {0}")]
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
        
        // La first key doit be en transition
        let key1 = manager.get_key(key_id1).unwrap();
        assert_eq!(key1.metadata.state, KeyState::Transitioning);
        
        // La seconde key doit be active
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
        
        // La suivante doit fail
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
        
        // Nettoyage immediat (retention = 0)
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
        
        // Attendre l'expiration
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
        
        // Attendre l'expiration
        thread::sleep(Duration::from_millis(150));
        
        // Rotation automatique
        let new_key_id = manager.auto_rotate().unwrap();
        assert!(new_key_id.is_some());
        
        let new_id = new_key_id.unwrap();
        assert_ne!(new_id, key_id1);
        assert_eq!(manager.active_key_id, Some(new_id));
        
        // L'oldne key doit be en transition
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
        
        // Key en generation - pas de verification
        assert!(!manager.can_verify_with_key(key_id));
        
        // Key active - verification OK
        manager.activate_key(key_id).unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Key en transition - verification OK
        let key = manager.keys.get_mut(&key_id).unwrap();
        key.transition().unwrap();
        assert!(manager.can_verify_with_key(key_id));
        
        // Key revoquee - pas de verification
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