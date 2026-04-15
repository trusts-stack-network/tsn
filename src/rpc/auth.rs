//! Authentication par API keys for the RPC TSN
//!
//! Supporte :
//! - API keys with permissions (read, write, admin)
//! - Rate limiting par key API
//! - Expiration and revocation of keys
//! - HMAC-SHA256 for the validation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;
use tracing::{info, warn, error};

/// Permissions possibles for a API key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiPermission {
    /// Lecture only (getblock, gettransaction, etc.)
    Read,
    /// Writing (sendtransaction, submitblock)
    Write,
    /// Administration (peer management, debug, config)
    Admin,
}

impl ApiPermission {
    /// Checks if the permission allows l'access to a other permission
    pub fn allows(&self, required: &ApiPermission) -> bool {
        match (self, required) {
            (ApiPermission::Admin, _) => true,
            (ApiPermission::Write, ApiPermission::Read) => true,
            (ApiPermission::Write, ApiPermission::Write) => true,
            (ApiPermission::Read, ApiPermission::Read) => true,
            _ => false,
        }
    }
}

/// Metadata d'une API key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMetadata {
    /// Nom/description de the key
    pub name: String,
    /// Permissions associateds
    pub permissions: Vec<ApiPermission>,
    /// Timestamp de creation
    pub created_at: u64,
    /// Timestamp d'expiration (0 = jamais)
    pub expires_at: u64,
    /// Maximum number of requests per minute
    pub rate_limit_rpm: u32,
    /// Key est-elle active
    pub is_active: bool,
    /// Total number of performed requests
    pub total_requests: u64,
    /// Last utilisation
    pub last_used: Option<u64>,
}

impl ApiKeyMetadata {
    /// Creates a new metadata de key API
    pub fn new(name: impl Into<String>, permissions: Vec<ApiPermission>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            name: name.into(),
            permissions,
            created_at: now,
            expires_at: 0,
            rate_limit_rpm: 1000,
            is_active: true,
            total_requests: 0,
            last_used: None,
        }
    }

    /// Checks if the key a expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Checks if the key a the permission requise
    pub fn has_permission(&self, required: &ApiPermission) -> bool {
        self.permissions.iter().any(|p| p.allows(required))
    }
}

/// Gestionnaire d'authentification API
pub struct ApiKeyManager {
    /// Stockage of keys API (hash -> metadata)
    keys: Arc<RwLock<HashMap<String, ApiKeyMetadata>>>,
    /// Rate limiting par key (hash -> timestamps of requests)
    rate_limits: Arc<RwLock<HashMap<String, Vec<u64>>>>,
}

impl ApiKeyManager {
    /// Creates a new manager of keys API
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generates a new API key
    pub async fn generate_key(&self, metadata: ApiKeyMetadata) -> String {
        let key = Self::generate_random_key();
        let hash = Self::hash_key(&key);
        
        let mut keys = self.keys.write().await;
        keys.insert(hash.clone(), metadata);
        
        info!("Generated new API key: {} (permissions: {:?})", 
            &key[..16], 
            keys.get(&hash).map(|m| &m.permissions)
        );
        
        key
    }

    /// Validates a API key and returns ses metadata if valid
    pub async fn validate_key(&self, key: &str) -> Option<ApiKeyMetadata> {
        let hash = Self::hash_key(key);
        let mut keys = self.keys.write().await;
        
        if let Some(metadata) = keys.get_mut(&hash) {
            if !metadata.is_active {
                warn!("API key rejected: inactive");
                return None;
            }
            
            if metadata.is_expired() {
                warn!("API key rejected: expired");
                return None;
            }
            
            // Update the stats
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            metadata.total_requests += 1;
            metadata.last_used = Some(now);
            
            Some(metadata.clone())
        } else {
            None
        }
    }

    /// Verifies the rate limiting for a key
    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let hash = Self::hash_key(key);
        let keys = self.keys.read().await;
        
        let metadata = match keys.get(&hash) {
            Some(m) => m.clone(),
            None => return false,
        };
        drop(keys);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now.saturating_sub(60); // Window de 1 minute
        
        let mut rate_limits = self.rate_limits.write().await;
        let timestamps = rate_limits.entry(hash).or_default();
        
        // Clean up the anciennes entries
        timestamps.retain(|&t| t > window_start);
        
        // Check if on exceeds the limite
        if timestamps.len() >= metadata.rate_limit_rpm as usize {
            warn!("Rate limit exceeded for API key");
            return false;
        }
        
        timestamps.push(now);
        true
    }

    /// Revokes a API key
    pub async fn revoke_key(&self, key: &str) -> bool {
        let hash = Self::hash_key(key);
        let mut keys = self.keys.write().await;
        
        if keys.remove(&hash).is_some() {
            info!("Revoked API key: {}...", &key[..16]);
            true
        } else {
            false
        }
    }

    /// Lists all API keys (for admin)
    pub async fn list_keys(&self) -> Vec<(String, ApiKeyMetadata)> {
        let keys = self.keys.read().await;
        keys.iter()
            .map(|(hash, meta)| (hash.clone(), meta.clone()))
            .collect()
    }

    /// Generates a key random secure
    fn generate_random_key() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        format!("tsn_{}", hex::encode(bytes))
    }

    /// Hash a key API for the stockage
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Middleware d'extraction de l'API key from the headers
#[derive(Debug, Clone)]
pub struct ApiKeyExtractor {
    pub key: String,
    pub metadata: ApiKeyMetadata,
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing API key")]
    MissingKey,
    #[error("Invalid API key")]
    InvalidKey,
    #[error("API key expired")]
    ExpiredKey,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_key_generation() {
        let manager = ApiKeyManager::new();
        let metadata = ApiKeyMetadata::new("test", vec![ApiPermission::Read]);
        let key = manager.generate_key(metadata).await;
        
        assert!(key.starts_with("tsn_"));
        assert_eq!(key.len(), 32 + 4); // "tsn_" + 64 hex chars
    }

    #[tokio::test]
    async fn test_api_key_validation() {
        let manager = ApiKeyManager::new();
        let metadata = ApiKeyMetadata::new("test", vec![ApiPermission::Read]);
        let key = manager.generate_key(metadata).await;
        
        let validated = manager.validate_key(&key).await;
        assert!(validated.is_some());
        
        let invalid = manager.validate_key("invalid_key").await;
        assert!(invalid.is_none());
    }

    #[tokio::test]
    async fn test_permissions() {
        let manager = ApiKeyManager::new();
        let metadata = ApiKeyMetadata::new("test", vec![ApiPermission::Read, ApiPermission::Write]);
        let key = manager.generate_key(metadata).await;
        
        let validated = manager.validate_key(&key).await.unwrap();
        assert!(validated.has_permission(&ApiPermission::Read));
        assert!(validated.has_permission(&ApiPermission::Write));
        assert!(!validated.has_permission(&ApiPermission::Admin));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let manager = ApiKeyManager::new();
        let mut metadata = ApiKeyMetadata::new("test", vec![ApiPermission::Read]);
        metadata.rate_limit_rpm = 5;
        let key = manager.generate_key(metadata).await;
        
        // 5 requests should pass
        for _ in 0..5 {
            assert!(manager.check_rate_limit(&key).await);
        }
        
        // La 6th should be rejectede
        assert!(!manager.check_rate_limit(&key).await);
    }

    #[tokio::test]
    async fn test_key_revocation() {
        let manager = ApiKeyManager::new();
        let metadata = ApiKeyMetadata::new("test", vec![ApiPermission::Read]);
        let key = manager.generate_key(metadata).await;
        
        assert!(manager.validate_key(&key).await.is_some());
        assert!(manager.revoke_key(&key).await);
        assert!(manager.validate_key(&key).await.is_none());
    }
}
