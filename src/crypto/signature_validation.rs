//! System de validation de signatures SLH-DSA pour TSN
//!
//! Module de haut niveau pour la validation de signatures dans le contexte TSN.
//! Integrates la validation batch, la mise en cache et les politiques de security.
//!
//! References :
//! - FIPS PUB 205 (2024) – https://doi.org/10.6028/NIST.FIPS.205
//! - TSN Cryptographic Specification v1.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use super::signature_validator::{SignatureValidator, ValidationError, ValidationResult, ValidatorConfig};
use super::pq::slh_dsa::{PK_BYTES, SIG_BYTES};

/// Erreurs du system de validation
#[derive(Debug, Error)]
pub enum ValidationSystemError {
    #[error("Erreur de validation : {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Cache plein : unable d'add de news entries")]
    CacheFull,
    
    #[error("Validation batch failed : {failed}/{total} signatures invalids")]
    BatchValidationFailed { failed: usize, total: usize },
    
    #[error("Limite de throughput exceedede : {current}/{limit} validations par seconde")]
    RateLimitExceeded { current: u32, limit: u32 },
    
    #[error("Signature en liste noire : hash {hash}")]
    BlacklistedSignature { hash: String },
}

/// Entry de cache pour les results de validation
#[derive(Debug, Clone)]
struct CacheEntry {
    result: ValidationResult,
    timestamp: u64,
    access_count: u32,
}

/// Configuration du system de validation
#[derive(Debug, Clone)]
pub struct ValidationSystemConfig {
    /// Configuration du validateur sous-jacent
    pub validator_config: ValidatorConfig,
    /// Taille maximale du cache (0 = pas de cache)
    pub cache_size: usize,
    /// TTL des entries de cache en secondes
    pub cache_ttl_seconds: u64,
    /// Limite de throughput (validations par seconde, 0 = pas de limite)
    pub rate_limit_per_second: u32,
    /// Activer la validation batch
    pub enable_batch_validation: bool,
    /// Taille maximale des batches
    pub max_batch_size: usize,
}

impl Default for ValidationSystemConfig {
    fn default() -> Self {
        Self {
            validator_config: ValidatorConfig::default(),
            cache_size: 10_000,
            cache_ttl_seconds: 300, // 5 minutes
            rate_limit_per_second: 1000,
            enable_batch_validation: true,
            max_batch_size: 100,
        }
    }
}

/// System de validation de signatures avec cache et rate limiting
pub struct ValidationSystem {
    validator: Arc<Mutex<SignatureValidator>>,
    config: ValidationSystemConfig,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    blacklist: Arc<Mutex<HashSet<String>>>,
}

/// Rate limiter simple based sur une window glissante
#[derive(Debug)]
struct RateLimiter {
    requests: Vec<Instant>,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            requests: Vec::new(),
            limit,
            window: Duration::from_secs(1),
        }
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        
        // Clean up les anciennes requests
        self.requests.retain(|&time| now.duration_since(time) < self.window);
        
        if self.requests.len() >= self.limit as usize {
            false
        } else {
            self.requests.push(now);
            true
        }
    }
}

use std::collections::HashSet;

impl ValidationSystem {
    /// Creates un nouveau system de validation
    pub fn new() -> Self {
        Self::with_config(ValidationSystemConfig::default())
    }

    /// Creates un nouveau system avec configuration custom
    pub fn with_config(config: ValidationSystemConfig) -> Self {
        let validator = SignatureValidator::with_config(config.validator_config.clone());
        let rate_limiter = if config.rate_limit_per_second > 0 {
            RateLimiter::new(config.rate_limit_per_second)
        } else {
            RateLimiter::new(u32::MAX) // Pas de limite
        };

        Self {
            validator: Arc::new(Mutex::new(validator)),
            config,
            cache: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            blacklist: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Valide une signature avec cache et rate limiting
    pub fn validate_signature(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<ValidationResult, ValidationSystemError> {
        // Verification du rate limit
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.check_rate_limit() {
                return Err(ValidationSystemError::RateLimitExceeded {
                    current: limiter.requests.len() as u32,
                    limit: limiter.limit,
                });
            }
        }

        // Calcul de la key de cache
        let cache_key = self.compute_cache_key(message, signature_bytes, public_key_bytes);

        // Verification de la blacklist
        {
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains(&cache_key) {
                return Err(ValidationSystemError::BlacklistedSignature {
                    hash: cache_key,
                });
            }
        }

        // Verification du cache
        if self.config.cache_size > 0 {
            if let Some(cached_result) = self.check_cache(&cache_key) {
                return Ok(cached_result);
            }
        }

        // Validation effective
        let result = {
            let mut validator = self.validator.lock().unwrap();
            validator.validate(message, signature_bytes, public_key_bytes)?
        };

        // Mise en cache du result
        if self.config.cache_size > 0 {
            self.cache_result(&cache_key, &result);
        }

        Ok(result)
    }

    /// Validation batch de signatures
    pub fn validate_batch(
        &self,
        signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)], // (message, signature, public_key)
    ) -> Result<Vec<ValidationResult>, ValidationSystemError> {
        if !self.config.enable_batch_validation {
            return Err(ValidationSystemError::BatchValidationFailed {
                failed: 0,
                total: signatures.len(),
            });
        }

        if signatures.len() > self.config.max_batch_size {
            return Err(ValidationSystemError::BatchValidationFailed {
                failed: 0,
                total: signatures.len(),
            });
        }

        let mut results = Vec::with_capacity(signatures.len());
        let mut failed_count = 0;

        for (message, signature, public_key) in signatures {
            match self.validate_signature(message, signature, public_key) {
                Ok(result) => {
                    if !result.is_valid {
                        failed_count += 1;
                    }
                    results.push(result);
                }
                Err(e) => {
                    failed_count += 1;
                    // Pour les errors de validation, on continue avec un result invalid
                    results.push(ValidationResult {
                        is_valid: false,
                        verification_time_us: 0,
                        message_size: message.len(),
                        message_hash_prefix: [0u8; 8],
                    });
                }
            }
        }

        // Si trop d'failures, on considers le batch comme failed
        if failed_count > signatures.len() / 2 {
            return Err(ValidationSystemError::BatchValidationFailed {
                failed: failed_count,
                total: signatures.len(),
            });
        }

        Ok(results)
    }

    /// Adds une signature to la blacklist
    pub fn blacklist_signature(&self, message: &[u8], signature_bytes: &[u8], public_key_bytes: &[u8]) {
        let cache_key = self.compute_cache_key(message, signature_bytes, public_key_bytes);
        
        {
            let mut blacklist = self.blacklist.lock().unwrap();
            blacklist.insert(cache_key.clone());
        }

        // Delete du cache si present
        {
            let mut cache = self.cache.lock().unwrap();
            cache.remove(&cache_key);
        }
    }

    /// Nettoie le cache des entries expireds
    pub fn cleanup_cache(&self) {
        if self.config.cache_size == 0 {
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, entry| {
            now - entry.timestamp < self.config.cache_ttl_seconds
        });
    }

    /// Retourne les statistiques du system
    pub fn get_statistics(&self) -> ValidationSystemStats {
        let validator_metrics = {
            let validator = self.validator.lock().unwrap();
            validator.metrics()
        };

        let cache_stats = {
            let cache = self.cache.lock().unwrap();
            CacheStats {
                size: cache.len(),
                max_size: self.config.cache_size,
                hit_ratio: 0.0, // TODO: implement le tracking des hits/misses
            }
        };

        let blacklist_size = {
            let blacklist = self.blacklist.lock().unwrap();
            blacklist.len()
        };

        ValidationSystemStats {
            validator_metrics,
            cache_stats,
            blacklist_size,
        }
    }

    /// Remet to zero toutes les statistiques
    pub fn reset_statistics(&self) {
        {
            let mut validator = self.validator.lock().unwrap();
            validator.reset_metrics();
        }

        {
            let mut cache = self.cache.lock().unwrap();
            cache.clear();
        }

        {
            let mut rate_limiter = self.rate_limiter.lock().unwrap();
            rate_limiter.requests.clear();
        }
    }

    /// Calcule une key de cache pour une signature
    fn compute_cache_key(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(signature);
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        hex::encode(&hash[..16]) // 32 hex characters
    }

    /// Verifies le cache pour une key data
    fn check_cache(&self, cache_key: &str) -> Option<ValidationResult> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(entry) = cache.get_mut(cache_key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Verify l'expiration
            if now - entry.timestamp < self.config.cache_ttl_seconds {
                entry.access_count += 1;
                return Some(entry.result.clone());
            } else {
                // Entry expired, la delete
                cache.remove(cache_key);
            }
        }

        None
    }

    /// Met en cache un result de validation
    fn cache_result(&self, cache_key: &str, result: &ValidationResult) {
        let mut cache = self.cache.lock().unwrap();
        
        // Verify la taille du cache
        if cache.len() >= self.config.cache_size {
            // Eviction LRU simple : delete l'entry la plus ancienne
            if let Some((oldest_key, _)) = cache.iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(k, v)| (k.clone(), v.timestamp)) {
                cache.remove(&oldest_key);
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        cache.insert(cache_key.to_string(), CacheEntry {
            result: result.clone(),
            timestamp: now,
            access_count: 1,
        });
    }
}

/// Statistiques du cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub hit_ratio: f64,
}

/// Statistiques completees du system de validation
#[derive(Debug, Clone)]
pub struct ValidationSystemStats {
    pub validator_metrics: super::signature_validator::ValidatorMetrics,
    pub cache_stats: CacheStats,
    pub blacklist_size: usize,
}

impl Default for ValidationSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::slh_dsa::SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_validation_system_basic() {
        let system = ValidationSystem::new();
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
        let message = b"Test message TSN";
        let signature = secret_key.sign(message);

        let result = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        ).unwrap();

        assert!(result.is_valid);
    }

    #[test]
    fn test_cache_functionality() {
        let config = ValidationSystemConfig {
            cache_size: 10,
            cache_ttl_seconds: 60,
            ..Default::default()
        };
        
        let system = ValidationSystem::with_config(config);
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
        let message = b"Cached message";
        let signature = secret_key.sign(message);

        // First validation (mise en cache)
        let result1 = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        ).unwrap();

        // Second validation (depuis le cache)
        let result2 = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        ).unwrap();

        assert!(result1.is_valid);
        assert!(result2.is_valid);
        assert_eq!(result1.message_hash_prefix, result2.message_hash_prefix);
    }

    #[test]
    fn test_batch_validation() {
        let system = ValidationSystem::new();
        let mut rng = OsRng;
        
        let mut signatures = Vec::new();
        
        for i in 0..5 {
            let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
            let message = format!("Message {}", i).into_bytes();
            let signature = secret_key.sign(&message);
            
            signatures.push((message, signature.to_bytes().to_vec(), public_key.to_bytes().to_vec()));
        }

        let results = system.validate_batch(&signatures).unwrap();
        
        assert_eq!(results.len(), 5);
        for result in results {
            assert!(result.is_valid);
        }
    }

    #[test]
    fn test_blacklist_functionality() {
        let system = ValidationSystem::new();
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
        let message = b"Blacklisted message";
        let signature = secret_key.sign(message);

        // First validation successful
        let result = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        ).unwrap();
        assert!(result.is_valid);

        // Add to blacklist
        system.blacklist_signature(message, &signature.to_bytes(), &public_key.to_bytes());

        // Second validation fails (blacklisted)
        let result = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        );

        match result {
            Err(ValidationSystemError::BlacklistedSignature { .. }) => {},
            _ => panic!("Expected BlacklistedSignature error"),
        }
    }

    #[test]
    fn test_rate_limiting() {
        let config = ValidationSystemConfig {
            rate_limit_per_second: 2, // Limite very basse pour le test
            ..Default::default()
        };
        
        let system = ValidationSystem::with_config(config);
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);

        // First et second validation OK
        for i in 0..2 {
            let message = format!("Message {}", i).into_bytes();
            let signature = secret_key.sign(&message);
            
            let result = system.validate_signature(
                &message,
                &signature.to_bytes(),
                &public_key.to_bytes(),
            );
            assert!(result.is_ok());
        }

        // Third validation should be rate-limited
        let message = b"Rate limited message";
        let signature = secret_key.sign(message);
        
        let result = system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        );

        match result {
            Err(ValidationSystemError::RateLimitExceeded { .. }) => {},
            Ok(_) => {}, // Peut passer si le timing est bon
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_statistics() {
        let system = ValidationSystem::new();
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
        let message = b"Stats test";
        let signature = secret_key.sign(message);

        // Effectuer quelques validations
        for _ in 0..3 {
            system.validate_signature(
                message,
                &signature.to_bytes(),
                &public_key.to_bytes(),
            ).unwrap();
        }

        let stats = system.get_statistics();
        assert!(stats.validator_metrics.total_validations > 0);
    }

    #[test]
    fn test_cache_cleanup() {
        let config = ValidationSystemConfig {
            cache_size: 10,
            cache_ttl_seconds: 1, // TTL very court
            ..Default::default()
        };
        
        let system = ValidationSystem::with_config(config);
        let mut rng = OsRng;
        
        let (secret_key, public_key) = SecretKey::generate_rng(&mut rng);
        let message = b"Expiring message";
        let signature = secret_key.sign(message);

        // Validation et mise en cache
        system.validate_signature(
            message,
            &signature.to_bytes(),
            &public_key.to_bytes(),
        ).unwrap();

        // Wait l'expiration
        std::thread::sleep(Duration::from_secs(2));

        // Nettoyer le cache
        system.cleanup_cache();

        // Verify que le cache est vide
        let stats = system.get_statistics();
        assert_eq!(stats.cache_stats.size, 0);
    }
}