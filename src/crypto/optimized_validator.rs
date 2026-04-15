//! Validateur cryptographique optimized for the performances
//!
//! Implements of validations de signatures and preuves ZK optimized
//! with reuse de memory and reduction of allocations.
//!
//! Utilise the memory pool for avoidr the allocations repeateds
//! and implements of techniques d'optimisation specific aux
//! algorithmes cryptographiques post-quantiques.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use crate::crypto::memory_pool::{global_pool_manager, PooledBuffer};
use crate::crypto::signature_validation::{SLHDSAValidator, ValidationResult};
use crate::crypto::halo2_proofs::{Halo2Verifier, ProofVerificationResult};

/// Cache of keys publics recently validatedes
const PUBLIC_KEY_CACHE_SIZE: usize = 1024;
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Entry of the cache de keys publics
#[derive(Debug, Clone)]
struct CachedPublicKey {
    key_hash: [u8; 32],
    validated_at: Instant,
    validation_count: u64,
}

impl CachedPublicKey {
    fn new(key_hash: [u8; 32]) -> Self {
        Self {
            key_hash,
            validated_at: Instant::now(),
            validation_count: 1,
        }
    }

    fn is_expired(&self) -> bool {
        self.validated_at.elapsed() > CACHE_TTL
    }

    fn touch(&mut self) {
        self.validated_at = Instant::now();
        self.validation_count += 1;
    }
}

/// Validateur cryptographique optimized with cache and memory pooling
pub struct OptimizedCryptoValidator {
    slh_dsa_validator: SLHDSAValidator,
    halo2_verifier: Halo2Verifier,
    public_key_cache: HashMap<[u8; 32], CachedPublicKey>,
    stats: ValidationStats,
}

#[derive(Debug, Default, Clone)]
pub struct ValidationStats {
    pub total_signature_validations: u64,
    pub total_proof_validations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_validation_time_ms: u64,
    pub average_signature_time_ms: f64,
    pub average_proof_time_ms: f64,
    pub memory_pool_usage_mb: f64,
}

impl OptimizedCryptoValidator {
    /// Creates a new validateur optimized
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            slh_dsa_validator: SLHDSAValidator::new()?,
            halo2_verifier: Halo2Verifier::new()?,
            public_key_cache: HashMap::with_capacity(PUBLIC_KEY_CACHE_SIZE),
            stats: ValidationStats::default(),
        })
    }

    /// Validates a signature SLH-DSA with optimisations memory
    pub fn validate_signature_optimized(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<ValidationResult, String> {
        let start_time = Instant::now();
        self.stats.total_signature_validations += 1;

        // Calculate the hash de the key publique for the cache
        let key_hash = self.compute_key_hash(public_key)?;

        // Verify the cache of keys publics
        if let Some(cached_key) = self.public_key_cache.get_mut(&key_hash) {
            if !cached_key.is_expired() {
                cached_key.touch();
                self.stats.cache_hits += 1;
                
                // Utilise a buffer pooled for the validation
                let mut buffer = global_pool_manager()
                    .get_signature_buffer()
                    .map_err(|e| format!("Failed to get signature buffer: {}", e))?;

                let result = self.validate_with_pooled_buffer(
                    message, 
                    signature, 
                    public_key, 
                    &mut buffer
                )?;

                // Returns the buffer at the pool
                global_pool_manager()
                    .return_signature_buffer(buffer)
                    .map_err(|e| format!("Failed to return signature buffer: {}", e))?;

                self.update_signature_timing(start_time);
                return Ok(result);
            } else {
                // Removes l'entry expired
                self.public_key_cache.remove(&key_hash);
            }
        }

        // Cache miss - validation completee
        self.stats.cache_misses += 1;
        
        let mut buffer = global_pool_manager()
            .get_signature_buffer()
            .map_err(|e| format!("Failed to get signature buffer: {}", e))?;

        let result = self.validate_with_pooled_buffer(
            message, 
            signature, 
            public_key, 
            &mut buffer
        )?;

        // Update the cache if the validation succeeds
        if matches!(result, ValidationResult::Valid) {
            self.update_public_key_cache(key_hash);
        }

        // Returns the buffer at the pool
        global_pool_manager()
            .return_signature_buffer(buffer)
            .map_err(|e| format!("Failed to return signature buffer: {}", e))?;

        self.update_signature_timing(start_time);
        Ok(result)
    }

    /// Validates a preuve Halo2 with optimisations memory
    pub fn validate_proof_optimized(
        &mut self,
        proof: &[u8],
        public_inputs: &[u8],
        circuit_params: &[u8],
    ) -> Result<ProofVerificationResult, String> {
        let start_time = Instant::now();
        self.stats.total_proof_validations += 1;

        // Utilise a buffer pooled plus grand for the preuves ZK
        let mut buffer = global_pool_manager()
            .get_proof_buffer()
            .map_err(|e| format!("Failed to get proof buffer: {}", e))?;

        let result = self.verify_proof_with_pooled_buffer(
            proof,
            public_inputs,
            circuit_params,
            &mut buffer,
        )?;

        // Returns the buffer at the pool
        global_pool_manager()
            .return_proof_buffer(buffer)
            .map_err(|e| format!("Failed to return proof buffer: {}", e))?;

        self.update_proof_timing(start_time);
        Ok(result)
    }

    /// Validation par batch for improve the performances
    pub fn validate_signatures_batch(
        &mut self,
        signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)], // (message, signature, public_key)
    ) -> Result<Vec<ValidationResult>, String> {
        let mut results = Vec::with_capacity(signatures.len());
        
        // Pre-allocates multiple buffers for the processing par batch
        let mut buffers = Vec::new();
        for _ in 0..std::cmp::min(signatures.len(), 8) {
            buffers.push(global_pool_manager().get_signature_buffer()?);
        }

        for (i, (message, signature, public_key)) in signatures.iter().enumerate() {
            let buffer_idx = i % buffers.len();
            let result = self.validate_with_pooled_buffer(
                message,
                signature,
                public_key,
                &mut buffers[buffer_idx],
            )?;
            results.push(result);
        }

        // Returns all buffers at the pool
        for buffer in buffers {
            global_pool_manager().return_signature_buffer(buffer)?;
        }

        Ok(results)
    }

    /// Validation with buffer pooled reusable
    fn validate_with_pooled_buffer(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        buffer: &mut PooledBuffer,
    ) -> Result<ValidationResult, String> {
        // Utilise the buffer pooled for the operations intermediates
        let work_slice = buffer.as_mut_slice();
        
        // Copie the data in the buffer de travail if necessary
        if message.len() + signature.len() + public_key.len() <= work_slice.len() {
            let mut offset = 0;
            
            // Copie the message
            work_slice[offset..offset + message.len()].copy_from_slice(message);
            offset += message.len();
            
            // Copie the signature
            work_slice[offset..offset + signature.len()].copy_from_slice(signature);
            offset += signature.len();
            
            // Copie the key publique
            work_slice[offset..offset + public_key.len()].copy_from_slice(public_key);
            
            // Utilise the validateur SLH-DSA with the data of the buffer
            self.slh_dsa_validator.validate_from_buffer(work_slice, message.len(), signature.len())
        } else {
            // Fallback if the data are trop large for the buffer
            self.slh_dsa_validator.validate(message, signature, public_key)
        }
    }

    /// Verification de preuve with buffer pooled
    fn verify_proof_with_pooled_buffer(
        &self,
        proof: &[u8],
        public_inputs: &[u8],
        circuit_params: &[u8],
        buffer: &mut PooledBuffer,
    ) -> Result<ProofVerificationResult, String> {
        // Utilise the buffer pooled for the calculations intermediates
        let work_slice = buffer.as_mut_slice();
        
        // Optimisation : utilise the buffer for the operations de verification
        self.halo2_verifier.verify_with_buffer(
            proof,
            public_inputs,
            circuit_params,
            work_slice,
        )
    }

    /// Calculates the hash d'une key publique for the cache
    fn compute_key_hash(&self, public_key: &[u8]) -> Result<[u8; 32], String> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let result = hasher.finalize();
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Updates the cache of keys publics
    fn update_public_key_cache(&mut self, key_hash: [u8; 32]) {
        // Clean the cache if il is plein
        if self.public_key_cache.len() >= PUBLIC_KEY_CACHE_SIZE {
            self.cleanup_expired_cache_entries();
            
            // Si toujours plein, removes the entries the plus anciennes
            if self.public_key_cache.len() >= PUBLIC_KEY_CACHE_SIZE {
                let oldest_key = self.public_key_cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.validated_at)
                    .map(|(k, _)| *k);
                
                if let Some(key) = oldest_key {
                    self.public_key_cache.remove(&key);
                }
            }
        }

        self.public_key_cache.insert(key_hash, CachedPublicKey::new(key_hash));
    }

    /// Cleans up the entries expireds of the cache
    fn cleanup_expired_cache_entries(&mut self) {
        self.public_key_cache.retain(|_, entry| !entry.is_expired());
    }

    /// Updates the statistics de timing for the signatures
    fn update_signature_timing(&mut self, start_time: Instant) {
        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        self.stats.total_validation_time_ms += elapsed_ms;
        
        // Calculate the moyenne mobile
        let total_sigs = self.stats.total_signature_validations;
        if total_sigs > 0 {
            self.stats.average_signature_time_ms = 
                (self.stats.average_signature_time_ms * (total_sigs - 1) as f64 + elapsed_ms as f64) / total_sigs as f64;
        }
    }

    /// Updates the statistics de timing for the preuves
    fn update_proof_timing(&mut self, start_time: Instant) {
        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        self.stats.total_validation_time_ms += elapsed_ms;
        
        // Calculate the moyenne mobile
        let total_proofs = self.stats.total_proof_validations;
        if total_proofs > 0 {
            self.stats.average_proof_time_ms = 
                (self.stats.average_proof_time_ms * (total_proofs - 1) as f64 + elapsed_ms as f64) / total_proofs as f64;
        }
    }

    /// Returns the statistics de validation
    pub fn stats(&self) -> ValidationStats {
        let mut stats = self.stats.clone();
        
        // Update the statistics of the memory pool
        if let Ok(pool_summary) = global_pool_manager().summary() {
            stats.memory_pool_usage_mb = pool_summary.estimated_memory_saved_mb;
        }
        
        stats
    }

    /// Remet to zero the statistics
    pub fn reset_stats(&mut self) {
        self.stats = ValidationStats::default();
    }

    /// Cleans the cache and optimise the memory
    pub fn cleanup(&mut self) {
        self.cleanup_expired_cache_entries();
        
        // Force the cleanup of the memory pool if necessary
        if let Err(e) = global_pool_manager().cleanup() {
            eprintln!("Warning: Failed to cleanup memory pools: {}", e);
        }
    }

    /// Returns of metrics de performance detailed
    pub fn performance_metrics(&self) -> PerformanceMetrics {
        let cache_hit_rate = if self.stats.cache_hits + self.stats.cache_misses > 0 {
            (self.stats.cache_hits as f64 / (self.stats.cache_hits + self.stats.cache_misses) as f64) * 100.0
        } else {
            0.0
        };

        PerformanceMetrics {
            total_validations: self.stats.total_signature_validations + self.stats.total_proof_validations,
            cache_hit_rate,
            average_signature_time_ms: self.stats.average_signature_time_ms,
            average_proof_time_ms: self.stats.average_proof_time_ms,
            memory_efficiency_mb: self.stats.memory_pool_usage_mb,
            cache_size: self.public_key_cache.len(),
            cache_capacity: PUBLIC_KEY_CACHE_SIZE,
        }
    }
}

impl Default for OptimizedCryptoValidator {
    fn default() -> Self {
        Self::new().expect("Failed to create OptimizedCryptoValidator")
    }
}

/// Performance metrics of the validateur
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub total_validations: u64,
    pub cache_hit_rate: f64,
    pub average_signature_time_ms: f64,
    pub average_proof_time_ms: f64,
    pub memory_efficiency_mb: f64,
    pub cache_size: usize,
    pub cache_capacity: usize,
}

impl std::fmt::Display for PerformanceMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Crypto Validator Performance ===")?;
        writeln!(f, "Total Validations: {}", self.total_validations)?;
        writeln!(f, "Cache Hit Rate: {:.2}%", self.cache_hit_rate)?;
        writeln!(f, "Avg Signature Time: {:.2}ms", self.average_signature_time_ms)?;
        writeln!(f, "Avg Proof Time: {:.2}ms", self.average_proof_time_ms)?;
        writeln!(f, "Memory Efficiency: {:.2}MB saved", self.memory_efficiency_mb)?;
        writeln!(f, "Cache Usage: {}/{}", self.cache_size, self.cache_capacity)?;
        Ok(())
    }
}

/// Thread-safe global validator instance using OnceLock (no unsafe).
/// Previously used `static mut` which caused Undefined Behavior when
/// accessed from multiple threads simultaneously.
static GLOBAL_VALIDATOR: std::sync::OnceLock<std::sync::Mutex<OptimizedCryptoValidator>> = std::sync::OnceLock::new();

/// Access the global optimized validator (thread-safe).
pub fn global_validator() -> std::sync::MutexGuard<'static, OptimizedCryptoValidator> {
    GLOBAL_VALIDATOR
        .get_or_init(|| {
            std::sync::Mutex::new(
                OptimizedCryptoValidator::new().expect("Failed to initialize global validator")
            )
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_validator_creation() {
        let validator = OptimizedCryptoValidator::new();
        assert!(validator.is_ok());
    }

    #[test]
    fn test_cache_functionality() {
        let mut validator = OptimizedCryptoValidator::new().unwrap();
        
        // Test data
        let message = b"test message";
        let signature = vec![0u8; 64]; // Mock signature
        let public_key = vec![1u8; 32]; // Mock public key
        
        // Premier appel - cache miss
        let _result1 = validator.validate_signature_optimized(message, &signature, &public_key);
        
        // Second appel - should be a cache hit
        let _result2 = validator.validate_signature_optimized(message, &signature, &public_key);
        
        let stats = validator.stats();
        assert!(stats.total_signature_validations >= 2);
    }

    #[test]
    fn test_batch_validation() {
        let mut validator = OptimizedCryptoValidator::new().unwrap();
        
        let signatures = vec![
            (vec![1u8; 32], vec![0u8; 64], vec![1u8; 32]),
            (vec![2u8; 32], vec![0u8; 64], vec![2u8; 32]),
            (vec![3u8; 32], vec![0u8; 64], vec![3u8; 32]),
        ];
        
        let results = validator.validate_signatures_batch(&signatures);
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 3);
    }

    #[test]
    fn test_performance_metrics() {
        let validator = OptimizedCryptoValidator::new().unwrap();
        let metrics = validator.performance_metrics();
        
        assert_eq!(metrics.total_validations, 0);
        assert_eq!(metrics.cache_size, 0);
        assert_eq!(metrics.cache_capacity, PUBLIC_KEY_CACHE_SIZE);
    }

    #[test]
    fn test_cache_expiration() {
        let mut validator = OptimizedCryptoValidator::new().unwrap();
        
        // Adds a entry at the cache
        let key_hash = [1u8; 32];
        validator.public_key_cache.insert(key_hash, CachedPublicKey::new(key_hash));
        
        // Simulate l'expiration in modifiant the timestamp
        if let Some(entry) = validator.public_key_cache.get_mut(&key_hash) {
            entry.validated_at = Instant::now() - Duration::from_secs(400);
        }
        
        // Force the cleanup
        validator.cleanup_expired_cache_entries();
        
        assert_eq!(validator.public_key_cache.len(), 0);
    }
}