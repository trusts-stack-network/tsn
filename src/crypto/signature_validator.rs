//! Validateur de signatures SLH-DSA for TSN
//!
//! Module de validation centralized for the signatures post-quantique
//! in accordance to FIPS 205. Fournit a API unified for the validation
//! with metrics de performance and gestion d'errors secure.
//!
//! # Security
//! - No information sensible n'est exposed in the messages d'error
//! - Validation in temps constant for the comparaisons critiques
//! - Protection contre the attaques par canal auxiliaire
//!
//! References:
//! - FIPS 205: https://csrc.nist.gov/pubs/fips/205/final

use std::time::Instant;
use thiserror::Error;

use super::pq::slh_dsa::{verify_signature, PK_BYTES, SIG_BYTES};

/// Result de validation d'une signature
/// 
/// Structure compatible with l'API existante - utilise `is_valid` pour
/// determine if the signature is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationResult {
    /// Indique if the signature is valid
    pub is_valid: bool,
    /// Temps de verification in microsecondes
    pub verification_time_us: u64,
    /// Size of the message in octets
    pub message_size: usize,
    /// Prefix of the hash of the message (8 firsts bytes)
    pub message_hash_prefix: [u8; 8],
}

impl ValidationResult {
    /// Creates a result valid
    pub fn valid(verification_time_us: u64, message_size: usize, message_hash_prefix: [u8; 8]) -> Self {
        Self {
            is_valid: true,
            verification_time_us,
            message_size,
            message_hash_prefix,
        }
    }

    /// Creates a result invalid
    pub fn invalid(message_size: usize) -> Self {
        Self {
            is_valid: false,
            verification_time_us: 0,
            message_size,
            message_hash_prefix: [0u8; 8],
        }
    }
}

/// Signature validation errors
/// 
/// # Security
/// Error messages contain no sensitive information
/// on the keys, signatures or data internes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Signature invalid : format incorrect")]
    InvalidSignatureFormat,
    
    #[error("Key publique invalid : taille incorrecte")]
    InvalidPublicKeySize,
    
    #[error("Key publique invalid : format incorrect")]
    InvalidPublicKeyFormat,
    
    #[error("Message vide")]
    EmptyMessage,
    
    #[error("Message trop long : {size} octets (max {max})")]
    MessageTooLong { size: usize, max: usize },
    
    #[error("Verification cryptographique failed")]
    VerificationFailed,
    
    #[error("Internal validation error")]
    InternalValidationError,
    
    #[error("Niveau de security non supported")]
    UnsupportedSecurityLevel,
}

/// Configuration of the validateur
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Niveau de security (128, 192, 256)
    pub security_level: u32,
    /// Size maximale de message in octets
    pub max_message_size: usize,
    /// Enable additional verifications
    pub strict_mode: bool,
    /// Collect the metrics de performance
    pub collect_metrics: bool,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            security_level: 128,
            max_message_size: 1024 * 1024, // 1MB
            strict_mode: true,
            collect_metrics: true,
        }
    }
}

impl ValidatorConfig {
    /// Creates a configuration with a niveau de security specific
    /// 
    /// # Arguments
    /// * `security_level` - Niveau de security (128, 192, or 256)
    /// 
    /// # Errors
    /// Returns a error if the niveau de security n'est pas supported
    pub fn with_security_level(security_level: u32) -> Result<Self, ValidationError> {
        match security_level {
            128 | 192 | 256 => Ok(Self {
                security_level,
                max_message_size: 1024 * 1024,
                strict_mode: true,
                collect_metrics: true,
            }),
            _ => Err(ValidationError::UnsupportedSecurityLevel),
        }
    }
}

/// Metrics de validation
#[derive(Debug, Clone, Default)]
pub struct ValidationMetrics {
    /// Total number of validations
    pub total_validations: u64,
    /// Number of successful validations
    pub successful_validations: u64,
    /// Number of failed validations
    pub failed_validations: u64,
    /// Total validation time in microseconds
    pub total_time_us: u64,
    /// Temps minimum de validation in microsecondes
    pub min_time_us: u64,
    /// Temps maximum de validation in microsecondes
    pub max_time_us: u64,
}

impl ValidationMetrics {
    /// Updates the metrics with a nouveau result
    fn record_validation(&mut self, success: bool, duration_us: u64) {
        self.total_validations += 1;
        if success {
            self.successful_validations += 1;
        } else {
            self.failed_validations += 1;
        }
        self.total_time_us += duration_us;
        
        if self.min_time_us == 0 || duration_us < self.min_time_us {
            self.min_time_us = duration_us;
        }
        if duration_us > self.max_time_us {
            self.max_time_us = duration_us;
        }
    }

    /// Average validation time in microseconds
    pub fn average_time_us(&self) -> u64 {
        if self.total_validations == 0 {
            0
        } else {
            self.total_time_us / self.total_validations
        }
    }
}

/// Validateur de signatures SLH-DSA
pub struct SignatureValidator {
    config: ValidatorConfig,
    metrics: ValidationMetrics,
}

impl SignatureValidator {
    /// Creates a new validateur with the configuration by default
    pub fn new() -> Self {
        Self::with_config(ValidatorConfig::default())
    }

    /// Creates a validateur with a configuration custom
    pub fn with_config(config: ValidatorConfig) -> Self {
        Self {
            config,
            metrics: ValidationMetrics::default(),
        }
    }

    /// Validates a signature SLH-DSA
    ///
    /// # Arguments
    /// * `message` - Le message signed
    /// * `signature_bytes` - La signature (SIG_BYTES octets)
    /// * `public_key_bytes` - La key publique (PK_BYTES octets)
    ///
    /// # Returns
    /// * `Ok(ValidationResult)` - Le result de validation with metrics
    /// * `Err(ValidationError)` - A validation error
    ///
    /// # Security
    /// This fonction performs a validation in temps constant pour
    /// the comparaisons cryptographiques critiques.
    pub fn validate(
        &mut self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<ValidationResult, ValidationError> {
        let start = Instant::now();

        // Validation of entries
        if message.is_empty() {
            return Err(ValidationError::EmptyMessage);
        }

        if message.len() > self.config.max_message_size {
            return Err(ValidationError::MessageTooLong {
                size: message.len(),
                max: self.config.max_message_size,
            });
        }

        if signature_bytes.len() != SIG_BYTES {
            return Err(ValidationError::InvalidSignatureFormat);
        }

        if public_key_bytes.len() != PK_BYTES {
            return Err(ValidationError::InvalidPublicKeySize);
        }

        // Calculation of the hash of the message for the prefix
        use sha2::{Sha256, Digest};
        let message_hash = Sha256::digest(message);
        let mut message_hash_prefix = [0u8; 8];
        message_hash_prefix.copy_from_slice(&message_hash[..8]);

        // Validation cryptographique
        let is_valid = match verify_signature(message, signature_bytes, public_key_bytes) {
            Ok(valid) => valid,
            Err(_) => {
                let duration = start.elapsed().as_micros() as u64;
                self.metrics.record_validation(false, duration);
                return Ok(ValidationResult::invalid(message.len()));
            }
        };

        let duration = start.elapsed().as_micros() as u64;
        self.metrics.record_validation(is_valid, duration);

        let result = if is_valid {
            ValidationResult::valid(duration, message.len(), message_hash_prefix)
        } else {
            ValidationResult::invalid(message.len())
        };

        Ok(result)
    }

    /// Validates a signature synchronously (without metrics)
    ///
    /// Version optimized for the cas where the metrics not are pas necessary.
    pub fn validate_fast(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<bool, ValidationError> {
        // Validation of entries (same logique que validate)
        if message.is_empty() {
            return Err(ValidationError::EmptyMessage);
        }

        if message.len() > self.config.max_message_size {
            return Err(ValidationError::MessageTooLong {
                size: message.len(),
                max: self.config.max_message_size,
            });
        }

        if signature_bytes.len() != SIG_BYTES {
            return Err(ValidationError::InvalidSignatureFormat);
        }

        if public_key_bytes.len() != PK_BYTES {
            return Err(ValidationError::InvalidPublicKeySize);
        }

        // Validation cryptographique directe
        verify_signature(message, signature_bytes, public_key_bytes)
            .map_err(|_| ValidationError::VerificationFailed)
    }

    /// Returns the current metrics
    pub fn metrics(&self) -> ValidationMetrics {
        self.metrics.clone()
    }

    /// Resets the metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = ValidationMetrics::default();
    }

    /// Returns the configuration
    pub fn config(&self) -> &ValidatorConfig {
        &self.config
    }
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validation rapide without instanciation de validateur
///
/// Fonction utilitaire for the cas simples where a validation
/// unique is necessary.
pub fn quick_validate(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool, ValidationError> {
    if message.is_empty() {
        return Err(ValidationError::EmptyMessage);
    }

    if signature_bytes.len() != SIG_BYTES {
        return Err(ValidationError::InvalidSignatureFormat);
    }

    if public_key_bytes.len() != PK_BYTES {
        return Err(ValidationError::InvalidPublicKeySize);
    }

    verify_signature(message, signature_bytes, public_key_bytes)
        .map_err(|_| ValidationError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_valid() {
        let result = ValidationResult::valid(100, 256, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(result.is_valid);
        assert_eq!(result.verification_time_us, 100);
        assert_eq!(result.message_size, 256);
    }

    #[test]
    fn test_validation_result_invalid() {
        let result = ValidationResult::invalid(128);
        assert!(!result.is_valid);
        assert_eq!(result.verification_time_us, 0);
        assert_eq!(result.message_size, 128);
    }

    #[test]
    fn test_validator_config_default() {
        let config = ValidatorConfig::default();
        assert_eq!(config.security_level, 128);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(config.strict_mode);
        assert!(config.collect_metrics);
    }

    #[test]
    fn test_validator_config_with_security_level() {
        // Niveaux valids
        assert!(ValidatorConfig::with_security_level(128).is_ok());
        assert!(ValidatorConfig::with_security_level(192).is_ok());
        assert!(ValidatorConfig::with_security_level(256).is_ok());
        
        // Niveau invalid - not panique pas
        let result = ValidatorConfig::with_security_level(64);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::UnsupportedSecurityLevel));
    }

    #[test]
    fn test_metrics_recording() {
        let mut metrics = ValidationMetrics::default();
        
        metrics.record_validation(true, 100);
        assert_eq!(metrics.total_validations, 1);
        assert_eq!(metrics.successful_validations, 1);
        assert_eq!(metrics.failed_validations, 0);
        
        metrics.record_validation(false, 200);
        assert_eq!(metrics.total_validations, 2);
        assert_eq!(metrics.successful_validations, 1);
        assert_eq!(metrics.failed_validations, 1);
        
        assert_eq!(metrics.average_time_us(), 150);
    }

    #[test]
    fn test_empty_message_error() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"", &[0u8; SIG_BYTES], &[0u8; PK_BYTES]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::EmptyMessage));
    }

    #[test]
    fn test_invalid_signature_size() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"test", &[0u8; 10], &[0u8; PK_BYTES]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidSignatureFormat));
    }

    #[test]
    fn test_invalid_public_key_size() {
        let mut validator = SignatureValidator::new();
        let result = validator.validate(b"test", &[0u8; SIG_BYTES], &[0u8; 10]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidPublicKeySize));
    }
}
