//! Block and transaction signature validation
//! Support hybride ML-DSA-65 (legacy) and SLH-DSA (nouveau)
//! 
//! INVARIANTS:
//! - A key can only be used once in SLH-DSA
//! - Les addresses de signature doivent be monotonically increasing
//! - The transition between ML-DSA and SLH-DSA is managed by an activation point
//!
//! ## References
//! - FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)

use crate::crypto::{SignatureScheme, PublicKey, Signature, CryptoError};
use crate::crypto::pq::slh_dsa_impl::{self, PublicKey as SlhDsaPublicKey, Signature as SlhDsaSignature};
use crate::crypto::signature::verify_mldsa65;
use crate::core::{Block, Transaction, BlockHeader};
use thiserror::Error;
use std::collections::HashSet;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Key SLH-DSA reused: {0}")]
    SlhDsaKeyReuse(String),
    #[error("Invalid signature address: {0}")]
    InvalidSignatureAddress(u64),
    #[error("Schema de signature non supported: {0}")]
    UnsupportedScheme(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("SLH-DSA error: {0}")]
    SlhDsaError(String),
    #[error("Invalid signature size: expected {expected}, received {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },
}

impl From<slh_dsa_impl::SlhDsaError> for SignatureError {
    fn from(err: slh_dsa_impl::SlhDsaError) -> Self {
        SignatureError::SlhDsaError(err.to_string())
    }
}

/// Activation point for the ML-DSA → SLH-DSA transition
const SLH_DSA_ACTIVATION_HEIGHT: u64 = 1_000_000; // To be calibrated with the team

/// Default SLH-DSA parameters for consensus
const DEFAULT_SLH_DSA_PARAMS: slh_dsa_impl::SlhDsaParameterSet = slh_dsa_impl::SlhDsaParameterSet::Sha2_128s;

/// Signature validator for consensus
pub struct SignatureValidator {
    /// Set of already used SLH-DSA keys (prevents reuse)
    used_slh_keys: HashSet<[u8; 32]>,
    /// Current SLH-DSA signature address
    current_signature_address: u64,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self {
            used_slh_keys: HashSet::new(),
            current_signature_address: 0,
        }
    }

    /// Validates the signature d'un bloc in fonction de sa hauteur
    pub fn validate_block_signature(
        &mut self,
        block: &Block,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Determine the signature scheme to use
        let scheme = self.get_signature_scheme(block.header.height);
        
        match scheme {
            SignatureScheme::MlDsa65 => {
                self.validate_mldsa_signature(block, public_key, signature)
            }
            SignatureScheme::SlhDsa => {
                self.validate_slh_signature(block, public_key, signature)
            }
        }
    }

    /// Validates a transaction's signature
    pub fn validate_transaction_signature(
        &mut self,
        tx: &Transaction,
        public_key: &PublicKey,
        signature: &Signature,
        block_height: u64,
    ) -> Result<(), SignatureError> {
        let scheme = self.get_signature_scheme(block_height);
        
        match scheme {
            SignatureScheme::MlDsa65 => {
                self.validate_mldsa_signature(tx, public_key, signature)
            }
            SignatureScheme::SlhDsa => {
                // For transactions, we use an address derived from the hash
                let signature_address = self.derive_signature_address(tx);
                self.validate_slh_signature_with_address(
                    tx,
                    public_key,
                    signature,
                    signature_address,
                )
            }
        }
    }

    /// Determine the signature scheme to use selon the height of the bloc
    fn get_signature_scheme(&self, block_height: u64) -> SignatureScheme {
        if block_height >= SLH_DSA_ACTIVATION_HEIGHT {
            SignatureScheme::SlhDsa
        } else {
            SignatureScheme::MlDsa65
        }
    }

    /// Validates an ML-DSA-65 signature (legacy)
    fn validate_mldsa_signature(
        &self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Call the crypto module's ML-DSA-65 validation
        verify_mldsa65(public_key, data.as_ref(), signature)
            .map_err(|e| SignatureError::CryptoError(e))?;
        Ok(())
    }

    /// Validates an SLH-DSA signature with anti-reuse verification
    fn validate_slh_signature(
        &mut self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let key_id = self.derive_key_id(public_key);
        
        // Verify that the key n'a pas been used
        if self.used_slh_keys.contains(&key_id) {
            return Err(SignatureError::SlhDsaKeyReuse(
                format!("Key already used: {:?}", key_id)
            ));
        }

        // Validate the signature via the SLH-DSA crypto module
        self.verify_slh_signature(data, public_key, signature)?;

        // Mark the key as used
        self.used_slh_keys.insert(key_id);
        self.current_signature_address += 1;

        Ok(())
    }

    /// Validates an SLH-DSA signature with specific address
    fn validate_slh_signature_with_address(
        &mut self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
        signature_address: u64,
    ) -> Result<(), SignatureError> {
        // Verify that the address is valid
        if signature_address != self.current_signature_address {
            return Err(SignatureError::InvalidSignatureAddress(signature_address));
        }

        self.validate_slh_signature(data, public_key, signature)
    }

    /// Derives a unique identifier for a public key
    fn derive_key_id(&self, public_key: &PublicKey) -> [u8; 32] {
        // Use SHA-256 to derive a unique identifier from the public key
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        hasher.finalize().into()
    }

    /// Derives a signature address for a transaction
    fn derive_signature_address(&self, tx: &Transaction) -> u64 {
        // Use part of the transaction hash as an address
        // The first 8 bytes of the hash form the address
        let hash_bytes = tx.hash.as_ref();
        if hash_bytes.len() >= 8 {
            let bytes: [u8; 8] = hash_bytes[0..8].try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(bytes)
        } else {
            0
        }
    }

    /// Verifies an SLH-DSA signature (call to crypto module)
    /// 
    /// ## Implementation
    /// This function uses the `slh_dsa_impl` module for verification
    /// cryptographique conforme to FIPS 205.
    ///
    /// ## Security parameters
    /// - Algorithme: SLH-DSA-SHA2-128s (by default)
    /// - Security level: 128 bits post-quantum
    /// - Signature size: ~7.8 KB
    /// - Public key size: 32 bytes
    fn verify_slh_signature(
        &self,
        data: &impl AsRef<[u8]>,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        // Verify the signature size (≈8KB for Sha2_128s)
        let expected_sig_size = DEFAULT_SLH_DSA_PARAMS.signature_size();
        let sig_bytes = signature.as_ref();
        
        if sig_bytes.len() != expected_sig_size {
            return Err(SignatureError::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: sig_bytes.len(),
            });
        }
        
        // Verify public key size
        let expected_pk_size = DEFAULT_SLH_DSA_PARAMS.public_key_size();
        let pk_bytes = public_key.as_bytes();
        
        if pk_bytes.len() != expected_pk_size {
            return Err(SignatureError::SlhDsaError(format!(
                "Invalid public key size: expected {}, received {}",
                expected_pk_size, pk_bytes.len()
            )));
        }
        
        // Convert to SLH-DSA types
        let slh_pk = SlhDsaPublicKey::from_bytes(pk_bytes)
            .map_err(|e| SignatureError::SlhDsaError(format!("Invalid public key: {}", e)))?;
        
        let slh_sig = SlhDsaSignature::from_bytes(sig_bytes)
            .map_err(|e| SignatureError::SlhDsaError(format!("Invalid signature: {}", e)))?;
        
        // Call the crypto module's SLH-DSA verification
        slh_dsa_impl::verify(&slh_pk, data.as_ref(), &slh_sig)
            .map_err(|e| SignatureError::from(e))?;
        
        Ok(())
    }
    
    /// Generates an SLH-DSA key pair for tests
    #[cfg(test)]
    pub fn generate_slh_keypair(
        &self,
    ) -> Result<(slh_dsa_impl::SecretKey, slh_dsa_impl::PublicKey), SignatureError> {
        let (sk, pk) = slh_dsa_impl::generate_keypair(DEFAULT_SLH_DSA_PARAMS)
            .map_err(|e| SignatureError::from(e))?;
        Ok((sk, pk))
    }
    
    /// Signs data with an SLH-DSA key (for tests)
    #[cfg(test)]
    pub fn sign_with_slh(
        &self,
        data: &[u8],
        secret_key: &slh_dsa_impl::SecretKey,
    ) -> Result<Vec<u8>, SignatureError> {
        let signature = slh_dsa_impl::sign(secret_key, data)
            .map_err(|e| SignatureError::from(e))?;
        Ok(signature.to_bytes().to_vec())
    }
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, Hash};
    use crate::crypto::{PrivateKey, KeyPair};

    fn create_test_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                timestamp: 1234567890,
                previous_hash: Hash::from_bytes([0u8; 32]),
                merkle_root: Hash::from_bytes([1u8; 32]),
                state_root: Hash::from_bytes([2u8; 32]),
                difficulty: 1000,
                nonce: 0,
            },
            transactions: vec![],
            signature: Signature::from_bytes(&[0u8; 64]).unwrap(),
        }
    }

    #[test]
    fn test_signature_scheme_selection() {
        let validator = SignatureValidator::new();
        
        // Before activation: ML-DSA-65
        assert_eq!(
            validator.get_signature_scheme(SLH_DSA_ACTIVATION_HEIGHT - 1),
            SignatureScheme::MlDsa65
        );
        
        // After activation: SLH-DSA
        assert_eq!(
            validator.get_signature_scheme(SLH_DSA_ACTIVATION_HEIGHT),
            SignatureScheme::SlhDsa
        );
    }

    #[test]
    fn test_slh_key_reuse_prevention() {
        let mut validator = SignatureValidator::new();
        let pk = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        
        // First validation
        let key_id = validator.derive_key_id(&pk);
        assert!(!validator.used_slh_keys.contains(&key_id));
        
        // Simulate adding the key
        validator.used_slh_keys.insert(key_id);
        assert!(validator.used_slh_keys.contains(&key_id));
    }

    #[test]
    fn test_signature_address_derivation() {
        let validator = SignatureValidator::new();
        let tx = Transaction::default();
        
        // The address must be derived from the first 8 bytes of the hash
        let address = validator.derive_signature_address(&tx);
        
        // Verify that the address is consistent
        let expected_address = if tx.hash.as_ref().len() >= 8 {
            let bytes: [u8; 8] = tx.hash.as_ref()[0..8].try_into().unwrap();
            u64::from_le_bytes(bytes)
        } else {
            0
        };
        
        assert_eq!(address, expected_address);
    }
    
    #[test]
    fn test_key_id_derivation() {
        let validator = SignatureValidator::new();
        let pk1 = PublicKey::from_bytes(&[1u8; 32]).unwrap();
        let pk2 = PublicKey::from_bytes(&[2u8; 32]).unwrap();
        
        let id1 = validator.derive_key_id(&pk1);
        let id2 = validator.derive_key_id(&pk2);
        
        // IDs must be different for different keys
        assert_ne!(id1, id2);
        
        // IDs must be deterministic
        assert_eq!(id1, validator.derive_key_id(&pk1));
    }
}