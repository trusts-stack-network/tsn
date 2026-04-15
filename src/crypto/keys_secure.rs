//! Gestion of keys post-quantiques secure - VERSION SANS PANIC
//!
//! This module replaces src/crypto/keys.rs with robust error handling.
//! No expect() on the operations de generation de keys.
//!
//! # Security
//! - Gestion of failures de RNG
//! - Validation of keys generatedes
//! - No panic on cryptographic errors

use fips204::ml_dsa_65;
use fips204::traits::SerDes;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Address;

/// Key management errors
#[derive(Error, Debug, Clone)]
pub enum KeyError {
    #[error("Random number generator failure: {0}")]
    RngFailure(String),
    #[error("Key invalid: {0}")]
    InvalidKey(String),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("Signature invalid")]
    InvalidSignature,
    #[error("Verification de signature failed")]
    SignatureVerificationFailed,
}

/// Key publique ML-DSA-65
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) key: ml_dsa_65::PublicKey,
}

/// Key secret ML-DSA-65 - erased automatically
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)] // La key interne manages son propre effacement
    pub(crate) key: ml_dsa_65::SecretKey,
}

/// Signature ML-DSA-65
#[derive(Clone, Debug)]
pub struct Signature {
    pub(crate) sig: ml_dsa_65::Signature,
}

/// Paire de keys post-quantiques
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Generates a new paire de keys de manner secure
    /// 
    /// # Security
    /// Returns a error if the RNG fails rather que de paniquer
    /// 
    /// # Exemple
    /// ```
    /// use tsn::crypto::keys_secure::KeyPair;
    /// 
    /// let keypair = KeyPair::generate()
    ///     .expect("Key generation should succeed in normal conditions");
    /// ```
    pub fn generate() -> Result<Self, KeyError> {
        let (public_key, secret_key) = ml_dsa_65::try_keygen()
            .map_err(|e| KeyError::RngFailure(format!("{:?}", e)))?;
        
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Generates a paire de keys deterministic to partir d'une graine
    /// 
    /// # Security
    /// Utile for the tests and the retrieval, but moins secure
    /// que the generation random for the production.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        use fips204::traits::KeyGen;
        let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(seed);
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Signe a message
    /// 
    /// # Security
    /// La signature is performede de manner constant-time
    pub fn sign(&self, message: &[u8]) -> Result<Signature, KeyError> {
        let sig = ml_dsa_65::sign(&self.secret_key.key, message, b"TSN")
            .map_err(|e| KeyError::InvalidSignature)?;
        
        Ok(Signature { sig })
    }

    /// Verifies a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool, KeyError> {
        let valid = ml_dsa_65::verify(&self.public_key.key, message, b"TSN", &signature.sig)
            .map_err(|e| KeyError::SignatureVerificationFailed)?;
        
        Ok(valid)
    }

    /// Serializes the paire de keys
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeyError> {
        let mut result = Vec::new();
        
        // Serialization de the key public
        let pk_bytes = self.public_key.key.into_bytes();
        result.extend_from_slice(&pk_bytes);
        
        // Serialization de the key secret
        let sk_bytes = self.secret_key.key.into_bytes();
        result.extend_from_slice(&sk_bytes);
        
        Ok(result)
    }

    /// Deserializes a paire de keys
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        // ML-DSA-65 tailles: pk = 1952 bytes, sk = 4032 bytes
        const PK_SIZE: usize = 1952;
        const SK_SIZE: usize = 4032;
        
        if bytes.len() < PK_SIZE + SK_SIZE {
            return Err(KeyError::DeserializationFailed(
                "Insufficient bytes for keypair".to_string()
            ));
        }
        
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(&bytes[..PK_SIZE])
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        let secret_key = ml_dsa_65::SecretKey::try_from_bytes(&bytes[PK_SIZE..PK_SIZE + SK_SIZE])
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self {
            public_key: PublicKey { key: public_key },
            secret_key: SecretKey { key: secret_key },
        })
    }

    /// Derives a adresse to partir de the key public
    pub fn derive_address(&self) -> Address {
        Address::from_public_key(&self.public_key.key.into_bytes())
    }
}

impl PublicKey {
    /// Serializes the key public
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.into_bytes()
    }

    /// Deserializes a key public
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key = ml_dsa_65::PublicKey::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { key })
    }
}

impl SecretKey {
    /// Serializes the key secret
    /// 
    /// # Avertissement
    /// This method exposes the secret key. Use with caution.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.into_bytes()
    }

    /// Deserializes a key secret
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key = ml_dsa_65::SecretKey::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { key })
    }
}

impl Signature {
    /// Serializes the signature
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sig.into_bytes()
    }

    /// Deserializes a signature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let sig = ml_dsa_65::Signature::try_from_bytes(bytes)
            .map_err(|e| KeyError::DeserializationFailed(format!("{:?}", e)))?;
        
        Ok(Self { sig })
    }
}

/// Manager de keys secure
pub struct KeyManager {
    keys: Vec<KeyPair>,
}

impl KeyManager {
    /// Creates a new manager of keys
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
        }
    }

    /// Generates a new key
    pub fn generate_key(&mut self) -> Result<&KeyPair, KeyError> {
        let keypair = KeyPair::generate()?;
        self.keys.push(keypair);
        Ok(self.keys.last().unwrap())
    }

    /// Retrieves a key par index
    pub fn get_key(&self, index: usize) -> Option<&KeyPair> {
        self.keys.get(index)
    }

    /// Number of managed keys
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Checks if the manager is vide
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(message, &signature).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";
        let wrong_message = b"Wrong message";
        
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(wrong_message, &signature).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let keypair = KeyPair::generate().unwrap();
        let bytes = keypair.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(&bytes).unwrap();
        
        assert_eq!(keypair.public_key.to_bytes(), recovered.public_key.to_bytes());
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_bytes = vec![0u8; 100]; // Trop court
        let result = KeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::new();
        assert!(manager.is_empty());
        
        let key = manager.generate_key().unwrap();
        assert_eq!(manager.len(), 1);
        
        let retrieved = manager.get_key(0).unwrap();
        assert_eq!(key.public_key.to_bytes(), retrieved.public_key.to_bytes());
    }
}
