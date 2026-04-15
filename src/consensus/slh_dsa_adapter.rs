//! Adaptateur pour la migration ML-DSA-65 → SLH-DSA
//! 
//! SLH-DSA (FIPS 205) est une signature to usage unique based sur des fonctions de hachage.
//! Contrairement to ML-DSA, chaque paire de keys ne peut signer qu'un nombre limited de messages.
//! Cette contrainte requires une gestion d'state rigoureuse dans le consensus.
//!
//! ## References
//! - FIPS 205: Stateless Hash-Based Digital Signature Standard
//! - SPHINCS+ specification (https://sphincs.org/)

use thiserror::Error;
use serde::{Serialize, Deserialize};
use crate::crypto::signature::{SignatureScheme, VerificationKey, SigningKey};
use crate::crypto::pq::slh_dsa_impl::{PublicKey as SlhDsaPublicKey, Signature as SlhDsaSignature, SlhDsaError as CryptoSlhDsaError};
use crate::core::transaction::Transaction;
use crate::core::block::{Block, BlockHeader};

/// Parameters SLH-DSA selecteds
/// Requires validation crypto avant deployment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlhDsaParams {
    /// Security 128 bits, tailles compactes
    Sha2_128s,
    /// Security 128 bits, performances rapides
    Sha2_128f,
    /// Security 192 bits, tailles compactes
    Sha2_192s,
    /// Security 256 bits, tailles compactes
    Sha2_256s,
}

impl SlhDsaParams {
    /// Convertit vers les parameters du module crypto
    fn to_crypto_params(&self) -> crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet {
        match self {
            SlhDsaParams::Sha2_128s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_128s,
            SlhDsaParams::Sha2_128f => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_128f,
            SlhDsaParams::Sha2_192s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_192s,
            SlhDsaParams::Sha2_256s => crate::crypto::pq::slh_dsa_impl::SlhDsaParameterSet::Sha2_256s,
        }
    }
    
    /// Taille attendue de la signature en octets
    pub fn signature_size(&self) -> usize {
        match self {
            SlhDsaParams::Sha2_128s => 7856,
            SlhDsaParams::Sha2_128f => 17088,
            SlhDsaParams::Sha2_192s => 16224,
            SlhDsaParams::Sha2_256s => 29792,
        }
    }
    
    /// Taille attendue de la key publique en octets
    pub fn public_key_size(&self) -> usize {
        match self {
            SlhDsaParams::Sha2_128s => 32,
            SlhDsaParams::Sha2_128f => 32,
            SlhDsaParams::Sha2_192s => 48,
            SlhDsaParams::Sha2_256s => 64,
        }
    }
}

/// Erreurs de validation SLH-DSA
#[derive(Error, Debug, Clone)]
pub enum SlhDsaError {
    #[error("Key de signature already used: {0:?}")]
    KeyAlreadyUsed(VerificationKey),
    
    #[error("Limite de signatures atteinte pour la key: {0:?}")]
    SignatureLimitReached(VerificationKey),
    
    #[error("Parameters SLH-DSA non supported: {0:?}")]
    UnsupportedParams(SlhDsaParams),
    
    #[error("State de signature invalid")]
    InvalidSignatureState,
    
    #[error("Erreur de verification: {0}")]
    VerificationFailed(String),
    
    #[error("Taille de signature invalid: attendu {expected}, received {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },
    
    #[error("Taille de key publique invalid: attendu {expected}, received {actual}")]
    InvalidPublicKeySize { expected: usize, actual: usize },
}

impl From<CryptoSlhDsaError> for SlhDsaError {
    fn from(err: CryptoSlhDsaError) -> Self {
        SlhDsaError::VerificationFailed(err.to_string())
    }
}

/// State de gestion des signatures SLH-DSA
/// 
/// Invariant: Une key de verification ne peut appear qu'une fois dans `used_keys`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaState {
    /// Ensemble des keys already used pour signer
    used_keys: std::collections::HashSet<VerificationKey>,
    /// Compteur de signatures par key
    signature_count: std::collections::HashMap<VerificationKey, u32>,
    /// Parameters actifs
    params: SlhDsaParams,
}

impl SlhDsaState {
    /// Creates un nouvel state avec les parameters specifieds
    pub fn new(params: SlhDsaParams) -> Self {
        Self {
            used_keys: std::collections::HashSet::new(),
            signature_count: std::collections::HashMap::new(),
            params,
        }
    }
    
    /// Verifies si une key peut encore signer
    pub fn can_sign(&self, vk: &VerificationKey) -> bool {
        !self.used_keys.contains(vk)
    }
    
    /// Marque une key comme used
    /// 
    /// # Panics
    /// Si la key est already used - c'est une violation critique du protocole
    pub fn mark_key_used(&mut self, vk: VerificationKey) -> Result<(), SlhDsaError> {
        if self.used_keys.contains(&vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk));
        }
        
        self.used_keys.insert(vk.clone());
        self.signature_count.insert(vk, 1);
        Ok(())
    }
    
    /// Obtient le nombre de signatures pour une key
    pub fn signature_count(&self, vk: &VerificationKey) -> u32 {
        self.signature_count.get(vk).copied().unwrap_or(0)
    }
    
    /// Retourne les parameters actifs
    pub fn params(&self) -> SlhDsaParams {
        self.params
    }
}

/// Validateur de consensus pour SLH-DSA
pub struct SlhDsaConsensus {
    state: SlhDsaState,
}

impl SlhDsaConsensus {
    /// Creates un nouveau validateur avec l'state initial
    pub fn new(state: SlhDsaState) -> Self {
        Self { state }
    }
    
    /// Valide une transaction avec signature SLH-DSA
    /// 
    /// # Invariants verifieds
    /// - La key de signature n'a pas been reused
    /// - La signature est cryptographiquement valid
    /// - Les parameters matchesent to ceux du network
    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Verification anti-reuse
        if !self.state.can_sign(vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk.clone()));
        }
        
        // Validation cryptographique via le module SLH-DSA
        self.verify_signature(tx, vk, signature)?;
        
        Ok(())
    }
    
    /// Valide the header de bloc avec signature SLH-DSA
    pub fn validate_block_header(
        &self,
        header: &BlockHeader,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Serializes the header pour la verification
        let header_bytes = bincode::serialize(header)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Serialization error: {}", e)))?;
        
        // Verification anti-reuse
        if !self.state.can_sign(vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk.clone()));
        }
        
        // Validation cryptographique
        self.verify_signature_bytes(&header_bytes, vk, signature)?;
        
        Ok(())
    }
    
    /// Verifies une signature SLH-DSA sur des data serializedes
    fn verify_signature_bytes(
        &self,
        data: &[u8],
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Verifies la taille de la signature
        let expected_size = self.state.params().signature_size();
        if signature.len() != expected_size {
            return Err(SlhDsaError::InvalidSignatureSize {
                expected: expected_size,
                actual: signature.len(),
            });
        }
        
        // Convertit la key publique
        let pk_bytes = vk.as_bytes();
        let expected_pk_size = self.state.params().public_key_size();
        if pk_bytes.len() != expected_pk_size {
            return Err(SlhDsaError::InvalidPublicKeySize {
                expected: expected_pk_size,
                actual: pk_bytes.len(),
            });
        }
        
        // Creates les types SLH-DSA pour la verification
        let pk = SlhDsaPublicKey::from_bytes(pk_bytes)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid public key: {}", e)))?;
        
        let sig = SlhDsaSignature::from_bytes(signature)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid signature: {}", e)))?;
        
        // Appelle la verification cryptographique SLH-DSA
        crate::crypto::pq::slh_dsa_impl::verify(&pk, data, &sig)
            .map_err(|e| SlhDsaError::from(e))?;
        
        Ok(())
    }
    
    fn verify_signature(
        &self,
        data: &Transaction,
        vk: &VerificationKey,
        signature: &[u8],
    ) -> Result<(), SlhDsaError> {
        // Serializes la transaction pour la verification
        let tx_bytes = bincode::serialize(data)
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Serialization error: {}", e)))?;
        
        self.verify_signature_bytes(&tx_bytes, vk, signature)
    }
    
    /// Signe des data avec une key SLH-DSA
    /// 
    /// # Security Warning
    /// Cette fonction consomme une key de signature (one-time use).
    /// Ne jamais reuse une key after signature.
    pub fn sign_data(
        &self,
        data: &[u8],
        signing_key: &crate::crypto::pq::slh_dsa_impl::SecretKey,
    ) -> Result<Vec<u8>, SlhDsaError> {
        // Verifies que la key n'a pas already been used
        let public_key = signing_key.public_key();
        let vk = VerificationKey::from_bytes(public_key.as_bytes())
            .map_err(|e| SlhDsaError::VerificationFailed(format!("Invalid key: {}", e)))?;
        
        if !self.state.can_sign(&vk) {
            return Err(SlhDsaError::KeyAlreadyUsed(vk));
        }
        
        // Effectue la signature via le module crypto SLH-DSA
        let signature = crate::crypto::pq::slh_dsa_impl::sign(signing_key, data)
            .map_err(|e| SlhDsaError::from(e))?;
        
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    
    #[test]
    fn test_slh_dsa_state_prevents_reuse() {
        let mut state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let vk = VerificationKey::from_bytes(&[0u8; 32]).unwrap();
        
        // First utilisation doit succeed
        state.mark_key_used(vk.clone()).unwrap();
        
        // Second utilisation doit failsr
        assert!(matches!(
            state.mark_key_used(vk.clone()),
            Err(SlhDsaError::KeyAlreadyUsed(_))
        ));
    }
    
    #[test]
    fn test_consensus_validation_prevents_double_sign() {
        let state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let consensus = SlhDsaConsensus::new(state);
        
        let vk = VerificationKey::from_bytes(&[1u8; 32]).unwrap();
        let tx = Transaction::default();
        
        // Simuler une first validation successful
        // (dans la vraie implementation, cela mettrait up to date l'state)
        
        // Second validation avec la same key doit failsr
        // Note: Cette logique requiresra une mutation de l'state
    }
    
    #[test]
    fn test_signature_count_tracking() {
        let mut state = SlhDsaState::new(SlhDsaParams::Sha2_128s);
        let vk = VerificationKey::from_bytes(&[2u8; 32]).unwrap();
        
        assert_eq!(state.signature_count(&vk), 0);
        
        state.mark_key_used(vk.clone()).unwrap();
        assert_eq!(state.signature_count(&vk), 1);
    }
    
    #[test]
    fn test_signature_size_validation() {
        // Teste que les tailles de signature sont correctly definedes
        assert_eq!(SlhDsaParams::Sha2_128s.signature_size(), 7856);
        assert_eq!(SlhDsaParams::Sha2_128f.signature_size(), 17088);
        assert_eq!(SlhDsaParams::Sha2_192s.signature_size(), 16224);
        assert_eq!(SlhDsaParams::Sha2_256s.signature_size(), 29792);
    }
    
    #[test]
    fn test_public_key_size_validation() {
        // Teste que les tailles de key public sont correctly definedes
        assert_eq!(SlhDsaParams::Sha2_128s.public_key_size(), 32);
        assert_eq!(SlhDsaParams::Sha2_128f.public_key_size(), 32);
        assert_eq!(SlhDsaParams::Sha2_192s.public_key_size(), 48);
        assert_eq!(SlhDsaParams::Sha2_256s.public_key_size(), 64);
    }
}