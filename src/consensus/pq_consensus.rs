//! Consensus post-quantique avec support SLH-DSA et ML-DSA-65
//! Manages la validation des signatures et la transition entre algorithmes

use crate::crypto::pq::{slh_dsa, ml_dsa};
use crate::core::{Block, Transaction, ValidationError};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ML-DSA-65 (Dilithium) - algorithme actuel
    MlDsa65,
    /// SLH-DSA-SHA2-128S - algorithme de transition
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128F - variante plus rapide
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192S - niveau de security NIST 3
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-256S - niveau de security maximal
    SlhDsaSha2_256s,
}

impl SignatureAlgorithm {
    /// Rsendinge true si l'algorithme est considered comme "moderne" (SLH-DSA)
    pub fn is_modern(&self) -> bool {
        matches!(self, 
            SignatureAlgorithm::SlhDsaSha2_128s |
            SignatureAlgorithm::SlhDsaSha2_128f |
            SignatureAlgorithm::SlhDsaSha2_192s |
            SignatureAlgorithm::SlhDsaSha2_256s
        )
    }

    /// Renvoie la taille de signature en octets
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureAlgorithm::MlDsa65 => ml_dsa::SIGNATURE_SIZE,
            SignatureAlgorithm::SlhDsaSha2_128s => slh_dsa::SLH_SHA2_128S_SIGNATURE_SIZE,
            SignatureAlgorithm::SlhDsaSha2_128f => slh_dsa::SLH_SHA2_128F_SIGNATURE_SIZE,
            SignatureAlgorithm::SlhDsaSha2_192s => slh_dsa::SLH_SHA2_192S_SIGNATURE_SIZE,
            SignatureAlgorithm::SlhDsaSha2_256s => slh_dsa::SLH_SHA2_256S_SIGNATURE_SIZE,
        }
    }

    /// Renvoie la taille de key publique en octets
    pub fn public_key_size(&self) -> usize {
        match self {
            SignatureAlgorithm::MlDsa65 => ml_dsa::PUBLIC_KEY_SIZE,
            SignatureAlgorithm::SlhDsaSha2_128s => slh_dsa::SLH_SHA2_128S_PUBLIC_KEY_SIZE,
            SignatureAlgorithm::SlhDsaSha2_128f => slh_dsa::SLH_SHA2_128F_PUBLIC_KEY_SIZE,
            SignatureAlgorithm::SlhDsaSha2_192s => slh_dsa::SLH_SHA2_192S_PUBLIC_KEY_SIZE,
            SignatureAlgorithm::SlhDsaSha2_256s => slh_dsa::SLH_SHA2_256S_PUBLIC_KEY_SIZE,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Signature invalid: {0}")]
    InvalidSignature(String),
    #[error("Algorithme de signature non supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("Transition d'algorithme invalid")]
    InvalidAlgorithmTransition,
    #[error("Malformed block: {0}")]
    MalformedBlock(String),
}

/// Configuration du consensus pour la gestion des transitions d'algorithmes
#[derive(Debug, Clone)]
pub struct PqConsensusConfig {
    /// Hauteur de bloc to partir de laquelle SLH-DSA devient obligatoire
    pub slh_dsa_activation_height: u64,
    /// Algorithme by default pour les nouveaux blocs
    pub default_algorithm: SignatureAlgorithm,
    /// Period de thanks to pour la transition (en blocs)
    pub transition_period: u64,
}

impl Default for PqConsensusConfig {
    fn default() -> Self {
        Self {
            slh_dsa_activation_height: u64::MAX, // Pas encore enabled by default
            default_algorithm: SignatureAlgorithm::MlDsa65,
            transition_period: 10080, // ~1 semaine de blocs
        }
    }
}

/// Validateur de consensus post-quantique
pub struct PqConsensusValidator {
    config: PqConsensusConfig,
}

impl PqConsensusValidator {
    pub fn new(config: PqConsensusConfig) -> Self {
        Self { config }
    }

    /// Valide une signature selon l'algorithme specified
    pub fn validate_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<bool, ConsensusError> {
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                ml_dsa::verify_signature(message, signature, public_key)
                    .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))
            }
            SignatureAlgorithm::SlhDsaSha2_128s => {
                slh_dsa::verify_slh_sha2_128s(message, signature, public_key)
                    .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))
            }
            SignatureAlgorithm::SlhDsaSha2_128f => {
                slh_dsa::verify_slh_sha2_128f(message, signature, public_key)
                    .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))
            }
            SignatureAlgorithm::SlhDsaSha2_192s => {
                slh_dsa::verify_slh_sha2_192s(message, signature, public_key)
                    .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))
            }
            SignatureAlgorithm::SlhDsaSha2_256s => {
                slh_dsa::verify_slh_sha2_256s(message, signature, public_key)
                    .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))
            }
        }
    }

    /// Determines l'algorithme de signature attendu pour un bloc given
    pub fn expected_algorithm(&self, block_height: u64) -> SignatureAlgorithm {
        if block_height >= self.config.slh_dsa_activation_height {
            // After l'activation, SLH-DSA devient obligatoire
            SignatureAlgorithm::SlhDsaSha2_128s
        } else if block_height >= self.config.slh_dsa_activation_height.saturating_sub(self.config.transition_period) {
            // Pendant la period de transition, ML-DSA est toujours acceptsd
            SignatureAlgorithm::MlDsa65
        } else {
            // Avant la transition, ML-DSA by default
            self.config.default_algorithm
        }
    }

    /// Valide la signature d'un bloc
    pub fn validate_block_signature(
        &self,
        block: &Block,
        public_key: &[u8],
        signature: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<(), ConsensusError> {
        let expected = self.expected_algorithm(block.height);
        
        // Verifies la compatibility de l'algorithme
        if !self.is_algorithm_allowed(block.height, algorithm) {
            return Err(ConsensusError::InvalidAlgorithmTransition);
        }

        // Serializes le bloc pour la verification
        let block_hash = block.hash()
            .map_err(|e| ConsensusError::MalformedBlock(e.to_string()))?;

        // Valide la signature
        let is_valid = self.validate_signature(
            &block_hash,
            signature,
            public_key,
            algorithm,
        )?;

        if !is_valid {
            return Err(ConsensusError::InvalidSignature(
                format!("Signature invalid pour le bloc {}", block.height)
            ));
        }

        Ok(())
    }

    /// Verifies si un algorithme est authorized to une hauteur data
    fn is_algorithm_allowed(&self, height: u64, algorithm: SignatureAlgorithm) -> bool {
        let expected = self.expected_algorithm(height);
        
        match height.cmp(&self.config.slh_dsa_activation_height) {
            std::cmp::Ordering::Less => {
                // Avant l'activation : ML-DSA only
                algorithm == SignatureAlgorithm::MlDsa65
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                // After l'activation : SLH-DSA only
                algorithm.is_modern()
            }
        }
    }

    /// Valide la signature d'une transaction
    pub fn validate_transaction_signature(
        &self,
        tx: &Transaction,
        public_key: &[u8],
        signature: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<(),