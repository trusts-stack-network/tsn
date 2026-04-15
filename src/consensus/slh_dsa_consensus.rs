//! Consensus SLH-DSA - Signature stateful
//! 
//! ⚠️  SECURITY WARNING: SLH-DSA is a stateful signature.
//!    - Un same state ne doit JAMAIS be reused
//!    - L'state doit be persistant et atomique
//!    - En cas de desynchronization, le node doit s'shutdowner
//! 
//! Cette implementation inclut des garde-fous stricts pour preventsr
//! la reuse d'state, mais ne peut pas garantir la security
//! dans un environnement distributed real.

use crate::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SlhDsaError};
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use serde::{Serialize, Deserialize};

/// Erreurs de validation SLH-DSA
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaConsensusError {
    #[error("State SLH-DSA desynchronized - shutdown du node requis")]
    StateDesync,
    #[error("Signature SLH-DSA invalid")]
    InvalidSignature,
    #[error("Reuse d'state detectede - attaque potentielle")]
    StateReuseDetected,
    #[error("Erreur interne SLH-DSA: {0}")]
    InternalError(String),
}

/// State d'un validateur SLH-DSA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaValidatorState {
    /// Last compteur used
    pub last_counter: u64,
    /// Hash du last bloc validated
    pub last_block_hash: Hash,
    /// Nombre de signatures performedes
    pub signature_count: u64,
}

/// Manager d'state SLH-DSA
/// 
/// Thread-safe avec verrouillage strict pour prevent
/// toute utilisation concurrente de l'state
pub struct SlhDsaStateManager {
    state: Arc<Mutex<SlhDsaValidatorState>>,
    max_signatures: u64,
}

impl SlhDsaStateManager {
    /// Creates un nouveau manager d'state
    pub fn new(initial_counter: u64, max_signatures: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(SlhDsaValidatorState {
                last_counter: initial_counter,
                last_block_hash: Hash::zero(),
                signature_count: 0,
            })),
            max_signatures,
        }
    }

    /// Met up to date l'state after une signature successful
    /// 
    /// # Panics
    /// Si l'state est corrupted ou exceeded - par security
    pub fn update_signature_state(&self, new_counter: u64, block_hash: Hash) -> Result<(), SlhDsaConsensusError> {
        let mut state = self.state.lock()
            .map_err(|_| SlhDsaConsensusError::InternalError("Mutex poisoned".to_string()))?;
        
        // Verification anti-reuse
        if new_counter <= state.last_counter {
            panic!("CRITICAL: Reuse d'state SLH-DSA detectede - shutdown immediate");
        }
        
        // Verification de limite
        state.signature_count += 1;
        if state.signature_count > self.max_signatures {
            return Err(SlhDsaConsensusError::StateDesync);
        }
        
        state.last_counter = new_counter;
        state.last_block_hash = block_hash;
        
        Ok(())
    }

    /// Gets une copie de l'state actuel
    pub fn get_state(&self) -> SlhDsaValidatorState {
        // Mutex poisoning means a previous holder panicked — propagate
        self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned")
            .clone()
    }

    /// Verifies si l'state est proche de la limite
    pub fn is_near_limit(&self) -> bool {
        let state = self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned");
        state.signature_count >= self.max_signatures - 1000
    }
}

/// Validateur de consensus SLH-DSA
pub struct SlhDsaConsensus {
    state_manager: Arc<SlhDsaStateManager>,
    verifier: SlhDsaVerifier,
}

impl SlhDsaConsensus {
    pub fn new(state_manager: Arc<SlhDsaStateManager>, verifier: SlhDsaVerifier) -> Self {
        Self {
            state_manager,
            verifier,
        }
    }

    /// Valide la signature d'un bloc
    /// 
    /// # Errors
    /// Returns une error si la signature est invalid ou si l'state est compromis
    pub fn validate_block_signature(&self, block: &Block) -> Result<(), SlhDsaConsensusError> {
        // Verify que l'state n'est pas proche de la limite
        if self.state_manager.is_near_limit() {
            return Err(SlhDsaConsensusError::StateDesync);
        }

        // Get le message signed (hash du bloc)
        let message = block.hash().as_bytes();
        
        // Extraire la signature et le compteur du bloc
        let (signature, counter) = self.extract_signature_data(block)?;
        
        // Verify la signature
        self.verifier
            .verify(&message, &signature, counter)
            .map_err(|e| match e {
                SlhDsaError::InvalidSignature => SlhDsaConsensusError::InvalidSignature,
                _ => SlhDsaConsensusError::InternalError(format!("Verification failed: {:?}", e)),
            })?;

        // Update l'state
        self.state_manager
            .update_signature_state(counter, block.hash())
            .map_err(|_| SlhDsaConsensusError::StateReuseDetected)?;

        Ok(())
    }

    /// Valide la signature d'une transaction
    pub fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), SlhDsaConsensusError> {
        // Pour les transactions, on utilise une key different et un compteur separated
        // Cette implementation depends du format de transaction
        // TODO: Implement selon le format de transaction TSN
        Ok(())
    }

    /// Extrait la signature et le compteur des data du bloc
    fn extract_signature_data(&self, block: &Block) -> Result<(Vec<u8>, u64), SlhDsaConsensusError> {
        // The format depends on the TSN block implementation
        // Assumption: the block contains signature and counter fields
        block
            .get_signature_data()
            .ok_or_else(|| SlhDsaConsensusError::InternalError("Data de signature missinges".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Hash;
    use rand::Rng;

    struct MockBlock {
        hash: Hash,
        signature: Vec<u8>,
        counter: u64,
    }

    impl MockBlock {
        fn new(counter: u64) -> Self {
            let mut rng = rand::thread_rng();
            let mut hash_bytes = [0u8; 32];
            rng.fill(&mut hash_bytes);
            
            Self {
                hash: Hash::from_bytes(&hash_bytes),
                signature: vec![0u8; 64], // Signature mock
                counter,
            }
        }
    }

    impl Block for MockBlock {
        fn hash(&self) -> Hash {
            self.hash
        }

        fn get_signature_data(&self) -> Option<(Vec<u8>, u64)> {
            Some((self.signature.clone(), self.counter))
        }
    }

    #[test]
    fn test_state_manager_prevents_reuse() {
        let manager = SlhDsaStateManager::new(0, 1000);
        
        // First update should succeed
        assert!(manager.update_signature_state(1,