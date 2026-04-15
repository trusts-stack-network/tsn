//! Consensus SLH-DSA - Signature stateful
//! 
//! ⚠️  SECURITY WARNING: SLH-DSA is a stateful signature.
//!    - Un same state not must JAMAIS be reused
//!    - L'state must be persistant and atomique
//!    - En cas de desynchronization, the node must s'shutdowner
//! 
//! This implementation includes strict safeguards to prevent
//! state reuse, but cannot fully guarantee security
//! in a environnement distributed real.

use crate::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SlhDsaError};
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use serde::{Serialize, Deserialize};

/// SLH-DSA validation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaConsensusError {
    #[error("State SLH-DSA desynchronized - shutdown du node requis")]
    StateDesync,
    #[error("Signature SLH-DSA invalid")]
    InvalidSignature,
    #[error("Reuse d'state detectede - attaque potentielle")]
    StateReuseDetected,
    #[error("Internal SLH-DSA error: {0}")]
    InternalError(String),
}

/// State d'un validateur SLH-DSA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaValidatorState {
    /// Last counter used
    pub last_counter: u64,
    /// Hash of the last bloc validated
    pub last_block_hash: Hash,
    /// Number of performed signatures
    pub signature_count: u64,
}

/// Manager d'state SLH-DSA
/// 
/// Thread-safe with strict locking to prevent
/// toute utilisation concurrente de l'state
pub struct SlhDsaStateManager {
    state: Arc<Mutex<SlhDsaValidatorState>>,
    max_signatures: u64,
}

impl SlhDsaStateManager {
    /// Creates a new state manager
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

    /// Updates the state after a successful signature
    /// 
    /// # Panics
    /// Si l'state is corrupted or exceeded - par security
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

    /// Gets a copie de l'state actuel
    pub fn get_state(&self) -> SlhDsaValidatorState {
        // Mutex poisoning means a previous holder panicked — propagate
        self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned")
            .clone()
    }

    /// Checks if l'state is proche de the limite
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

    /// Validates the signature d'un bloc
    /// 
    /// # Errors
    /// Returns a error if the signature is invalid or if l'state is compromis
    pub fn validate_block_signature(&self, block: &Block) -> Result<(), SlhDsaConsensusError> {
        // Verify que l'state n'est pas proche de the limite
        if self.state_manager.is_near_limit() {
            return Err(SlhDsaConsensusError::StateDesync);
        }

        // Get the message signed (hash of the bloc)
        let message = block.hash().as_bytes();
        
        // Extraire the signature and the counter of the bloc
        let (signature, counter) = self.extract_signature_data(block)?;
        
        // Verify the signature
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

    /// Validates a transaction's signature
    pub fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), SlhDsaConsensusError> {
        // For transactions, we use a different key and a separate counter
        // This implementation depends on the transaction format
        // TODO: Implement selon the format de transaction TSN
        Ok(())
    }

    /// Extrait the signature and the counter of data of the bloc
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