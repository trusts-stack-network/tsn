//! SLH-DSA Consensus - Stateful signature
//!
//! ⚠️  SECURITY WARNING: SLH-DSA is a stateful signature.
//!    - The same state must NEVER be reused
//!    - The state must be persistent and atomic
//!    - In case of desynchronization, the node must shut down
//!
//! This implementation includes strict safeguards to prevent
//! state reuse, but cannot fully guarantee security
//! in a real distributed environment.

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
    #[error("SLH-DSA state desynchronized - node shutdown required")]
    StateDesync,
    #[error("Signature SLH-DSA invalid")]
    InvalidSignature,
    #[error("State reuse detected - potential attack")]
    StateReuseDetected,
    #[error("Internal SLH-DSA error: {0}")]
    InternalError(String),
}

/// SLH-DSA validator state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaValidatorState {
    /// Last counter used
    pub last_counter: u64,
    /// Hash of the last validated block
    pub last_block_hash: Hash,
    /// Number of performed signatures
    pub signature_count: u64,
}

/// SLH-DSA state manager
///
/// Thread-safe with strict locking to prevent
/// any concurrent use of the state
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
    /// If the state is corrupted or exceeded - for security
    pub fn update_signature_state(&self, new_counter: u64, block_hash: Hash) -> Result<(), SlhDsaConsensusError> {
        let mut state = self.state.lock()
            .map_err(|_| SlhDsaConsensusError::InternalError("Mutex poisoned".to_string()))?;
        
        // Anti-reuse verification
        if new_counter <= state.last_counter {
            panic!("CRITICAL: SLH-DSA state reuse detected - immediate shutdown");
        }
        
        // Limit verification
        state.signature_count += 1;
        if state.signature_count > self.max_signatures {
            return Err(SlhDsaConsensusError::StateDesync);
        }
        
        state.last_counter = new_counter;
        state.last_block_hash = block_hash;
        
        Ok(())
    }

    /// Gets a copy of the current state
    pub fn get_state(&self) -> SlhDsaValidatorState {
        // Mutex poisoning means a previous holder panicked — propagate
        self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned")
            .clone()
    }

    /// Checks if the state is near the limit
    pub fn is_near_limit(&self) -> bool {
        let state = self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned");
        state.signature_count >= self.max_signatures - 1000
    }
}

/// SLH-DSA consensus validator
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

    /// Validates a block's signature
    ///
    /// # Errors
    /// Returns an error if the signature is invalid or if the state is compromised
    pub fn validate_block_signature(&self, block: &Block) -> Result<(), SlhDsaConsensusError> {
        // Verify that the state is not near the limit
        if self.state_manager.is_near_limit() {
            return Err(SlhDsaConsensusError::StateDesync);
        }

        // Get the signed message (block hash)
        let message = block.hash().as_bytes();
        
        // Extract the signature and counter from the block
        let (signature, counter) = self.extract_signature_data(block)?;
        
        // Verify signature
        self.verifier
            .verify(&message, &signature, counter)
            .map_err(|e| match e {
                SlhDsaError::InvalidSignature => SlhDsaConsensusError::InvalidSignature,
                _ => SlhDsaConsensusError::InternalError(format!("Verification failed: {:?}", e)),
            })?;

        // Update state
        self.state_manager
            .update_signature_state(counter, block.hash())
            .map_err(|_| SlhDsaConsensusError::StateReuseDetected)?;

        Ok(())
    }

    /// Validates a transaction's signature
    pub fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), SlhDsaConsensusError> {
        // For transactions, we use a different key and a separate counter
        // This implementation depends on the transaction format
        // TODO: Implement according to TSN transaction format
        Ok(())
    }

    /// Extracts the signature and counter from block data
    fn extract_signature_data(&self, block: &Block) -> Result<(Vec<u8>, u64), SlhDsaConsensusError> {
        // The format depends on the TSN block implementation
        // Assumption: the block contains signature and counter fields
        block
            .get_signature_data()
            .ok_or_else(|| SlhDsaConsensusError::InternalError("Signature data missing".to_string()))
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