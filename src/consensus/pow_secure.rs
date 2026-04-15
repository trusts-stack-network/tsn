//! Proof-of-work secure - VERSION SANS PANIC
//!
//! This module replaces src/consensus/pow.rs with robust error handling.
//! No unwrap() or expect() on SystemTime or other system operations.
//!
//! # Security
//! - System clock error handling
//! - Timestamp validation
//! - No panic on malformed entries

use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tracing::{info, debug, warn};
use thiserror::Error;

use crate::core::ShieldedBlock;
use crate::crypto::hash::Hash;

/// PoW module errors
#[derive(Error, Debug, Clone)]
pub enum PowError {
    #[error("System clock error: {0}")]
    SystemTimeError(String),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u64),
    #[error("Invalid difficulty: {0}")]
    InvalidDifficulty(u32),
    #[error("Nonce overflow")]
    NonceOverflow,
    #[error("Calculation de hash failed")]
    HashCalculationFailed,
    #[error("Invalid target")]
    InvalidTarget,
}

/// PoW mining configuration
pub struct PowConfig {
    pub target_difficulty: u32,
    pub max_nonce: u64,
    pub timestamp_tolerance: u64, // secondes
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            target_difficulty: 4,
            max_nonce: u64::MAX,
            timestamp_tolerance: 300, // 5 minutes
        }
    }
}

/// Mineur PoW secure
pub struct SecureMiner {
    config: PowConfig,
}

impl SecureMiner {
    /// Creates a new miner with the default configuration
    pub fn new() -> Self {
        Self {
            config: PowConfig::default(),
        }
    }

    /// Creates a miner with a custom configuration
    pub fn with_config(config: PowConfig) -> Self {
        Self { config }
    }

    /// Gets the current timestamp securely
    /// 
    /// # Security
    /// Returns an error if the system clock is invalid
    /// rather than panicking with unwrap()
    pub fn current_timestamp(&self) -> Result<u64, PowError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| PowError::SystemTimeError(format!("Clock before epoch: {:?}", e)))
    }

    /// Validates a timestamp
    /// 
    /// # Security
    /// Verifies that the timestamp is reasonable
    fn validate_timestamp(&self, timestamp: u64) -> Result<(), PowError> {
        let current = self.current_timestamp()?;
        
        // Not in the future (with tolerance)
        if timestamp > current + self.config.timestamp_tolerance {
            return Err(PowError::InvalidTimestamp(timestamp));
        }
        
        // Pas trop vieux (24h)
        if timestamp + 86400 < current {
            warn!("Very old timestamp detected: {} (current: {})", timestamp, current);
        }
        
        Ok(())
    }

    /// Mines a block with secure error handling
    /// 
    /// # Security
    /// Never panics, all errors are propagated
    pub fn mine_block(&self,
        mut block: ShieldedBlock,
        coinbase_address: &[u8; 32],
    ) -> Result<ShieldedBlock, PowError> {
        
        // Obtention secure of the timestamp
        let timestamp = self.current_timestamp()?;
        block.header.timestamp = timestamp;
        
        // Validation of the timestamp
        self.validate_timestamp(timestamp)?;
        
        info!("Mining block at height {} with difficulty {}", 
            block.header.height, 
            self.config.target_difficulty
        );
        
        let mut nonce: u64 = 0;
        
        loop {
            // Verification of the overflow
            if nonce >= self.config.max_nonce {
                return Err(PowError::NonceOverflow);
            }
            
            block.header.nonce = nonce;
            
            // Hash calculation (simulated - to be replaced by Poseidon)
            let hash = block.hash();
            
            // Verification de the difficulty
            if self.meets_difficulty(&hash, self.config.target_difficulty) {
                info!("Block mined! Nonce: {}, Hash: {:?}", nonce, hash);
                return Ok(block);
            }
            
            nonce += 1;
            
            // Log periodic
            if nonce % 10000 == 0 {
                debug!("Mining... nonce: {}", nonce);
            }
        }
    }

    /// Checks if a hash satisfait the difficulty cible
    fn meets_difficulty(&self, hash: &Hash, difficulty: u32) -> bool {
        let hash_bytes = hash.as_bytes();
        let leading_zeros = hash_bytes.iter()
            .take_while(|&&b| b == 0)
            .count();
        
        leading_zeros >= difficulty as usize
    }

    /// Verifies the proof of work for a block
    /// 
    /// # Security
    /// Complete validation without panic
    pub fn verify_pow(&self, block: &ShieldedBlock) -> Result<bool, PowError> {
        // Validation of the timestamp
        self.validate_timestamp(block.header.timestamp)?;
        
        // Verification de the difficulty
        let hash = block.hash();
        let valid = self.meets_difficulty(&hash, self.config.target_difficulty);
        
        Ok(valid)
    }

    /// Ajuste the difficulty in fonction of the temps elapsed
    /// 
    /// # Security
    /// Computation error handling
    pub fn adjust_difficulty(
        &self,
        current_difficulty: u32,
        actual_time: u64,
        target_time: u64,
    ) -> Result<u32, PowError> {
        if target_time == 0 {
            return Err(PowError::InvalidTarget);
        }
        
        let ratio = actual_time as f64 / target_time as f64;
        
        // Limites d'ajustement (×4 or ÷4 max)
        let adjusted = if ratio > 4.0 {
            current_difficulty.saturating_sub(1)
        } else if ratio < 0.25 {
            current_difficulty.saturating_add(1)
        } else {
            current_difficulty
        };
        
        // Limites de difficulty
        let clamped = adjusted.clamp(1, 32);
        
        Ok(clamped)
    }
}

impl Default for SecureMiner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp_success() {
        let miner = SecureMiner::new();
        let ts = miner.current_timestamp();
        assert!(ts.is_ok());
        assert!(ts.unwrap() > 1600000000); // After 2020
    }

    #[test]
    fn test_validate_timestamp_future() {
        let miner = SecureMiner::new();
        let future_ts = u64::MAX;
        let result = miner.validate_timestamp(future_ts);
        assert!(result.is_err());
    }

    #[test]
    fn test_adjust_difficulty_bounds() {
        let miner = SecureMiner::new();
        
        // Test augmentation
        let diff = miner.adjust_difficulty(10, 1, 100).unwrap();
        assert_eq!(diff, 11);
        
        // Test diminution
        let diff = miner.adjust_difficulty(10, 400, 100).unwrap();
        assert_eq!(diff, 9);
        
        // Test limite lower
        let diff = miner.adjust_difficulty(1, 400, 100).unwrap();
        assert_eq!(diff, 1);
        
        // Test limite higher
        let diff = miner.adjust_difficulty(32, 1, 100).unwrap();
        assert_eq!(diff, 32);
    }

    #[test]
    fn test_adjust_difficulty_invalid_target() {
        let miner = SecureMiner::new();
        let result = miner.adjust_difficulty(10, 100, 0);
        assert!(matches!(result, Err(PowError::InvalidTarget)));
    }
}
