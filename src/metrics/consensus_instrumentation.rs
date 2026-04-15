//! Instrumentation specialized for the consensus TSN
//!
//! This module provides wrappers and utilitaires for instrumenter
//! facilement the operations critiques of the consensus.

use crate::metrics::{CONSENSUS_METRICS, measure_duration, inc_counter, set_gauge};
use crate::core::{Block, BlockHeader};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn, error, debug};

/// Wrapper for instrumenter the validation d'un bloc
pub struct InstrumentedBlockValidator;

impl InstrumentedBlockValidator {
    /// Validates a bloc with instrumentation completee
    pub async fn validate_block<F, R, E>(
        block: &Block,
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&Block) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let start_time = Instant::now();
        
        // Increment the counter de blocs in progress de validation
        CONSENSUS_METRICS.blocks_validating_current.inc();
        
        debug!(
            block_hash = %hex::encode(&block.header.hash),
            block_height = block.header.height,
            "Start validation bloc"
        );
        
        // Execute the validation with mesure de duration
        let result = measure_duration!(
            CONSENSUS_METRICS.block_validation_duration,
            validator_fn(block)
        );
        
        // Decrement the counter de blocs in progress
        CONSENSUS_METRICS.blocks_validating_current.dec();
        
        // Register the result
        match &result {
            Ok(_) => {
                CONSENSUS_METRICS.blocks_validated_total.inc();
                info!(
                    block_hash = %hex::encode(&block.header.hash),
                    block_height = block.header.height,
                    duration_ms = start_time.elapsed().as_millis(),
                    "Bloc validated avec success"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.blocks_rejected_total.inc();
                warn!(
                    block_hash = %hex::encode(&block.header.hash),
                    block_height = block.header.height,
                    duration_ms = start_time.elapsed().as_millis(),
                    error = ?e,
                    "Bloc rejected lors de la validation"
                );
            }
        }
        
        result
    }
    
    /// Instrumente specificment the validation of commitments
    pub async fn validate_commitment_root<F, R, E>(
        block: &Block,
        commitment_root: &[u8],
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&Block, &[u8]) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.commitment_validation_duration,
            validator_fn(block, commitment_root)
        );
        
        match &result {
            Ok(_) => {
                debug!(
                    block_hash = %hex::encode(&block.header.hash),
                    commitment_root = %hex::encode(commitment_root),
                    "Commitment root validated"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.invalid_commitment_root_errors.inc();
                error!(
                    block_hash = %hex::encode(&block.header.hash),
                    commitment_root = %hex::encode(commitment_root),
                    error = ?e,
                    "ERREUR: Invalid commitment root detectede"
                );
            }
        }
        
        result
    }
}

/// Wrapper for instrumenter the operations Proof of Work
pub struct InstrumentedPoWValidator;

impl InstrumentedPoWValidator {
    /// Validates a PoW with instrumentation
    pub fn validate_pow<F, R, E>(
        block_header: &BlockHeader,
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&BlockHeader) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.pow_validation_duration,
            validator_fn(block_header)
        );
        
        match &result {
            Ok(_) => {
                debug!(
                    block_hash = %hex::encode(&block_header.hash),
                    difficulty = block_header.difficulty,
                    "PoW validated"
                );
            }
            Err(e) => {
                CONSENSUS_METRICS.pow_validation_failures.inc();
                warn!(
                    block_hash = %hex::encode(&block_header.hash),
                    difficulty = block_header.difficulty,
                    error = ?e,
                    "Failure validation PoW"
                );
            }
        }
        
        result
    }
    
    /// Updates the difficulty of the network
    pub fn update_network_difficulty(new_difficulty: f64) {
        CONSENSUS_METRICS.network_difficulty.set(new_difficulty);
        info!(difficulty = new_difficulty, "Difficulty network update");
    }
}

/// Wrapper for instrumenter the operations de chain
pub struct InstrumentedChainManager;

impl InstrumentedChainManager {
    /// Updates the height de the chain
    pub fn update_chain_height(height: u64) {
        CONSENSUS_METRICS.chain_height.set(height as i64);
        debug!(height = height, "Chain height update");
    }
    
    /// Updates the travail cumulatif
    pub fn update_cumulative_work(work: f64) {
        CONSENSUS_METRICS.cumulative_work.set(work);
        debug!(work = work, "Cumulative work updated");
    }
    
    /// Records a reorganization de chain
    pub fn record_chain_reorg(depth: u64) {
        CONSENSUS_METRICS.chain_reorgs_total.inc();
        CONSENSUS_METRICS.last_reorg_depth.set(depth as i64);
        warn!(
            depth = depth,
            "Reorganization de chain detectede"
        );
    }
    
    /// Records the detection d'un fork
    pub fn record_fork_detected() {
        CONSENSUS_METRICS.forks_detected_total.inc();
        info!("Fork detected dans la chain");
    }
    
    /// Updates the orphan block count
    pub fn update_orphan_blocks_count(count: u64) {
        CONSENSUS_METRICS.orphan_blocks_count.set(count as i64);
        debug!(count = count, "Orphan block count updated");
    }
    
    /// Records l'intervalle entre blocs
    pub fn record_block_interval(previous_timestamp: u64, current_timestamp: u64) {
        if current_timestamp > previous_timestamp {
            let interval = (current_timestamp - previous_timestamp) as f64;
            CONSENSUS_METRICS.block_interval.observe(interval);
            debug!(
                interval_seconds = interval,
                "Intervalle entre blocs registered"
            );
        }
    }
}

/// Wrapper for instrumenter the preuves ZK
pub struct InstrumentedZKValidator;

impl InstrumentedZKValidator {
    /// Validates a preuve ZK with instrumentation
    pub async fn validate_zk_proof<F, R, E>(
        proof_data: &[u8],
        validator_fn: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&[u8]) -> Result<R, E>,
        E: std::fmt::Debug,
    {
        let result = measure_duration!(
            CONSENSUS_METRICS.zk_proof_validation_duration,
            validator_fn(proof_data)
        );
        
        match &result {
            Ok(_) => {
                CONSENSUS_METRICS.zk_proofs_validated_total.inc();
                debug!(
                    proof_size = proof_data.len(),
                    "Preuve ZK validatede avec success"
                );
            }
            Err(e) => {
                warn!(
                    proof_size = proof_data.len(),
                    error = ?e,
                    "Failure validation preuve ZK"
                );
            }
        }
        
        result
    }
}

/// Wrapper for instrumenter the mempool
pub struct InstrumentedMempool;

impl InstrumentedMempool {
    /// Updates the size of the mempool
    pub fn update_mempool_size(size: usize) {
        CONSENSUS_METRICS.mempool_size.set(size as i64);
        debug!(size = size, "Size mempool update");
    }
}

/// Collectionur de metrics system
pub struct SystemMetricsCollector;

impl SystemMetricsCollector {
    /// Updates l'utilisation memory of the consensus
    pub fn update_consensus_memory_usage() {
        // Estimation basique - to improve with mesures reals
        let memory_usage = Self::estimate_memory_usage();
        CONSENSUS_METRICS.consensus_memory_usage.set(memory_usage);
        debug!(memory_bytes = memory_usage, "Memory usage update");
    }
    
    /// Estime l'utilisation memory (placeholder)
    fn estimate_memory_usage() -> f64 {
        // TODO: Implement a mesure real de the memory
        // For now, returns a dummy value
        1024.0 * 1024.0 // 1MB
    }
}

/// Utilitaires for the debugging of the bug "Invalid commitment root"
pub struct CommitmentRootDebugger;

impl CommitmentRootDebugger {
    /// Log detailed for diagnostiquer the errors de commitment root
    pub fn log_commitment_validation_details(
        block_hash: &[u8],
        expected_root: &[u8],
        actual_root: &[u8],
        merkle_path: &[Vec<u8>],
    ) {
        error!(
            block_hash = %hex::encode(block_hash),
            expected_root = %hex::encode(expected_root),
            actual_root = %hex::encode(actual_root),
            merkle_path_length = merkle_path.len(),
            "DIAGNOSTIC: Details de l'error commitment root"
        );
        
        // Log each element of the path Merkle for debug
        for (i, path_element) in merkle_path.iter().enumerate() {
            debug!(
                path_index = i,
                path_element = %hex::encode(path_element),
                "Element path Merkle"
            );
        }
        
        // Increment the counter d'errors specialized
        CONSENSUS_METRICS.invalid_commitment_root_errors.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Block, BlockHeader, Transaction};
    
    #[tokio::test]
    async fn test_instrumented_block_validation() {
        let block = create_test_block();
        
        let result = InstrumentedBlockValidator::validate_block(
            &block,
            |_block| -> Result<(), &'static str> {
                Ok(())
            }
        ).await;
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_pow_validation_instrumentation() {
        let header = create_test_header();
        
        let result = InstrumentedPoWValidator::validate_pow(
            &header,
            |_header| -> Result<(), &'static str> {
                Ok(())
            }
        );
        
        assert!(result.is_ok());
    }
    
    fn create_test_block() -> Block {
        Block {
            header: create_test_header(),
            transactions: vec![],
        }
    }
    
    fn create_test_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            previous_hash: vec![0; 32],
            merkle_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty: 1000.0,
            nonce: 0,
            hash: vec![0; 32],
        }
    }
}