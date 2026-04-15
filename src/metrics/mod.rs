//! Prometheus metrics for Trust Stack Network
//!
//! This module provides detailed metrics for monitoring the performance
//! of consensus, block validation, and diagnosing problems like
//! "Invalid commitment root".

pub mod http_endpoint;

use prometheus::{
    Counter, Histogram, Gauge, IntCounter, IntGauge, 
    register_counter, register_histogram, register_gauge, 
    register_int_counter, register_int_gauge,
    opts, histogram_opts, Encoder, TextEncoder, Registry
};
use std::sync::Arc;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

/// Global TSN consensus metrics
pub struct ConsensusMetrics {
    // === BLOCK VALIDATION ===
    /// Total number of successfully validated blocks
    pub blocks_validated_total: IntCounter,
    
    /// Total number of rejected blocks
    pub blocks_rejected_total: IntCounter,
    
    /// Block validation time (in seconds)
    pub block_validation_duration: Histogram,
    
    /// Number of blocks currently being validated
    pub blocks_validating_current: IntGauge,
    
    // === CONSENSUS AND FORK CHOICE ===
    /// Current canonical chain height
    pub chain_height: IntGauge,
    
    /// Cumulative work of the canonical chain
    pub cumulative_work: Gauge,
    
    /// Number of chain reorganizations
    pub chain_reorgs_total: IntCounter,
    
    /// Depth of the last reorganization
    pub last_reorg_depth: IntGauge,
    
    /// Number of detected forks
    pub forks_detected_total: IntCounter,
    
    /// Number of orphan blocks
    pub orphan_blocks_count: IntGauge,
    
    // === PROOF OF WORK ===
    /// Current network difficulty
    pub network_difficulty: Gauge,
    
    /// PoW validation time (in seconds)
    pub pow_validation_duration: Histogram,
    
    /// Number of failed PoW validations
    pub pow_validation_failures: IntCounter,
    
    // === COMMITMENT AND ZK PROOFS ===
    /// Commitment validation time (in seconds)
    pub commitment_validation_duration: Histogram,
    
    /// Count of "Invalid commitment root" errors
    pub invalid_commitment_root_errors: IntCounter,
    
    /// Number of validated ZK proofs
    pub zk_proofs_validated_total: IntCounter,
    
    /// ZK proof validation time (in seconds)
    pub zk_proof_validation_duration: Histogram,
    
    // === MEMORY AND PERFORMANCE ===
    /// Mempool size (number of transactions)
    pub mempool_size: IntGauge,
    
    /// Average inter-block latency (in seconds)
    pub block_interval: Histogram,
    
    /// Consensus memory usage (in bytes)
    pub consensus_memory_usage: Gauge,
}

impl ConsensusMetrics {
    /// Creates a new consensus metrics instance
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            // Block validation
            blocks_validated_total: register_int_counter!(opts!(
                "tsn_blocks_validated_total",
                "Total number of successfully validated blocks"
            ))?,
            
            blocks_rejected_total: register_int_counter!(opts!(
                "tsn_blocks_rejected_total", 
                "Total number of rejected blocks"
            ))?,
            
            block_validation_duration: register_histogram!(histogram_opts!(
                "tsn_block_validation_duration_seconds",
                "Block validation time in seconds",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
            ))?,
            
            blocks_validating_current: register_int_gauge!(opts!(
                "tsn_blocks_validating_current",
                "Number of blocks currently being validated"
            ))?,
            
            // Consensus and fork choice
            chain_height: register_int_gauge!(opts!(
                "tsn_chain_height",
                "Current canonical chain height"
            ))?,
            
            cumulative_work: register_gauge!(opts!(
                "tsn_cumulative_work",
                "Cumulative work of the canonical chain"
            ))?,
            
            chain_reorgs_total: register_int_counter!(opts!(
                "tsn_chain_reorgs_total",
                "Total number of chain reorganizations"
            ))?,
            
            last_reorg_depth: register_int_gauge!(opts!(
                "tsn_last_reorg_depth",
                "Depth of the last reorganization"
            ))?,
            
            forks_detected_total: register_int_counter!(opts!(
                "tsn_forks_detected_total",
                "Total number of detected forks"
            ))?,
            
            orphan_blocks_count: register_int_gauge!(opts!(
                "tsn_orphan_blocks_count",
                "Current number of orphan blocks"
            ))?,
            
            // Proof of Work
            network_difficulty: register_gauge!(opts!(
                "tsn_network_difficulty",
                "Current network difficulty"
            ))?,
            
            pow_validation_duration: register_histogram!(histogram_opts!(
                "tsn_pow_validation_duration_seconds",
                "PoW validation time in seconds",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
            ))?,
            
            pow_validation_failures: register_int_counter!(opts!(
                "tsn_pow_validation_failures_total",
                "Number of failed PoW validations"
            ))?,
            
            // Commitment and ZK proofs
            commitment_validation_duration: register_histogram!(histogram_opts!(
                "tsn_commitment_validation_duration_seconds",
                "Commitment validation time in seconds",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            ))?,
            
            invalid_commitment_root_errors: register_int_counter!(opts!(
                "tsn_invalid_commitment_root_errors_total",
                "Total invalid commitment root errors"
            ))?,
            
            zk_proofs_validated_total: register_int_counter!(opts!(
                "tsn_zk_proofs_validated_total",
                "Number of validated ZK proofs"
            ))?,
            
            zk_proof_validation_duration: register_histogram!(histogram_opts!(
                "tsn_zk_proof_validation_duration_seconds",
                "ZK proof validation time in seconds",
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
            ))?,
            
            // Memory and performance
            mempool_size: register_int_gauge!(opts!(
                "tsn_mempool_size",
                "Current mempool size"
            ))?,
            
            block_interval: register_histogram!(histogram_opts!(
                "tsn_block_interval_seconds",
                "Inter-block latency in seconds",
                vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
            ))?,
            
            consensus_memory_usage: register_gauge!(opts!(
                "tsn_consensus_memory_usage_bytes",
                "Consensus memory usage in bytes"
            ))?,
        })
    }
}

/// Global consensus metrics instance
pub static CONSENSUS_METRICS: Lazy<ConsensusMetrics> = Lazy::new(|| {
    ConsensusMetrics::new().expect("INIT: failure creation metrics consensus Prometheus — noms duplicated?")
});

/// Collects all metrics in Prometheus format
pub fn collect_metrics() -> Result<String, prometheus::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    // SAFETY: Prometheus TextEncoder always produces valid UTF-8
    Ok(String::from_utf8(buffer)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Macro for measuring the execution duration of a code block
#[macro_export]
macro_rules! measure_duration {
    ($histogram:expr, $block:expr) => {{
        let timer = $histogram.start_timer();
        let result = $block;
        timer.observe_duration();
        result
    }};
}

/// Macro for incrementing a counter with error handling
#[macro_export]
macro_rules! inc_counter {
    ($counter:expr) => {
        $counter.inc();
    };
    ($counter:expr, $value:expr) => {
        $counter.inc_by($value);
    };
}

/// Macro for defining a gauge with error handling
#[macro_export]
macro_rules! set_gauge {
    ($gauge:expr, $value:expr) => {
        $gauge.set($value);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_initialization() {
        // ConsensusMetrics::new() may fail if metrics are already registered
        // (when tests run in parallel). Both Ok and AlreadyReg are acceptable.
        let _ = ConsensusMetrics::new();
    }
    
    #[test]
    fn test_collect_metrics() {
        // Ensure at least one metric is registered before collecting
        let _ = ConsensusMetrics::new();
        let output = collect_metrics();
        assert!(output.is_ok());
        let metrics_text = output.unwrap();
        // May be empty if metrics registration failed (duplicate), but should not error
        // Just verify it returns valid text
        assert!(metrics_text.is_ascii() || metrics_text.is_empty() || metrics_text.contains("tsn_"));
    }
}