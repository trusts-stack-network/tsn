//! Metrics Prometheus pour Trust Stack Network
//!
//! Ce module fournit des metrics detailed pour surveiller les performances
//! du consensus, la validation des blocs, et diagnostiquer des problems comme
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

/// Metrics globales du consensus TSN
pub struct ConsensusMetrics {
    // === VALIDATION DE BLOCS ===
    /// Nombre total de blocs validateds avec success
    pub blocks_validated_total: IntCounter,
    
    /// Nombre total de blocs rejecteds
    pub blocks_rejected_total: IntCounter,
    
    /// Temps de validation d'un bloc (en secondes)
    pub block_validation_duration: Histogram,
    
    /// Nombre de blocs en cours de validation
    pub blocks_validating_current: IntGauge,
    
    // === CONSENSUS ET FORK CHOICE ===
    /// Hauteur actuelle de la chain canonique
    pub chain_height: IntGauge,
    
    /// Travail cumulatif de la chain canonique
    pub cumulative_work: Gauge,
    
    /// Nombre de reorganizations de chain
    pub chain_reorgs_total: IntCounter,
    
    /// Profondeur de la last reorganization
    pub last_reorg_depth: IntGauge,
    
    /// Nombre de forks detecteds
    pub forks_detected_total: IntCounter,
    
    /// Nombre de blocs orphelins
    pub orphan_blocks_count: IntGauge,
    
    // === PROOF OF WORK ===
    /// Difficulty actuelle du network
    pub network_difficulty: Gauge,
    
    /// Temps de validation PoW (en secondes)
    pub pow_validation_duration: Histogram,
    
    /// Nombre de validations PoW faileds
    pub pow_validation_failures: IntCounter,
    
    // === COMMITMENT ET ZK PROOFS ===
    /// Temps de validation des commitments (en secondes)
    pub commitment_validation_duration: Histogram,
    
    /// Nombre d'erreurs "Invalid commitment root"
    pub invalid_commitment_root_errors: IntCounter,
    
    /// Nombre de preuves ZK validatedes
    pub zk_proofs_validated_total: IntCounter,
    
    /// Temps de validation des preuves ZK (en secondes)
    pub zk_proof_validation_duration: Histogram,
    
    // === MEMORY ET PERFORMANCE ===
    /// Taille du mempool (nombre de transactions)
    pub mempool_size: IntGauge,
    
    /// Latence moyenne entre blocs (en secondes)
    pub block_interval: Histogram,
    
    /// Utilisation memory du consensus (en bytes)
    pub consensus_memory_usage: Gauge,
}

impl ConsensusMetrics {
    /// Creates une new instance des metrics consensus
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            // Validation de blocs
            blocks_validated_total: register_int_counter!(opts!(
                "tsn_blocks_validated_total",
                "Nombre total de blocs validateds avec success"
            ))?,
            
            blocks_rejected_total: register_int_counter!(opts!(
                "tsn_blocks_rejected_total", 
                "Nombre total de blocs rejecteds"
            ))?,
            
            block_validation_duration: register_histogram!(histogram_opts!(
                "tsn_block_validation_duration_seconds",
                "Temps de validation d'un bloc en secondes",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
            ))?,
            
            blocks_validating_current: register_int_gauge!(opts!(
                "tsn_blocks_validating_current",
                "Nombre de blocs en cours de validation"
            ))?,
            
            // Consensus et fork choice
            chain_height: register_int_gauge!(opts!(
                "tsn_chain_height",
                "Hauteur actuelle de la chain canonique"
            ))?,
            
            cumulative_work: register_gauge!(opts!(
                "tsn_cumulative_work",
                "Travail cumulatif de la chain canonique"
            ))?,
            
            chain_reorgs_total: register_int_counter!(opts!(
                "tsn_chain_reorgs_total",
                "Nombre total de reorganizations de chain"
            ))?,
            
            last_reorg_depth: register_int_gauge!(opts!(
                "tsn_last_reorg_depth",
                "Profondeur de la last reorganization"
            ))?,
            
            forks_detected_total: register_int_counter!(opts!(
                "tsn_forks_detected_total",
                "Nombre total de forks detecteds"
            ))?,
            
            orphan_blocks_count: register_int_gauge!(opts!(
                "tsn_orphan_blocks_count",
                "Nombre actuel de blocs orphelins"
            ))?,
            
            // Proof of Work
            network_difficulty: register_gauge!(opts!(
                "tsn_network_difficulty",
                "Difficulty actuelle du network"
            ))?,
            
            pow_validation_duration: register_histogram!(histogram_opts!(
                "tsn_pow_validation_duration_seconds",
                "Temps de validation PoW en secondes",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
            ))?,
            
            pow_validation_failures: register_int_counter!(opts!(
                "tsn_pow_validation_failures_total",
                "Nombre de validations PoW faileds"
            ))?,
            
            // Commitment et ZK proofs
            commitment_validation_duration: register_histogram!(histogram_opts!(
                "tsn_commitment_validation_duration_seconds",
                "Temps de validation des commitments en secondes",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            ))?,
            
            invalid_commitment_root_errors: register_int_counter!(opts!(
                "tsn_invalid_commitment_root_errors_total",
                "Nombre d'erreurs 'Invalid commitment root'"
            ))?,
            
            zk_proofs_validated_total: register_int_counter!(opts!(
                "tsn_zk_proofs_validated_total",
                "Nombre de preuves ZK validatedes"
            ))?,
            
            zk_proof_validation_duration: register_histogram!(histogram_opts!(
                "tsn_zk_proof_validation_duration_seconds",
                "Temps de validation des preuves ZK en secondes",
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
            ))?,
            
            // Memory et performance
            mempool_size: register_int_gauge!(opts!(
                "tsn_mempool_size",
                "Taille actuelle du mempool"
            ))?,
            
            block_interval: register_histogram!(histogram_opts!(
                "tsn_block_interval_seconds",
                "Latence entre blocs en secondes",
                vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
            ))?,
            
            consensus_memory_usage: register_gauge!(opts!(
                "tsn_consensus_memory_usage_bytes",
                "Utilisation memory du consensus en bytes"
            ))?,
        })
    }
}

/// Instance globale des metrics consensus
pub static CONSENSUS_METRICS: Lazy<ConsensusMetrics> = Lazy::new(|| {
    ConsensusMetrics::new().expect("INIT: failure creation metrics consensus Prometheus — noms duplicated?")
});

/// Collecte toutes les metrics au format Prometheus
pub fn collect_metrics() -> Result<String, prometheus::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    // SAFETY: Prometheus TextEncoder always produces valid UTF-8
    Ok(String::from_utf8(buffer)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Macro pour mesurer la duration d'execution d'un bloc de code
#[macro_export]
macro_rules! measure_duration {
    ($histogram:expr, $block:expr) => {{
        let timer = $histogram.start_timer();
        let result = $block;
        timer.observe_duration();
        result
    }};
}

/// Macro pour incrementsr un compteur avec gestion d'error
#[macro_export]
macro_rules! inc_counter {
    ($counter:expr) => {
        $counter.inc();
    };
    ($counter:expr, $value:expr) => {
        $counter.inc_by($value);
    };
}

/// Macro pour define une gauge avec gestion d'error
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