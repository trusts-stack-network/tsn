//! Monitoring system for TSN nodes with Prometheus metrics.
//!
//! This module exposes key metrics from the TSN node:
//! - Block height
//! - Peer count
//! - Mempool size
//! - P2P latency
//! - Mining stats
//! - Transaction throughput

use prometheus::{
    Counter, Gauge, Histogram, Registry, Encoder, TextEncoder,
    HistogramOpts, Opts, Result as PrometheusResult,
};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{info, warn, error};

use crate::core::ShieldedBlockchain;
use crate::network::{Mempool, AppState};

/// Prometheus metrics for TSN node monitoring
pub struct TsnMetrics {
    /// Prometheus registry for all metrics
    pub registry: Registry,
    
    // === BLOCKCHAIN METRICS ===
    /// Current blockchain height
    pub block_height: Gauge,
    /// Total number of mined blocks
    pub blocks_total: Counter,
    /// Block processing time (in seconds)
    pub block_processing_duration: Histogram,
    /// Average block size (in bytes)
    pub block_size_bytes: Histogram,
    
    // === NETWORK METRICS ===
    /// Number of connected peers
    pub peer_count: Gauge,
    /// Average P2P latency (in milliseconds)
    pub p2p_latency_ms: Histogram,
    /// Number of received P2P messages
    pub p2p_messages_received: Counter,
    /// Number of sent P2P messages
    pub p2p_messages_sent: Counter,
    /// Network synchronization errors
    pub sync_errors_total: Counter,
    
    // === MEMPOOL METRICS ===
    /// Current mempool size (number of transactions)
    pub mempool_size: Gauge,
    /// Pending V1 transactions
    pub mempool_v1_transactions: Gauge,
    /// Pending V2 transactions
    pub mempool_v2_transactions: Gauge,
    /// Rejected transactions (invalid)
    pub mempool_rejected_transactions: Counter,
    
    // === MINING METRICS ===
    /// Current hashrate (hashes per second)
    pub mining_hashrate_hps: Gauge,
    /// Number of mining attempts
    pub mining_attempts_total: Counter,
    /// Successfully mined blocks
    pub mining_blocks_found: Counter,
    /// Last block mining time (in milliseconds)
    pub mining_last_block_time_ms: Gauge,
    
    // === TRANSACTION METRICS ===
    /// Total submitted transactions
    pub transactions_submitted_total: Counter,
    /// Confirmed transactions
    pub transactions_confirmed_total: Counter,
    /// Average transaction fees
    pub transaction_fees_avg: Histogram,
    /// Transaction confirmation time
    pub transaction_confirmation_time: Histogram,
    
    // === SYSTEM METRICS ===
    /// Node uptime (in seconds)
    pub node_uptime_seconds: Gauge,
    /// Memory usage (in bytes)
    pub memory_usage_bytes: Gauge,
    /// Database size (in bytes)
    pub database_size_bytes: Gauge,
}

impl TsnMetrics {
    /// Creates a new TSN metrics instance
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();
        
        // === BLOCKCHAIN METRICS ===
        let block_height = Gauge::with_opts(Opts::new(
            "tsn_block_height",
            "Current TSN blockchain height"
        ))?;
        
        let blocks_total = Counter::with_opts(Opts::new(
            "tsn_blocks_total",
            "Total number of mined blocks"
        ))?;
        
        let block_processing_duration = Histogram::with_opts(HistogramOpts::new(
            "tsn_block_processing_duration_seconds",
            "Block processing time in seconds"
        ))?;
        
        let block_size_bytes = Histogram::with_opts(HistogramOpts::new(
            "tsn_block_size_bytes",
            "Block size in bytes"
        ))?;
        
        // === NETWORK METRICS ===
        let peer_count = Gauge::with_opts(Opts::new(
            "tsn_peer_count",
            "Number of connected peers"
        ))?;
        
        let p2p_latency_ms = Histogram::with_opts(HistogramOpts::new(
            "tsn_p2p_latency_milliseconds",
            "P2P latency in milliseconds"
        ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0]))?;
        
        let p2p_messages_received = Counter::with_opts(Opts::new(
            "tsn_p2p_messages_received_total",
            "Number of received P2P messages"
        ))?;
        
        let p2p_messages_sent = Counter::with_opts(Opts::new(
            "tsn_p2p_messages_sent_total",
            "Number of sent P2P messages"
        ))?;
        
        let sync_errors_total = Counter::with_opts(Opts::new(
            "tsn_sync_errors_total",
            "Network synchronization errors"
        ))?;
        
        // === MEMPOOL METRICS ===
        let mempool_size = Gauge::with_opts(Opts::new(
            "tsn_mempool_size",
            "Current mempool size (number of transactions)"
        ))?;
        
        let mempool_v1_transactions = Gauge::with_opts(Opts::new(
            "tsn_mempool_v1_transactions",
            "Pending V1 transactions in mempool"
        ))?;
        
        let mempool_v2_transactions = Gauge::with_opts(Opts::new(
            "tsn_mempool_v2_transactions",
            "Pending V2 transactions in mempool"
        ))?;
        
        let mempool_rejected_transactions = Counter::with_opts(Opts::new(
            "tsn_mempool_rejected_transactions_total",
            "Rejected transactions (invalid)"
        ))?;
        
        // === MINING METRICS ===
        let mining_hashrate_hps = Gauge::with_opts(Opts::new(
            "tsn_mining_hashrate_hps",
            "Current hashrate in hashes per second"
        ))?;
        
        let mining_attempts_total = Counter::with_opts(Opts::new(
            "tsn_mining_attempts_total",
            "Total number of mining attempts"
        ))?;
        
        let mining_blocks_found = Counter::with_opts(Opts::new(
            "tsn_mining_blocks_found_total",
            "Successfully mined blocks"
        ))?;
        
        let mining_last_block_time_ms = Gauge::with_opts(Opts::new(
            "tsn_mining_last_block_time_milliseconds",
            "Last block mining time in milliseconds"
        ))?;
        
        // === TRANSACTION METRICS ===
        let transactions_submitted_total = Counter::with_opts(Opts::new(
            "tsn_transactions_submitted_total",
            "Total submitted transactions"
        ))?;
        
        let transactions_confirmed_total = Counter::with_opts(Opts::new(
            "tsn_transactions_confirmed_total",
            "Confirmed transactions"
        ))?;
        
        let transaction_fees_avg = Histogram::with_opts(HistogramOpts::new(
            "tsn_transaction_fees_avg",
            "Average transaction fees"
        ))?;
        
        let transaction_confirmation_time = Histogram::with_opts(HistogramOpts::new(
            "tsn_transaction_confirmation_time_seconds",
            "Transaction confirmation time in seconds"
        ))?;
        
        // === SYSTEM METRICS ===
        let node_uptime_seconds = Gauge::with_opts(Opts::new(
            "tsn_node_uptime_seconds",
            "Node uptime in seconds"
        ))?;
        
        let memory_usage_bytes = Gauge::with_opts(Opts::new(
            "tsn_memory_usage_bytes",
            "Memory usage in bytes"
        ))?;
        
        let database_size_bytes = Gauge::with_opts(Opts::new(
            "tsn_database_size_bytes",
            "Database size in bytes"
        ))?;
        
        // Register all metrics
        registry.register(Box::new(block_height.clone()))?;
        registry.register(Box::new(blocks_total.clone()))?;
        registry.register(Box::new(block_processing_duration.clone()))?;
        registry.register(Box::new(block_size_bytes.clone()))?;
        
        registry.register(Box::new(peer_count.clone()))?;
        registry.register(Box::new(p2p_latency_ms.clone()))?;
        registry.register(Box::new(p2p_messages_received.clone()))?;
        registry.register(Box::new(p2p_messages_sent.clone()))?;
        registry.register(Box::new(sync_errors_total.clone()))?;
        
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(mempool_v1_transactions.clone()))?;
        registry.register(Box::new(mempool_v2_transactions.clone()))?;
        registry.register(Box::new(mempool_rejected_transactions.clone()))?;
        
        registry.register(Box::new(mining_hashrate_hps.clone()))?;
        registry.register(Box::new(mining_attempts_total.clone()))?;
        registry.register(Box::new(mining_blocks_found.clone()))?;
        registry.register(Box::new(mining_last_block_time_ms.clone()))?;
        
        registry.register(Box::new(transactions_submitted_total.clone()))?;
        registry.register(Box::new(transactions_confirmed_total.clone()))?;
        registry.register(Box::new(transaction_fees_avg.clone()))?;
        registry.register(Box::new(transaction_confirmation_time.clone()))?;
        
        registry.register(Box::new(node_uptime_seconds.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(database_size_bytes.clone()))?;
        
        Ok(Self {
            registry,
            block_height,
            blocks_total,
            block_processing_duration,
            block_size_bytes,
            peer_count,
            p2p_latency_ms,
            p2p_messages_received,
            p2p_messages_sent,
            sync_errors_total,
            mempool_size,
            mempool_v1_transactions,
            mempool_v2_transactions,
            mempool_rejected_transactions,
            mining_hashrate_hps,
            mining_attempts_total,
            mining_blocks_found,
            mining_last_block_time_ms,
            transactions_submitted_total,
            transactions_confirmed_total,
            transaction_fees_avg,
            transaction_confirmation_time,
            node_uptime_seconds,
            memory_usage_bytes,
            database_size_bytes,
        })
    }
    
    /// Updates metrics with the current node state
    ///
    /// Note: unwrap() on RwLock::read() is intentional — a poisoned mutex
    /// means a thread panicked while modifying state, and propagation is correct.
    pub fn update_metrics(&self, state: &AppState, start_time: Instant) {
        // === BLOCKCHAIN METRICS ===
        {
            let blockchain = state.blockchain.read().unwrap();
            self.block_height.set(blockchain.height() as f64);
            self.blocks_total.inc_by(blockchain.height());
        }
        
        // === NETWORK METRICS ===
        {
            let peers = state.peers.read().unwrap();
            self.peer_count.set(peers.len() as f64);
        }
        
        // === MEMPOOL METRICS ===
        {
            let mempool = state.mempool.read().unwrap();
            let v1_count = mempool.get_transactions(1000).len();
            let v2_count = mempool.get_v2_transactions(1000).len();
            let total_size = v1_count + v2_count;
            
            self.mempool_size.set(total_size as f64);
            self.mempool_v1_transactions.set(v1_count as f64);
            self.mempool_v2_transactions.set(v2_count as f64);
        }
        
        // === MINING METRICS ===
        {
            let miner_stats = state.miner_stats.read().unwrap();
            self.mining_hashrate_hps.set(miner_stats.hashrate_hps as f64);
            if miner_stats.last_attempts > 0 {
                self.mining_attempts_total.inc_by(miner_stats.last_attempts);
            }
            if miner_stats.last_elapsed_ms > 0 {
                self.mining_last_block_time_ms.set(miner_stats.last_elapsed_ms as f64);
            }
        }
        
        // === SYSTEM METRICS ===
        let uptime = start_time.elapsed().as_secs();
        self.node_uptime_seconds.set(uptime as f64);
        
        // Memory usage (basic estimate)
        if let Ok(memory_info) = sys_info::mem_info() {
            let used_memory = (memory_info.total - memory_info.free) * 1024; // Convert to bytes
            self.memory_usage_bytes.set(used_memory as f64);
        }
    }
    
    /// Exports metrics in Prometheus format
    pub fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
    
    /// Records a measured P2P latency
    pub fn record_p2p_latency(&self, latency_ms: f64) {
        self.p2p_latency_ms.observe(latency_ms);
    }
    
    /// Records a received P2P message
    pub fn record_p2p_message_received(&self) {
        self.p2p_messages_received.inc();
    }
    
    /// Records a sent P2P message
    pub fn record_p2p_message_sent(&self) {
        self.p2p_messages_sent.inc();
    }
    
    /// Records a synchronization error
    pub fn record_sync_error(&self) {
        self.sync_errors_total.inc();
    }
    
    /// Records a rejected transaction
    pub fn record_rejected_transaction(&self) {
        self.mempool_rejected_transactions.inc();
    }
    
    /// Records a submitted transaction
    pub fn record_transaction_submitted(&self) {
        self.transactions_submitted_total.inc();
    }
    
    /// Records a confirmed transaction
    pub fn record_transaction_confirmed(&self) {
        self.transactions_confirmed_total.inc();
    }
    
    /// Records a transaction's fees
    pub fn record_transaction_fee(&self, fee: u64) {
        self.transaction_fees_avg.observe(fee as f64);
    }
    
    /// Records a block's processing time
    pub fn record_block_processing_time(&self, duration: Duration) {
        self.block_processing_duration.observe(duration.as_secs_f64());
    }
    
    /// Records a block's size
    pub fn record_block_size(&self, size_bytes: usize) {
        self.block_size_bytes.observe(size_bytes as f64);
    }
    
    /// Records a mined block
    pub fn record_block_mined(&self) {
        self.mining_blocks_found.inc();
    }
}

/// Monitoring service that periodically updates metrics
pub struct MonitoringService {
    metrics: Arc<TsnMetrics>,
    start_time: Instant,
}

impl MonitoringService {
    /// Creates a new monitoring service
    pub fn new(metrics: Arc<TsnMetrics>) -> Self {
        Self {
            metrics,
            start_time: Instant::now(),
        }
    }
    
    /// Starts the monitoring service with periodic updates
    pub async fn start(&self, state: Arc<AppState>) {
        let mut interval = interval(Duration::from_secs(30)); // Update every 30 seconds
        
        info!("TSN monitoring service started - updating every 30 seconds");
        
        loop {
            interval.tick().await;
            
            match std::panic::catch_unwind(|| {
                self.metrics.update_metrics(&state, self.start_time);
            }) {
                Ok(_) => {
                    // Update successful
                }
                Err(e) => {
                    error!("Error updating metrics: {:?}", e);
                }
            }
        }
    }
}

/// Initializes the Prometheus monitoring system
pub fn init_monitoring() -> Result<Arc<TsnMetrics>, Box<dyn std::error::Error>> {
    let metrics = TsnMetrics::new()?;
    info!("Prometheus monitoring system initialized");
    Ok(Arc::new(metrics))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_creation() {
        let metrics = TsnMetrics::new().expect("Failed to create metrics");
        assert!(metrics.export_metrics().is_ok());
    }
    
    #[test]
    fn test_metrics_update() {
        let metrics = TsnMetrics::new().expect("Failed to create metrics");
        
        // Test metrics recording
        metrics.record_p2p_latency(25.5);
        metrics.record_p2p_message_received();
        metrics.record_p2p_message_sent();
        metrics.record_transaction_submitted();
        metrics.record_transaction_fee(1000);
        metrics.record_block_mined();
        
        let exported = metrics.export_metrics().expect("Failed to export metrics");
        assert!(exported.contains("tsn_p2p_latency_milliseconds"));
        assert!(exported.contains("tsn_p2p_messages_received_total"));
        assert!(exported.contains("tsn_transactions_submitted_total"));
    }
}