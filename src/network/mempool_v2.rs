//! Advanced mempool with smart memory management.
//!
//! This version improves the original mempool with:
//! - Memory pressure management with smart eviction
//! - Anti-DoS with per-peer rate limiting
//! - Prioritization based on fees and seniority
//! - Detailed metrics for monitoring
//! - Full async support with tokio

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};

use crate::core::{ShieldedState, ShieldedTransaction, Transaction};
use crate::network::mempool_manager::{MempoolMemoryManager, MempoolMemoryConfig, MempoolError};
use crate::network::types::{TransactionId, TransactionV1, TransactionV2};
use crate::network::anti_dos::RateLimiter;

/// Advanced mempool configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolV2Config {
    /// Memory manager configuration.
    pub memory: MempoolMemoryConfig,
    
    /// Transaction limit per peer per minute.
    pub max_tx_per_peer_per_minute: u32,
    
    /// Maximum transaction size in bytes.
    pub max_transaction_size: usize,
    
    /// Minimum absolute fee (anti-spam).
    pub min_absolute_fee: u64,
    
    /// Enable strict transaction validation.
    pub strict_validation: bool,
    
    /// Inactive peer cleanup interval.
    pub peer_cleanup_interval_seconds: u64,
}

impl Default for MempoolV2Config {
    fn default() -> Self {
        Self {
            memory: MempoolMemoryConfig::default(),
            max_tx_per_peer_per_minute: 100,
            max_transaction_size: 1024 * 1024, // 1 MB
            min_absolute_fee: 1000, // 1000 sats minimum
            strict_validation: true,
            peer_cleanup_interval_seconds: 300, // 5 minutes
        }
    }
}

/// Detailed mempool statistics.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MempoolV2Stats {
    /// Number of V1 transactions.
    pub v1_transactions: usize,
    
    /// Number of V2 transactions.
    pub v2_transactions: usize,
    
    /// Total number of transactions.
    pub total_transactions: usize,
    
    /// Number of pending nullifiers.
    pub pending_nullifiers: usize,
    
    /// Total number of transaction additions.
    pub total_adds: u64,
    
    /// Total number of rejections.
    pub total_rejections: u64,
    
    /// Number of double-spend rejections.
    pub double_spend_rejections: u64,
    
    /// Number of insufficient fee rejections.
    pub fee_rejections: u64,
    
    /// Number of rate limiting rejections.
    pub rate_limit_rejections: u64,
    
    /// Number of validation rejections.
    pub validation_rejections: u64,
    
    /// Memory statistics.
    pub memory_stats: crate::network::mempool_manager::MemoryStats,
    
    /// Average fee per transaction.
    pub average_fee: f64,
    
    /// Average transaction size.
    pub average_size: f64,
    
    /// Last statistics update.
    pub last_updated: u64,
}

/// Peer information for rate limiting.
#[derive(Debug, Clone)]
struct PeerInfo {
    /// Number of transactions submitted in the current window.
    tx_count: u32,
    
    /// Rate limiting window start.
    window_start: Instant,
    
    /// Last peer activity.
    last_activity: Instant,
    
    /// Reputation score (0.0 = bad, 1.0 = excellent).
    reputation: f64,
}

impl PeerInfo {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            tx_count: 0,
            window_start: now,
            last_activity: now,
            reputation: 1.0, // Start with a good reputation
        }
    }
    
    /// Verify if the peer can submit a transaction.
    fn can_submit(&mut self, max_per_minute: u32) -> bool {
        let now = Instant::now();
        
        // Reset the window if more than one minute has elapsed
        if now.duration_since(self.window_start) >= Duration::from_secs(60) {
            self.tx_count = 0;
            self.window_start = now;
        }
        
        self.last_activity = now;
        
        if self.tx_count >= max_per_minute {
            // Penalize the reputation for spam
            self.reputation = (self.reputation * 0.9).max(0.1);
            false
        } else {
            self.tx_count += 1;
            // Slightly improve the reputation for normal behavior
            self.reputation = (self.reputation * 1.001).min(1.0);
            true
        }
    }
    
    /// Verify if the peer is inactive.
    fn is_inactive(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Advanced mempool with smart memory management.
pub struct MempoolV2 {
    /// Configuration.
    config: MempoolV2Config,
    
    /// Pending V1 transactions.
    v1_transactions: Arc<RwLock<HashMap<TransactionId, ShieldedTransaction>>>,
    
    /// Pending V2 transactions.
    v2_transactions: Arc<RwLock<HashMap<TransactionId, Transaction>>>,
    
    /// Pending nullifiers (double-spend detection).
    pending_nullifiers: Arc<RwLock<HashSet<[u8; 32]>>>,
    
    /// Memory manager.
    memory_manager: MempoolMemoryManager,
    
    /// Peer information for rate limiting.
    peer_info: Arc<RwLock<HashMap<String, PeerInfo>>>,
    
    /// Statistics.
    stats: Arc<RwLock<MempoolV2Stats>>,
    
    /// Validation state.
    shielded_state: Option<Arc<RwLock<ShieldedState>>>,
}

impl MempoolV2 {
    /// Create a new advanced mempool.
    pub fn new(config: MempoolV2Config) -> Self {
        let memory_manager = MempoolMemoryManager::new(config.memory.clone());
        
        Self {
            config,
            v1_transactions: Arc::new(RwLock::new(HashMap::new())),
            v2_transactions: Arc::new(RwLock::new(HashMap::new())),
            pending_nullifiers: Arc::new(RwLock::new(HashSet::new())),
            memory_manager,
            peer_info: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(MempoolV2Stats::default())),
            shielded_state: None,
        }
    }
    
    /// Configure the shielded state for validation.
    pub fn set_shielded_state(&mut self, state: Arc<RwLock<ShieldedState>>) {
        self.shielded_state = Some(state);
    }
    
    /// Add a V1 transaction to the mempool.
    pub async fn add_transaction(
        &self,
        tx: ShieldedTransaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v1(&tx);
        let tx_fee = tx.fee;
        
        // Preliminary verifications
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;

        // Verify if the transaction already exists
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }

        // Verify nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier.0) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }

        // Strict validation if enabled
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v1(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }

        // Verify memory pressure
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Add the transaction
        {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.insert(tx_hash, tx.clone());
        }

        // Add the nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier.0);
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v1_transactions += 1;
            stats.total_transactions += 1;
        }

        info!("Transaction V1 added to mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Add a V2 transaction to the mempool.
    pub async fn add_transaction_v2(
        &self,
        tx: Transaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v2(&tx);
        let tx_fee = tx.fee();
        
        // Preliminary verifications
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;

        // Verify if the transaction already exists
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }

        // Verify nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }

        // Strict validation if enabled
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v2(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }

        // Verify memory pressure
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Add the transaction
        {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.insert(tx_hash, tx.clone());
        }

        // Add the nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier);
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v2_transactions += 1;
            stats.total_transactions += 1;
        }

        info!("Transaction V2 added to mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Common basic validations.
    async fn validate_transaction_basic(
        &self,
        size: usize,
        fee: u64,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        // Verify the size
        if size > self.config.max_transaction_size {
            self.increment_rejection_stat("size").await;
            return Err(MempoolV2Error::TransactionTooLarge);
        }
        
        // Verify the minimum fees
        if fee < self.config.min_absolute_fee {
            self.increment_rejection_stat("fee").await;
            return Err(MempoolV2Error::InsufficientFee);
        }
        
        // Per-peer rate limiting
        if let Some(peer) = peer_id {
            let can_submit = {
                let mut peers = self.peer_info.write().await;
                let peer_info = peers.entry(peer.to_string()).or_insert_with(PeerInfo::new);
                peer_info.can_submit(self.config.max_tx_per_peer_per_minute)
            };
            
            if !can_submit {
                self.increment_rejection_stat("rate_limit").await;
                return Err(MempoolV2Error::RateLimited);
            }
        }
        
        Ok(())
    }
    
    /// V1-specific validation.
    /// Validates anchors and nullifiers against state (basic validation).
    /// Full ZK proof verification is done at block validation time.
    async fn validate_transaction_v1(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
    ) -> bool {
        match state.validate_transaction_basic(tx) {
            Ok(()) => true,
            Err(e) => {
                warn!("Mempool V1 validation failed: {}", e);
                false
            }
        }
    }

    /// V2-specific validation.
    /// Validates anchors, nullifiers, and ownership signatures against state.
    /// Full STARK proof verification is done at block validation time.
    async fn validate_transaction_v2(
        &self,
        tx: &Transaction,
        state: &ShieldedState,
    ) -> bool {
        match tx {
            Transaction::V1(v1_tx) => {
                match state.validate_transaction_basic(v1_tx) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!("Mempool V2 validation (V1 tx) failed: {}", e);
                        false
                    }
                }
            }
            Transaction::V2(v2_tx) => {
                match state.validate_transaction_v2_basic(v2_tx) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!("Mempool V2 validation failed: {}", e);
                        false
                    }
                }
            }
            Transaction::Migration(_) => {
                // Migration transactions are validated during block processing
                true
            }
        }
    }
    
    /// Remove a transaction from the mempool.
    pub async fn remove_transaction(&self, tx_hash: &TransactionId) -> bool {
        let mut removed = false;
        
        // Remove from V1
        if let Some(tx) = {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.remove(tx_hash)
        } {
            // Remove the nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier.0);
                }
            }
            
            // Delete from the memory manager
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.v1_transactions = stats.v1_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }

            removed = true;
        }

        // Remove from V2
        if let Some(tx) = {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.remove(tx_hash)
        } {
            // Remove the nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier);
                }
            }
            
            // Delete from the memory manager
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.v2_transactions = stats.v2_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }
            
            removed = true;
        }
        
        if removed {
            debug!("Transaction removed from mempool: {}", hex::encode(tx_hash));
        }
        
        removed
    }
    
    /// Verify if a transaction is in the mempool.
    pub async fn contains(&self, tx_hash: &TransactionId) -> bool {
        let v1_contains = self.v1_transactions.read().await.contains_key(tx_hash);
        let v2_contains = self.v2_transactions.read().await.contains_key(tx_hash);
        v1_contains || v2_contains
    }
    
    /// Get transactions by priority for mining.
    pub async fn get_transactions_for_mining(&self, limit: usize) -> (Vec<ShieldedTransaction>, Vec<Transaction>) {
        // Get IDs sorted by priority
        let priority_ids = self.memory_manager.get_transactions_by_priority(limit * 2).await;
        
        let mut v1_txs = Vec::new();
        let mut v2_txs = Vec::new();
        
        let v1_map = self.v1_transactions.read().await;
        let v2_map = self.v2_transactions.read().await;
        
        for tx_id in priority_ids {
            if v1_txs.len() + v2_txs.len() >= limit {
                break;
            }
            
            if let Some(tx) = v1_map.get(&tx_id) {
                v1_txs.push(tx.clone());
            } else if let Some(tx) = v2_map.get(&tx_id) {
                v2_txs.push(tx.clone());
            }
        }
        
        (v1_txs, v2_txs)
    }
    
    /// Remove confirmed transactions.
    pub async fn remove_confirmed_transactions(&self, tx_hashes: &[TransactionId]) {
        for hash in tx_hashes {
            self.remove_transaction(hash).await;
        }
        
        info!("Removed {} confirmed transactions from mempool", tx_hashes.len());
    }
    
    /// Remove transactions with spent nullifiers.
    pub async fn remove_spent_nullifiers(&self, spent_nullifiers: &[[u8; 32]]) {
        let mut to_remove = Vec::new();
        
        // Identify transactions to remove
        {
            let v1_txs = self.v1_transactions.read().await;
            for (hash, tx) in v1_txs.iter() {
                for nullifier in tx.nullifiers() {
                    if spent_nullifiers.contains(&nullifier.0) {
                        to_remove.push(*hash);
                        break;
                    }
                }
            }
        }
        
        {
            let v2_txs = self.v2_transactions.read().await;
            for (hash, tx) in v2_txs.iter() {
                for nullifier in tx.nullifiers() {
                    if spent_nullifiers.contains(&nullifier) {
                        to_remove.push(*hash);
                        break;
                    }
                }
            }
        }
        
        // Remove identified transactions
        for hash in &to_remove {
            self.remove_transaction(hash).await;
        }
        
        if !to_remove.is_empty() {
            info!("Removed {} transactions with spent nullifiers", to_remove.len());
        }
    }
    
    /// Periodic cleanup.
    pub async fn cleanup(&self) -> Result<usize, MempoolV2Error> {
        let mut total_cleaned = 0;
        
        // Memory manager cleanup
        total_cleaned += self.memory_manager.cleanup().await
            .map_err(|e| MempoolV2Error::Internal(e.to_string()))?;
        
        // Cleanup inactive peers
        let inactive_timeout = Duration::from_secs(self.config.peer_cleanup_interval_seconds * 2);
        {
            let mut peers = self.peer_info.write().await;
            let before_count = peers.len();
            peers.retain(|_, info| !info.is_inactive(inactive_timeout));
            let cleaned_peers = before_count - peers.len();
            if cleaned_peers > 0 {
                debug!("Cleaned up {} inactive peers", cleaned_peers);
            }
        }
        
        // Update the statistics
        self.update_stats().await;
        
        Ok(total_cleaned)
    }
    
    /// Update statistics.
    async fn update_stats(&self) {
        let v1_count = self.v1_transactions.read().await.len();
        let v2_count = self.v2_transactions.read().await.len();
        let nullifiers_count = self.pending_nullifiers.read().await.len();
        let memory_stats = self.memory_manager.get_stats().await;
        
        let mut stats = self.stats.write().await;
        stats.v1_transactions = v1_count;
        stats.v2_transactions = v2_count;
        stats.total_transactions = v1_count + v2_count;
        stats.pending_nullifiers = nullifiers_count;
        stats.memory_stats = memory_stats;
        stats.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Calculate averages
        if stats.total_transactions > 0 {
            stats.average_fee = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
            stats.average_size = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
        }
    }
    
    /// Increment rejection statistics.
    async fn increment_rejection_stat(&self, reason: &str) {
        let mut stats = self.stats.write().await;
        stats.total_rejections += 1;
        
        match reason {
            "double_spend" => stats.double_spend_rejections += 1,
            "fee" => stats.fee_rejections += 1,
            "rate_limit" => stats.rate_limit_rejections += 1,
            "validation" => stats.validation_rejections += 1,
            _ => {}
        }
    }
    
    /// Get statistics.
    pub async fn get_stats(&self) -> MempoolV2Stats {
        self.update_stats().await;
        self.stats.read().await.clone()
    }
    
    /// Estimate the size of a V1 transaction.
    fn estimate_transaction_size_v1(&self, tx: &ShieldedTransaction) -> usize {
        // Basic estimate - to improve with real serialization
        std::mem::size_of::<ShieldedTransaction>() + 
        tx.nullifiers().len() * 32 + 
        tx.commitments().len() * 32
    }
    
    /// Estimate the size of a V2 transaction.
    fn estimate_transaction_size_v2(&self, tx: &Transaction) -> usize {
        // Basic estimate - to improve with real serialization
        match tx {
            Transaction::V1(_) => 1000, // Estimate
            Transaction::V2(_) => 1500, // Larger estimate for post-quantum
            Transaction::Migration(_) => 2000, // Estimate for migration
        }
    }
    
    /// Start automatic cleanup background tasks.
    pub async fn start_background_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        
        // Memory manager cleanup task
        handles.push(self.memory_manager.start_cleanup_task().await);
        
        // General mempool cleanup task
        let mempool = self.clone();
        let cleanup_interval = Duration::from_secs(self.config.peer_cleanup_interval_seconds);
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = mempool.cleanup().await {
                    warn!("Error cleaning mempool: {:?}", e);
                }
            }
        }));
        
        handles
    }
}

// Clone implementation to allow usage in async tasks
impl Clone for MempoolV2 {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            v1_transactions: Arc::clone(&self.v1_transactions),
            v2_transactions: Arc::clone(&self.v2_transactions),
            pending_nullifiers: Arc::clone(&self.pending_nullifiers),
            memory_manager: self.memory_manager.clone(),
            peer_info: Arc::clone(&self.peer_info),
            stats: Arc::clone(&self.stats),
            shielded_state: self.shielded_state.clone(),
        }
    }
}

/// Advanced mempool errors.
#[derive(Debug, thiserror::Error)]
pub enum MempoolV2Error {
    #[error("Transaction already in mempool")]
    DuplicateTransaction,
    
    #[error("Double-spend detected")]
    DoubleSpend,
    
    #[error("Transaction too large")]
    TransactionTooLarge,
    
    #[error("Insufficient fees")]
    InsufficientFee,
    
    #[error("Rate limit exceeded for this peer")]
    RateLimited,
    
    #[error("Transaction validation failed")]
    ValidationFailed,
    
    #[error("Memory pressure - mempool full")]
    MemoryPressure,
    
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ShieldedTransaction;
    
    #[tokio::test]
    async fn test_mempool_v2_basic() {
        let config = MempoolV2Config::default();
        let mempool = MempoolV2::new(config);
        
        // Create a test transaction
        let tx = ShieldedTransaction::default(); // Placeholder
        
        // Add the transaction
        let result = mempool.add_transaction(tx, Some("peer1")).await;
        // Note: this test will fail because ShieldedTransaction::default() doesn't exist
        // Need to create a valid transaction for real tests
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = MempoolV2Config::default();
        config.max_tx_per_peer_per_minute = 2;
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implement tests with real transactions
    }
    
    #[tokio::test]
    async fn test_memory_pressure() {
        let mut config = MempoolV2Config::default();
        config.memory.max_memory_bytes = 1024; // Very small to force eviction
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implement memory pressure tests
    }
}