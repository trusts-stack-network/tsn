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
    
    /// Limite de transactions par peer par minute.
    pub max_tx_per_peer_per_minute: u32,
    
    /// Maximum transaction size in bytes.
    pub max_transaction_size: usize,
    
    /// Frais minimum absolu (anti-spam).
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
    
    /// Statistiques memory.
    pub memory_stats: crate::network::mempool_manager::MemoryStats,
    
    /// Frais moyen par transaction.
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
    
    /// Score de reputation (0.0 = mauvais, 1.0 = excellent).
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
    
    /// Verify if the peer can soumettre a transaction.
    fn can_submit(&mut self, max_per_minute: u32) -> bool {
        let now = Instant::now();
        
        // Reset de the window if plus d'une minute s'est elapsed
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
            // Improve lightment the reputation for comportement normal
            self.reputation = (self.reputation * 1.001).min(1.0);
            true
        }
    }
    
    /// Verify if the peer is inactif.
    fn is_inactive(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Mempool advanced with gestion smart de the memory.
pub struct MempoolV2 {
    /// Configuration.
    config: MempoolV2Config,
    
    /// Pending V1 transactions.
    v1_transactions: Arc<RwLock<HashMap<TransactionId, ShieldedTransaction>>>,
    
    /// Pending V2 transactions.
    v2_transactions: Arc<RwLock<HashMap<TransactionId, Transaction>>>,
    
    /// Nullifiers in pending (detection double-spend).
    pending_nullifiers: Arc<RwLock<HashSet<[u8; 32]>>>,
    
    /// Manager de memory.
    memory_manager: MempoolMemoryManager,
    
    /// Informations of peers for rate limiting.
    peer_info: Arc<RwLock<HashMap<String, PeerInfo>>>,
    
    /// Statistiques.
    stats: Arc<RwLock<MempoolV2Stats>>,
    
    /// State de validation.
    shielded_state: Option<Arc<RwLock<ShieldedState>>>,
}

impl MempoolV2 {
    /// Create a nouveau mempool advanced.
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
    
    /// Configure l'state shielded for validation.
    pub fn set_shielded_state(&mut self, state: Arc<RwLock<ShieldedState>>) {
        self.shielded_state = Some(state);
    }
    
    /// Ajouter a transaction V1 at the mempool.
    pub async fn add_transaction(
        &self,
        tx: ShieldedTransaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v1(&tx);
        let tx_fee = tx.fee;
        
        // Verifications preliminary
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;
        
        // Verify if the transaction exists already
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }
        
        // Verify the nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier.0) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }
        
        // Validation stricte if enabled
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v1(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }
        
        // Verify the pression memory
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Ajouter the transaction
        {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.insert(tx_hash, tx.clone());
        }
        
        // Ajouter the nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier.0);
            }
        }
        
        // Update the statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v1_transactions += 1;
            stats.total_transactions += 1;
        }
        
        info!("Transaction V1 addede au mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Ajouter a transaction V2 at the mempool.
    pub async fn add_transaction_v2(
        &self,
        tx: Transaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v2(&tx);
        let tx_fee = tx.fee();
        
        // Verifications preliminary
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;
        
        // Verify if the transaction exists already
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }
        
        // Verify the nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }
        
        // Validation stricte if enabled
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v2(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }
        
        // Verify the pression memory
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Ajouter the transaction
        {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.insert(tx_hash, tx.clone());
        }
        
        // Ajouter the nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier);
            }
        }
        
        // Update the statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v2_transactions += 1;
            stats.total_transactions += 1;
        }
        
        info!("Transaction V2 addede au mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Validations de base communes.
    async fn validate_transaction_basic(
        &self,
        size: usize,
        fee: u64,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        // Verify the taille
        if size > self.config.max_transaction_size {
            self.increment_rejection_stat("size").await;
            return Err(MempoolV2Error::TransactionTooLarge);
        }
        
        // Verify the fees minimum
        if fee < self.config.min_absolute_fee {
            self.increment_rejection_stat("fee").await;
            return Err(MempoolV2Error::InsufficientFee);
        }
        
        // Rate limiting par peer
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
    
    /// Validation specific V1.
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

    /// Validation specific V2.
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
    
    /// Supprimer a transaction of the mempool.
    pub async fn remove_transaction(&self, tx_hash: &TransactionId) -> bool {
        let mut removed = false;
        
        // Supprimer de V1
        if let Some(tx) = {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.remove(tx_hash)
        } {
            // Supprimer the nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier.0);
                }
            }
            
            // Delete of the manager de memory
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Update the statistics
            {
                let mut stats = self.stats.write().await;
                stats.v1_transactions = stats.v1_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }
            
            removed = true;
        }
        
        // Supprimer de V2
        if let Some(tx) = {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.remove(tx_hash)
        } {
            // Supprimer the nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier);
                }
            }
            
            // Delete of the manager de memory
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Update the statistics
            {
                let mut stats = self.stats.write().await;
                stats.v2_transactions = stats.v2_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }
            
            removed = true;
        }
        
        if removed {
            debug!("Transaction removede du mempool: {}", hex::encode(tx_hash));
        }
        
        removed
    }
    
    /// Verify if a transaction is in the mempool.
    pub async fn contains(&self, tx_hash: &TransactionId) -> bool {
        let v1_contains = self.v1_transactions.read().await.contains_key(tx_hash);
        let v2_contains = self.v2_transactions.read().await.contains_key(tx_hash);
        v1_contains || v2_contains
    }
    
    /// Get the transactions par priority for mining.
    pub async fn get_transactions_for_mining(&self, limit: usize) -> (Vec<ShieldedTransaction>, Vec<Transaction>) {
        // Get the IDs sorted par priority
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
    
    /// Delete the transactions confirmed.
    pub async fn remove_confirmed_transactions(&self, tx_hashes: &[TransactionId]) {
        for hash in tx_hashes {
            self.remove_transaction(hash).await;
        }
        
        info!("Removed {} transactions confirmed du mempool", tx_hashes.len());
    }
    
    /// Delete the transactions with nullifiers spents.
    pub async fn remove_spent_nullifiers(&self, spent_nullifiers: &[[u8; 32]]) {
        let mut to_remove = Vec::new();
        
        // Identify the transactions to delete
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
        
        // Delete the transactions identifiesdes
        for hash in &to_remove {
            self.remove_transaction(hash).await;
        }
        
        if !to_remove.is_empty() {
            info!("Removed {} transactions avec nullifiers spents", to_remove.len());
        }
    }
    
    /// Cleanup periodic.
    pub async fn cleanup(&self) -> Result<usize, MempoolV2Error> {
        let mut total_cleaned = 0;
        
        // Cleanup of the manager de memory
        total_cleaned += self.memory_manager.cleanup().await
            .map_err(|e| MempoolV2Error::Internal(e.to_string()))?;
        
        // Nettoyage of peers inactifs
        let inactive_timeout = Duration::from_secs(self.config.peer_cleanup_interval_seconds * 2);
        {
            let mut peers = self.peer_info.write().await;
            let before_count = peers.len();
            peers.retain(|_, info| !info.is_inactive(inactive_timeout));
            let cleaned_peers = before_count - peers.len();
            if cleaned_peers > 0 {
                debug!("Cleaned up {} peers inactifs", cleaned_peers);
            }
        }
        
        // Update the statistics
        self.update_stats().await;
        
        Ok(total_cleaned)
    }
    
    /// Update the statistics.
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
        
        // Calculer the moyennes
        if stats.total_transactions > 0 {
            stats.average_fee = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
            stats.average_size = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
        }
    }
    
    /// Increment the statistics de rejet.
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
    
    /// Obtenir the statistics.
    pub async fn get_stats(&self) -> MempoolV2Stats {
        self.update_stats().await;
        self.stats.read().await.clone()
    }
    
    /// Estimer the size d'une transaction V1.
    fn estimate_transaction_size_v1(&self, tx: &ShieldedTransaction) -> usize {
        // Estimation basique - to improve with the serialization real
        std::mem::size_of::<ShieldedTransaction>() + 
        tx.nullifiers().len() * 32 + 
        tx.commitments().len() * 32
    }
    
    /// Estimer the size d'une transaction V2.
    fn estimate_transaction_size_v2(&self, tx: &Transaction) -> usize {
        // Estimation basique - to improve with the serialization real
        match tx {
            Transaction::V1(_) => 1000, // Estimation
            Transaction::V2(_) => 1500, // Larger estimate for post-quantum
            Transaction::Migration(_) => 2000, // Estimate for migration
        }
    }
    
    /// Start the tasks de cleanup automatique.
    pub async fn start_background_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        
        // Task de cleanup of the manager de memory
        handles.push(self.memory_manager.start_cleanup_task().await);
        
        // Task de cleanup general of the mempool
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

// Implementation de Clone for allowstre l'utilisation in the tasks async
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

/// Errors of the mempool advanced.
#[derive(Debug, thiserror::Error)]
pub enum MempoolV2Error {
    #[error("Transaction already present dans le mempool")]
    DuplicateTransaction,
    
    #[error("Double-spend detected")]
    DoubleSpend,
    
    #[error("Transaction trop volumineuse")]
    TransactionTooLarge,
    
    #[error("Frais insuffisants")]
    InsufficientFee,
    
    #[error("Rate limit exceeded pour ce peer")]
    RateLimited,
    
    #[error("Validation de la transaction failed")]
    ValidationFailed,
    
    #[error("Pression memory - mempool plein")]
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
        
        // Create a transaction de test
        let tx = ShieldedTransaction::default(); // Placeholder
        
        // Ajouter the transaction
        let result = mempool.add_transaction(tx, Some("peer1")).await;
        // Note: this test failsra car ShieldedTransaction::default() n'exists pas
        // Need to create a valid transaction for real tests
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = MempoolV2Config::default();
        config.max_tx_per_peer_per_minute = 2;
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implement of tests with de vraies transactions
    }
    
    #[tokio::test]
    async fn test_memory_pressure() {
        let mut config = MempoolV2Config::default();
        config.memory.max_memory_bytes = 1024; // Very small to force eviction
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implement of tests de pression memory
    }
}