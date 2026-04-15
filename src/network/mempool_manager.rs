//! Gestionnaire de memory intelligent pour le mempool.
//!
//! Ce module implemente une gestion avancee de la memory du mempool avec :
//! - Eviction intelligente basee sur les frais, l'oldte et la taille
//! - Prevention des attaques OOM (Out of Memory)
//! - Metrics detaillees pour monitoring
//! - Algorithmes d'eviction configurables

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};

use crate::network::types::TransactionId;

/// Configuration du manager de memory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolMemoryConfig {
    /// Limite de memory maximale en bytes (defaut: 256 MB).
    pub max_memory_bytes: usize,
    
    /// Seuil de pression memory (% de max_memory_bytes).
    pub pressure_threshold: f64,
    
    /// Seuil critique de memory (% de max_memory_bytes).
    pub critical_threshold: f64,
    
    /// Nombre maximum de transactions.
    pub max_transactions: usize,
    
    /// Taille maximale d'une transaction individuelle.
    pub max_single_transaction_size: usize,
    
    /// Strategie d'eviction.
    pub eviction_strategy: EvictionStrategy,
    
    /// Intervalle de nettoyage automatique en secondes.
    pub cleanup_interval_seconds: u64,
    
    /// Age maximum d'une transaction en secondes.
    pub max_transaction_age_seconds: u64,
    
    /// Facteur de boost pour les frais eleves.
    pub high_fee_boost_factor: f64,
    
    /// Seuil de frais pour considerer une transaction comme "haute priority".
    pub high_fee_threshold: u64,
}

impl Default for MempoolMemoryConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            pressure_threshold: 0.8, // 80%
            critical_threshold: 0.95, // 95%
            max_transactions: 100_000,
            max_single_transaction_size: 1024 * 1024, // 1 MB
            eviction_strategy: EvictionStrategy::SmartLRU,
            cleanup_interval_seconds: 60, // 1 minute
            max_transaction_age_seconds: 3600, // 1 heure
            high_fee_boost_factor: 2.0,
            high_fee_threshold: 10_000, // 10k sats
        }
    }
}

/// Strategies d'eviction disponibles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EvictionStrategy {
    /// LRU simple (Least Recently Used).
    LRU,
    
    /// LRU intelligent avec priority aux frais eleves.
    SmartLRU,
    
    /// Eviction basee sur le score de priority.
    PriorityBased,
    
    /// Eviction basee sur le ratio frais/taille.
    FeeRateBased,
}

/// Metadata d'une transaction dans le manager.
#[derive(Debug, Clone)]
struct TransactionMetadata {
    /// ID de la transaction.
    id: TransactionId,
    
    /// Taille en bytes.
    size: usize,
    
    /// Frais de la transaction.
    fee: u64,
    
    /// Timestamp d'ajout.
    added_at: Instant,
    
    /// Timestamp du dernier acces.
    last_accessed: Instant,
    
    /// Nombre d'acces.
    access_count: u64,
    
    /// Score de priority calcule.
    priority_score: f64,
}

impl TransactionMetadata {
    fn new(id: TransactionId, size: usize, fee: u64) -> Self {
        let now = Instant::now();
        Self {
            id,
            size,
            fee,
            added_at: now,
            last_accessed: now,
            access_count: 1,
            priority_score: 0.0,
        }
    }
    
    /// Calculer le score de priority.
    fn calculate_priority_score(&mut self, config: &MempoolMemoryConfig) -> f64 {
        let age_seconds = self.added_at.elapsed().as_secs() as f64;
        let fee_rate = self.fee as f64 / self.size as f64;
        
        // Score de base base sur le ratio frais/taille
        let mut score = fee_rate;
        
        // Boost pour les frais eleves
        if self.fee >= config.high_fee_threshold {
            score *= config.high_fee_boost_factor;
        }
        
        // Penalite pour l'age (transactions oldnes ont moins de priority)
        let age_penalty = 1.0 - (age_seconds / config.max_transaction_age_seconds as f64).min(1.0);
        score *= age_penalty.max(0.1); // Minimum 10% du score original
        
        // Bonus pour l'activity recente
        let access_bonus = (self.access_count as f64).ln().max(1.0);
        score *= access_bonus;
        
        self.priority_score = score;
        score
    }
    
    /// Marquer comme accede.
    fn mark_accessed(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }
    
    /// Check if la transaction est expiree.
    fn is_expired(&self, max_age: Duration) -> bool {
        self.added_at.elapsed() > max_age
    }
}

/// Statistiques de memory.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MemoryStats {
    /// Memory currentlement utilisee en bytes.
    pub current_memory_bytes: usize,
    
    /// Memory maximale autorisee.
    pub max_memory_bytes: usize,
    
    /// Pourcentage d'utilisation memory.
    pub memory_usage_percent: f64,
    
    /// Nombre de transactions currentles.
    pub current_transactions: usize,
    
    /// Nombre maximum de transactions.
    pub max_transactions: usize,
    
    /// Nombre total d'evictions.
    pub total_evictions: u64,
    
    /// Nombre d'evictions par pression memory.
    pub memory_pressure_evictions: u64,
    
    /// Nombre d'evictions par age.
    pub age_evictions: u64,
    
    /// Nombre d'evictions par priority faible.
    pub low_priority_evictions: u64,
    
    /// Taille moyenne des transactions.
    pub average_transaction_size: f64,
    
    /// Frais moyens.
    pub average_fee: f64,
    
    /// Derniere eviction.
    pub last_eviction_timestamp: u64,
}

/// Gestionnaire de memory du mempool.
pub struct MempoolMemoryManager {
    /// Configuration.
    config: MempoolMemoryConfig,
    
    /// Metadata des transactions.
    transactions: Arc<RwLock<HashMap<TransactionId, TransactionMetadata>>>,
    
    /// Index par priority (score -> transaction_id).
    priority_index: Arc<RwLock<BTreeMap<u64, TransactionId>>>,
    
    /// Queue LRU pour eviction.
    lru_queue: Arc<Mutex<VecDeque<TransactionId>>>,
    
    /// Statistiques.
    stats: Arc<RwLock<MemoryStats>>,
    
    /// Memory currentlement utilisee.
    current_memory: Arc<RwLock<usize>>,
}

impl MempoolMemoryManager {
    /// Create a nouveau manager de memory.
    pub fn new(config: MempoolMemoryConfig) -> Self {
        let stats = MemoryStats {
            max_memory_bytes: config.max_memory_bytes,
            max_transactions: config.max_transactions,
            ..Default::default()
        };
        
        Self {
            config,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            priority_index: Arc::new(RwLock::new(BTreeMap::new())),
            lru_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(stats)),
            current_memory: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Ajouter une transaction.
    pub async fn add_transaction(
        &self,
        tx_id: TransactionId,
        size: usize,
        fee: u64,
    ) -> Result<(), MempoolError> {
        // Verifications preliminaires
        if size > self.config.max_single_transaction_size {
            return Err(MempoolError::TransactionTooLarge);
        }
        
        // Check if on a besoin d'eviction
        let current_memory = *self.current_memory.read().await;
        let current_count = self.transactions.read().await.len();
        
        let would_exceed_memory = current_memory + size > self.config.max_memory_bytes;
        let would_exceed_count = current_count >= self.config.max_transactions;
        
        if would_exceed_memory || would_exceed_count {
            // Tenter l'eviction
            let evicted = self.evict_if_needed(size).await?;
            if evicted == 0 && (would_exceed_memory || would_exceed_count) {
                return Err(MempoolError::MemoryPressure);
            }
        }
        
        // Calculer le score de priority
        let mut metadata = TransactionMetadata::new(tx_id, size, fee);
        let priority_score = metadata.calculate_priority_score(&self.config);
        
        // Check if les frais sont suffisants en cas de pression memory
        if self.is_under_pressure().await {
            let min_fee_rate = self.calculate_minimum_fee_rate().await;
            let tx_fee_rate = fee as f64 / size as f64;
            
            if tx_fee_rate < min_fee_rate {
                return Err(MempoolError::InsufficientFeeRate);
            }
        }
        
        // Ajouter la transaction
        {
            let mut transactions = self.transactions.write().await;
            transactions.insert(tx_id, metadata);
        }
        
        // Mettre a jour l'index de priority
        {
            let mut priority_index = self.priority_index.write().await;
            let priority_key = (priority_score * 1_000_000.0) as u64;
            priority_index.insert(priority_key, tx_id);
        }
        
        // Ajouter a la queue LRU
        {
            let mut lru_queue = self.lru_queue.lock().await;
            lru_queue.push_back(tx_id);
        }
        
        // Mettre a jour la memory utilisee
        {
            let mut current_memory = self.current_memory.write().await;
            *current_memory += size;
        }
        
        debug!("Transaction addede au manager de memory: {} (size: {}, fee: {}, priority: {:.2})",
               hex::encode(&tx_id), size, fee, priority_score);
        
        Ok(())
    }
    
    /// Delete une transaction.
    pub async fn remove_transaction(&self, tx_id: &TransactionId) -> bool {
        let metadata = {
            let mut transactions = self.transactions.write().await;
            transactions.remove(tx_id)
        };
        
        if let Some(metadata) = metadata {
            // Delete de l'index de priority
            {
                let mut priority_index = self.priority_index.write().await;
                let priority_key = (metadata.priority_score * 1_000_000.0) as u64;
                priority_index.remove(&priority_key);
            }
            
            // Delete de la queue LRU
            {
                let mut lru_queue = self.lru_queue.lock().await;
                if let Some(pos) = lru_queue.iter().position(|id| id == tx_id) {
                    lru_queue.remove(pos);
                }
            }
            
            // Mettre a jour la memory utilisee
            {
                let mut current_memory = self.current_memory.write().await;
                *current_memory = current_memory.saturating_sub(metadata.size);
            }
            
            debug!("Transaction deletede du manager de memory: {}", hex::encode(tx_id));
            true
        } else {
            false
        }
    }
    
    /// Obtenir les transactions par ordre de priority.
    pub async fn get_transactions_by_priority(&self, limit: usize) -> Vec<TransactionId> {
        let priority_index = self.priority_index.read().await;
        
        priority_index
            .iter()
            .rev() // Plus haute priority en premier
            .take(limit)
            .map(|(_, tx_id)| *tx_id)
            .collect()
    }
    
    /// Marquer une transaction comme accedee.
    pub async fn mark_accessed(&self, tx_id: &TransactionId) {
        let mut transactions = self.transactions.write().await;
        if let Some(metadata) = transactions.get_mut(tx_id) {
            metadata.mark_accessed();
            
            // Recalculer le score de priority
            let new_score = metadata.calculate_priority_score(&self.config);
            
            // Mettre a jour l'index de priority
            drop(transactions);
            let mut priority_index = self.priority_index.write().await;
            let priority_key = (new_score * 1_000_000.0) as u64;
            priority_index.insert(priority_key, *tx_id);
        }
    }
    
    /// Check if le mempool est sous pression memory.
    async fn is_under_pressure(&self) -> bool {
        let current_memory = *self.current_memory.read().await;
        let usage_ratio = current_memory as f64 / self.config.max_memory_bytes as f64;
        usage_ratio >= self.config.pressure_threshold
    }
    
    /// Calculer le taux de frais minimum requis.
    async fn calculate_minimum_fee_rate(&self) -> f64 {
        let transactions = self.transactions.read().await;
        
        if transactions.is_empty() {
            return 0.0;
        }
        
        // Calculer la median des taux de frais
        let mut fee_rates: Vec<f64> = transactions
            .values()
            .map(|tx| tx.fee as f64 / tx.size as f64)
            .collect();
        
        fee_rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let median_index = fee_rates.len() / 2;
        fee_rates.get(median_index).copied().unwrap_or(0.0)
    }
    
    /// Eviction if needed.
    async fn evict_if_needed(&self, needed_space: usize) -> Result<usize, MempoolError> {
        let mut evicted_count = 0;
        let mut evicted_space = 0;
        
        // Eviction par age d'abord
        evicted_count += self.evict_expired().await;
        
        // Check if on a assez d'espace maintenant
        let current_memory = *self.current_memory.read().await;
        if current_memory + needed_space <= self.config.max_memory_bytes {
            return Ok(evicted_count);
        }
        
        // Eviction par strategie
        match self.config.eviction_strategy {
            EvictionStrategy::LRU => {
                evicted_count += self.evict_lru(needed_space - evicted_space).await;
            }
            EvictionStrategy::SmartLRU => {
                evicted_count += self.evict_smart_lru(needed_space - evicted_space).await;
            }
            EvictionStrategy::PriorityBased => {
                evicted_count += self.evict_low_priority(needed_space - evicted_space).await;
            }
            EvictionStrategy::FeeRateBased => {
                evicted_count += self.evict_low_fee_rate(needed_space - evicted_space).await;
            }
        }
        
        Ok(evicted_count)
    }
    
    /// Eviction des transactions expirees.
    async fn evict_expired(&self) -> usize {
        let max_age = Duration::from_secs(self.config.max_transaction_age_seconds);
        let mut to_evict = Vec::new();
        
        {
            let transactions = self.transactions.read().await;
            for (tx_id, metadata) in transactions.iter() {
                if metadata.is_expired(max_age) {
                    to_evict.push(*tx_id);
                }
            }
        }
        
        let evicted_count = to_evict.len();
        for tx_id in to_evict {
            self.remove_transaction(&tx_id).await;
        }
        
        if evicted_count > 0 {
            let mut stats = self.stats.write().await;
            stats.age_evictions += evicted_count as u64;
            stats.total_evictions += evicted_count as u64;
            stats.last_eviction_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            info!("Eviction par age: {} transactions deletedes", evicted_count);
        }
        
        evicted_count
    }
    
    /// Eviction LRU simple.
    async fn evict_lru(&self, needed_space: usize) -> usize {
        let mut evicted_count = 0;
        let mut freed_space = 0;
        
        while freed_space < needed_space {
            let tx_id = {
                let mut lru_queue = self.lru_queue.lock().await;
                lru_queue.pop_front()
            };
            
            if let Some(tx_id) = tx_id {
                let size = {
                    let transactions = self.transactions.read().await;
                    transactions.get(&tx_id).map(|m| m.size).unwrap_or(0)
                };
                
                if self.remove_transaction(&tx_id).await {
                    evicted_count += 1;
                    freed_space += size;
                }
            } else {
                break; // Plus de transactions a evincer
            }
        }
        
        if evicted_count > 0 {
            let mut stats = self.stats.write().await;
            stats.memory_pressure_evictions += evicted_count as u64;
            stats.total_evictions += evicted_count as u64;
            
            info!("Eviction LRU: {} transactions deletedes", evicted_count);
        }
        
        evicted_count
    }
    
    /// Eviction LRU intelligente (evite les transactions haute priority).
    async fn evict_smart_lru(&self, needed_space: usize) -> usize {
        let mut evicted_count = 0;
        let mut freed_space = 0;
        
        // Obtenir les transactions triees par priority (plus faible en premier)
        let low_priority_txs = {
            let priority_index = self.priority_index.read().await;
            priority_index
                .iter()
                .take(100) // Considerer les 100 plus faibles prioritys
                .map(|(_, tx_id)| *tx_id)
                .collect::<Vec<_>>()
        };
        
        for tx_id in low_priority_txs {
            if freed_space >= needed_space {
                break;
            }
            
            let size = {
                let transactions = self.transactions.read().await;
                transactions.get(&tx_id).map(|m| m.size).unwrap_or(0)
            };
            
            if self.remove_transaction(&tx_id).await {
                evicted_count += 1;
                freed_space += size;
            }
        }
        
        if evicted_count > 0 {
            let mut stats = self.stats.write().await;
            stats.low_priority_evictions += evicted_count as u64;
            stats.total_evictions += evicted_count as u64;
            
            info!("Eviction Smart LRU: {} transactions deletedes", evicted_count);
        }
        
        evicted_count
    }
    
    /// Eviction basee sur la priority.
    async fn evict_low_priority(&self, needed_space: usize) -> usize {
        // Similaire a smart_lru mais plus agressif
        self.evict_smart_lru(needed_space).await
    }
    
    /// Eviction basee sur le taux de frais.
    async fn evict_low_fee_rate(&self, needed_space: usize) -> usize {
        let mut candidates = Vec::new();
        
        {
            let transactions = self.transactions.read().await;
            for (tx_id, metadata) in transactions.iter() {
                let fee_rate = metadata.fee as f64 / metadata.size as f64;
                candidates.push((fee_rate, *tx_id, metadata.size));
            }
        }
        
        // Trier par taux de frais (plus faible en premier)
        candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        
        let mut evicted_count = 0;
        let mut freed_space = 0;
        
        for (_, tx_id, size) in candidates {
            if freed_space >= needed_space {
                break;
            }
            
            if self.remove_transaction(&tx_id).await {
                evicted_count += 1;
                freed_space += size;
            }
        }
        
        if evicted_count > 0 {
            let mut stats = self.stats.write().await;
            stats.low_priority_evictions += evicted_count as u64;
            stats.total_evictions += evicted_count as u64;
            
            info!("Eviction par taux de frais: {} transactions deletedes", evicted_count);
        }
        
        evicted_count
    }
    
    /// Nettoyage general.
    pub async fn cleanup(&self) -> Result<usize, MempoolError> {
        let mut total_cleaned = 0;
        
        // Nettoyage des transactions expirees
        total_cleaned += self.evict_expired().await;
        
        // Recalcul des scores de priority
        self.recalculate_priority_scores().await;
        
        // Mise a jour des statistiques
        self.update_stats().await;
        
        Ok(total_cleaned)
    }
    
    /// Recalculer tous les scores de priority.
    async fn recalculate_priority_scores(&self) {
        let mut updates = Vec::new();
        
        {
            let mut transactions = self.transactions.write().await;
            for (tx_id, metadata) in transactions.iter_mut() {
                let old_score = metadata.priority_score;
                let new_score = metadata.calculate_priority_score(&self.config);
                
                if (new_score - old_score).abs() > 0.01 {
                    updates.push((*tx_id, old_score, new_score));
                }
            }
        }
        
        // Mettre a jour l'index de priority
        if !updates.is_empty() {
            let mut priority_index = self.priority_index.write().await;
            
            for (tx_id, old_score, new_score) in updates {
                // Delete l'old score
                let old_key = (old_score * 1_000_000.0) as u64;
                priority_index.remove(&old_key);
                
                // Ajouter le nouveau score
                let new_key = (new_score * 1_000_000.0) as u64;
                priority_index.insert(new_key, tx_id);
            }
        }
    }
    
    /// Mettre a jour les statistiques.
    async fn update_stats(&self) {
        let current_memory = *self.current_memory.read().await;
        let transactions = self.transactions.read().await;
        
        let mut stats = self.stats.write().await;
        stats.current_memory_bytes = current_memory;
        stats.memory_usage_percent = (current_memory as f64 / stats.max_memory_bytes as f64) * 100.0;
        stats.current_transactions = transactions.len();
        
        if !transactions.is_empty() {
            let total_size: usize = transactions.values().map(|m| m.size).sum();
            let total_fee: u64 = transactions.values().map(|m| m.fee).sum();
            
            stats.average_transaction_size = total_size as f64 / transactions.len() as f64;
            stats.average_fee = total_fee as f64 / transactions.len() as f64;
        }
    }
    
    /// Obtenir les statistiques.
    pub async fn get_stats(&self) -> MemoryStats {
        self.update_stats().await;
        self.stats.read().await.clone()
    }
    
    /// Start the task de nettoyage automatique.
    pub async fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.cleanup_interval_seconds);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                if let Err(e) = manager.cleanup().await {
                    warn!("Erreur lors du nettoyage du manager de memory: {:?}", e);
                }
            }
        })
    }
}

// Implementation de Clone pour allowstre l'utilisation dans les tasks async
impl Clone for MempoolMemoryManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            transactions: Arc::clone(&self.transactions),
            priority_index: Arc::clone(&self.priority_index),
            lru_queue: Arc::clone(&self.lru_queue),
            stats: Arc::clone(&self.stats),
            current_memory: Arc::clone(&self.current_memory),
        }
    }
}

/// Erreurs du manager de memory.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("Transaction trop volumineuse")]
    TransactionTooLarge,
    
    #[error("Pression memory - impossible d'ajouter la transaction")]
    MemoryPressure,
    
    #[error("Taux de frais insuffisant pour la pression memory currentle")]
    InsufficientFeeRate,
    
    #[error("Erreur interne: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_manager_basic() {
        let config = MempoolMemoryConfig::default();
        let manager = MempoolMemoryManager::new(config);
        
        let tx_id = [1u8; 32];
        let result = manager.add_transaction(tx_id, 1000, 5000).await;
        assert!(result.is_ok());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.current_transactions, 1);
        assert_eq!(stats.current_memory_bytes, 1000);
    }
    
    #[tokio::test]
    async fn test_eviction_by_memory_pressure() {
        let mut config = MempoolMemoryConfig::default();
        config.max_memory_bytes = 2000; // Tres petit pour forcer l'eviction
        config.max_transactions = 10;
        
        let manager = MempoolMemoryManager::new(config);
        
        // Ajouter des transactions jusqu'a la limite
        for i in 0..3 {
            let tx_id = [i as u8; 32];
            let result = manager.add_transaction(tx_id, 1000, 1000 + i as u64).await;
            
            if i < 2 {
                assert!(result.is_ok());
            } else {
                // La troisieme devrait declencher une eviction ou be rejetee
                // selon la strategie d'eviction
            }
        }
        
        let stats = manager.get_stats().await;
        assert!(stats.current_memory_bytes <= 2000);
    }
    
    #[tokio::test]
    async fn test_priority_ordering() {
        let config = MempoolMemoryConfig::default();
        let manager = MempoolMemoryManager::new(config);
        
        // Ajouter des transactions avec differents frais
        let tx1 = [1u8; 32];
        let tx2 = [2u8; 32];
        let tx3 = [3u8; 32];
        
        manager.add_transaction(tx1, 1000, 1000).await.unwrap(); // Fee rate: 1.0
        manager.add_transaction(tx2, 1000, 2000).await.unwrap(); // Fee rate: 2.0
        manager.add_transaction(tx3, 1000, 500).await.unwrap();  // Fee rate: 0.5
        
        let priority_txs = manager.get_transactions_by_priority(3).await;
        
        // tx2 devrait be en premier (frais les plus eleves)
        assert_eq!(priority_txs[0], tx2);
    }
}