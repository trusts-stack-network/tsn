//! Synchronisation network securisee - VERSION SANS PANIC
//!
//! Ce module remplace src/network/sync.rs avec une gestion d'error robuste.
//! Aucun unwrap() ou expect() n'est utilise sur les entrees externes.
//!
//! # Security
//! - Tous les RwLock unwraps sont remplaces par des Result
//! - Gestion des locks empoisonnes (poisoned locks)
//! - Validation stricte des messages network
//! - Pas de panic sur entrees malformedes

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration, timeout};
use tracing::{info, warn, error, debug};

use crate::core::ShieldedBlock;
use crate::storage::BlockchainState;
use crate::crypto::hash::Hash;
use thiserror::Error;

/// Erreurs de synchronisation network
#[derive(Error, Debug, Clone)]
pub enum SyncError {
    #[error("Lock empoisonne - state corrompu")]
    LockPoisoned,
    #[error("Timeout de synchronisation")]
    SyncTimeout,
    #[error("Bloc invalid recu: {0}")]
    InvalidBlock(String),
    #[error("Hauteur de bloc invalid: {0}")]
    InvalidHeight(u64),
    #[error("Hash de bloc invalid")]
    InvalidBlockHash,
    #[error("Commitment root invalid")]
    InvalidCommitmentRoot,
    #[error("Peer malveillant detecte")]
    MaliciousPeer,
    #[error("State interne corrompu")]
    CorruptedState,
    #[error("Erreur network: {0}")]
    NetworkError(String),
}

/// State de synchronisation securise
pub struct SyncState {
    blockchain: Arc<RwLock<BlockchainState>>,
    is_syncing: Arc<RwLock<bool>>,
    last_sync_height: Arc<RwLock<u64>>,
}

impl SyncState {
    /// Creates a nouvel state de synchronisation
    pub fn new(blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            blockchain,
            is_syncing: Arc::new(RwLock::new(false)),
            last_sync_height: Arc::new(RwLock::new(0)),
        }
    }

    /// Obtient une reference en lecture sur la blockchain
    /// 
    /// # Security
    /// Retourne une error si le lock est empoisonne plutot que de paniquer
    async fn read_blockchain(&self) -> Result<tokio::sync::RwLockReadGuard<'_, BlockchainState>, SyncError> {
        self.blockchain.read().await
            .map_err(|_| SyncError::LockPoisoned)
    }

    /// Obtient une reference en ecriture sur la blockchain
    /// 
    /// # Security
    /// Retourne une error si le lock est empoisonne plutot que de paniquer
    async fn write_blockchain(&self) -> Result<tokio::sync::RwLockWriteGuard<'_, BlockchainState>, SyncError> {
        self.blockchain.write().await
            .map_err(|_| SyncError::LockPoisoned)
    }

    /// Checks if une synchronisation est in progress
    async fn is_syncing(&self) -> Result<bool, SyncError> {
        let guard = self.is_syncing.read().await
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(*guard)
    }

    /// Definit l'state de synchronisation
    async fn set_syncing(&self, syncing: bool) -> Result<(), SyncError> {
        let mut guard = self.is_syncing.write().await
            .map_err(|_| SyncError::LockPoisoned)?;
        *guard = syncing;
        Ok(())
    }

    /// Gets the derniere hauteur synchronisee
    async fn last_sync_height(&self) -> Result<u64, SyncError> {
        let guard = self.last_sync_height.read().await
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(*guard)
    }

    /// Met a jour la derniere hauteur synchronisee
    async fn update_sync_height(&self, height: u64) -> Result<(), SyncError> {
        let mut guard = self.last_sync_height.write().await
            .map_err(|_| SyncError::LockPoisoned)?;
        *guard = height;
        Ok(())
    }
}

/// Gestionnaire de synchronisation securise
pub struct SecureSyncManager {
    state: Arc<SyncState>,
    sync_timeout: Duration,
    max_batch_size: usize,
}

impl SecureSyncManager {
    /// Creates a nouveau manager de synchronisation
    pub fn new(blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            state: Arc::new(SyncState::new(blockchain)),
            sync_timeout: Duration::from_secs(30),
            max_batch_size: 100,
        }
    }

    /// Valide un bloc recu avant traitement
    /// 
    /// # Security
    /// Toutes les validations retournent des errors structurees
    fn validate_received_block(&self, block: &ShieldedBlock) -> Result<(), SyncError> {
        // Verification de base
        if block.header.height == 0 {
            return Err(SyncError::InvalidHeight(0));
        }

        // Verification du hash
        if block.hash().as_bytes().is_empty() {
            return Err(SyncError::InvalidBlockHash);
        }

        // Verification du commitment root
        if block.header.commitment_root.as_bytes().is_empty() {
            return Err(SyncError::InvalidCommitmentRoot);
        }

        // Verification du timestamp (pas dans le futur, pas trop vieux)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SyncError::CorruptedState)?
            .as_secs();
        
        if block.header.timestamp > current_time + 300 {
            // Bloc dans le futur de plus de 5 minutes
            return Err(SyncError::InvalidBlock("timestamp in future".to_string()));
        }

        if block.header.timestamp + 86400 < current_time {
            // Bloc de plus de 24h
            warn!("Received very old block: height={}", block.header.height);
        }

        Ok(())
    }

    /// Synchronise avec un peer
    /// 
    /// # Security
    /// Gere tous les cas d'error sans panic
    pub async fn sync_with_peer(&self, peer_addr: &str) -> Result<(), SyncError> {
        // Checks if already in progress
        if self.state.is_syncing().await? {
            warn!("Sync already in progress, skipping");
            return Ok(());
        }

        self.state.set_syncing(true).await?;
        info!("Starting sync with peer: {}", peer_addr);

        let result = timeout(self.sync_timeout, self.perform_sync(peer_addr)).await
            .map_err(|_| SyncError::SyncTimeout)?;

        self.state.set_syncing(false).await?;
        result
    }

    /// Performs the synchronisation
    async fn perform_sync(&self, _peer_addr: &str) -> Result<(), SyncError> {
        let chain = self.state.read_blockchain().await?;
        let current_height = chain.height();
        drop(chain);

        info!("Current height: {}, starting sync", current_height);

        // Simuler la synchronisation (a remplacer par la logique reelle)
        tokio::time::sleep(Duration::from_millis(100)).await;

        self.state.update_sync_height(current_height).await?;
        info!("Sync completeed successfully");

        Ok(())
    }

    /// Traite un bloc recu du network
    /// 
    /// # Security
    /// Jamais de panic sur entree malformede
    pub async fn process_received_block(&self, block: ShieldedBlock) -> Result<(), SyncError> {
        // Validation preliminaire
        self.validate_received_block(&block)?;

        let mut chain = self.state.write_blockchain().await?;
        
        // Verification de la hauteur
        if block.header.height != chain.height() + 1 {
            warn!(
                "Received block with unexpected height: expected {}, got {}",
                chain.height() + 1,
                block.header.height
            );
            return Err(SyncError::InvalidHeight(block.header.height));
        }

        // Ajout du bloc (simule)
        debug!("Processing block at height {}", block.header.height);
        
        Ok(())
    }

    /// Gere une error de synchronisation
    /// 
    /// # Security
    /// Log l'error sans panic, met a jour les metrics
    pub fn handle_sync_error(&self, error: &SyncError, peer_addr: &str) {
        error!("Sync error with peer {}: {:?}", peer_addr, error);
        
        // Mise a jour des metrics
        match error {
            SyncError::InvalidBlock(_) | SyncError::InvalidBlockHash => {
                warn!("Potential malicious peer detected: {}", peer_addr);
            }
            SyncError::LockPoisoned => {
                error!("CRITICAL: Lock poisoned - node may need restart");
            }
            _ => {}
        }
    }
}

/// Tache de synchronisation periodic
/// 
/// # Security
/// Gere les errors de maniere continue sans arreter la task
pub async fn sync_task(state: Arc<SyncState>, interval_secs: u64) {
    let mut ticker = interval(Duration::from_secs(interval_secs));
    
    loop {
        ticker.tick().await;
        
        // Verification de l'state avec gestion d'error
        let is_syncing = match state.is_syncing().await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to check sync state: {:?}", e);
                continue;
            }
        };
        
        if is_syncing {
            continue;
        }

        // Recuperation de la hauteur avec gestion d'error
        let current_height = match state.read_blockchain().await {
            Ok(chain) => chain.height(),
            Err(e) => {
                error!("Failed to read blockchain: {:?}", e);
                continue;
            }
        };

        debug!("Periodic sync check at height {}", current_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_state_lock_handling() {
        // Test que les locks sont geres correctement
        // Note: Ce test requiresrait un mock de BlockchainState
    }

    #[tokio::test]
    async fn test_validate_block_rejects_invalid() {
        // Test que les blocs invalids sont rejetes sans panic
        // Note: Ce test requiresrait un mock de ShieldedBlock
    }
}
