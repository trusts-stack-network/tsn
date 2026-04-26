//! Wallet service wrapper for thread-safe wallet access.
//!
//! Provides `Arc<Mutex<ShieldedWallet>>` to coordinate access between
//! the mining loop, API endpoints, and CLI commands.

use std::sync::Arc;
use tokio::sync::Mutex;

use super::wallet::{ShieldedWallet, WalletError, WalletTxRecord};
use crate::core::ShieldedBlock;

/// Thread-safe wallet service for use across the node.
pub struct WalletService {
    pub wallet: Arc<Mutex<ShieldedWallet>>,
}

impl WalletService {
    /// Create a new wallet service from an opened wallet.
    pub fn new(wallet: ShieldedWallet) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(wallet)),
        }
    }

    /// Get the wallet's public key hash.
    pub async fn pk_hash(&self) -> [u8; 32] {
        let w = self.wallet.lock().await;
        w.pk_hash()
    }

    /// Get the raw ML-DSA-65 public key bytes (1952 bytes).
    /// Used by relays to produce endorsement records where the pk_hash
    /// must be derivable from the full public key.
    pub async fn public_key_bytes(&self) -> Vec<u8> {
        let w = self.wallet.lock().await;
        w.keypair().public_key_bytes().to_vec()
    }

    /// Sign an arbitrary message with the wallet's ML-DSA-65 secret key.
    /// Used by relays to endorse a block header hash (v2.5.3 relay pool).
    pub async fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        let w = self.wallet.lock().await;
        crate::crypto::signature::sign(message, w.keypair()).as_bytes().to_vec()
    }

    /// Get the wallet's address as hex string.
    pub async fn address_hex(&self) -> String {
        let w = self.wallet.lock().await;
        w.address().to_hex()
    }

    /// Get the current balance (sum of unspent notes).
    pub async fn balance(&self) -> u64 {
        let w = self.wallet.lock().await;
        w.balance()
    }

    /// Get the number of unspent notes.
    pub async fn unspent_count(&self) -> usize {
        let w = self.wallet.lock().await;
        w.unspent_count()
    }

    /// Get the last scanned block height.
    pub async fn last_scanned_height(&self) -> u64 {
        let w = self.wallet.lock().await;
        w.last_scanned_height()
    }

    /// Scan a block for incoming notes. Returns the number of new notes found.
    pub async fn scan_block(&self, block: &ShieldedBlock, start_position: u64) -> Result<usize, WalletError> {
        let mut w = self.wallet.lock().await;
        let new_notes = w.scan_block(block, start_position);
        if new_notes > 0 {
            w.save("").ok(); // Save triggers persist_to_db if SQLite is available
        }
        Ok(new_notes)
    }

    /// Get transaction history.
    pub async fn tx_history(&self, limit: usize) -> Vec<WalletTxRecord> {
        let w = self.wallet.lock().await;
        w.tx_history().iter().rev().take(limit).cloned().collect()
    }

    /// Clear all notes and reset scan height (rescan).
    pub async fn clear_notes(&self) -> Result<(), WalletError> {
        let mut w = self.wallet.lock().await;
        w.clear_notes();
        w.save("").ok();
        Ok(())
    }

    /// Get the viewing key for this wallet.
    pub async fn viewing_key(&self) -> crate::crypto::note::ViewingKey {
        let w = self.wallet.lock().await;
        w.viewing_key().clone()
    }

    /// Flush the database (WAL checkpoint) for graceful shutdown.
    pub async fn flush(&self) -> Result<(), WalletError> {
        let w = self.wallet.lock().await;
        w.flush_db()
    }

    /// Get a clone of the inner Arc for sharing across tasks.
    pub fn inner(&self) -> Arc<Mutex<ShieldedWallet>> {
        self.wallet.clone()
    }
}
