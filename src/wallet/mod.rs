//! Wallet module for managing private funds.

mod wallet;
pub mod wallet_db;
pub mod service;

pub use wallet::{ShieldedWallet, WalletNote, WalletError, WalletTxRecord, WalletLock};
pub use wallet_db::WalletDb;
pub use service::WalletService;

// Legacy support
pub use wallet::LegacyWallet;
