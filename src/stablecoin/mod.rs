// ZST — TSN Gold Stable Protocol
// Module principal du stablecoin indexe sur l'or
//
// 3 actifs: TSN (collateral) → ZST (stablecoin or) + ZRS (token de reserve)
// Modele Djed/Zephyr: surcollateralisation 150-400%, frais dynamiques, circuit breaker

pub mod config;
pub mod errors;
pub mod mint_burn;
pub mod oracle;
pub mod reserve;
pub mod types;

#[cfg(test)]
pub mod tests;

pub use config::StablecoinConfig;
pub use errors::StablecoinError;
pub use mint_burn::MintBurnManager;
pub use oracle::OracleManager;
pub use reserve::ReserveEngine;
pub use types::*;
