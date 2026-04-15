// ZST — TSN Gold Stable Protocol
// Module principal of the stablecoin indexed sur l'or
//
// 3 assets: TSN (collateral) → ZST (gold stablecoin) + ZRS (reserve token)
// Model Djed/Zephyr: surcollateralisation 150-400%, fees dynamiques, circuit breaker

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
