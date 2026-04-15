// ZST — Configuration of the protocole

use serde::{Deserialize, Serialize};

/// Configuration completee of the protocole stablecoin ZST
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StablecoinConfig {
    // === Reserve Ratios (en bps: 10000 = 100%) ===
    /// Ratio minimum for autoriser the mint ZST (15000 = 150%)
    pub min_reserve_ratio: u64,
    /// Ratio cible of the protocole (40000 = 400%)
    pub target_reserve_ratio: u64,
    /// Ratio max for autoriser the mint ZRS (80000 = 800%)
    pub max_reserve_ratio_mint_zrs: u64,
    /// Ratio minimum for autoriser the burn ZRS (20000 = 200%)
    pub min_reserve_ratio_burn_zrs: u64,

    // === Frais (en bps: 100 = 1%) ===
    /// Frais mint ZST (30 = 0.30%)
    pub fee_mint_zst_bps: u64,
    /// Frais burn ZST normal (30 = 0.30%)
    pub fee_burn_zst_bps: u64,
    /// Frais mint ZRS (30 = 0.30%)
    pub fee_mint_zrs_bps: u64,
    /// Frais burn ZRS (50 = 0.50%)
    pub fee_burn_zrs_bps: u64,
    /// Frais de stress maximum (500 = 5.00%)
    pub fee_stress_max_bps: u64,

    // === Oracle ===
    /// Quorum minimum d'oracles
    pub oracle_quorum: u8,
    /// Maximum oracle price age (in seconds)
    pub oracle_max_age_secs: u64,
    /// Deviation maximum inter-oracle (en bps)
    pub oracle_max_deviation_bps: u64,
    /// Circuit breaker oracle: variation max in 1h (en bps)
    pub oracle_circuit_breaker_bps: u64,

    // === Anti-Bank-Run ===
    /// Max % of the supply ZST burnable par bloc (en bps: 500 = 5%)
    pub cooldown_max_burn_pct: u64,
    /// Ratio triggersur of the circuit breaker (12000 = 120%)
    pub circuit_breaker_ratio: u64,
    /// Duration of the circuit breaker in secondes (86400 = 24h)
    pub circuit_breaker_duration: u64,

    // === Activation ===
    /// Height d'activation of the module stablecoin
    pub activation_height: u64,
    /// Decimals for ZST (8, like TSN)
    pub zst_decimals: u8,

    // === Distribution of fees ===
    /// Part of fees to the reserve (en bps: 8000 = 80%)
    pub fee_to_reserve_bps: u64,
    /// Part of fees to the treasury (en bps: 2000 = 20%)
    pub fee_to_treasury_bps: u64,

    // === TWAP ===
    /// Number of blocks for TWAP
    pub twap_blocks: u64,
}

impl Default for StablecoinConfig {
    fn default() -> Self {
        Self {
            min_reserve_ratio: 15_000,
            target_reserve_ratio: 40_000,
            max_reserve_ratio_mint_zrs: 80_000,
            min_reserve_ratio_burn_zrs: 20_000,

            fee_mint_zst_bps: 30,
            fee_burn_zst_bps: 30,
            fee_mint_zrs_bps: 30,
            fee_burn_zrs_bps: 50,
            fee_stress_max_bps: 500,

            oracle_quorum: 3,
            oracle_max_age_secs: 1800,
            oracle_max_deviation_bps: 1000,
            oracle_circuit_breaker_bps: 2500,

            cooldown_max_burn_pct: 500,
            circuit_breaker_ratio: 12_000,
            circuit_breaker_duration: 86_400,

            activation_height: 0,
            zst_decimals: 8,

            fee_to_reserve_bps: 8000,
            fee_to_treasury_bps: 2000,

            twap_blocks: 10,
        }
    }
}

impl StablecoinConfig {
    /// Configuration for the tests (quorum reduces, etc.)
    pub fn testnet() -> Self {
        Self {
            oracle_quorum: 1,
            oracle_max_age_secs: 3600,
            activation_height: 0,
            ..Default::default()
        }
    }
}
