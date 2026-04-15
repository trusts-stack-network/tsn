// ZST — TSN Gold Stable Protocol
// Types of data principaux

use serde::{Deserialize, Serialize};

/// Type d'actif in the protocole ZST
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// Token natif TSN (collateral)
    TSN = 0,
    /// ZST Gold Stable (1 ZST = 1g XAU)
    ZST = 1,
    /// ZRS Reserve Share (absorbe the volatility)
    ZRS = 2,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::TSN => write!(f, "TSN"),
            AssetType::ZST => write!(f, "ZST"),
            AssetType::ZRS => write!(f, "ZRS"),
        }
    }
}

/// Prix soumis par a operator d'oracle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OraclePrice {
    /// Prix de l'or in microdollars (ex: 2_300_000_000 = $2300.00)
    pub xau_usd: u64,
    /// Prix of the TSN in microdollars (ex: 1_500_000 = $1.50)
    pub tsn_usd: u64,
    /// Unix timestamp de the soumission
    pub timestamp: u64,
    /// Height of the bloc de soumission
    pub block_height: u64,
    /// Key public de l'operator d'oracle
    pub oracle_id: [u8; 32],
    /// Signature ML-DSA-65
    pub signature: Vec<u8>,
}

/// Niveau de confiance of the prix aggregated
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceConfidence {
    /// >= 4 oracles, low deviation
    High,
    /// 3 oracles or moderate deviation
    Medium,
    /// Quorum minimum, deviation high
    Low,
    /// Prix expired
    Stale,
}

/// Prix aggregated after median + TWAP
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedPrice {
    /// Combien de micro-TSN for 1g d'or
    /// Ex: if 1 TSN = $1.50 and 1g or = $95, alors tsn_per_xau = 63_333_333 (~63.33 TSN)
    /// Stored with 6 decimals de precision (micro-units)
    pub tsn_per_xau: u64,
    /// Timestamp of the prix
    pub timestamp: u64,
    /// Number of contributing oracles
    pub oracle_count: u8,
    /// Niveau de confiance
    pub confidence: PriceConfidence,
}

impl Default for AggregatedPrice {
    fn default() -> Self {
        Self {
            tsn_per_xau: 0,
            timestamp: 0,
            oracle_count: 0,
            confidence: PriceConfidence::Stale,
        }
    }
}

/// State global de the reserve of the protocole ZST
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveState {
    /// Total TSN in the reserve (en units atomiques, 8 decimals)
    pub reserve_tsn: u128,
    /// Total ZST in circulation
    pub supply_zst: u128,
    /// Total ZRS in circulation
    pub supply_zrs: u128,
    /// Last prix aggregated
    pub last_price: AggregatedPrice,
    /// Frais accumulated for the treasury
    pub treasury_tsn: u128,
    /// Height of the last bloc processed
    pub last_block_height: u64,
    /// Timestamp d'activation of the circuit breaker (0 = inactif)
    pub circuit_breaker_activated: u64,
    /// ZST amount burned in the current block (for cooldown)
    pub current_block_burned_zst: u128,
    /// Height of the bloc courant for the tracking cooldown
    pub current_block_height: u64,
}

impl Default for ReserveState {
    fn default() -> Self {
        Self {
            reserve_tsn: 0,
            supply_zst: 0,
            supply_zrs: 0,
            last_price: AggregatedPrice::default(),
            treasury_tsn: 0,
            last_block_height: 0,
            circuit_breaker_activated: 0,
            current_block_burned_zst: 0,
            current_block_height: 0,
        }
    }
}

/// Action stablecoin possible
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StablecoinAction {
    /// Deposit TSN → recevoir ZST
    MintZST,
    /// Burn ZST → retrieve TSN
    BurnZST,
    /// Deposit TSN → recevoir ZRS
    MintZRS,
    /// Burn ZRS → retrieve TSN
    BurnZRS,
}

impl std::fmt::Display for StablecoinAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StablecoinAction::MintZST => write!(f, "MintZST"),
            StablecoinAction::BurnZST => write!(f, "BurnZST"),
            StablecoinAction::MintZRS => write!(f, "MintZRS"),
            StablecoinAction::BurnZRS => write!(f, "BurnZRS"),
        }
    }
}

/// Request de mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnRequest {
    /// Requested action
    pub action: StablecoinAction,
    /// Montant d'entry (en units atomiques)
    pub amount_in: u128,
    /// Montant minimum de sortie (slippage protection)
    pub min_amount_out: u128,
    /// Height of the bloc of the prix oracle used
    pub price_ref: u64,
}

/// Result d'une operation mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnResult {
    /// Action performed
    pub action: StablecoinAction,
    /// Montant d'entry consumed
    pub amount_in: u128,
    /// Montant de sortie produit
    pub amount_out: u128,
    /// Frais prhighs (en TSN)
    pub fee: u128,
    /// Frais to the treasury (20%)
    pub fee_treasury: u128,
    /// Frais to the reserve (80%)
    pub fee_reserve: u128,
    /// Reserve ratio before l'operation (en bps, ex: 40000 = 400%)
    pub ratio_before: u64,
    /// Reserve ratio after l'operation
    pub ratio_after: u64,
    /// Prix oracle used (TSN par XAU)
    pub price_used: u64,
}

/// Shielded stablecoin transaction (for future integration)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedMintBurn {
    /// Action
    pub action: StablecoinAction,
    /// Nullifiers of notes destroyed
    pub nullifiers_in: Vec<[u8; 32]>,
    /// Commitments of notes created
    pub commitments_out: Vec<[u8; 32]>,
    /// Height of the bloc of the prix oracle used
    pub price_ref_height: u64,
    /// Preuve Plonky3
    pub proof: Vec<u8>,
    /// Commitment of fees
    pub fee_commitment: [u8; 32],
}

/// Transaction stablecoin (extension of the Transaction existant)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StablecoinTx {
    /// Soumission de prix oracle
    OracleSubmit(OraclePrice),
    /// Mint transparent (phase 1-2)
    MintTransparent(MintBurnRequest),
    /// Burn transparent (phase 1-2)
    BurnTransparent(MintBurnRequest),
    /// Mint shielded (phase 3+)
    MintShielded(ShieldedMintBurn),
    /// Burn shielded (phase 3+)
    BurnShielded(ShieldedMintBurn),
}

/// Constantes de precision
pub const DECIMALS: u32 = 8;
pub const ATOMIC_UNIT: u128 = 100_000_000; // 10^8
pub const BPS_SCALE: u64 = 10_000; // 100% = 10000 bps
pub const MICRO_UNIT: u64 = 1_000_000; // Pour les prix en micro-units
