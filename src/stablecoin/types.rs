// ZST — TSN Gold Stable Protocol
// Types of data principaux

use serde::{Deserialize, Serialize};

/// Type d'actif dans le protocole ZST
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// Token natif TSN (collateral)
    TSN = 0,
    /// ZST Gold Stable (1 ZST = 1g XAU)
    ZST = 1,
    /// ZRS Reserve Share (absorbe la volatilite)
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

/// Prix soumis par un operateur d'oracle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OraclePrice {
    /// Prix de l'or en microdollars (ex: 2_300_000_000 = $2300.00)
    pub xau_usd: u64,
    /// Prix du TSN en microdollars (ex: 1_500_000 = $1.50)
    pub tsn_usd: u64,
    /// Unix timestamp de la soumission
    pub timestamp: u64,
    /// Hauteur du bloc de soumission
    pub block_height: u64,
    /// Key publique de l'operateur d'oracle
    pub oracle_id: [u8; 32],
    /// Signature ML-DSA-65
    pub signature: Vec<u8>,
}

/// Niveau de confiance du prix agrege
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceConfidence {
    /// >= 4 oracles, faible deviation
    High,
    /// 3 oracles ou deviation moderee
    Medium,
    /// Quorum minimum, deviation elevee
    Low,
    /// Prix expire
    Stale,
}

/// Prix agrege after median + TWAP
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedPrice {
    /// Combien de micro-TSN pour 1g d'or
    /// Ex: si 1 TSN = $1.50 et 1g or = $95, alors tsn_per_xau = 63_333_333 (~63.33 TSN)
    /// Stocke avec 6 decimales de precision (micro-unites)
    pub tsn_per_xau: u64,
    /// Timestamp du prix
    pub timestamp: u64,
    /// Nombre d'oracles ayant contribue
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

/// State global de la reserve du protocole ZST
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveState {
    /// Total TSN dans la reserve (en unites atomiques, 8 decimales)
    pub reserve_tsn: u128,
    /// Total ZST en circulation
    pub supply_zst: u128,
    /// Total ZRS en circulation
    pub supply_zrs: u128,
    /// Dernier prix agrege
    pub last_price: AggregatedPrice,
    /// Frais accumules pour la tresorerie
    pub treasury_tsn: u128,
    /// Hauteur du dernier bloc traite
    pub last_block_height: u64,
    /// Timestamp d'activation du circuit breaker (0 = inactif)
    pub circuit_breaker_activated: u64,
    /// Montant ZST brule dans le bloc courant (pour cooldown)
    pub current_block_burned_zst: u128,
    /// Hauteur du bloc courant pour le tracking cooldown
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
    /// Deposer TSN → recevoir ZST
    MintZST,
    /// Bruler ZST → retrieve TSN
    BurnZST,
    /// Deposer TSN → recevoir ZRS
    MintZRS,
    /// Bruler ZRS → retrieve TSN
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

/// Requete de mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnRequest {
    /// Action demandee
    pub action: StablecoinAction,
    /// Montant d'entree (en unites atomiques)
    pub amount_in: u128,
    /// Montant minimum de sortie (slippage protection)
    pub min_amount_out: u128,
    /// Hauteur du bloc du prix oracle utilise
    pub price_ref: u64,
}

/// Resultat d'une operation mint/burn
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintBurnResult {
    /// Action effectuee
    pub action: StablecoinAction,
    /// Montant d'entree consomme
    pub amount_in: u128,
    /// Montant de sortie produit
    pub amount_out: u128,
    /// Frais preleves (en TSN)
    pub fee: u128,
    /// Frais vers la tresorerie (20%)
    pub fee_treasury: u128,
    /// Frais vers la reserve (80%)
    pub fee_reserve: u128,
    /// Reserve ratio avant l'operation (en bps, ex: 40000 = 400%)
    pub ratio_before: u64,
    /// Reserve ratio after l'operation
    pub ratio_after: u64,
    /// Prix oracle utilise (TSN par XAU)
    pub price_used: u64,
}

/// Transaction stablecoin shielded (pour l'integration future)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedMintBurn {
    /// Action
    pub action: StablecoinAction,
    /// Nullifiers des notes detruites
    pub nullifiers_in: Vec<[u8; 32]>,
    /// Commitments des notes creees
    pub commitments_out: Vec<[u8; 32]>,
    /// Hauteur du bloc du prix oracle utilise
    pub price_ref_height: u64,
    /// Preuve Plonky3
    pub proof: Vec<u8>,
    /// Commitment des frais
    pub fee_commitment: [u8; 32],
}

/// Transaction stablecoin (extension du Transaction existant)
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
pub const MICRO_UNIT: u64 = 1_000_000; // Pour les prix en micro-unites
