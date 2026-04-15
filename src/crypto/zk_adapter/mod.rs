//! Couche d'adaptation ZK pour TSN - Migration Plonky2 → Plonky3
//!
//! Ce module fournit une abstraction unified sur les systems de preuve ZK,
//! allowstant une migration progressive de Plonky2 vers Plonky3.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Application TSN                 │
//! ├─────────────────────────────────────────┤
//! │    ZkProofSystem (trait commun)         │
//! ├─────────────────────────────────────────┤
//! │  Plonky2Adapter    │  Plonky3Adapter    │
//! ├─────────────────────────────────────────┤
//! │  plonky2::plonk    │  p3-uni-stark/AIR  │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Feature Flags
//!
//! - `zk-plonky2` : Active le backend Plonky2 (legacy, stable)
//! - `zk-plonky3` : Active le backend Plonky3 (default, AIR-based)
//! - `zk-compat` : Active les deux backends avec selection runtime
//!
//! ## Security Considerations
//!
//! - Les preuves Plonky2 utilisent FRI (post-quantique, hash-based)
//! - Les preuves Plonky3 utilisent FRI + AIR (post-quantique, Poseidon2 natif)
//! - Les deux fournissent ~128 bits de security post-quantique
//!
//! References:
//! - Plonky2: https://github.com/0xPolygonZero/plonky2
//! - Plonky3: https://github.com/Plonky3/Plonky3

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Version du system de preuve used
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ZkSystemVersion {
    /// Plonky2 STARKs - system legacy, post-quantique pur
    Plonky2,
    /// Plonky3 AIR - system actuel, FRI + Poseidon2 natif sur Goldilocks
    Plonky3,
}

impl ZkSystemVersion {
    /// Retourne l'identifiant de version pour la serialization
    pub fn as_u8(&self) -> u8 {
        match self {
            ZkSystemVersion::Plonky2 => 1,
            ZkSystemVersion::Plonky3 => 3,
        }
    }

    /// Parse l'identifiant de version
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ZkSystemVersion::Plonky2),
            3 => Some(ZkSystemVersion::Plonky3),
            _ => None,
        }
    }
}

/// Erreurs du system de preuve ZK
#[derive(Debug, Error)]
pub enum ZkAdapterError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Unsupported proof system: {0}")]
    UnsupportedSystem(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Balance mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    BalanceMismatch { inputs: u64, outputs: u64, fee: u64 },
}

/// Preuve ZK generic independsante du backend
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    /// Version du system de preuve
    pub version: ZkSystemVersion,
    /// Data de la preuve (format specific au backend)
    #[serde(with = "hex_serde")]
    pub proof_data: Vec<u8>,
    /// Entries publics serializedes
    #[serde(with = "hex_serde")]
    pub public_inputs: Vec<u8>,
    /// Metadata additionnelles (taille, timestamp, etc.)
    pub metadata: ProofMetadata,
}

/// Metadata d'une preuve
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Taille de la preuve en bytes
    pub proof_size: usize,
    /// Nombre de contraintes dans le circuit
    pub constraint_count: Option<usize>,
    /// Temps de generation en ms (si measured)
    pub generation_time_ms: Option<u64>,
    /// Version du circuit
    pub circuit_version: u32,
}

impl ZkProof {
    /// Creates une new preuve
    pub fn new(
        version: ZkSystemVersion,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Self {
        let proof_size = proof_data.len();
        Self {
            version,
            proof_data,
            public_inputs,
            metadata: ProofMetadata {
                proof_size,
                ..Default::default()
            },
        }
    }

    /// Retourne la taille totale de la preuve
    pub fn size(&self) -> usize {
        self.proof_data.len() + self.public_inputs.len()
    }

    /// Verifies que la preuve est du format attendu
    pub fn validate_format(&self) -> Result<(), ZkAdapterError> {
        if self.proof_data.is_empty() {
            return Err(ZkAdapterError::InvalidProofFormat(
                "Empty proof data".to_string(),
            ));
        }
        if self.proof_data.len() > MAX_PROOF_SIZE {
            return Err(ZkAdapterError::InvalidProofFormat(format!(
                "Proof too large: {} bytes (max: {})",
                self.proof_data.len(),
                MAX_PROOF_SIZE
            )));
        }
        Ok(())
    }
}

/// Taille maximale d'une preuve (protection DoS)
pub const MAX_PROOF_SIZE: usize = 500 * 1024; // 500 KB

/// Entries publics d'une transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    /// Racines Merkle (une par spend)
    pub merkle_roots: Vec<[u8; 32]>,
    /// Nullifiers (un par spend)
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments des notes (un par output)
    pub note_commitments: Vec<[u8; 32]>,
    /// Frais de transaction
    pub fee: u64,
}

/// Witness pour le spending d'une note
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendWitness {
    /// Valeur de la note (private)
    pub value: u64,
    /// Hash de la key public du destinataire (private)
    pub recipient_pk_hash: [u8; 32],
    /// Randomness de la note (private)
    #[zeroize(skip)]
    pub randomness: [u8; 32],
    /// Key de nullification (private)
    #[zeroize(skip)]
    pub nullifier_key: [u8; 32],
    /// Position dans l'arbre de commitments
    pub position: u64,
    /// Witness Merkle (path + racine)
    pub merkle_path: Vec<[u8; 32]>,
    /// Index de la feuille
    pub leaf_index: usize,
}

/// Witness pour la creation d'une output
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct OutputWitness {
    /// Valeur de la note
    pub value: u64,
    /// Hash de la key publique du destinataire
    pub recipient_pk_hash: [u8; 32],
    /// Randomness pour le commitment
    #[zeroize(skip)]
    pub randomness: [u8; 32],
}

/// Trait principal pour les systems de preuve ZK
///
/// Ce trait defines l'interface commune entre Plonky2 et Plonky3.
/// Les implementations doivent garantir:
/// - La soundness: une preuve invalid ne passe pas la verification
/// - La completeness: une preuve valid passe toujours
/// - La zero-knowledge: pas de fuite d'information
pub trait ZkProofSystem: Send + Sync {
    /// Generates une preuve de transaction
    ///
    /// # Arguments
    /// * `spends` - Witnesses pour les notes spentes
    /// * `outputs` - Witnesses pour les notes created
    /// * `fee` - Frais de transaction
    ///
    /// # Security
    /// - Les witnesses sont zeroized after usage
    /// - Utilise OsRng pour la randomness
    fn prove_transaction(
        &self,
        spends: &[SpendWitness],
        outputs: &[OutputWitness],
        fee: u64,
    ) -> Result<ZkProof, ZkAdapterError>;

    /// Verifies une preuve de transaction
    ///
    /// # Arguments
    /// * `proof` - La preuve to verify
    /// * `public_inputs` - Les entries publics
    fn verify_transaction(
        &self,
        proof: &ZkProof,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<bool, ZkAdapterError>;

    /// Retourne la version du system
    fn version(&self) -> ZkSystemVersion;

    /// Returns le nombre maximum de spends supported
    fn max_spends(&self) -> usize;

    /// Returns le nombre maximum d'outputs supported
    fn max_outputs(&self) -> usize;

    /// Preloads les parameters du circuit (optimisation)
    fn preload_circuit_params(&mut self) -> Result<(), ZkAdapterError>;
}

/// Factory pour create le system de preuve appropriate
pub struct ZkSystemFactory;

impl ZkSystemFactory {
    /// Creates le system de preuve by default (Plonky3)
    pub fn create_default() -> Result<Box<dyn ZkProofSystem>, ZkAdapterError> {
        Ok(Box::new(plonky3_adapter::Plonky3Adapter::new()?))
    }

    /// Creates un system de preuve specific
    pub fn create(version: ZkSystemVersion) -> Result<Box<dyn ZkProofSystem>, ZkAdapterError> {
        match version {
            ZkSystemVersion::Plonky2 => {
                Ok(Box::new(plonky2_adapter::Plonky2Adapter::new()?))
            }
            ZkSystemVersion::Plonky3 => {
                Ok(Box::new(plonky3_adapter::Plonky3Adapter::new()?))
            }
        }
    }
}

// Backend modules
pub mod plonky2_adapter;
pub mod plonky3_adapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_serialization() {
        assert_eq!(ZkSystemVersion::Plonky2.as_u8(), 1);
        assert_eq!(ZkSystemVersion::Plonky3.as_u8(), 3);
        assert_eq!(ZkSystemVersion::from_u8(1), Some(ZkSystemVersion::Plonky2));
        assert_eq!(ZkSystemVersion::from_u8(3), Some(ZkSystemVersion::Plonky3));
        assert_eq!(ZkSystemVersion::from_u8(2), None); // Halo2 removed
        assert_eq!(ZkSystemVersion::from_u8(99), None);
    }

    #[test]
    fn test_proof_validation() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![1, 2, 3],
            vec![4, 5],
        );
        assert!(proof.validate_format().is_ok());
        assert_eq!(proof.size(), 5);
    }

    #[test]
    fn test_proof_empty_validation() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![],
            vec![],
        );
        assert!(proof.validate_format().is_err());
    }

    #[test]
    fn test_proof_oversized() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![0u8; MAX_PROOF_SIZE + 1],
            vec![],
        );
        assert!(proof.validate_format().is_err());
    }
}

// Helper pour la serialization hex
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
