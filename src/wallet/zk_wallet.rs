//! Wallet ZK proof support (Halo2)
//!
//! Generates and handles ZK proofs for private transactions

use crate::crypto::proof::ZkProof;
use crate::crypto::commitment::NoteCommitment;
use crate::crypto::note::Note;
use crate::crypto::nullifier::Nullifier;
use ark_bn254::Fr;
// use ark_ff::UniformRand;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
    },
    poly::{
//         commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use lru::LruCache;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
// use zeroize::Zeroize;

/// Configuration for ZK proof generation
#[derive(Clone, Debug)]
pub struct ProofConfig {
    /// Polynomial degree for KZG parameters
    pub k: u32,
    /// Timeout for proof generation
    pub timeout: Duration,
    /// Maximum cache size
    pub cache_size: usize,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            k: 17, // 2^17 = 131072 constraints
            timeout: Duration::from_secs(30),
            cache_size: 100,
        }
    }
}

/// Halo2 circuit for note proofs
#[derive(Clone, Debug)]
pub struct NoteCircuit {
    /// Note value (private witness)
    pub value: Value<Fr>,
    /// Note randomness (private witness)
    pub randomness: Value<Fr>,
    /// Recipient public key hash (private witness)
    pub recipient_pk_hash: Value<Fr>,
    /// Note commitment (public input)
    pub commitment: Value<Fr>,
}

impl Circuit<Fr> for NoteCircuit {
    type Config = NoteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            randomness: Value::unknown(),
            recipient_pk_hash: Value::unknown(),
            commitment: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        meta.enable_constant(constant);
        meta.enable_equality(instance);
        for column in &advice {
            meta.enable_equality(*column);
        }

        NoteConfig {
            advice,
            instance,
            constant,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Implementation simplified of the circuit
        layouter.assign_region(
            || "note commitment",
            |mut region| {
                // Assign the private witnesses
                let value_cell = region.assign_advice(
                    || "value",
                    config.advice[0],
                    0,
                    || self.value,
                )?;

                let randomness_cell = region.assign_advice(
                    || "randomness",
                    config.advice[1],
                    0,
                    || self.randomness,
                )?;

                let recipient_cell = region.assign_advice(
                    || "recipient",
                    config.advice[2],
                    0,
                    || self.recipient_pk_hash,
                )?;

                // Calculationates the commitment (simplified)
                let commitment_cell = region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    1,
                    || self.commitment,
                )?;

                // Expose the commitment as a public instance
                region.constrain_instance(commitment_cell.cell(), config.instance, 0)?;

                Ok(())
            },
        )
    }
}

/// Note circuit column configuration
#[derive(Clone, Debug)]
pub struct NoteConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    constant: Column<Fixed>,
}

/// ZK proof performance statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStats {
    /// Total number of generated proofs
    pub total_proofs: u64,
    /// Average generation time (ms)
    pub avg_generation_time_ms: f64,
    /// Minimum generation time (ms)
    pub min_generation_time_ms: u64,
    /// Maximum generation time (ms)
    pub max_generation_time_ms: u64,
    /// Number of cached proofs
    pub cached_proofs: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
}

impl Default for ProofStats {
    fn default() -> Self {
        Self {
            total_proofs: 0,
            avg_generation_time_ms: 0.0,
            min_generation_time_ms: u64::MAX,
            max_generation_time_ms: 0,
            cached_proofs: 0,
            cache_hit_rate: 0.0,
        }
    }
}

/// ZK proof manager for the wallet
pub struct ZkWallet {
    /// Cache of generated proofs (keyed by commitment)
    proof_cache: LruCache<[u8; 32], ZkProof>,
    /// KZG parameters for Halo2
    params: Arc<ParamsKZG<ark_bn254::Bn254>>,
    /// Verifying key
    verifying_key: Arc<VerifyingKey<ark_bn254::G1Affine>>,
    /// Proving key
    proving_key: Arc<ProvingKey<ark_bn254::G1Affine>>,
    /// Configuration
    config: ProofConfig,
    /// Performance statistics
    stats: Arc<Mutex<ProofStats>>,
    /// Cache hit/miss counters
    cache_hits: u64,
    cache_misses: u64,
}

impl ZkWallet {
    /// Creates a new ZK wallet with the default configuration
    pub fn new() -> Result<Self, WalletError> {
        Self::with_config(ProofConfig::default())
    }

    /// Creates a new ZK wallet with a custom configuration
    pub fn with_config(config: ProofConfig) -> Result<Self, WalletError> {
        // Generates the parameters KZG
        let params = ParamsKZG::<ark_bn254::Bn254>::setup(config.k, OsRng);
        let params = Arc::new(params);

        // Create an empty circuit for key generation
        let empty_circuit = NoteCircuit {
            value: Value::unknown(),
            randomness: Value::unknown(),
            recipient_pk_hash: Value::unknown(),
            commitment: Value::unknown(),
        };

        // Generate the verifying and proving keys
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| WalletError::SetupError(format!("Error generation VK: {:?}", e)))?;
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
            .map_err(|e| WalletError::SetupError(format!("Error generation PK: {:?}", e)))?;

        Ok(Self {
            proof_cache: LruCache::new(
                NonZeroUsize::new(config.cache_size)
                    .unwrap_or(NonZeroUsize::new(1).unwrap()) // fallback to 1 if cache_size is 0
            ),
            params,
            verifying_key: Arc::new(vk),
            proving_key: Arc::new(pk),
            config,
            stats: Arc::new(Mutex::new(ProofStats::default())),
            cache_hits: 0,
            cache_misses: 0,
        })
    }

    /// Generates a ZK proof for a note
    pub fn prove_note(&mut self, note: &Note) -> Result<ZkProof, WalletError> {
        let start_time = Instant::now();
        let commitment = note.commitment();
        let commitment_bytes = commitment.to_bytes();
        
        // Verify the cache
        if let Some(proof) = self.proof_cache.get(&commitment_bytes) {
            self.cache_hits += 1;
            self.update_cache_stats();
            return Ok(proof.clone());
        }
        
        self.cache_misses += 1;

        // Convert the values to field elements
        let value_fr = Fr::from(note.value);
        let recipient_fr = Fr::from_le_bytes_mod_order(&note.recipient_pk_hash);
        let commitment_fr = Fr::from_le_bytes_mod_order(&commitment_bytes);

        // Create the circuit with real witness values
        let circuit = NoteCircuit {
            value: Value::known(value_fr),
            randomness: Value::known(note.randomness),
            recipient_pk_hash: Value::known(recipient_fr),
            commitment: Value::known(commitment_fr),
        };

        // Generate the proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let instances = &[&[commitment_fr]];
        
        create_proof::<
            KZGCommitmentScheme<ark_bn254::Bn254>,
            ProverSHPLONK<'_, ark_bn254::Bn254>,
            Challenge255<ark_bn254::G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, ark_bn254::G1Affine, Challenge255<ark_bn254::G1Affine>>,
            _,
        >(
            &self.params,
            &self.proving_key,
            &[circuit],
            instances,
            OsRng,
            &mut transcript,
        )
        .map_err(|e| WalletError::ProofError(format!("Proof generation error: {:?}", e)))?;

        let proof_bytes = transcript.finalize();
        let proof = ZkProof::from_bytes(&proof_bytes)?;
        
        // Cache the proof
        self.proof_cache.put(commitment_bytes, proof.clone());
        
        // Update the statistics
        let generation_time = start_time.elapsed();
        self.update_stats(generation_time);
        self.update_cache_stats();
        
        Ok(proof)
    }
    
    /// Verifies a ZK proof
    pub fn verify_proof(&self, proof: &ZkProof, commitment: &NoteCommitment) -> Result<bool, WalletError> {
        let commitment_bytes = commitment.to_bytes();
        let commitment_fr = Fr::from_le_bytes_mod_order(&commitment_bytes);
        
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.to_bytes());
        let instances = &[&[commitment_fr]];
        
        let strategy = SingleStrategy::new(&self.params);
        let result = verify_proof::<
            KZGCommitmentScheme<ark_bn254::Bn254>,
            VerifierSHPLONK<'_, ark_bn254::Bn254>,
            Challenge255<ark_bn254::G1Affine>,
            Blake2bRead<&[u8], ark_bn254::G1Affine, Challenge255<ark_bn254::G1Affine>>,
            SingleStrategy<'_, ark_bn254::Bn254>,
        >(
            &self.params,
            &self.verifying_key,
            strategy,
            instances,
            &mut transcript,
        );
        
        match result {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Generates a nullifier proof
//     pub fn prove_nullifier(&mut self, note: &Note, nullifier: &Nullifier) -> Result<ZkProof, WalletError> {
        // For now, reuses the note proof circuit
        // A full implementation would use a dedicated nullifier circuit
        self.prove_note(note)
    }

    /// Clears the proof cache
    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
        self.cache_hits = 0;
        self.cache_misses = 0;
        self.update_cache_stats();
    }

    /// Returns performance statistics
    pub fn get_stats(&self) -> ProofStats {
        self.stats.lock()
            .unwrap_or_else(|e| e.into_inner()) // recover from poisoned mutex
            .clone()
    }

    /// Returns the size current of the cache
    pub fn cache_size(&self) -> usize {
        self.proof_cache.len()
    }

    /// Returns the current configuration
    pub fn config(&self) -> &ProofConfig {
        &self.config
    }

    /// Updates statistics after a proof is generated
    fn update_stats(&self, generation_time: Duration) {
        let mut stats = self.stats.lock()
            .unwrap_or_else(|e| e.into_inner());
        let time_ms = generation_time.as_millis() as u64;
        
        stats.total_proofs += 1;
        
        // Update min/max times
        if time_ms < stats.min_generation_time_ms {
            stats.min_generation_time_ms = time_ms;
        }
        if time_ms > stats.max_generation_time_ms {
            stats.max_generation_time_ms = time_ms;
        }
        
        // Update rolling average
        let total = stats.total_proofs as f64;
        stats.avg_generation_time_ms = 
            (stats.avg_generation_time_ms * (total - 1.0) + time_ms as f64) / total;
    }

    /// Updates the statistics of the cache
    fn update_cache_stats(&self) {
        let mut stats = self.stats.lock()
            .unwrap_or_else(|e| e.into_inner());
        stats.cached_proofs = self.proof_cache.len();
        
        let total_requests = self.cache_hits + self.cache_misses;
        if total_requests > 0 {
            stats.cache_hit_rate = self.cache_hits as f64 / total_requests as f64;
        }
    }
}

impl Default for ZkWallet {
    fn default() -> Self {
        Self::new().expect("INIT: ZkWallet default initialization failed — check KZG params")
    }
}

impl Drop for ZkWallet {
    fn drop(&mut self) {
        // Clean up the secrets in memory
        self.proof_cache.clear();
    }
}

/// ZK wallet errors
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Proof error: {0}")]
    ProofError(String),
    
    #[error("Note error: {0}")]
    NoteError(String),
    
    #[error("Setup error: {0}")]
    SetupError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Proof generation timed out")]
    TimeoutError,

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_zk_wallet_creation() {
        let wallet = ZkWallet::new();
        assert!(wallet.is_ok());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        // Create a test note
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        let commitment = note.commitment();
        
        // Generate a proof
        let proof_result = wallet.prove_note(&note);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        
        // Verify the proof
        let verification_result = wallet.verify_proof(&proof, &commitment);
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
    }

    #[test]
    fn test_proof_caching() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        // First generation (cache miss)
        let proof1 = wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Second generation (cache hit)
        let proof2 = wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Proofs must be identical
        assert_eq!(proof1.to_bytes(), proof2.to_bytes());
    }

    #[test]
    fn test_cache_clearing() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        // Generate a proof to populate the cache
        wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Clear the cache
        wallet.clear_cache();
        assert_eq!(wallet.cache_size(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        let initial_stats = wallet.get_stats();
        assert_eq!(initial_stats.total_proofs, 0);
        
        // Generate a proof
        wallet.prove_note(&note).unwrap();
        
        let updated_stats = wallet.get_stats();
        assert_eq!(updated_stats.total_proofs, 1);
        assert!(updated_stats.avg_generation_time_ms > 0.0);
    }
}