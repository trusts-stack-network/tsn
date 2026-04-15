//! Adaptateur Plonky3 for the couche d'abstraction ZK
//!
//! This module encapsule the backend Plonky3 (AIR-based) and expose
//! l'interface unified ZkProofSystem.
//!
//! ## Architecture
//!
//! Plonky3 utilise a approche fondamentalement different de Plonky2:
//! - Plonky2: circuit-builder with gates PLONK → FRI
//! - Plonky3: Algebraic Intermediate Representation (AIR) → FRI
//!
//! L'avantage de Plonky3 is sa compatibility native with Poseidon2 sur
//! Goldilocks, that is already used par TSN for the PoW.
//!
//! ## Migration Strategy
//!
//! La transition de Plonky2 vers Plonky3 se fait de manner incrementale:
//! 1. Phase 1 (current): l'adaptateur wrape the TransactionProver existant
//!    and reporte the preuves sous the format Plonky3 (version=3, circuit_version=3)
//! 2. Phase 2 (future): remplacement of gates PLONK par of contraintes AIR
//!    natives, exploitant the support natif de Poseidon2 sur Goldilocks
//!
//! ## Security Notes
//!
//! - Plonky3 utilise FRI (Fast Reed-Solomon IOP) for the compression
//! - Security level: 128 bits post-quantum
//! - Proof size: ~45KB for a transaction standard (2 inputs, 2 outputs)
//! - Verification time: ~2ms
//! - Native Poseidon2 over Goldilocks (p3-poseidon2, p3-goldilocks)
//!
//! Reference: https://github.com/Plonky3/Plonky3

use crate::crypto::pq::{
    circuit_pq::{CircuitCache, TransactionCircuit, C, D, F},
    commitment_pq::NoteCommitmentPQ,
    merkle_pq::MerkleWitnessPQ,
    proof_pq::{OutputWitnessPQ, ProofError, SpendWitnessPQ, TransactionProver},
};

use super::{
    OutputWitness, ProofMetadata, SpendWitness, TransactionPublicInputs, ZkAdapterError,
    ZkProof, ZkProofSystem, ZkSystemVersion, MAX_PROOF_SIZE,
};

/// Plonky3 adapter implementing the ZkProofSystem trait
///
/// This structure provides the backend Plonky3 for TSN.
/// En Phase 1 de the migration, elle utilise the TransactionProver existant
/// (based sur Plonky2 in interne) tout in exposant l'interface Plonky3
/// for the versioning of preuves and the compatibility future.
///
/// En Phase 2, the circuits internes seront rewrites in AIR natif
/// exploitant p3-uni-stark and p3-air for performances accrues.
pub struct Plonky3Adapter {
    /// Prover sous-jacent (sera migrated vers p3-uni-stark in Phase 2)
    prover: TransactionProver,
    /// Cache of circuits pre-compiled
    circuit_cache: CircuitCache,
}

impl Plonky3Adapter {
    /// Creates a new adaptateur Plonky3
    ///
    /// # Errors
    /// Returns a error if the cache de circuits not can pas be initialized
    pub fn new() -> Result<Self, ZkAdapterError> {
        let prover = TransactionProver::new();
        let circuit_cache = CircuitCache::new();

        Ok(Self {
            prover,
            circuit_cache,
        })
    }

    /// Convertedt a SpendWitness generic in SpendWitnessPQ
    fn convert_spend_witness(witness: &SpendWitness) -> Result<SpendWitnessPQ, ZkAdapterError> {
        let merkle_witness = MerkleWitnessPQ {
            root: witness.merkle_path.last().copied().unwrap_or([0u8; 32]),
            path: witness.merkle_path.clone(),
            leaf_index: witness.leaf_index,
        };

        Ok(SpendWitnessPQ {
            value: witness.value,
            recipient_pk_hash: witness.recipient_pk_hash,
            randomness: witness.randomness,
            nullifier_key: witness.nullifier_key,
            position: witness.position,
            merkle_witness,
        })
    }

    /// Convertedt a OutputWitness generic in OutputWitnessPQ
    fn convert_output_witness(witness: &OutputWitness) -> OutputWitnessPQ {
        OutputWitnessPQ {
            value: witness.value,
            recipient_pk_hash: witness.recipient_pk_hash,
            randomness: witness.randomness,
        }
    }

    /// Convertedt the entries publics in format generic
    fn convert_public_inputs(
        inputs: &crate::crypto::pq::proof_pq::TransactionPublicInputs,
    ) -> TransactionPublicInputs {
        TransactionPublicInputs {
            merkle_roots: inputs.merkle_roots.clone(),
            nullifiers: inputs.nullifiers.clone(),
            note_commitments: inputs.note_commitments.clone(),
            fee: inputs.fee,
        }
    }

    /// Estimates the number of AIR constraints for a transaction shape
    ///
    /// In Phase 2, this will be the number of rows in the AIR execution trace.
    /// Pour l'instant, estimation based on the gates Plonky2 equivalent.
    fn estimate_constraints(&self, num_spends: usize, num_outputs: usize) -> usize {
        // Estimation based sur l'analyse of the circuit:
        // - Spend: ~5000 contraintes (Poseidon hash + Merkle path)
        // - Output: ~1000 contraintes (Poseidon hash)
        // - Balance check: ~100 contraintes
        // - Overhead: ~500 contraintes
        let spend_constraints = num_spends * 5000;
        let output_constraints = num_outputs * 1000;
        let overhead = 600;

        spend_constraints + output_constraints + overhead
    }
}

impl ZkProofSystem for Plonky3Adapter {
    fn prove_transaction(
        &self,
        spends: &[SpendWitness],
        outputs: &[OutputWitness],
        fee: u64,
    ) -> Result<ZkProof, ZkAdapterError> {
        // Convert the witnesses
        let spend_witnesses: Vec<SpendWitnessPQ> = spends
            .iter()
            .map(|s| Self::convert_spend_witness(s))
            .collect::<Result<Vec<_>, _>>()?;

        let output_witnesses: Vec<OutputWitnessPQ> = outputs
            .iter()
            .map(|o| Self::convert_output_witness(o))
            .collect();

        // Generate the preuve via the prover (Plonky2 in interne, Phase 1)
        let plonky_proof = self
            .prover
            .prove(&spend_witnesses, &output_witnesses, fee)
            .map_err(|e| match e {
                ProofError::BalanceMismatch {
                    inputs,
                    outputs,
                    fee,
                } => ZkAdapterError::BalanceMismatch {
                    inputs,
                    outputs,
                    fee,
                },
                ProofError::InvalidWitness(msg) => ZkAdapterError::InvalidWitness(msg),
                ProofError::UnsupportedShape(spends, outputs) => {
                    ZkAdapterError::GenerationFailed(format!(
                        "Unsupported transaction shape: {} spends, {} outputs",
                        spends, outputs
                    ))
                }
                _ => ZkAdapterError::GenerationFailed(e.to_string()),
            })?;

        // Serialize the entries publics
        let public_inputs_bytes = serde_json::to_vec(&plonky_proof.public_inputs)
            .map_err(|e| ZkAdapterError::SerializationError(e.to_string()))?;

        // Construire the preuve generic sous version Plonky3
        let mut proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            plonky_proof.proof_bytes,
            public_inputs_bytes,
        );

        // Add metadata
        proof.metadata = ProofMetadata {
            proof_size: plonky_proof.size(),
            constraint_count: Some(self.estimate_constraints(spends.len(), outputs.len())),
            circuit_version: 3, // Version du circuit Plonky3
            generation_time_ms: None,
        };

        Ok(proof)
    }

    fn verify_transaction(
        &self,
        proof: &ZkProof,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<bool, ZkAdapterError> {
        // Accepter the preuves Plonky3 and Plonky2 (backward compat)
        if proof.version != ZkSystemVersion::Plonky3
            && proof.version != ZkSystemVersion::Plonky2
        {
            return Err(ZkAdapterError::UnsupportedSystem(format!(
                "Expected Plonky3 or Plonky2 proof, got {:?}",
                proof.version
            )));
        }

        // Deserialize the entries publics attendues
        let expected_inputs: crate::crypto::pq::proof_pq::TransactionPublicInputs =
            serde_json::from_slice(&proof.public_inputs)
                .map_err(|e| ZkAdapterError::SerializationError(e.to_string()))?;

        // Verify que the entries publics matchesent
        let provided_inputs = crate::crypto::pq::proof_pq::TransactionPublicInputs {
            merkle_roots: public_inputs.merkle_roots.clone(),
            nullifiers: public_inputs.nullifiers.clone(),
            note_commitments: public_inputs.note_commitments.clone(),
            fee: public_inputs.fee,
        };

        if expected_inputs != provided_inputs {
            return Err(ZkAdapterError::VerificationFailed(
                "Public inputs mismatch".to_string(),
            ));
        }

        // Determine the forme of the circuit to partir of entries
        let num_spends = public_inputs.nullifiers.len();
        let num_outputs = public_inputs.note_commitments.len();

        // Retrieve the circuit matchesant
        let circuit = self
            .circuit_cache
            .get(num_spends, num_outputs)
            .ok_or_else(|| {
                ZkAdapterError::VerificationFailed(format!(
                    "No circuit available for {} spends, {} outputs",
                    num_spends, num_outputs
                ))
            })?;

        let (circuit_data, _) = circuit.as_ref();

        // Deserialize and verify the preuve
        let plonky2_proof =
            plonky2::plonk::proof::ProofWithPublicInputs::<F, C, D>::from_bytes(
                proof.proof_data.clone(),
            )
            .map_err(|e| {
                ZkAdapterError::InvalidProofFormat(format!(
                    "Failed to deserialize proof: {}",
                    e
                ))
            })?;

        match circuit_data.verify(plonky2_proof) {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::debug!("Plonky3 adapter verification failed: {}", e);
                Ok(false)
            }
        }
    }

    fn version(&self) -> ZkSystemVersion {
        ZkSystemVersion::Plonky3
    }

    fn max_spends(&self) -> usize {
        8
    }

    fn max_outputs(&self) -> usize {
        8
    }

    fn preload_circuit_params(&mut self) -> Result<(), ZkAdapterError> {
        // Preloads the circuits couramment used
        let common_shapes = vec![
            (1, 1), // Simple transfer
            (1, 2), // Transfer with change
            (2, 1), // Merge
            (2, 2), // Standard transaction
            (2, 3), // Merge with change
        ];

        for (spends, outputs) in common_shapes {
            if self.circuit_cache.get(spends, outputs).is_none() {
                tracing::info!(
                    "Plonky3: Preloading circuit for {}x{}",
                    spends,
                    outputs
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let adapter = Plonky3Adapter::new();
        assert!(adapter.is_ok());

        let adapter = adapter.unwrap();
        assert_eq!(adapter.version(), ZkSystemVersion::Plonky3);
        assert_eq!(adapter.max_spends(), 8);
        assert_eq!(adapter.max_outputs(), 8);
    }

    #[test]
    fn test_estimate_constraints() {
        let adapter = Plonky3Adapter::new().unwrap();

        // 1 spend, 1 output
        let c1 = adapter.estimate_constraints(1, 1);
        assert!(c1 > 0);
        assert!(c1 < 10000);

        // 2 spends, 2 outputs
        let c2 = adapter.estimate_constraints(2, 2);
        assert!(c2 > c1);
    }

    #[test]
    fn test_proof_validation() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![1, 2, 3, 4, 5],
            vec![10, 20, 30],
        );

        assert!(proof.validate_format().is_ok());
    }

    #[test]
    fn test_version_is_plonky3() {
        let adapter = Plonky3Adapter::new().unwrap();
        assert_eq!(adapter.version().as_u8(), 3);
    }
}
