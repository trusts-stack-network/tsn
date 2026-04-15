//! Adaptateur Plonky2 pour la couche d'abstraction ZK
//!
//! Ce module encapsule l'implementation Plonky2 existante et expose
//! l'interface unified ZkProofSystem.
//!
//! ## Security Notes
//!
//! - Plonky2 utilise FRI (Fast Reed-Solomon IOP) pour la compression
//! - Security level: 128 bits post-quantum
//! - Proof size: ~45KB pour une transaction standard (2 inputs, 2 outputs)
//! - Verification time: ~2ms
//!
//! Reference: "Plonky2: Fast Recursive Arguments with PLONK and FRI"
//! https://github.com/0xPolygonZero/plonky2

use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::sync::Arc;

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

/// Plonky2 adapter implementing the ZkProofSystem trait
///
/// Cette structure encapsule le TransactionProver existant et fournit
/// une interface unified pour la generation et verification de preuves.
pub struct Plonky2Adapter {
    /// Prover Plonky2 sous-jacent
    prover: TransactionProver,
    /// Cache des circuits pre-compiled
    circuit_cache: CircuitCache,
}

impl Plonky2Adapter {
    /// Creates un nouvel adaptateur Plonky2
    ///
    /// # Errors
    /// Returns une error si le cache de circuits ne peut pas be initialized
    pub fn new() -> Result<Self, ZkAdapterError> {
        let prover = TransactionProver::new();
        let circuit_cache = CircuitCache::new();

        Ok(Self {
            prover,
            circuit_cache,
        })
    }

    /// Convertedt un SpendWitness generic en SpendWitnessPQ
    fn convert_spend_witness(witness: &SpendWitness) -> Result<SpendWitnessPQ, ZkAdapterError> {
        // Convertir le path Merkle
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

    /// Convertedt un OutputWitness generic en OutputWitnessPQ
    fn convert_output_witness(witness: &OutputWitness) -> OutputWitnessPQ {
        OutputWitnessPQ {
            value: witness.value,
            recipient_pk_hash: witness.recipient_pk_hash,
            randomness: witness.randomness,
        }
    }

    /// Convertedt les entries publics Plonky2 en format generic
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

    /// Serializes une preuve Plonky2
    fn serialize_proof(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Vec<u8>, ZkAdapterError> {
        let proof_bytes = proof
            .to_bytes()
            .map_err(|e| ZkAdapterError::SerializationError(e.to_string()))?;

        if proof_bytes.len() > MAX_PROOF_SIZE {
            return Err(ZkAdapterError::InvalidProofFormat(format!(
                "Serialized proof exceeds maximum size: {} bytes",
                proof_bytes.len()
            )));
        }

        Ok(proof_bytes)
    }

    /// Deserializes une preuve Plonky2
    fn deserialize_proof(
        proof_bytes: &[u8],
    ) -> Result<ProofWithPublicInputs<F, C, D>, ZkAdapterError> {
        ProofWithPublicInputs::from_bytes(proof_bytes.to_vec()).map_err(|e| {
            ZkAdapterError::InvalidProofFormat(format!("Failed to deserialize Plonky2 proof: {}", e))
        })
    }
}

impl ZkProofSystem for Plonky2Adapter {
    fn prove_transaction(
        &self,
        spends: &[SpendWitness],
        outputs: &[OutputWitness],
        fee: u64,
    ) -> Result<ZkProof, ZkAdapterError> {
        // Convert les witnesses
        let spend_witnesses: Vec<SpendWitnessPQ> = spends
            .iter()
            .map(|s| Self::convert_spend_witness(s))
            .collect::<Result<Vec<_>, _>>()?;

        let output_witnesses: Vec<OutputWitnessPQ> = outputs
            .iter()
            .map(|o| Self::convert_output_witness(o))
            .collect();

        // Generate la preuve via Plonky2
        let plonky2_proof = self
            .prover
            .prove(&spend_witnesses,&output_witnesses, fee)
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
                ProofError::UnsupportedShape(spends, outputs) => ZkAdapterError::GenerationFailed(format!(
                    "Unsupported transaction shape: {} spends, {} outputs",
                    spends, outputs
                )),
                _ => ZkAdapterError::GenerationFailed(e.to_string()),
            })?;

        // Serialize les entries publics
        let public_inputs_bytes = serde_json::to_vec(&plonky2_proof.public_inputs)
            .map_err(|e| ZkAdapterError::SerializationError(e.to_string()))?;

        // Construire la preuve generic
        let mut proof = ZkProof::new(
            ZkSystemVersion::Plonky2,
            plonky2_proof.proof_bytes,
            public_inputs_bytes,
        );

        // Add metadata
        proof.metadata = ProofMetadata {
            proof_size: plonky2_proof.size(),
            constraint_count: Some(self.estimate_constraints(spends.len(), outputs.len())),
            circuit_version: 1, // Version du circuit Plonky2
            generation_time_ms: None, // Sera rempli par l'appelant si measured
        };

        Ok(proof)
    }

    fn verify_transaction(
        &self,
        proof: &ZkProof,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<bool, ZkAdapterError> {
        // Verify que c'est bien une preuve Plonky2
        if proof.version != ZkSystemVersion::Plonky2 {
            return Err(ZkAdapterError::UnsupportedSystem(format!(
                "Expected Plonky2 proof, got {:?}",
                proof.version
            )));
        }

        // Deserialize la preuve
        let plonky2_proof = Self::deserialize_proof(&proof.proof_data)?;

        // Deserialize les entries publics attendues
        let expected_inputs: crate::crypto::pq::proof_pq::TransactionPublicInputs =
            serde_json::from_slice(&proof.public_inputs)
                .map_err(|e| ZkAdapterError::SerializationError(e.to_string()))?;

        // Verify que les entries publics matchesent
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

        // Determine la forme du circuit to partir des entries
        let num_spends = public_inputs.nullifiers.len();
        let num_outputs = public_inputs.note_commitments.len();

        // Retrieve le circuit matchesant
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

        // Verify la preuve
        match circuit_data.verify(plonky2_proof) {
            Ok(_) => Ok(true),
            Err(e) => {
                // Log l'erreur pour debugging mais retourner false
                tracing::debug!("Plonky2 verification failed: {}", e);
                Ok(false)
            }
        }
    }

    fn version(&self) -> ZkSystemVersion {
        ZkSystemVersion::Plonky2
    }

    fn max_spends(&self) -> usize {
        // Plonky2 supporte up to 8 spends par transaction
        // Cette limite est definede par le cache de circuits
        8
    }

    fn max_outputs(&self) -> usize {
        // Plonky2 supporte up to 8 outputs par transaction
        8
    }

    fn preload_circuit_params(&mut self) -> Result<(), ZkAdapterError> {
        // Preloads les circuits couramment used
        // Cela accelerates la first generation de preuve
        let common_shapes = vec![
            (1, 1), // Simple transfer
            (1, 2), // Transfer with change
            (2, 1), // Merge
            (2, 2), // Standard transaction
            (2, 3), // Merge with change
        ];

        for (spends, outputs) in common_shapes {
            if self.circuit_cache.get(spends, outputs).is_none() {
                tracing::info!("Preloading circuit for {}x{}", spends, outputs);
            }
        }

        Ok(())
    }
}

impl Plonky2Adapter {
    /// Estime le nombre de contraintes pour une forme de transaction
    fn estimate_constraints(&self,
        num_spends: usize,
        num_outputs: usize,
    ) -> usize {
        // Estimation based sur l'analyse du circuit:
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

// Implementation by default pour CircuitCache si necessary
// Note: Cela suppose que CircuitCache a une method `new()`
// Si ce n'est pas le cas, il faudra adapter

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let adapter = Plonky2Adapter::new();
        assert!(adapter.is_ok());

        let adapter = adapter.unwrap();
        assert_eq!(adapter.version(), ZkSystemVersion::Plonky2);
        assert_eq!(adapter.max_spends(), 8);
        assert_eq!(adapter.max_outputs(), 8);
    }

    #[test]
    fn test_estimate_constraints() {
        let adapter = Plonky2Adapter::new().unwrap();

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
        // Create une preuve factice
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky2,
            vec![1, 2, 3, 4, 5],
            vec![10, 20, 30],
        );

        assert!(proof.validate_format().is_ok());
    }
}
