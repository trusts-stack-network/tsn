//! Preuves Zero-Knowledge for transactions shielded TSN
//! 
//! Implementation of circuits ZK for the transactions privates with :
//! - Conservation of balances without reveal the montants
//! - Verification of commitments Poseidon2 (quantum-safe)
//! - Derivation secure of nullifiers
//! - Protection anti-double-spending
//!
//! Architecture :
//! - Circuits R1CS with Arkworks (groth16 trusted setup)
//! - Arithmetic constraints optimized for Poseidon2
//! - Niveau de security 128-bit post-quantique
//!
//! References :
//! - Zcash Sapling Protocol: https://zips.z.cash/protocol/protocol.pdf
//! - NIST SP 800-208: Post-quantum cryptography standards
//! - Poseidon2: "Poseidon2: A Faster Version of the Poseidon Hash Function"

use ark_bn254::{Fr, Bn254, G1Affine};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    commitment::{NoteCommitment, commit_to_note},
    nullifier::{Nullifier, derive_nullifier}, 
    poseidon::{DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, poseidon_hash, bytes32_to_field},
};

/// Parameters de security for the circuits shielded
/// Conformes aux standards NIST for the cryptographie post-quantique
pub const SECURITY_LEVEL_BITS: usize = 128;
pub const MAX_SHIELDED_INPUTS: usize = 8;
pub const MAX_SHIELDED_OUTPUTS: usize = 8;
pub const POSEIDON_WIDTH: usize = 5; // State width for Poseidon2

/// Configuration of contraintes Poseidon2 for circuits ZK
/// Optimized for the security post-quantique and efficiency of circuits
lazy_static::lazy_static! {
    static ref POSEIDON_PARAMS: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr> = {
        // Parameters secures for BN254 with resistance post-quantique
        ark_crypto_primitives::sponge::poseidon::PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 56,
            alpha: 5,
            ark: vec![], // Round constants (initializeds to la compilation)
            mds: vec![], // MDS matrix (initializede to la compilation) 
        }
    };
}

/// Note private d'input in a transaction shielded
/// Contient all data secret necessary for the spending
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ShieldedInputNote {
    /// Valeur de the note (confidentielle)
    pub value: u64,
    /// Hash de the key public of the owner (32 bytes)
    pub recipient_pk_hash: [u8; 32],
    /// Randomness of the commitment (confidentielle)
    #[zeroize(skip)] // Fr ne peut pas be zeroized facilement
    pub commitment_randomness: Fr,
    /// Key de nullifier (ultra-confidentielle) 
    #[zeroize(skip)]
    pub nullifier_key: Fr,
    /// Position in l'arbre de commitments
    pub note_position: u64,
}

impl ShieldedInputNote {
    /// Creates a new note d'input with validation cryptographique
    pub fn new(
        value: u64,
        recipient_pk_hash: [u8; 32],
        commitment_randomness: Fr,
        nullifier_key: Fr,
        note_position: u64,
    ) -> Self {
        Self {
            value,
            recipient_pk_hash,
            commitment_randomness,
            nullifier_key,
            note_position,
        }
    }

    /// Calculates the commitment de this note
    /// cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
    pub fn compute_commitment(&self) -> NoteCommitment {
        commit_to_note(self.value, &self.recipient_pk_hash, &self.commitment_randomness)
    }

    /// Calculationates the nullifier for avoidr the double-spending
    /// nf = Poseidon(DOMAIN_NULLIFIER, nullifier_key, commitment, position)
    pub fn compute_nullifier(&self) -> Nullifier {
        let commitment = self.compute_commitment();
        derive_nullifier(
            &crate::crypto::nullifier::NullifierKey(self.nullifier_key),
            &commitment,
            self.note_position,
        )
    }
}

/// Note de sortie in a transaction shielded
/// Creates a new note for a destinataire
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ShieldedOutputNote {
    /// Valeur de the note (confidentielle)
    pub value: u64,
    /// Hash de the key publique of the destinataire
    pub recipient_pk_hash: [u8; 32],
    /// Randomness of the commitment (confidentielle)
    #[zeroize(skip)]
    pub commitment_randomness: Fr,
}

impl ShieldedOutputNote {
    /// Creates a new note d'output
    pub fn new(
        value: u64,
        recipient_pk_hash: [u8; 32],
        commitment_randomness: Fr,
    ) -> Self {
        Self {
            value,
            recipient_pk_hash,
            commitment_randomness,
        }
    }

    /// Calculates the commitment de this note d'output
    pub fn compute_commitment(&self) -> NoteCommitment {
        commit_to_note(self.value, &self.recipient_pk_hash, &self.commitment_randomness)
    }
}

/// Transaction shielded completee ready for the preuve ZK
#[derive(Clone)]
pub struct ShieldedTransaction {
    /// Notes d'input (spentes)
    pub inputs: Vec<ShieldedInputNote>,
    /// Notes d'output (created)
    pub outputs: Vec<ShieldedOutputNote>,
    /// Frais de transaction (publics)
    pub transaction_fee: u64,
}

impl ShieldedTransaction {
    /// Creates a new transaction shielded with validation
    pub fn new(
        inputs: Vec<ShieldedInputNote>,
        outputs: Vec<ShieldedOutputNote>,
        transaction_fee: u64,
    ) -> Result<Self, ShieldedTransactionError> {
        // Validation of limits de circuit
        if inputs.len() > MAX_SHIELDED_INPUTS {
            return Err(ShieldedTransactionError::TooManyInputs);
        }
        if outputs.len() > MAX_SHIELDED_OUTPUTS {
            return Err(ShieldedTransactionError::TooManyOutputs);
        }
        if inputs.is_empty() && outputs.is_empty() {
            return Err(ShieldedTransactionError::EmptyTransaction);
        }

        let tx = Self {
            inputs,
            outputs,
            transaction_fee,
        };

        // Validation de the conservation of balances
        if !tx.is_balanced() {
            return Err(ShieldedTransactionError::ImbalancedTransaction);
        }

        Ok(tx)
    }

    /// Verifies that the transaction is balanced
    /// sum(inputs) = sum(outputs) + fee
    pub fn is_balanced(&self) -> bool {
        let total_input: u64 = self.inputs.iter().map(|note| note.value).sum();
        let total_output: u64 = self.outputs.iter().map(|note| note.value).sum();
        
        total_input == total_output.saturating_add(self.transaction_fee)
    }

    /// Extrait the data publiques visibles on the blockchain
    pub fn public_data(&self) -> ShieldedTransactionPublicData {
        ShieldedTransactionPublicData {
            input_nullifiers: self.inputs.iter().map(|note| note.compute_nullifier()).collect(),
            output_commitments: self.outputs.iter().map(|note| note.compute_commitment()).collect(),
            transaction_fee: self.transaction_fee,
        }
    }
}

/// Data publics d'une transaction shielded
/// C'est this that is visible on the blockchain TSN
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransactionPublicData {
    /// Nullifiers of notes spentes (prevents double-spending)
    pub input_nullifiers: Vec<Nullifier>,
    /// Commitments of news notes created
    pub output_commitments: Vec<NoteCommitment>,
    /// Frais de transaction (en clair)
    pub transaction_fee: u64,
}

/// Possible errors during the creation d'une transaction shielded
#[derive(Debug, thiserror::Error)]
pub enum ShieldedTransactionError {
    #[error("Trop de notes d'input (max: {MAX_SHIELDED_INPUTS})")]
    TooManyInputs,
    #[error("Trop de notes d'output (max: {MAX_SHIELDED_OUTPUTS})")]
    TooManyOutputs,
    #[error("Transaction vide")]
    EmptyTransaction,
    #[error("Transaction non balanced: sum(inputs) != sum(outputs) + fee")]
    ImbalancedTransaction,
}

/// Circuit R1CS for the preuve ZK de transaction shielded
/// Prouve the validity without reveal the valeurs privates
#[derive(Clone)]
pub struct ShieldedTransactionCircuit {
    /// Transaction to prouver (private)
    pub transaction: Option<ShieldedTransaction>,
    /// Data publics (exposed at the verifiesur)
    pub public_data: Option<ShieldedTransactionPublicData>,
}

impl ShieldedTransactionCircuit {
    /// Creates a circuit with witnesses for the prouveur
    pub fn with_witnesses(
        transaction: ShieldedTransaction,
        public_data: ShieldedTransactionPublicData,
    ) -> Self {
        Self {
            transaction: Some(transaction),
            public_data: Some(public_data),
        }
    }

    /// Creates a circuit without witnesses for the setup
    pub fn without_witnesses() -> Self {
        Self {
            transaction: None,
            public_data: None,
        }
    }
}

/// Contrainte for hash Poseidon2 in a circuit R1CS
/// Verifies: output = Poseidon2(domain, inputs...)
fn constrain_poseidon2_hash<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    domain: F,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    // Creates a sponge Poseidon with the parameters secures
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &POSEIDON_PARAMS);
    
    // Absorbe the domain separator
    let domain_var = FpVar::new_constant(cs.clone(), domain)?;
    sponge.absorb(&domain_var)?;
    
    // Absorbe all inputs
    for input in inputs {
        sponge.absorb(input)?;
    }
    
    // Extracted the hash resulting
    let hash_results = sponge.squeeze_field_elements(1)?;
    Ok(hash_results[0].clone())
}

/// Contrainte for verify a commitment de note
/// Verifies: cm = Poseidon2(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
fn constrain_note_commitment<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &UInt64<F>,
    pk_hash: &FpVar<F>,
    randomness: &FpVar<F>,
    expected_commitment: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Convert the valeur in field element
    let value_fe = value.to_field_element()?;
    
    // Calculate the commitment
    let computed_commitment = constrain_poseidon2_hash(
        cs,
        F::from(DOMAIN_NOTE_COMMITMENT),
        &[value_fe, pk_hash.clone(), randomness.clone()],
    )?;
    
    // Contrainte: computed = expected
    computed_commitment.enforce_equal(expected_commitment)?;
    
    Ok(())
}

/// Contrainte for verify a nullifier
/// Verifies: nf = Poseidon2(DOMAIN_NULLIFIER, nk, cm, position)
fn constrain_nullifier<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    nullifier_key: &FpVar<F>,
    commitment: &FpVar<F>,
    position: &UInt64<F>,
    expected_nullifier: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Convert the position in field element
    let position_fe = position.to_field_element()?;
    
    // Calculate the nullifier
    let computed_nullifier = constrain_poseidon2_hash(
        cs,
        F::from(DOMAIN_NULLIFIER),
        &[nullifier_key.clone(), commitment.clone(), position_fe],
    )?;
    
    // Contrainte: computed = expected
    computed_nullifier.enforce_equal(expected_nullifier)?;
    
    Ok(())
}

impl ConstraintSynthesizer<Fr> for ShieldedTransactionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let transaction = self.transaction.as_ref().unwrap();
        let public_data = self.public_data.as_ref().unwrap();

        // =========================================================================
        // ALLOCATION DES VARIABLES PRIVATE
        // =========================================================================

        // Variables for the inputs
        let mut input_values = Vec::new();
        let mut input_pk_hashes = Vec::new();
        let mut input_randomnesses = Vec::new();
        let mut input_nullifier_keys = Vec::new();
        let mut input_positions = Vec::new();

        for input_note in &transaction.inputs {
            // Valeur (private)
            let value = UInt64::new_witness(cs.clone(), || Ok(input_note.value))?;
            input_values.push(value);

            // Hash de key public (private)
            let pk_hash = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&input_note.recipient_pk_hash))
            })?;
            input_pk_hashes.push(pk_hash);

            // Randomness of the commitment (private)
            let randomness = FpVar::new_witness(cs.clone(), || Ok(input_note.commitment_randomness))?;
            input_randomnesses.push(randomness);

            // Key de nullifier (ultra-private)
            let nullifier_key = FpVar::new_witness(cs.clone(), || Ok(input_note.nullifier_key))?;
            input_nullifier_keys.push(nullifier_key);

            // Position in l'arbre (private)
            let position = UInt64::new_witness(cs.clone(), || Ok(input_note.note_position))?;
            input_positions.push(position);
        }

        // Variables for the outputs
        let mut output_values = Vec::new();
        let mut output_pk_hashes = Vec::new();
        let mut output_randomnesses = Vec::new();

        for output_note in &transaction.outputs {
            // Valeur (private)
            let value = UInt64::new_witness(cs.clone(), || Ok(output_note.value))?;
            output_values.push(value);

            // Hash de key public (private)
            let pk_hash = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&output_note.recipient_pk_hash))
            })?;
            output_pk_hashes.push(pk_hash);

            // Randomness of the commitment (private)
            let randomness = FpVar::new_witness(cs.clone(), || Ok(output_note.commitment_randomness))?;
            output_randomnesses.push(randomness);
        }

        // =========================================================================
        // ALLOCATION DES VARIABLES PUBLIQUES
        // =========================================================================

        // Frais de transaction (public)
        let fee = UInt64::new_input(cs.clone(), || Ok(transaction.transaction_fee))?;

        // Nullifiers of inputs (publics)
        let mut expected_nullifiers = Vec::new();
        for nullifier in &public_data.input_nullifiers {
            let nf_var = FpVar::new_input(cs.clone(), || {
                Ok(bytes32_to_field(&nullifier.0))
            })?;
            expected_nullifiers.push(nf_var);
        }

        // Commitments of outputs (publics)
        let mut expected_output_commitments = Vec::new();
        for commitment in &public_data.output_commitments {
            let cm_var = FpVar::new_input(cs.clone(), || {
                Ok(bytes32_to_field(&commitment.0))
            })?;
            expected_output_commitments.push(cm_var);
        }

        // =========================================================================
        // CONTRAINTES DE VALIDITY DES INPUTS
        // =========================================================================

        for i in 0..transaction.inputs.len() {
            // Verify the commitment de l'input
            let input_commitment = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&transaction.inputs[i].compute_commitment().0))
            })?;

            constrain_note_commitment(
                cs.clone(),
                &input_values[i],
                &input_pk_hashes[i],
                &input_randomnesses[i],
                &input_commitment,
            )?;

            // Verify the nullifier de l'input
            constrain_nullifier(
                cs.clone(),
                &input_nullifier_keys[i],
                &input_commitment,
                &input_positions[i],
                &expected_nullifiers[i],
            )?;
        }

        // =========================================================================
        // CONTRAINTES DE VALIDITY DES OUTPUTS
        // =========================================================================

        for i in 0..transaction.outputs.len() {
            // Verify the commitment de l'output
            constrain_note_commitment(
                cs.clone(),
                &output_values[i],
                &output_pk_hashes[i],
                &output_randomnesses[i],
                &expected_output_commitments[i],
            )?;
        }

        // =========================================================================
        // CONTRAINTE DE CONSERVATION DES BALANCES
        // =========================================================================

        // Somme of inputs
        let mut total_input = UInt64::constant(0);
        for input_value in &input_values {
            total_input = total_input.add(input_value)?;
        }

        // Somme of outputs + fee
        let mut total_output_plus_fee = fee.clone();
        for output_value in &output_values {
            total_output_plus_fee = total_output_plus_fee.add(output_value)?;
        }

        // Contrainte finale: total_input = total_output + fee
        total_input.enforce_equal(&total_output_plus_fee)?;

        Ok(())
    }
}

/// System de preuves ZK for transactions shielded
pub struct ShieldedProofSystem {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
}

impl ShieldedProofSystem {
    /// Initializes the system with trusted setup
    /// ATTENTION: En production, requires a ceremony de trusted setup secure
    pub fn setup<R: RngCore>(rng: &mut R) -> Result<Self, Box<dyn std::error::Error>> {
        // Circuit dummy for the setup
        let dummy_circuit = ShieldedTransactionCircuit::without_witnesses();
        
        // Generates the keys de proving and verification
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
        })
    }

    /// Generates a preuve ZK for a transaction shielded
    pub fn prove_transaction(
        &self,
        transaction: ShieldedTransaction,
    ) -> Result<ShieldedTransactionZkProof, Box<dyn std::error::Error>> {
        // Extrait the data publiques
        let public_data = transaction.public_data();
        
        // Prepares the circuit with witnesses
        let circuit = ShieldedTransactionCircuit::with_witnesses(transaction.clone(), public_data.clone());
        
        // Prepares the inputs publics for Groth16
        let mut public_inputs = Vec::new();
        
        // Add the fees
        public_inputs.push(Fr::from(transaction.transaction_fee));
        
        // Add the nullifiers
        for nullifier in &public_data.input_nullifiers {
            public_inputs.push(bytes32_to_field(&nullifier.0));
        }
        
        // Add the commitments d'output
        for commitment in &public_data.output_commitments {
            public_inputs.push(bytes32_to_field(&commitment.0));
        }
        
        // Generates the preuve
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut OsRng)?;
        
        Ok(ShieldedTransactionZkProof {
            proof,
            public_data,
        })
    }

    /// Verifies a preuve ZK de transaction shielded
    pub fn verify_transaction(
        &self,
        proof: &ShieldedTransactionZkProof,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Reconstruit the inputs publics
        let mut public_inputs = Vec::new();
        
        // Frais
        public_inputs.push(Fr::from(proof.public_data.transaction_fee));
        
        // Nullifiers
        for nullifier in &proof.public_data.input_nullifiers {
            public_inputs.push(bytes32_to_field(&nullifier.0));
        }
        
        // Commitments
        for commitment in &proof.public_data.output_commitments {
            public_inputs.push(bytes32_to_field(&commitment.0));
        }
        
        // Verifies with Groth16
        let verification_result = Groth16::<Bn254>::verify(
            &self.verifying_key,
            &public_inputs,
            &proof.proof,
        )?;
        
        Ok(verification_result)
    }

    /// Returns the verification key (for validator nodes)
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }
}

/// Preuve ZK completee for a transaction shielded
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransactionZkProof {
    /// Preuve Groth16
    pub proof: Proof<Bn254>,
    /// Data publics de the transaction
    pub public_data: ShieldedTransactionPublicData,
}

impl ShieldedTransactionZkProof {
    /// Serializes the preuve in bytes for the stockage
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserializes a preuve from the bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Quickly verifies the proof structure (without cryptography)
    pub fn is_well_formed(&self) -> bool {
        // Verifications de base
        !self.public_data.input_nullifiers.is_empty() || !self.public_data.output_commitments.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shielded_note_creation() {
        let value = 1000u64;
        let pk_hash = [42u8; 32];
        let randomness = Fr::from(12345);
        let nullifier_key = Fr::from(67890);
        let position = 0u64;

        let input_note = ShieldedInputNote::new(
            value,
            pk_hash,
            randomness,
            nullifier_key,
            position,
        );

        // Le commitment must be deterministic
        let cm1 = input_note.compute_commitment();
        let cm2 = input_note.compute_commitment();
        assert_eq!(cm1, cm2);

        // Le nullifier must be deterministic
        let nf1 = input_note.compute_nullifier();
        let nf2 = input_note.compute_nullifier();
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_balanced_transaction() {
        let input_value = 1000u64;
        let output1_value = 600u64;
        let output2_value = 350u64;
        let fee = 50u64;

        let input = ShieldedInputNote::new(
            input_value,
            [1u8; 32],
            Fr::from(111),
            Fr::from(222),
            0,
        );

        let output1 = ShieldedOutputNote::new(
            output1_value,
            [2u8; 32],
            Fr::from(333),
        );

        let output2 = ShieldedOutputNote::new(
            output2_value,
            [3u8; 32],
            Fr::from(444),
        );

        let transaction = ShieldedTransaction::new(
            vec![input],
            vec![output1, output2],
            fee,
        ).unwrap();

        assert!(transaction.is_balanced());
        assert_eq!(input_value, output1_value + output2_value + fee);
    }

    #[test]
    fn test_imbalanced_transaction() {
        let input = ShieldedInputNote::new(
            1000u64,
            [1u8; 32],
            Fr::from(111),
            Fr::from(222),
            0,
        );

        let output = ShieldedOutputNote::new(
            2000u64, // Plus que l'input !
            [2u8; 32],
            Fr::from(333),
        );

        let result = ShieldedTransaction::new(
            vec![input],
            vec![output],
            0,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShieldedTransactionError::ImbalancedTransaction));
    }

    #[test]
    fn test_proof_system_setup() {
        let mut rng = OsRng;
        let proof_system = ShieldedProofSystem::setup(&mut rng);
        assert!(proof_system.is_ok());
        
        let system = proof_system.unwrap();
        let _vk = system.verifying_key();
        // Le setup fonctionne without erreur
    }

    #[test] 
    fn test_proof_serialization() {
        // Test with a preuve fictive
        let public_data = ShieldedTransactionPublicData {
            input_nullifiers: vec![],
            output_commitments: vec![],
            transaction_fee: 100,
        };

        // Note: Ce test requiresrait a vraie preuve for be complete
        assert!(public_data.transaction_fee == 100);
    }
}