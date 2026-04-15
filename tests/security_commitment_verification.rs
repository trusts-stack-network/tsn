// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de security: Verification des commitments Plonky2
//!
//! Ce module teste la vulnerability identifiee dans TODO #3:
//! "Check the preuve Plonky2 avant d'accepter le commitment"
//!
//! # Menace
//! Sans verification de la preuve ZK, un attaquant peut create des commitments
//! invalids qui seraient acceptes par le system, compromettant l'integrite
//! des transactions confidentielles.
//!
//! # Mitigation
//! - Verification complete de la preuve Plonky2
//! - Validation des public inputs
//! - Verification du commitment root

use tsn::crypto::commitment::{Commitment, CommitmentProof};
use tsn::crypto::poseidon2::Poseidon2Hash;
use tsn::plonky2::{verify_proof, Plonky2Config};

/// Test: Rejet d'un commitment avec preuve invalid
#[test]
fn test_commitment_rejects_invalid_proof() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Create a preuve invalid (data randoms)
    let invalid_proof = CommitmentProof::from_bytes(&[0xFFu8; 1024]
    ).expect("Preuve creee");

    // La verification doit fail
    let result = commitment.verify_plonky2_proof(&invalid_proof);
    assert!(result.is_err(), "Preuve invalid doit be rejetee");
    
    match result {
        Err(CommitmentError::InvalidProof) => {},
        Err(e) => panic!("Mauvaise error: {:?}", e),
        Ok(_) => panic!("Preuve invalid acceptee - VULNERABILITY!"),
    }
}

/// Test: Acceptation d'un commitment avec preuve valide
#[test]
fn test_commitment_accepts_valid_proof() {
    // Create a commitment valide avec preuve Plonky2
    let (commitment, proof) = create_valid_commitment_with_proof();

    // La verification doit reussir
    let result = commitment.verify_plonky2_proof(&proof);
    assert!(result.is_ok(), "Preuve valide doit be acceptee: {:?}", result);
}

/// Test: Verification du commitment root
#[test]
fn test_commitment_root_verification() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0xab; 32]),
        5000u64,
    );

    // Root incorrect
    let wrong_root = Poseidon2Hash::from_bytes(&[0x00; 32]
    );

    let result = commitment.verify_against_root(&wrong_root);
    assert!(result.is_err(), "Mauvais root doit be rejete");
}

/// Test: Attaque par malleabilite de la preuve
#[test]
fn test_proof_malleability_protection() {
    let (commitment, mut proof) = create_valid_commitment_with_proof();

    // Modifier legerement la preuve
    if let Some(byte) = proof.bytes_mut().last_mut() {
        *byte = byte.wrapping_add(1);
    }

    // La preuve modifiee doit be rejetee
    let result = commitment.verify_plonky2_proof(&proof);
    assert!(result.is_err(), "Preuve malleable doit be rejetee");
}

/// Test: Verification des public inputs
#[test]
fn test_public_inputs_validation() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Create a preuve avec mauvais public inputs
    let wrong_inputs_proof = create_proof_with_wrong_inputs(&commitment
    );

    let result = commitment.verify_plonky2_proof(&wrong_inputs_proof);
    assert!(result.is_err(), "Mauvais public inputs doivent be rejetes");
}

/// Test: Performance de verification
#[test]
fn test_proof_verification_performance() {
    use std::time::Instant;

    let (commitment, proof) = create_valid_commitment_with_proof();

    let start = Instant::now();
    for _ in 0..100 {
        let _ = commitment.verify_plonky2_proof(&proof);
    }
    let elapsed = start.elapsed();

    // La verification doit be raisonnablement rapide
    assert!(
        elapsed.as_millis() < 5000,
        "Verification trop lente: {:?}",
        elapsed
    );
}

/// Test: Batch verification de commitments
#[test]
fn test_batch_commitment_verification() {
    let mut commitments = vec![];
    let mut proofs = vec![];

    for i in 0..10 {
        let (comm, proof) = create_valid_commitment_with_proof_with_value(i * 100);
        commitments.push(comm);
        proofs.push(proof);
    }

    // Verification batch
    let results: Vec<bool> = commitments.iter()
        .zip(proofs.iter())
        .map(|(c, p)| c.verify_plonky2_proof(p).is_ok())
        .collect();

    // Toutes doivent passer
    assert!(results.iter().all(|r| *r), "Toutes les preuves doivent be valides");
}

/// Test: Rejet si preuve manquante
#[test]
fn test_commitment_rejects_missing_proof() {
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        1000u64,
    );

    // Verification sans preuve
    let result = commitment.verify_without_proof();
    assert!(result.is_err(), "Commitment sans preuve doit be rejete");
}

/// Test: Serialization securisee
#[test]
fn test_commitment_serialization_integrity() {
    use tsn::storage::serialize;

    let (commitment, proof) = create_valid_commitment_with_proof();

    // Serialize
    let comm_bytes = serialize(&commitment).unwrap();
    let proof_bytes = serialize(&proof).unwrap();

    // Corrompre les bytes
    let mut corrupted = comm_bytes.clone();
    if let Some(last) = corrupted.last_mut() {
        *last ^= 0xFF;
    }

    // La deserialization doit fail ou detect la corruption
    let result: Result<Commitment, _> = serialize::deserialize(&corrupted);
    
    // Soit echec de deserialization, soit verification fails
    match result {
        Ok(comm) => {
            // Si deserialized, la verification doit fail
            assert!(comm.verify_plonky2_proof(&proof).is_err());
        }
        Err(_) => {
            // Failure de deserialization - acceptable
        }
    }
}

// Helper functions
fn create_valid_commitment_with_proof() -> (Commitment, CommitmentProof) {
    create_valid_commitment_with_proof_with_value(1000)
}

fn create_valid_commitment_with_proof_with_value(value: u64) -> (Commitment, CommitmentProof) {
    // Simuler la creation d'un commitment valide avec preuve Plonky2
    let config = Plonky2Config::default();
    let commitment = Commitment::new(
        Poseidon2Hash::from_bytes(&[0x12; 32]),
        value,
    );
    
    let proof = commitment.generate_proof(&config
    ).expect("Preuve generee");
    
    (commitment, proof)
}

fn create_proof_with_wrong_inputs(commitment: &Commitment) -> CommitmentProof {
    // Create a preuve avec des inputs qui ne correspondent pas au commitment
    CommitmentProof::from_bytes(&[0x00u8; 1024]
    ).expect("Preuve creee")
}

#[derive(Debug)]
enum CommitmentError {
    InvalidProof,
    InvalidRoot,
    MissingProof,
}
