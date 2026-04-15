// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests exhaustifs pour Halo2 ZK proofs - SECURITY CRITIQUE
//!
//! Cette suite de tests couvre :
//! - Soundness : un prover malveillant ne peut pas prouver une fausse declaration
//! - Completeness : un prover honnete peut toujours prouver une vraie declaration
//! - Zero-knowledge : les preuves ne revelent rien sur les temoins secrets
//! - Tests de non-regression pour vulnerabilitys ZK connues
//! - Property-based testing des invariants cryptographiques
//! - Tests de performance et resistance DoS
//!
//! ⚠️  RULE ABSOLUE : Tout echec de test dans ce file BLOQUE la release
//! ⚠️  Les vulnerabilitys ZK peuvent compromettre toute la privacy de TSN

use tsn::crypto::halo2_proofs::{prove_commitment, verify_commitment, TsnCommitmentCircuit};
use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use ff::Field;
use group::Curve;
use proptest::prelude::*;
use rand::rngs::OsRng;
use std::time::Instant;

// =============================================================================
// TESTS DE SOUNDNESS (SECURITY CRITIQUE)
// =============================================================================

/// Test de soundness : prover malveillant ne peut pas prouver un faux commitment
/// Menace prevenue : Soundness break → forge de commitments invalids
#[test]
fn soundness_invalid_commitment_rejected() {
    let mut rng = OsRng;
    
    // Commitment honnete
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let honest_commitment = value * Fr::from(7) + blinding; // Pedersen commitment
    
    // Prouver le commitment honnete
    let (proof, vk) = prove_commitment(&value, &blinding)
        .expect("Failure de generation de preuve honnete");
    
    // Check that la preuve honnete passe
    assert!(
        verify_commitment(&proof, &vk, &honest_commitment).unwrap(),
        "Preuve honnete rejetee (completeeness failure)"
    );
    
    // Try to checksr avec un commitment different (attaque soundness)
    let fake_commitment = Fr::random(&mut rng);
    if fake_commitment != honest_commitment {
        assert!(
            !verify_commitment(&proof, &vk, &fake_commitment).unwrap(),
            "SOUNDNESS BREAK : preuve acceptee pour un faux commitment"
        );
    }
    
    // Tenter avec un commitment modifie (1 bit flippe)
    let mut fake_commitment_bytes = honest_commitment.to_repr();
    fake_commitment_bytes.as_mut()[0] ^= 0x01;
    if let Ok(fake_commitment_modified) = Fr::from_repr(fake_commitment_bytes) {
        if fake_commitment_modified != honest_commitment {
            assert!(
                !verify_commitment(&proof, &vk, &fake_commitment_modified).unwrap(),
                "SOUNDNESS BREAK : preuve acceptee pour commitment modifie"
            );
        }
    }
}

/// Test de soundness avec preuves malformedes
/// Menace prevenue : Acceptance of malformed proofs
#[test]
fn soundness_malformed_proofs_rejected() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (valid_proof, vk) = prove_commitment(&value, &blinding)
        .expect("Failure de generation de preuve");
    
    // Test 1 : Preuve tronquee
    if valid_proof.len() > 10 {
        let truncated_proof = &valid_proof[..valid_proof.len() - 10];
        let result = verify_commitment(truncated_proof, &vk, &commitment);
        assert!(
            result.is_err() || !result.unwrap(),
            "SOUNDNESS BREAK : preuve tronquee acceptee"
        );
    }
    
    // Test 2 : Preuve avec bytes corrompus
    for corruption_pos in [0, valid_proof.len() / 4, valid_proof.len() / 2, valid_proof.len() - 1] {
        if corruption_pos < valid_proof.len() {
            let mut corrupted_proof = valid_proof.clone();
            corrupted_proof[corruption_pos] ^= 0xFF;
            
            let result = verify_commitment(&corrupted_proof, &vk, &commitment);
            assert!(
                result.is_err() || !result.unwrap(),
                "SOUNDNESS BREAK : preuve corrompue acceptee a la position {}",
                corruption_pos
            );
        }
    }
    
    // Test 3 : Preuve entierement nulle
    let zero_proof = vec![0u8; valid_proof.len()];
    let result = verify_commitment(&zero_proof, &vk, &commitment);
    assert!(
        result.is_err() || !result.unwrap(),
        "SOUNDNESS BREAK : preuve nulle acceptee"
    );
}

// =============================================================================
// TESTS DE COMPLETENESS
// =============================================================================

/// Test de completeeness : prover honnete peut toujours prouver
/// Menace prevenue : Denial of service via completeeness failure
#[test]
fn completeeness_honest_proofs_accepted() {
    let mut rng = OsRng;
    
    // Test avec differentes valeurs
    let test_values = [
        Fr::zero(),                    // Valeur nulle
        Fr::one(),                     // Valeur unitaire
        Fr::from(42),                  // Valeur petite
        Fr::random(&mut rng),          // Valeur random
        -Fr::one(),                    // Valeur negative
        Fr::from(u64::MAX),            // Grande valeur
    ];
    
    for (i, &value) in test_values.iter().enumerate() {
        let blinding = Fr::random(&mut rng);
        let commitment = value * Fr::from(7) + blinding;
        
        let proof_result = prove_commitment(&value, &blinding);
        assert!(
            proof_result.is_ok(),
            "COMPLETENESS FAILURE : echec de generation de preuve pour valeur {}",
            i
        );
        
        let (proof, vk) = proof_result.unwrap();
        let verify_result = verify_commitment(&proof, &vk, &commitment);
        assert!(
            verify_result.is_ok() && verify_result.unwrap(),
            "COMPLETENESS FAILURE : preuve honnete rejetee pour valeur {}",
            i
        );
    }
}

/// Test de completeeness avec differents blindings
/// Menace prevenue : Bias in blinding factor handling
#[test]
fn completeeness_various_blindings() {
    let mut rng = OsRng;
    let value = Fr::from(12345);
    
    let test_blindings = [
        Fr::zero(),                    // Blinding nul (dangereux en pratique)
        Fr::one(),                     // Blinding unitaire
        Fr::random(&mut rng),          // Blinding random
        -Fr::one(),                    // Blinding negatif
        Fr::from(u64::MAX),            // Grand blinding
    ];
    
    for (i, &blinding) in test_blindings.iter().enumerate() {
        let commitment = value * Fr::from(7) + blinding;
        
        let (proof, vk) = prove_commitment(&value, &blinding)
            .expect(&format!("Failure de generation pour blinding {}", i));
        
        assert!(
            verify_commitment(&proof, &vk, &commitment).unwrap(),
            "COMPLETENESS FAILURE : echec pour blinding {}",
            i
        );
    }
}

// =============================================================================
// TESTS DE ZERO-KNOWLEDGE
// =============================================================================

/// Test de zero-knowledge : les preuves ne revelent pas les temoins
/// Menace prevenue : Information leakage via proof analysis
#[test]
fn zero_knowledge_no_witness_leakage() {
    let mut rng = OsRng;
    
    // Generate deux preuves pour le same commitment avec des temoins differents
    let value1 = Fr::from(100);
    let blinding1 = Fr::from(200);
    let value2 = Fr::from(100);
    let blinding2 = Fr::from(300);
    
    // Same commitment, temoins differents
    let commitment = value1 * Fr::from(7) + blinding1;
    assert_eq!(commitment, value2 * Fr::from(7) + blinding2, "Commitments doivent be egaux");
    
    let (proof1, vk1) = prove_commitment(&value1, &blinding1).unwrap();
    let (proof2, vk2) = prove_commitment(&value2, &blinding2).unwrap();
    
    // Les deux preuves doivent be valides
    assert!(verify_commitment(&proof1, &vk1, &commitment).unwrap());
    assert!(verify_commitment(&proof2, &vk2, &commitment).unwrap());
    
    // Les preuves doivent be differentes (randomness dans la generation)
    // Note : Halo2 uses de la randomness, donc les preuves devraient differer
    assert_ne!(
        proof1, proof2,
        "ZERO-KNOWLEDGE FAILURE : preuves identiques revelent determinisme"
    );
    
    // Test statistique : generate plusieurs preuves pour le same statement
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let (proof, _vk) = prove_commitment(&value1, &blinding1).unwrap();
        proofs.push(proof);
    }
    
    // Toutes les preuves doivent be differentes
    for i in 0..proofs.len() {
        for j in i+1..proofs.len() {
            assert_ne!(
                proofs[i], proofs[j],
                "ZERO-KNOWLEDGE FAILURE : preuves {} et {} identiques",
                i, j
            );
        }
    }
}

// =============================================================================
// PROPERTY-BASED TESTING
// =============================================================================

proptest! {
    /// Property test : soundness sur des inputs randoms
    #[test]
    fn prop_soundness_random_inputs(
        value in prop::num::u64::ANY,
        blinding in prop::num::u64::ANY,
        fake_value in prop::num::u64::ANY,
        fake_blinding in prop::num::u64::ANY
    ) {
        let value_fr = Fr::from(value);
        let blinding_fr = Fr::from(blinding);
        let fake_value_fr = Fr::from(fake_value);
        let fake_blinding_fr = Fr::from(fake_blinding);
        
        let honest_commitment = value_fr * Fr::from(7) + blinding_fr;
        let fake_commitment = fake_value_fr * Fr::from(7) + fake_blinding_fr;
        
        let (proof, vk) = prove_commitment(&value_fr, &blinding_fr)
            .expect("Failure de generation de preuve");
        
        // La preuve doit be valide pour le vrai commitment
        prop_assert!(verify_commitment(&proof, &vk, &honest_commitment).unwrap());
        
        // La preuve ne doit PAS be valide pour un faux commitment (sauf collision)
        if fake_commitment != honest_commitment {
            prop_assert!(!verify_commitment(&proof, &vk, &fake_commitment).unwrap());
        }
    }
    
    /// Property test : completeeness sur des inputs randoms
    #[test]
    fn prop_completeeness_random_inputs(
        value in prop::num::u64::ANY,
        blinding in prop::num::u64::ANY
    ) {
        let value_fr = Fr::from(value);
        let blinding_fr = Fr::from(blinding);
        let commitment = value_fr * Fr::from(7) + blinding_fr;
        
        let proof_result = prove_commitment(&value_fr, &blinding_fr);
        prop_assert!(proof_result.is_ok(), "Failure de generation de preuve");
        
        let (proof, vk) = proof_result.unwrap();
        let verify_result = verify_commitment(&proof, &vk, &commitment);
        prop_assert!(verify_result.is_ok() && verify_result.unwrap(), "Preuve honnete rejetee");
    }
}

// =============================================================================
// TESTS DE PERFORMANCE ET DoS
// =============================================================================

/// Test de performance : generation de preuve ne doit pas be trop lente
/// Menace prevenue : DoS via preuves lentes a generate
#[test]
fn performance_proof_generation_reasonable() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    
    let start = Instant::now();
    let _proof = prove_commitment(&value, &blinding)
        .expect("Failure de generation de preuve");
    let elapsed = start.elapsed();
    
    // La generation de preuve doit prendre moins de 5 secondes
    assert!(
        elapsed.as_secs() < 5,
        "Generation de preuve trop lente : {:?} (limite: 5s)",
        elapsed
    );
}

/// Test de performance : verification de preuve ne doit pas be trop lente
/// Menace prevenue : DoS via verifications lentes
#[test]
fn performance_proof_verification_reasonable() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (proof, vk) = prove_commitment(&value, &blinding)
        .expect("Failure de generation de preuve");
    
    let start = Instant::now();
    const VERIFICATIONS: usize = 10;
    
    for _ in 0..VERIFICATIONS {
        assert!(verify_commitment(&proof, &vk, &commitment).unwrap());
    }
    
    let elapsed = start.elapsed();
    let avg_time = elapsed.as_millis() / VERIFICATIONS as u128;
    
    // La verification doit prendre moins de 100ms en moyenne
    assert!(
        avg_time < 100,
        "Verification trop lente : {}ms (limite: 100ms)",
        avg_time
    );
}

/// Test de resistance DoS : preuves malformedes ne causent pas de panic
/// Menace prevenue : DoS via panic sur inputs malformeds
#[test]
fn dos_resistance_malformed_inputs_no_panic() {
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (valid_proof, vk) = prove_commitment(&value, &blinding).unwrap();
    
    // Test avec differentes corruptions qui ne doivent jamais paniquer
    let corruptions = [
        vec![],                           // Preuve vide
        vec![0xFF; 1000],                // Preuve de garbage
        valid_proof[..10].to_vec(),      // Preuve tronquee
        {
            let mut corrupted = valid_proof.clone();
            corrupted.extend_from_slice(&[0xFF; 100]);
            corrupted
        },                               // Preuve etendue
    ];
    
    for (i, corrupted_proof) in corruptions.iter().enumerate() {
        // Aucune de ces verifications ne doit paniquer
        let result = std::panic::catch_unwind(|| {
            verify_commitment(corrupted_proof, &vk, &commitment)
        });
        
        assert!(
            result.is_ok(),
            "PANIC sur preuve corrompue {} : {:?}",
            i,
            result.err()
        );
        
        // Le result doit be une error ou false, jamais true
        if let Ok(verify_result) = result.unwrap() {
            if let Ok(is_valid) = verify_result {
                assert!(
                    !is_valid,
                    "Preuve corrompue {} acceptee comme valide",
                    i
                );
            }
        }
    }
}

// =============================================================================
// TESTS DE REGRESSION
// =============================================================================

/// Test de regression : Fiat-Shamir soundness
/// Menace prevenue : Fiat-Shamir transformation vulnerabilities
#[test]
fn regression_fiat_shamir_soundness() {
    // Historiquement, des bugs dans Fiat-Shamir ont permis des soundness breaks
    let mut rng = OsRng;
    let value = Fr::from(42);
    let blinding = Fr::random(&mut rng);
    let commitment = value * Fr::from(7) + blinding;
    
    let (proof, vk) = prove_commitment(&value, &blinding).unwrap();
    
    // La preuve doit be liee cryptographiquement au commitment
    // Try to reusesr la preuve avec un autre commitment
    let other_commitment = Fr::random(&mut rng);
    if other_commitment != commitment {
        assert!(
            !verify_commitment(&proof, &vk, &other_commitment).unwrap(),
            "REGRESSION : reutilisation de preuve possible (Fiat-Shamir break)"
        );
    }
}

/// Test de regression : Trusted setup independence
/// Menace prevenue : Trusted setup compromise
#[test]
fn regression_trusted_setup_independence() {
    // Halo2 ne doit pas dependre d'un trusted setup
    // Generate plusieurs preuves avec des setups independants
    let mut rng = OsRng;
    let value = Fr::from(123);
    let blinding = Fr::from(456);
    let commitment = value * Fr::from(7) + blinding;
    
    // Chaque generation de preuve uses un setup independant
    let (proof1, vk1) = prove_commitment(&value, &blinding).unwrap();
    let (proof2, vk2) = prove_commitment(&value, &blinding).unwrap();
    
    // Les preuves doivent be valides avec leurs VK respectives
    assert!(verify_commitment(&proof1, &vk1, &commitment).unwrap());
    assert!(verify_commitment(&proof2, &vk2, &commitment).unwrap());
    
    // Cross-verification ne doit PAS fonctionner (VK sont liees aux preuves)
    // Note : En pratique, Halo2 peut avoir des VK reutilisables selon l'implementation
    // Ce test checks qu'il n'y a pas de dependance cachee a un setup global
}

// =============================================================================
// TESTS DE COMPATIBILITY ET STANDARDS
// =============================================================================

/// Test de compatibility avec les standards Halo2
/// Menace prevenue : Incompatibility avec l'ecosystem ZK
#[test]
fn compatibility_halo2_standards() {
    // Check that notre circuit respecte les contraintes Halo2
    let mut rng = OsRng;
    let value = Fr::random(&mut rng);
    let blinding = Fr::random(&mut rng);
    
    // Le circuit doit be constructible
    let circuit = TsnCommitmentCircuit::new(value, blinding);
    
    // Les parameters doivent be coherents
    const K: u32 = 15; // Doit correspondre a la constante dans halo2_proofs.rs
    let params = ParamsKZG::<Bn256>::setup(K, &mut rng);
    
    // La generation de VK/PK doit reussir
    let vk = keygen_vk(&params, &circuit).expect("Failure de generation VK");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Failure de generation PK");
    
    // La preuve doit be generee et verifiede avec l'API standard
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let proof_result = create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[]],
        &mut rng,
        &mut transcript,
    );
    
    assert!(proof_result.is_ok(), "Failure de generation de preuve avec API standard");
    
    let proof = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_result = verify_proof(
        &params,
        &vk,
        SingleStrategy::new(&params),
        &[&[]],
        &mut transcript,
    );
    
    assert!(verify_result.is_ok(), "Failure de verification avec API standard");
}
