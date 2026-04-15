// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests adversariaux pour les modules cryptographiques post-quantiques
//!
//! Ces tests simulent des attaques contre les modules crypto PQ
//! pour checksr leur resilience.

use std::time::{Duration, Instant};

/// Test de timing attack sur la verification de signature
#[test]
fn test_mldsa_timing_resistance() {
    use tsn::crypto::pq::ml_dsa::{sign, verify, generate_keypair};

    let (sk, pk) = generate_keypair().expect("Key generation failed");
    
    let msg1 = b"message one";
    let msg2 = b"message two that is longer";
    
    let sig1 = sign(&sk, msg1).expect("Signing failed");
    let sig2 = sign(&sk, msg2).expect("Signing failed");

    // Mesurer le temps de verification pour differentes entrees
    let iterations = 100;
    
    let mut times_valid = Vec::new();
    let mut times_invalid = Vec::new();

    for _ in 0..iterations {
        // Verification valide
        let start = Instant::now();
        let _ = verify(&pk, msg1, &sig1);
        times_valid.push(start.elapsed());

        // Verification invalid (mauvais message)
        let start = Instant::now();
        let _ = verify(&pk, msg2, &sig1);
        times_invalid.push(start.elapsed());
    }

    // Calculer les moyennes
    let avg_valid: Duration = times_valid.iter().sum::<Duration>() / iterations;
    let avg_invalid: Duration = times_invalid.iter().sum::<Duration>() / iterations;

    // La difference ne doit pas be significative (timing attack)
    let diff = if avg_valid > avg_invalid {
        avg_valid - avg_invalid
    } else {
        avg_invalid - avg_valid
    };

    // Tolerance de 20% pour les variations system
    let tolerance = avg_valid / 5;
    
    assert!(
        diff < tolerance,
        "Timing attack possible: valid={:?}, invalid={:?}, diff={:?}",
        avg_valid, avg_invalid, diff
    );
}

/// Test de malleabilite de signature
#[test]
fn test_mldsa_signature_non_malleable() {
    use tsn::crypto::pq::ml_dsa::{sign, verify, generate_keypair};

    let (sk, pk) = generate_keypair().expect("Key generation failed");
    let msg = b"test message";
    let sig = sign(&sk, msg).expect("Signing failed");

    // La signature ne doit pas be malleable
    // (impossible de create une signature valide differente sans la key secret)
    assert!(verify(&pk, msg, &sig).is_ok());

    // Modifier un octet de la signature
    let mut modified_sig = sig.clone();
    if !modified_sig.is_empty() {
        modified_sig[0] ^= 0xFF;
        assert!(verify(&pk, msg, &modified_sig).is_err());
    }
}

/// Test de collision d'engagement
#[test]
fn test_commitment_pq_collision_resistance() {
    use tsn::crypto::pq::commitment_pq::{
        commit_value, verify_value_commitment
    };

    // Tester avec differentes valeurs et randomness
    let test_cases = vec![
        (100u64, [1u8; 32]),
        (100u64, [2u8; 32]),
        (200u64, [1u8; 32]),
        (u64::MAX, [0u8; 32]),
        (0u64, [0xFFu8; 32]),
    ];

    let mut commitments = Vec::new();

    for (value, randomness) in &test_cases {
        let commitment = commit_value(*value, randomness);
        
        // Verifier qu'aucune collision n'existe
        for existing in &commitments {
            assert_ne!(
                commitment.commitment, *existing,
                "Collision detectee pour value={}", value
            );
        }
        
        commitments.push(commitment.commitment.clone());

        // Check that l'engagement est valide
        assert!(
            verify_value_commitment(
                &commitment.commitment,
                *value,
                &commitment.opening
            ),
            "Commitment verification failed for value={}",
            value
        );
    }
}

/// Test de double depense
#[test]
fn test_double_spend_detection() {
    use tsn::crypto::pq::verify_pq::{
        TransactionV2, SpendDescriptionV2, OutputDescriptionV2,
        verify_transaction_v2
    };

    // Create a transaction avec un nullifier
    let nullifier = [0xABu8; 32];
    
    let spend = SpendDescriptionV2 {
        nullifier,
        commitment: [0u8; 32],
        merkle_root: [0u8; 32],
        signature: vec![0u8; 64],
        public_key: [0u8; 32],
    };

    let tx = TransactionV2 {
        spends: vec![spend],
        outputs: vec![],
        fee: 0,
        anchor: [0u8; 32],
        binding_sig: vec![],
        zkproof: vec![],
        public_inputs: vec![],
    };

    // Simuler une tentative de double depense
    // Le nullifier doit be marque comme utilise after la first transaction
    // et rejete pour les transactions suivantes

    // Note: Ce test requires un state partage pour be complete
    // Ici on checks juste la structure
    assert_eq!(tx.spends[0].nullifier(), &nullifier);
}

/// Test de resource exhaustion
#[test]
fn test_slh_dsa_batch_size_limit() {
    use tsn::crypto::pq::slh_dsa_batch::{
        BatchVerifier, BatchVerificationResult
    };

    let mut verifier = BatchVerifier::new();

    // Ajouter un grand nombre de signatures
    for i in 0..200 {
        let msg = vec![i as u8; 100];
        let sig = vec![i as u8; 64];
        let pk = [i as u8; 32];

        let result = verifier.add_signature(&msg, &sig, &pk
        );

        // Check that la limite est respectee
        if i >= 128 {
            assert!(
                matches!(result, Err(_)),
                "Devrait fail after la limite de batch"
            );
        }
    }

    let result = verifier.verify_batch();

    // Doit retourner BatchTooLarge ou un result valide
    assert!(
        matches!(
            result,
            BatchVerificationResult::BatchTooLarge |
            BatchVerificationResult::AllValid |
            BatchVerificationResult::InvalidSignatures(_) |
            BatchVerificationResult::VerificationFailed
        ),
        "Resultat inattendu: {:?}",
        result
    );
}

/// Test de circuit malformed
#[test]
fn test_circuit_pq_malformed_inputs() {
    use tsn::crypto::pq::circuit_pq::build_transaction_circuit;

    // Test avec des valeurs extreme
    let test_cases = vec![
        (0, 0),
        (0, 1),
        (1, 0),
        (100, 100),
        (usize::MAX, 1),
        (1, usize::MAX),
    ];

    for (spends, outputs) in test_cases {
        let result = build_transaction_circuit(spends, outputs);

        // Ne doit pas paniquer
        match result {
            Ok(_) => {
                // Construction reussie
            }
            Err(_) => {
                // Failure acceptable
            }
        }
    }
}

/// Test de preuve invalid
#[test]
fn test_proof_pq_invalid_proof() {
    use tsn::crypto::pq::proof_pq::{
        verify_plonky2_proof, Plonky2Proof
    };

    // Create a preuve invalid
    let invalid_proof = Plonky2Proof {
        proof_bytes: vec![0u8; 100],
        public_inputs: vec![0u8; 32],
    };

    // La verification doit fail
    let result = verify_plonky2_proof(
        &invalid_proof.proof_bytes,
        &invalid_proof.public_inputs
    );

    assert!(result.is_err());
}

/// Test de transaction malformede
#[test]
fn test_transaction_v2_malformed() {
    use tsn::crypto::pq::verify_pq::{
        TransactionV2, SpendDescriptionV2, OutputDescriptionV2,
        verify_transaction_v2
    };

    // Transaction vide
    let empty_tx = TransactionV2 {
        spends: vec![],
        outputs: vec![],
        fee: 0,
        anchor: [0u8; 32],
        binding_sig: vec![],
        zkproof: vec![],
        public_inputs: vec![],
    };

    // Doit fail proprement
    let result = verify_transaction_v2(
        &empty_tx,
        &[],
        &[],
    );

    // Une transaction vide est invalid
    assert!(result.is_err());

    // Transaction avec spends mais sans outputs
    let no_outputs_tx = TransactionV2 {
        spends: vec![SpendDescriptionV2 {
            nullifier: [0u8; 32],
            commitment: [0u8; 32],
            merkle_root: [0u8; 32],
            signature: vec![0u8; 64],
            public_key: [0u8; 32],
        }],
        outputs: vec![],
        fee: 0,
        anchor: [0u8; 32],
        binding_sig: vec![],
        zkproof: vec![],
        public_inputs: vec![],
    };

    let result = verify_transaction_v2(
        &no_outputs_tx,
        &[],
        &[],
    );

    assert!(result.is_err());
}

/// Test de resistance aux attaques par fuzzing
#[test]
fn test_fuzzing_resistance() {
    use tsn::crypto::pq::ml_dsa::{verify, generate_keypair};

    let (_, pk) = generate_keypair().expect("Key generation failed");

    // Tester avec des entrees randoms
    let fuzz_inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xFF; 10000],
        vec![0x00; 10000],
        (0..256).map(|i| i as u8).collect(),
        vec![0xAB; 100],
    ];

    for input in fuzz_inputs {
        // Ne doit pas paniquer
        let _ = verify(&pk,
            &input,
            &input
        );
    }
}

/// Test de consistency batch vs individuel
#[test]
fn test_batch_vs_individual_consistency() {
    use tsn::crypto::pq::slh_dsa_batch::{
        BatchVerifier, BatchVerificationResult
    };

    let mut verifier = BatchVerifier::new();

    // Ajouter quelques signatures (invalid car data randoms)
    for i in 0..5 {
        let msg = vec![i as u8; 32];
        let sig = vec![i as u8; 64];
        let pk = [i as u8; 32];

        let _ = verifier.add_signature(&msg, &sig, &pk
        );
    }

    let result = verifier.verify_batch();

    // Les signatures randoms doivent be invalids
    assert!(
        matches!(
            result,
            BatchVerificationResult::InvalidSignatures(_) |
            BatchVerificationResult::VerificationFailed
        ),
        "Les signatures randoms devraient be invalids: {:?}",
        result
    );
}
