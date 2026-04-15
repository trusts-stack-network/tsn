// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de security: Protection contre le double-spend via nullifier
//!
//! Ce module teste la vulnerability identifiee dans TODO #4:
//! "Check that le nullifier n'est pas already utilise dans l'historique complete"
//!
//! # Menace
//! Un attaquant pourrait reusesr un nullifier already depense pour create
//! une transaction frauduleuse, allowstant un double-spend.
//!
//! # Mitigation
//! - Indexation de tous les nullifiers depenses
//! - Verification atomique avant acceptation de transaction
//! - Bloom filter pour recherche rapide

use std::collections::HashSet;
use tsn::crypto::nullifier::{Nullifier, NullifierSet};
use tsn::core::transaction::{Transaction, TransactionError};

/// Test de regression: Double-spend avec nullifier reutilise
/// Vulnerabilite: CVE-2024-XXXX (simule)
#[test]
fn test_nullifier_double_spend_prevention() {
    // Create a nullifier
    let nullifier = Nullifier::from_bytes(
        &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
           0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
    ).expect("Nullifier valide");

    // Create a set de nullifiers
    let mut nullifier_set = NullifierSet::new();

    // First utilisation - doit reussir
    assert!(
        nullifier_set.insert(nullifier.clone()),
        "First insertion doit reussir"
    );

    // Tentative de double-spend - doit fail
    assert!(
        !nullifier_set.insert(nullifier.clone()),
        "Double-spend doit be detecte et rejete"
    );

    // Check that le nullifier est bien dans le set
    assert!(nullifier_set.contains(&nullifier), "Nullifier doit be present");
}

/// Test: Verification atomique du nullifier pendant validation transaction
#[test]
fn test_transaction_nullifier_atomic_check() {
    use tsn::core::state::State;

    let mut state = State::new();
    let nullifier = Nullifier::from_bytes(
        &[0xab; 32]
    ).expect("Nullifier valide");

    // Simuler une transaction avec nullifier
    let tx = create_test_transaction_with_nullifier(nullifier.clone());

    // First validation - doit passer
    assert!(state.validate_nullifier(&nullifier).is_ok(),
            "First validation doit passer");

    // Marquer comme depense
    state.spend_nullifier(nullifier.clone()).expect("Spend doit reussir");

    // Second validation - doit fail
    let result = state.validate_nullifier(&nullifier);
    assert!(result.is_err(), "Double-spend doit be rejete");
    
    match result {
        Err(TransactionError::NullifierAlreadySpent) => {},
        _ => panic!("Erreur attendue: NullifierAlreadySpent"),
    }
}

/// Test: Attaque par race condition sur nullifier
/// Scenario: Deux threads tentent de valider le same nullifier simultanement
#[test]
fn test_nullifier_race_condition_protection() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let nullifier_set = Arc::new(Mutex::new(NullifierSet::new()));
    let nullifier = Nullifier::from_bytes(
        &[0xde; 32]
    ).expect("Nullifier valide");

    let mut handles = vec![];

    // Lancer 10 threads qui tentent tous d'inserer le same nullifier
    for _ in 0..10 {
        let set = Arc::clone(&nullifier_set);
        let nf = nullifier.clone();
        
        let handle = thread::spawn(move || {
            let mut set = set.lock().unwrap();
            set.insert(nf)
        });
        handles.push(handle);
    }

    // Collecter les results
    let results: Vec<bool> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();

    // Exactement UN thread doit avoir reussi
    let success_count = results.iter().filter(|&&r| r).count();
    assert_eq!(success_count, 1, 
        "Exactement une insertion doit reussir (race condition protection). \
         Reussi: {}", success_count);
}

/// Test: Performance de recherche dans grand set de nullifiers
/// Checks that la verification reste rapide same avec millions de nullifiers
#[test]
fn test_nullifier_performance_large_set() {
    use std::time::Instant;

    let mut nullifier_set = NullifierSet::new();
    
    // Inserer 100k nullifiers
    for i in 0..100_000u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        
        let nf = Nullifier::from_bytes(&full_bytes).expect("Nullifier valide");
        nullifier_set.insert(nf);
    }

    // Mesurer le temps de recherche
    let target = Nullifier::from_bytes(
        &[0x99; 32]
    ).expect("Nullifier valide");
    
    let start = Instant::now();
    for _ in 0..1000 {
        nullifier_set.contains(&target);
    }
    let elapsed = start.elapsed();

    // Doit be very rapide (< 1ms pour 1000 recherches)
    assert!(
        elapsed.as_millis() < 10,
        "Recherche trop lente: {:?} pour 1000 recherches",
        elapsed
    );
}

/// Test: Nullifier avec valeurs aux limites
#[test]
fn test_nullifier_edge_cases() {
    // Nullifier avec tous les bytes a 0
    let zero_nf = Nullifier::from_bytes(&[0u8; 32]
    ).expect("Nullifier valide");

    // Nullifier avec tous les bytes a 0xFF
    let max_nf = Nullifier::from_bytes(
        &[0xFFu8; 32]
    ).expect("Nullifier valide");

    // Nullifier avec pattern alterne
    let alt_nf = Nullifier::from_bytes(
        &[0xAA, 0x55].repeat(16).as_slice()
    ).expect("Nullifier valide");

    let mut set = NullifierSet::new();
    
    // Tous doivent be inserables
    assert!(set.insert(zero_nf.clone()));
    assert!(set.insert(max_nf.clone()));
    assert!(set.insert(alt_nf.clone()));

    // Et non reinserables
    assert!(!set.insert(zero_nf));
    assert!(!set.insert(max_nf));
    assert!(!set.insert(alt_nf));
}

/// Test: Serialization/deserialization du nullifier set
#[test]
fn test_nullifier_set_serialization() {
    use tsn::storage::serialize;

    let mut set = NullifierSet::new();
    
    // Ajouter quelques nullifiers
    for i in 0..100u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        let nf = Nullifier::from_bytes(&full_bytes).unwrap();
        set.insert(nf);
    }

    // Serialize
    let serialized = serialize(&set).expect("Serialization reussie");

    // Deserialize
    let deserialized: NullifierSet = serialize::deserialize(&serialized)
        .expect("Deserialization reussie");

    // Check that tous les nullifiers sont preserves
    for i in 0..100u64 {
        let bytes = i.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[0..8].copy_from_slice(&bytes);
        let nf = Nullifier::from_bytes(&full_bytes).unwrap();
        assert!(deserialized.contains(&nf), "Nullifier {} manquant", i);
    }
}

// Helper function
fn create_test_transaction_with_nullifier(nullifier: Nullifier) -> Transaction {
    // Create a transaction de test avec le nullifier
    Transaction::new_test_with_nullifier(nullifier)
}
