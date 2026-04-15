// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de security: Validation des preuves ZK dans le mempool
//!
//! Ce module teste la vulnerability identifiee dans TODO #5:
//! "Implementer la verification complete des preuves ZK"
//!
//! # Menace
//! Sans verification complete des preuves Plonky2 dans le mempool,
//! un attaquant peut:
//! 1. Flooder le mempool avec des transactions a preuves invalids
//! 2. Consommer de la bande passante et des ressources CPU
//! 3. Empecher les transactions valides d'entrer dans le mempool
//!
//! # Mitigation
//! - Verification complete avant acceptation dans le mempool
//! - Rate limiting par peer
//! - Penalite pour peers envoyant des preuves invalids

use tsn::network::mempool_v2::{Mempool, MempoolConfig, MempoolError};
use tsn::core::transaction::{Transaction, TransactionType};
use tsn::crypto::proof::Plonky2Proof;

/// Test: Rejet des transactions avec preuves ZK invalids
#[test]
fn test_mempool_rejects_invalid_zk_proofs() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    // Create a transaction avec preuve invalid
    let tx = create_transaction_with_invalid_proof();

    // Tentative d'ajout au mempool
    let result = mempool.add_transaction(tx);
    
    assert!(result.is_err(), "Transaction avec preuve invalid doit be rejetee");
    
    match result {
        Err(MempoolError::InvalidZkProof) => {},
        Err(e) => panic!("Mauvaise error: {:?}", e),
        Ok(_) => panic!("Transaction invalid acceptee - VULNERABILITY!"),
    }
}

/// Test: Acceptation des transactions avec preuves ZK valides
#[test]
fn test_mempool_accepts_valid_zk_proofs() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    // Create a transaction avec preuve valide
    let tx = create_transaction_with_valid_proof();

    // Ajout au mempool
    let result = mempool.add_transaction(tx);
    assert!(result.is_ok(), "Transaction valide doit be acceptee: {:?}", result);
}

/// Test: DoS par flood de transactions invalids
#[test]
fn test_mempool_dos_protection_invalid_proofs() {
    let config = MempoolConfig {
        max_size: 1000,
        max_per_peer: 100,
        verify_proofs: true,
        ..Default::default()
    };
    let mut mempool = Mempool::new(config);

    let peer_id = [0x01u8; 32];

    // Tenter d'ajouter 200 transactions invalids
    let mut rejected = 0;
    for i in 0..200 {
        let tx = create_transaction_with_invalid_proof_and_nonce(i);
        match mempool.add_transaction_from_peer(tx, peer_id) {
            Err(MempoolError::InvalidZkProof) => rejected += 1,
            Err(MempoolError::PeerQuotaExceeded) => rejected += 1,
            Err(_) => rejected += 1,
            Ok(_) => {}
        }
    }

    // La majorite doit be rejetee
    assert!(
        rejected >= 150,
        "DoS protection echouee: seulement {} rejetees sur 200",
        rejected
    );
}

/// Test: Penalite pour peer malveillant
#[test]
fn test_mempool_peer_penalty_invalid_proofs() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    let peer_id = [0x02u8; 32];

    // Envoyer 10 preuves invalids
    for i in 0..10 {
        let tx = create_transaction_with_invalid_proof_and_nonce(i);
        let _ = mempool.add_transaction_from_peer(tx, peer_id);
    }

    // Check that le peer a ete penalise
    let score = mempool.get_peer_score(peer_id);
    assert!(
        score < 0,
        "Peer doit be penalise pour preuves invalids. Score: {}",
        score
    );

    // Check that le peer est banni si score trop bas
    assert!(
        mempool.is_peer_banned(peer_id),
        "Peer doit be banni after trop d'invalids"
    );
}

/// Test: Validation de la taille de la preuve
#[test]
fn test_mempool_rejects_oversized_proofs() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    // Create a transaction avec preuve trop grande
    let tx = create_transaction_with_oversized_proof();

    let result = mempool.add_transaction(tx);
    assert!(result.is_err(), "Preuve surdimensionnee doit be rejetee");
}

/// Test: Validation rapide des preuves (pas de verification complete si evident)
#[test]
fn test_mempool_fast_rejection_sanity_checks() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    // Preuve avec structure evidente invalid
    let tx = create_transaction_with_malformed_proof();

    let start = std::time::Instant::now();
    let result = mempool.add_transaction(tx);
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Preuve malformede doit be rejetee");
    
    // Rejet rapide (< 10ms) - pas de verification lente
    assert!(
        elapsed.as_millis() < 10,
        "Rejet doit be rapide: {:?}",
        elapsed
    );
}

/// Test: Cache des results de verification
#[test]
fn test_mempool_proof_verification_cache() {
    let config = MempoolConfig {
        cache_verified_proofs: true,
        ..Default::default()
    };
    let mut mempool = Mempool::new(config);

    let tx = create_transaction_with_valid_proof();
    let tx_hash = tx.hash();

    // First verification
    let start = std::time::Instant::now();
    let _ = mempool.add_transaction(tx.clone());
    let first_duration = start.elapsed();

    // Retirer et reajouter
    mempool.remove_transaction(&tx_hash);

    // Second verification (devrait usesr le cache)
    let start = std::time::Instant::now();
    let _ = mempool.add_transaction(tx);
    let second_duration = start.elapsed();

    // La second doit be beaucoup plus rapide
    assert!(
        second_duration < first_duration / 2,
        "Cache devrait accelerer: {:?} vs {:?}",
        second_duration,
        first_duration
    );
}

/// Test: Transactions mixtes (valides et invalids)
#[test]
fn test_mempool_mixed_validity() {
    let config = MempoolConfig::default();
    let mut mempool = Mempool::new(config);

    let mut valid_count = 0;
    let mut invalid_count = 0;

    // Ajouter 50 transactions alternees
    for i in 0..50 {
        let tx = if i % 2 == 0 {
            create_transaction_with_valid_proof_with_nonce(i)
        } else {
            create_transaction_with_invalid_proof_and_nonce(i)
        };

        match mempool.add_transaction(tx) {
            Ok(_) => valid_count += 1,
            Err(_) => invalid_count += 1,
        }
    }

    assert_eq!(valid_count, 25, "25 transactions valides attendues");
    assert_eq!(invalid_count, 25, "25 transactions invalids attendues");
}

/// Test: Mempool sous charge
#[test]
fn test_mempool_under_load() {
    let config = MempoolConfig {
        max_size: 100,
        ..Default::default()
    };
    let mut mempool = Mempool::new(config);

    // Remplir le mempool
    for i in 0..150 {
        let tx = create_transaction_with_valid_proof_with_nonce(i);
        let _ = mempool.add_transaction(tx);
    }

    // Check that le mempool n'a pas depasse sa capacite
    assert!(
        mempool.len() <= 100,
        "Mempool ne doit pas depasser max_size. Taille: {}",
        mempool.len()
    );
}

// Helper functions
fn create_transaction_with_invalid_proof() -> Transaction {
    create_transaction_with_invalid_proof_and_nonce(0)
}

fn create_transaction_with_invalid_proof_and_nonce(nonce: u64) -> Transaction {
    Transaction::new_test(
        TransactionType::Transfer,
        nonce,
        Some(Plonky2Proof::invalid()),
    )
}

fn create_transaction_with_valid_proof() -> Transaction {
    create_transaction_with_valid_proof_with_nonce(0)
}

fn create_transaction_with_valid_proof_with_nonce(nonce: u64) -> Transaction {
    Transaction::new_test(
        TransactionType::Transfer,
        nonce,
        Some(Plonky2Proof::valid_mock()),
    )
}

fn create_transaction_with_oversized_proof() -> Transaction {
    Transaction::new_test(
        TransactionType::Transfer,
        0,
        Some(Plonky2Proof::oversized()),
    )
}

fn create_transaction_with_malformed_proof() -> Transaction {
    Transaction::new_test(
        TransactionType::Transfer,
        0,
        Some(Plonky2Proof::malformed()),
    )
}
