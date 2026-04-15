//! Fuzzer: Transactions malformedes
//!
//! Ce fuzzer teste la validation des transactions contre des
//! entrees malveillantes qui pourraient causer:
//! - Panics
//! - Integer overflows
//! - Consommation excessive de memory
//! - Bypass de validation
//!
//! # Surfaces d'attaque
//! - Deserialization de transactions
//! - Validation des montants
//! - Parsing des signatures
//! - Verification des preuves ZK
//!
//! # Usage
//! ```bash
//! cargo fuzz run transaction_fuzzer
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsn::core::transaction::{Transaction, TransactionValidator};
use tsn::crypto::signature::SignatureVerifier;

fuzz_target!(|data: &[u8]| {
    // Test 1: Deserialization securisee
    // Ne doit jamais paniquer
    let tx_result = Transaction::deserialize(data);

    // Test 2: Si deserialization reussit, valider
    if let Ok(tx) = tx_result {
        // Validation basique
        let _ = TransactionValidator::validate_basic(&tx);

        // Check thes invariants
        if let Some(amount) = tx.amount() {
            // Pas d'overflow sur les montants
            assert!(
                amount <= u64::MAX / 2,
                "Montant suspect: {}"
            );
        }

        // Check the taille des signatures
        if let Some(sig) = tx.signature() {
            assert!(
                sig.len() <= 8096,
                "Signature surdimensionnee: {}",
                sig.len()
            );
        }

        // Check the taille des preuves ZK
        if let Some(proof) = tx.zk_proof() {
            assert!(
                proof.len() <= 100_000,
                "Preuve ZK surdimensionnee: {}",
                proof.len()
            );
        }
    }

    // Test 3: Tentative de validation de signature
    // Same avec des data randoms, ne doit pas paniquer
    if data.len() >= 64 {
        let sig = &data[0..64];
        let msg = &data[64..];
        let _ = SignatureVerifier::verify_mock(sig, msg);
    }

    // Test 4: Test de malleabilite
    // Modifier legerement les data et checksr que
    // la validation fails ou reussit de maniere coherente
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        
        let tx1 = Transaction::deserialize(data);
        let tx2 = Transaction::deserialize(&modified);

        // Si les deux parsent, ils devraient be differents
        if let (Ok(t1), Ok(t2)) = (&tx1, &tx2) {
            assert_ne!(
                t1.hash(),
                t2.hash(),
                "Malleabilite detectee"
            );
        }
    }
});
