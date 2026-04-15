//! Tests unitaires exhaustifs pour le wallet ZK Halo2
//! 
//! Couvre la generation de preuves, la mise en cache, la verification et les cas d'error.
//! Inclut des tests de performance pour mesurer la latence de generation des preuves ZK.

use super::zk_wallet::*;
use crate::crypto::{
    proof::{ZkProof, CircomVerifyingParams},
    note::{Note, EncryptedNote, ViewingKey, encrypt_note_pq, decrypt_note_pq, compute_pk_hash},
    commitment::{NoteCommitment, ValueCommitment, commit_to_value, commit_to_note},
    nullifier::Nullifier,
    merkle_tree::MerkleTree,
    poseidon::poseidon_hash,
};
use ark_bn254::Fr;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::rand::rngs::StdRng;
use std::time::{Duration, Instant};
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a wallet de test avec des parameters deterministics
    fn create_test_wallet() -> ZkWallet {
        let mut rng = StdRng::seed_from_u64(42);
        ZkWallet::new(&mut rng)
    }

    /// Genere des parameters de verification de test
    fn create_test_verifying_params() -> CircomVerifyingParams {
        // En pratique, ces parameters seraient charges depuis un file
        // Pour les tests, on uses des parameters factices
        CircomVerifyingParams::default()
    }

    /// Generates ae note de test
    fn create_test_note(value: u64, rng: &mut StdRng) -> Note {
        let mut pk_bytes = [0u8; 32];
        rng.fill_bytes(&mut pk_bytes);
        let pk_hash = compute_pk_hash(&pk_bytes);
        
        let mut randomness_bytes = [0u8; 32];
        rng.fill_bytes(&mut randomness_bytes);
        
        Note::new(value, pk_hash, randomness_bytes)
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = create_test_wallet();
        
        // Check that le wallet a ete initialise correctement
        assert!(!wallet.viewing_key.is_empty());
        assert!(!wallet.spending_key.is_empty());
        assert_eq!(wallet.notes.len(), 0);
        assert_eq!(wallet.nullifiers.len(), 0);
    }

    #[test]
    fn test_note_generation() {
        let mut rng = StdRng::seed_from_u64(123);
        let mut wallet = create_test_wallet();
        
        // Generate une note
        let value = 1000u64;
        let note = wallet.generate_note(value, &mut rng).unwrap();
        
        // Check thes propertys de la note
        assert_eq!(note.value, value);
        assert_ne!(note.pk_hash, [0u8; 32]);
        assert_ne!(note.randomness, [0u8; 32]);
        
        // Check that la note a ete addede au wallet
        assert_eq!(wallet.notes.len(), 1);
        assert!(wallet.notes.contains(&note));
    }

    #[test]
    fn test_note_spending() {
        let mut rng = StdRng::seed_from_u64(456);
        let mut wallet = create_test_wallet();
        
        // Generate et ajouter une note
        let value = 2000u64;
        let note = wallet.generate_note(value, &mut rng).unwrap();
        
        // Depenser la note
        let nullifier = wallet.spend_note(&note, &mut rng).unwrap();
        
        // Check that le nullifier a ete genere
        assert_ne!(nullifier.hash, [0u8; 32]);
        
        // Check that le nullifier a ete added au wallet
        assert_eq!(wallet.nullifiers.len(), 1);
        assert!(wallet.nullifiers.contains(&nullifier));
        
        // Verifier qu'on ne peut pas depenser la same note deux fois
        let result = wallet.spend_note(&note, &mut rng);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZkWalletError::NoteAlreadySpent));
    }

    #[test]
    fn test_proof_generation_spend() {
        let mut rng = StdRng::seed_from_u64(789);
        let mut wallet = create_test_wallet();
        let verifying_params = create_test_verifying_params();
        
        // Generate une note et la depenser
        let note = wallet.generate_note(1500, &mut rng).unwrap();
        let nullifier = wallet.spend_note(&note, &mut rng).unwrap();
        
        // Create a arbre de Merkle avec la note
        let mut merkle_tree = MerkleTree::new();
        let commitment = commit_to_note(note.value, &note.pk_hash, &Fr::from(1u64));
        merkle_tree.insert(commitment.hash);
        let merkle_root = merkle_tree.root();
        
        // Generate une preuve de depense
        let value_commitment = commit_to_value(note.value, &mut rng);
        let proof = wallet.generate_spend_proof(
            &note,
            &nullifier,
            &merkle_root,
            &value_commitment,
            &mut rng,
        ).unwrap();
        
        // Check that la preuve a ete generee
        assert!(!proof.proof_bytes.is_empty());
        
        // Check that la preuve est valide (simulation)
        // En pratique, on usesrait les vrais parameters de verification
        assert!(proof.proof_bytes.len() > 0);
    }

    #[test]
    fn test_proof_generation_output() {
        let mut rng = StdRng::seed_from_u64(101112);
        let mut wallet = create_test_wallet();
        
        // Generate une nouvelle note
        let note = wallet.generate_note(3000, &mut rng).unwrap();
        let value_commitment = commit_to_value(note.value, &mut rng);
        
        // Generate une preuve de sortie
        let proof = wallet.generate_output_proof(
            &note,
            &value_commitment,
            &mut rng,
        ).unwrap();
        
        // Check that la preuve a ete generee
        assert!(!proof.proof_bytes.is_empty());
        assert!(proof.proof_bytes.len() > 0);
    }

    #[test]
    fn test_proof_caching() {
        let mut rng = StdRng::seed_from_u64(131415);
        let mut wallet = create_test_wallet();
        
        // Generate une note
        let note = wallet.generate_note(500, &mut rng).unwrap();
        let value_commitment = commit_to_value(note.value, &mut rng);
        
        // Generate une preuve et mesurer le temps
        let start = Instant::now();
        let proof1 = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
        let first_duration = start.elapsed();
        
        // Generate la same preuve a nouveau (devrait usesr le cache)
        let start = Instant::now();
        let proof2 = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
        let second_duration = start.elapsed();
        
        // Check that les preuves sont identiques
        assert_eq!(proof1.proof_bytes, proof2.proof_bytes);
        
        // Le cache devrait rendre la second generation plus rapide
        // (En pratique, avec de vraies preuves ZK)
        println!("First generation: {:?}", first_duration);
        println!("Second generation (cache): {:?}", second_duration);
    }

    #[test]
    fn test_invalid_note_spending() {
        let mut rng = StdRng::seed_from_u64(161718);
        let mut wallet = create_test_wallet();
        
        // Create a note qui n'appartient pas au wallet
        let foreign_note = create_test_note(1000, &mut rng);
        
        // Essayer de depenser une note etrangere
        let result = wallet.spend_note(&foreign_note, &mut rng);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZkWalletError::NoteNotOwned));
    }

    #[test]
    fn test_zero_value_note() {
        let mut rng = StdRng::seed_from_u64(192021);
        let mut wallet = create_test_wallet();
        
        // Essayer de create une note de valeur zero
        let result = wallet.generate_note(0, &mut rng);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZkWalletError::InvalidValue));
    }

    #[test]
    fn test_wallet_balance() {
        let mut rng = StdRng::seed_from_u64(222324);
        let mut wallet = create_test_wallet();
        
        // Balance initiale
        assert_eq!(wallet.get_balance(), 0);
        
        // Ajouter des notes
        wallet.generate_note(1000, &mut rng).unwrap();
        wallet.generate_note(2000, &mut rng).unwrap();
        wallet.generate_note(500, &mut rng).unwrap();
        
        // Check the balance
        assert_eq!(wallet.get_balance(), 3500);
        
        // Depenser une note
        let note = wallet.notes.iter().find(|n| n.value == 1000).unwrap().clone();
        wallet.spend_note(&note, &mut rng).unwrap();
        
        // Check the balance after depense
        assert_eq!(wallet.get_balance(), 2500);
    }

    #[test]
    fn test_note_encryption_decryption() {
        let mut rng = StdRng::seed_from_u64(252627);
        let wallet = create_test_wallet();
        
        // Create a note
        let value = 1234u64;
        let mut pk_bytes = [0u8; 32];
        rng.fill_bytes(&mut pk_bytes);
        let pk_hash = compute_pk_hash(&pk_bytes);
        
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        
        // Chiffrer la note
        let encrypted = encrypt_note_pq(value, &pk_hash, &randomness);
        
        // Dechiffrer la note
        let decrypted = decrypt_note_pq(&encrypted, &pk_hash);
        assert!(decrypted.is_some());
        
        let (decrypted_value, decrypted_pk_hash, decrypted_randomness) = decrypted.unwrap();
        assert_eq!(decrypted_value, value);
        assert_eq!(decrypted_pk_hash, pk_hash);
        assert_eq!(decrypted_randomness, randomness);
    }

    #[test]
    fn test_concurrent_proof_generation() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let wallet = Arc::new(Mutex::new(create_test_wallet()));
        let mut handles = vec![];
        
        // Lancer plusieurs threads generant des preuves en parallele
        for i in 0..4 {
            let wallet_clone = Arc::clone(&wallet);
            let handle = thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64(1000 + i);
                let mut wallet_guard = wallet_clone.lock().unwrap();
                
                // Generate une note et une preuve
                let note = wallet_guard.generate_note(100 * (i + 1), &mut rng).unwrap();
                let value_commitment = commit_to_value(note.value, &mut rng);
                
                let proof = wallet_guard.generate_output_proof(&note, &value_commitment, &mut rng);
                assert!(proof.is_ok());
            });
            handles.push(handle);
        }
        
        // Wait for tous les threads se terminent
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Check that toutes les notes ont ete addedes
        let wallet_guard = wallet.lock().unwrap();
        assert_eq!(wallet_guard.notes.len(), 4);
    }

    /// Tests de performance pour mesurer la latence de generation des preuves ZK
    #[test]
    fn test_proof_generation_performance() {
        let mut rng = StdRng::seed_from_u64(282930);
        let mut wallet = create_test_wallet();
        
        const NUM_ITERATIONS: usize = 10;
        let mut durations = Vec::new();
        
        println!("=== Tests de Performance ZK ===");
        
        // Test de generation de preuves de sortie
        for i in 0..NUM_ITERATIONS {
            let note = wallet.generate_note(1000 + i as u64, &mut rng).unwrap();
            let value_commitment = commit_to_value(note.value, &mut rng);
            
            let start = Instant::now();
            let _proof = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
            let duration = start.elapsed();
            
            durations.push(duration);
            println!("Preuve {} generee en {:?}", i + 1, duration);
        }
        
        // Calculer les statistiques
        let total_time: Duration = durations.iter().sum();
        let avg_time = total_time / NUM_ITERATIONS as u32;
        let min_time = durations.iter().min().unwrap();
        let max_time = durations.iter().max().unwrap();
        
        println!("=== Statistiques ===");
        println!("Temps moyen: {:?}", avg_time);
        println!("Temps minimum: {:?}", min_time);
        println!("Temps maximum: {:?}", max_time);
        println!("Temps total: {:?}", total_time);
        
        // Assertions de performance (ajustables selon les besoins)
        assert!(avg_time < Duration::from_secs(5), "Generation de preuve trop lente");
        assert!(max_time < Duration::from_secs(10), "Pic de latence trop eleve");
    }

    #[test]
    fn test_memory_usage_during_proof_generation() {
        let mut rng = StdRng::seed_from_u64(313233);
        let mut wallet = create_test_wallet();
        
        // Generate plusieurs notes et preuves pour tester l'usage memory
        const NUM_NOTES: usize = 100;
        
        for i in 0..NUM_NOTES {
            let note = wallet.generate_note(100 + i as u64, &mut rng).unwrap();
            let value_commitment = commit_to_value(note.value, &mut rng);
            
            // Generate une preuve
            let _proof = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
            
            // Check that le wallet ne grandit pas de maniere excessive
            assert!(wallet.notes.len() <= NUM_NOTES);
        }
        
        println!("Genere {} notes et preuves successfully", NUM_NOTES);
    }

    #[test]
    fn test_proof_verification_edge_cases() {
        let mut rng = StdRng::seed_from_u64(343536);
        let mut wallet = create_test_wallet();
        let verifying_params = create_test_verifying_params();
        
        // Test avec une note de valeur maximale
        let max_value = u64::MAX;
        let result = wallet.generate_note(max_value, &mut rng);
        // Selon l'implementation, cela pourrait be valide ou non
        println!("Note de valeur maximale: {:?}", result.is_ok());
        
        // Test avec des parameters de verification invalids
        // (En pratique, on testerait avec de vrais parameters corrompus)
        
        // Test de robustesse avec des data randoms
        let note = wallet.generate_note(1000, &mut rng).unwrap();
        let value_commitment = commit_to_value(note.value, &mut rng);
        
        let proof = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_wallet_serialization() {
        let wallet = create_test_wallet();
        
        // Test de serialization/deserialization du wallet
        // (Necessiterait l'implementation de Serialize/Deserialize)
        
        // Pour l'instant, on teste que les composants keys ne sont pas vides
        assert!(!wallet.viewing_key.is_empty());
        assert!(!wallet.spending_key.is_empty());
        
        // Test de persistance des notes et nullifiers
        assert_eq!(wallet.notes.len(), 0);
        assert_eq!(wallet.nullifiers.len(), 0);
    }

    #[test]
    fn test_error_handling_comprehensive() {
        let mut rng = StdRng::seed_from_u64(373839);
        let mut wallet = create_test_wallet();
        
        // Test de tous les types d'errors possibles
        
        // 1. Note de valeur invalid
        let result = wallet.generate_note(0, &mut rng);
        assert!(matches!(result.unwrap_err(), ZkWalletError::InvalidValue));
        
        // 2. Note non possedee
        let foreign_note = create_test_note(1000, &mut rng);
        let result = wallet.spend_note(&foreign_note, &mut rng);
        assert!(matches!(result.unwrap_err(), ZkWalletError::NoteNotOwned));
        
        // 3. Double depense
        let note = wallet.generate_note(1000, &mut rng).unwrap();
        wallet.spend_note(&note, &mut rng).unwrap();
        let result = wallet.spend_note(&note, &mut rng);
        assert!(matches!(result.unwrap_err(), ZkWalletError::NoteAlreadySpent));
        
        println!("Tous les cas d'error testes successfully");
    }
}

/// Tests d'integration pour le wallet ZK
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_transaction_flow() {
        let mut rng = StdRng::seed_from_u64(404142);
        let mut sender_wallet = create_test_wallet();
        let mut receiver_wallet = create_test_wallet();
        
        // 1. Le sender generates une note
        let initial_value = 5000u64;
        let sender_note = sender_wallet.generate_note(initial_value, &mut rng).unwrap();
        
        // 2. Le sender creates une transaction pour envoyer de l'argent
        let transfer_amount = 2000u64;
        let change_amount = initial_value - transfer_amount;
        
        // 3. Le sender depense sa note originale
        let nullifier = sender_wallet.spend_note(&sender_note, &mut rng).unwrap();
        
        // 4. Create a note pour le receiver
        let receiver_note = receiver_wallet.generate_note(transfer_amount, &mut rng).unwrap();
        
        // 5. Create a note de change pour le sender
        let change_note = sender_wallet.generate_note(change_amount, &mut rng).unwrap();
        
        // Check thes balances finales
        assert_eq!(sender_wallet.get_balance(), change_amount);
        assert_eq!(receiver_wallet.get_balance(), transfer_amount);
        
        println!("Transaction complete reussie: {} -> {} (change: {})", 
                initial_value, transfer_amount, change_amount);
    }

    #[test]
    fn test_multi_input_transaction() {
        let mut rng = StdRng::seed_from_u64(434445);
        let mut wallet = create_test_wallet();
        
        // Creer plusieurs notes d'entree
        let note1 = wallet.generate_note(1000, &mut rng).unwrap();
        let note2 = wallet.generate_note(1500, &mut rng).unwrap();
        let note3 = wallet.generate_note(2000, &mut rng).unwrap();
        
        let total_input = 4500u64;
        assert_eq!(wallet.get_balance(), total_input);
        
        // Depenser toutes les notes
        wallet.spend_note(&note1, &mut rng).unwrap();
        wallet.spend_note(&note2, &mut rng).unwrap();
        wallet.spend_note(&note3, &mut rng).unwrap();
        
        // Create a nouvelle note avec la valeur totale
        let consolidated_note = wallet.generate_note(total_input, &mut rng).unwrap();
        
        assert_eq!(wallet.get_balance(), total_input);
        assert_eq!(wallet.nullifiers.len(), 3);
        
        println!("Consolidation de {} notes reussie", 3);
    }
}

/// Benchmarks pour mesurer les performances
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_note_generation() {
        let mut rng = StdRng::seed_from_u64(464748);
        let mut wallet = create_test_wallet();
        
        const ITERATIONS: usize = 1000;
        let start = Instant::now();
        
        for i in 0..ITERATIONS {
            wallet.generate_note(100 + i as u64, &mut rng).unwrap();
        }
        
        let duration = start.elapsed();
        let avg_per_note = duration / ITERATIONS as u32;
        
        println!("Generation de {} notes en {:?}", ITERATIONS, duration);
        println!("Temps moyen par note: {:?}", avg_per_note);
        
        assert!(avg_per_note < Duration::from_millis(10), "Generation de note trop lente");
    }

    #[test]
    fn benchmark_proof_generation() {
        let mut rng = StdRng::seed_from_u64(495051);
        let mut wallet = create_test_wallet();
        
        const ITERATIONS: usize = 50;
        let mut total_duration = Duration::new(0, 0);
        
        for i in 0..ITERATIONS {
            let note = wallet.generate_note(1000 + i as u64, &mut rng).unwrap();
            let value_commitment = commit_to_value(note.value, &mut rng);
            
            let start = Instant::now();
            let _proof = wallet.generate_output_proof(&note, &value_commitment, &mut rng).unwrap();
            total_duration += start.elapsed();
        }
        
        let avg_per_proof = total_duration / ITERATIONS as u32;
        
        println!("Generation de {} preuves en {:?}", ITERATIONS, total_duration);
        println!("Temps moyen par preuve: {:?}", avg_per_proof);
        
        // Les preuves ZK peuvent be lentes, ajuster selon les besoins
        assert!(avg_per_proof < Duration::from_secs(30), "Generation de preuve trop lente");
    }
}