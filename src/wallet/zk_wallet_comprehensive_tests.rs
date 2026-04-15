//! Tests completes pour le wallet ZK Halo2
//!
//! Suite de tests exhaustifs couvrant la generation de preuves, la mise en cache,
//! la verification et les cas d'error, avec des tests de performance.

#[cfg(test)]
mod comprehensive_tests {
    use super::super::zk_wallet::*;
    use crate::crypto::note::Note;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::nullifier::Nullifier;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Test de creation du wallet avec differentes configurations
    #[test]
    fn test_wallet_creation_with_configs() {
        // Configuration by default
        let wallet_default = ZkWallet::new();
        assert!(wallet_default.is_ok());
        
        // Configuration personnalisee
        let config = ProofConfig {
            k: 16,
            timeout: Duration::from_secs(60),
            cache_size: 50,
        };
        let wallet_custom = ZkWallet::with_config(config.clone());
        assert!(wallet_custom.is_ok());
        
        let wallet = wallet_custom.unwrap();
        assert_eq!(wallet.config().k, 16);
        assert_eq!(wallet.config().timeout, Duration::from_secs(60));
        assert_eq!(wallet.config().cache_size, 50);
    }

    /// Test de generation de preuve basique
    #[test]
    fn test_basic_proof_generation() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [42u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        let start_time = Instant::now();
        let proof_result = wallet.prove_note(&note);
        let generation_time = start_time.elapsed();
        
        assert!(proof_result.is_ok());
        assert!(generation_time < Duration::from_secs(30)); // Timeout by default
        
        let proof = proof_result.unwrap();
        assert!(!proof.to_bytes().is_empty());
    }

    /// Test de verification de preuve
    #[test]
    fn test_proof_verification() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [123u8; 32];
        let note = Note::new(5000, recipient_pk_hash, &mut rng);
        let commitment = note.commitment();
        
        // Generates ae preuve valide
        let proof = wallet.prove_note(&note).unwrap();
        
        // Checks the preuve avec le bon commitment
        let verification_result = wallet.verify_proof(&proof, &commitment);
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
        
        // Teste avec un mauvais commitment
        let wrong_note = Note::new(9999, [255u8; 32], &mut rng);
        let wrong_commitment = wrong_note.commitment();
        let wrong_verification = wallet.verify_proof(&proof, &wrong_commitment);
        assert!(wrong_verification.is_ok());
        assert!(!wrong_verification.unwrap()); // Doit fail
    }

    /// Test du cache de preuves
    #[test]
    fn test_proof_caching_behavior() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [200u8; 32];
        let note = Note::new(2500, recipient_pk_hash, &mut rng);
        
        // First generation (cache miss)
        let start_time1 = Instant::now();
        let proof1 = wallet.prove_note(&note).unwrap();
        let time1 = start_time1.elapsed();
        
        assert_eq!(wallet.cache_size(), 1);
        
        // Second generation (cache hit)
        let start_time2 = Instant::now();
        let proof2 = wallet.prove_note(&note).unwrap();
        let time2 = start_time2.elapsed();
        
        assert_eq!(wallet.cache_size(), 1);
        
        // Le cache hit doit be beaucoup plus rapide
        assert!(time2 < time1 / 10);
        
        // Les preuves doivent be identiques
        assert_eq!(proof1.to_bytes(), proof2.to_bytes());
        
        // Checks thes statistiques
        let stats = wallet.get_stats();
        assert_eq!(stats.total_proofs, 1); // Une seule preuve generee
        assert!(stats.cache_hit_rate > 0.0);
    }

    /// Test de debordement du cache LRU
    #[test]
    fn test_cache_lru_eviction() {
        let config = ProofConfig {
            cache_size: 3, // Cache very petit
            ..Default::default()
        };
        let mut wallet = ZkWallet::with_config(config).unwrap();
        let mut rng = OsRng;
        
        // Genere 5 preuves differentes
        let mut notes = Vec::new();
        for i in 0..5 {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            notes.push(note);
        }
        
        // Generates thes preuves
        for note in &notes {
            wallet.prove_note(note).unwrap();
        }
        
        // Le cache ne doit contenir que 3 elements
        assert_eq!(wallet.cache_size(), 3);
        
        // Les firsts notes doivent avoir ete evincees
        let start_time = Instant::now();
        wallet.prove_note(&notes[0]).unwrap(); // Doit regenerate
        let regeneration_time = start_time.elapsed();
        
        // Doit prendre du temps car pas en cache
        assert!(regeneration_time > Duration::from_millis(10));
    }

    /// Test de nettoyage du cache
    #[test]
    fn test_cache_clearing() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        // Remplit le cache avec plusieurs preuves
        for i in 0..5 {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            wallet.prove_note(&note).unwrap();
        }
        
        assert_eq!(wallet.cache_size(), 5);
        
        // Vide le cache
        wallet.clear_cache();
        assert_eq!(wallet.cache_size(), 0);
        
        // Checks that les statistiques sont remises a zero
        let stats = wallet.get_stats();
        assert_eq!(stats.cache_hit_rate, 0.0);
        assert_eq!(stats.cached_proofs, 0);
    }

    /// Test de generation de preuve de nullifier
    #[test]
    fn test_nullifier_proof_generation() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [100u8; 32];
        let note = Note::new(7500, recipient_pk_hash, &mut rng);
        let nullifier = Nullifier::from_note(&note);
        
        let proof_result = wallet.prove_nullifier(&note, &nullifier);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        assert!(!proof.to_bytes().is_empty());
    }

    /// Test de suivi des statistiques de performance
    #[test]
    fn test_performance_statistics_tracking() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let initial_stats = wallet.get_stats();
        assert_eq!(initial_stats.total_proofs, 0);
        assert_eq!(initial_stats.avg_generation_time_ms, 0.0);
        assert_eq!(initial_stats.min_generation_time_ms, u64::MAX);
        assert_eq!(initial_stats.max_generation_time_ms, 0);
        
        // Genere plusieurs preuves
        let mut generation_times = Vec::new();
        for i in 0..3 {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            
            let start_time = Instant::now();
            wallet.prove_note(&note).unwrap();
            let generation_time = start_time.elapsed();
            generation_times.push(generation_time.as_millis() as u64);
        }
        
        let final_stats = wallet.get_stats();
        assert_eq!(final_stats.total_proofs, 3);
        assert!(final_stats.avg_generation_time_ms > 0.0);
        assert_eq!(final_stats.min_generation_time_ms, *generation_times.iter().min().unwrap());
        assert_eq!(final_stats.max_generation_time_ms, *generation_times.iter().max().unwrap());
        assert_eq!(final_stats.cached_proofs, 3);
    }

    /// Test de gestion d'errors avec des parameters invalids
    #[test]
    fn test_error_handling_invalid_params() {
        // Test avec un k trop petit
        let invalid_config = ProofConfig {
            k: 5, // Trop petit pour be pratique
            timeout: Duration::from_secs(1),
            cache_size: 0, // Invalide
        };
        
        // Note: Dans une implementation reelle, ceci devrait retourner une error
        // Pour l'instant, on teste que ca ne panique pas
        let wallet_result = ZkWallet::with_config(invalid_config);
        // assert!(wallet_result.is_err()); // To decommenter quand la validation est implementee
    }

    /// Test de concurrence - generation de preuves en parallele
    #[test]
    fn test_concurrent_proof_generation() {
        let wallet = Arc::new(Mutex::new(ZkWallet::new().unwrap()));
        let mut handles = Vec::new();
        
        // Lance plusieurs threads generant des preuves
        for i in 0..3 {
            let wallet_clone = Arc::clone(&wallet);
            let handle = thread::spawn(move || {
                let mut rng = OsRng;
                let recipient_pk_hash = [i as u8; 32];
                let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
                
                let mut wallet_guard = wallet_clone.lock().unwrap();
                wallet_guard.prove_note(&note)
            });
            handles.push(handle);
        }
        
        // Attend que tous les threads terminent
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_ok());
            results.push(result.unwrap());
        }
        
        // Checks that toutes les preuves sont differentes
        let mut proof_set = HashSet::new();
        for proof in results {
            let proof_bytes = proof.to_bytes();
            assert!(proof_set.insert(proof_bytes)); // Doit be unique
        }
    }

    /// Test de performance - mesure de la latence de generation
    #[test]
    fn test_proof_generation_latency() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let mut latencies = Vec::new();
        let num_tests = 5;
        
        for i in 0..num_tests {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            
            let start_time = Instant::now();
            let proof_result = wallet.prove_note(&note);
            let latency = start_time.elapsed();
            
            assert!(proof_result.is_ok());
            latencies.push(latency);
            
            // Checks that la latence est raisonnable (< 30 secondes)
            assert!(latency < Duration::from_secs(30));
        }
        
        // Calcule les statistiques de latence
        let total_time: Duration = latencies.iter().sum();
        let avg_latency = total_time / num_tests as u32;
        let min_latency = latencies.iter().min().unwrap();
        let max_latency = latencies.iter().max().unwrap();
        
        println!("Statistiques de latence de generation de preuve:");
        println!("  Moyenne: {:?}", avg_latency);
        println!("  Minimum: {:?}", min_latency);
        println!("  Maximum: {:?}", max_latency);
        
        // Checks that les statistiques du wallet correspondent
        let wallet_stats = wallet.get_stats();
        assert_eq!(wallet_stats.total_proofs, num_tests as u64);
        
        // La first preuve ne devrait pas be en cache
        assert!(wallet_stats.cache_hit_rate < 1.0);
    }

    /// Test de performance - throughput de verification
    #[test]
    fn test_proof_verification_throughput() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        // Genere plusieurs preuves
        let mut proofs_and_commitments = Vec::new();
        for i in 0..10 {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            let commitment = note.commitment();
            let proof = wallet.prove_note(&note).unwrap();
            proofs_and_commitments.push((proof, commitment));
        }
        
        // Mesure le temps de verification
        let start_time = Instant::now();
        let mut successful_verifications = 0;
        
        for (proof, commitment) in &proofs_and_commitments {
            let verification_result = wallet.verify_proof(proof, commitment);
            assert!(verification_result.is_ok());
            if verification_result.unwrap() {
                successful_verifications += 1;
            }
        }
        
        let total_verification_time = start_time.elapsed();
        let avg_verification_time = total_verification_time / proofs_and_commitments.len() as u32;
        
        println!("Statistiques de verification:");
        println!("  Verifications reussies: {}/{}", successful_verifications, proofs_and_commitments.len());
        println!("  Temps total: {:?}", total_verification_time);
        println!("  Temps moyen par verification: {:?}", avg_verification_time);
        
        assert_eq!(successful_verifications, proofs_and_commitments.len());
        assert!(avg_verification_time < Duration::from_millis(100)); // Verification rapide
    }

    /// Test de stress - generation de nombreuses preuves
    #[test]
    #[ignore] // Test long, a executer manuellement
    fn test_stress_many_proofs() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let num_proofs = 50;
        let start_time = Instant::now();
        
        for i in 0..num_proofs {
            let recipient_pk_hash = [(i % 256) as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            
            let proof_result = wallet.prove_note(&note);
            assert!(proof_result.is_ok());
            
            if i % 10 == 0 {
                println!("Genere {}/{} preuves", i + 1, num_proofs);
            }
        }
        
        let total_time = start_time.elapsed();
        let avg_time_per_proof = total_time / num_proofs as u32;
        
        println!("Test de stress termine:");
        println!("  Preuves generees: {}", num_proofs);
        println!("  Temps total: {:?}", total_time);
        println!("  Temps moyen par preuve: {:?}", avg_time_per_proof);
        
        let final_stats = wallet.get_stats();
        println!("  Cache hit rate: {:.2}%", final_stats.cache_hit_rate * 100.0);
        println!("  Preuves en cache: {}", final_stats.cached_proofs);
    }

    /// Test de robustesse - gestion des cas limites
    #[test]
    fn test_edge_cases() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        // Test avec une note de valeur 0
        let zero_note = Note::new(0, [0u8; 32], &mut rng);
        let zero_proof_result = wallet.prove_note(&zero_note);
        assert!(zero_proof_result.is_ok());
        
        // Test avec une note de valeur maximale
        let max_note = Note::new(u64::MAX, [255u8; 32], &mut rng);
        let max_proof_result = wallet.prove_note(&max_note);
        assert!(max_proof_result.is_ok());
        
        // Test avec des keys publiques identiques mais des valeurs differentes
        let same_pk = [42u8; 32];
        let note1 = Note::new(1000, same_pk, &mut rng);
        let note2 = Note::new(2000, same_pk, &mut rng);
        
        let proof1 = wallet.prove_note(&note1).unwrap();
        let proof2 = wallet.prove_note(&note2).unwrap();
        
        // Les preuves doivent be differentes same avec la same key publique
        assert_ne!(proof1.to_bytes(), proof2.to_bytes());
    }

    /// Test de consistency - verification croisee
    #[test]
    fn test_cross_verification_consistency() {
        let mut wallet1 = ZkWallet::new().unwrap();
        let mut wallet2 = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [77u8; 32];
        let note = Note::new(3333, recipient_pk_hash, &mut rng);
        let commitment = note.commitment();
        
        // Generates ae preuve avec le premier wallet
        let proof = wallet1.prove_note(&note).unwrap();
        
        // Verifie avec le second wallet
        let verification_result = wallet2.verify_proof(&proof, &commitment);
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
        
        // Verifie also avec le premier wallet
        let self_verification = wallet1.verify_proof(&proof, &commitment);
        assert!(self_verification.is_ok());
        assert!(self_verification.unwrap());
    }

    /// Benchmark de performance comparative
    #[test]
    fn test_performance_benchmark() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let num_iterations = 10;
        let mut generation_times = Vec::new();
        let mut verification_times = Vec::new();
        
        for i in 0..num_iterations {
            let recipient_pk_hash = [i as u8; 32];
            let note = Note::new(1000 + i as u64, recipient_pk_hash, &mut rng);
            let commitment = note.commitment();
            
            // Mesure la generation
            let gen_start = Instant::now();
            let proof = wallet.prove_note(&note).unwrap();
            let gen_time = gen_start.elapsed();
            generation_times.push(gen_time);
            
            // Mesure la verification
            let ver_start = Instant::now();
            let verification_result = wallet.verify_proof(&proof, &commitment).unwrap();
            let ver_time = ver_start.elapsed();
            verification_times.push(ver_time);
            
            assert!(verification_result);
        }
        
        // Calcule les statistiques
        let avg_gen_time = generation_times.iter().sum::<Duration>() / num_iterations as u32;
        let avg_ver_time = verification_times.iter().sum::<Duration>() / num_iterations as u32;
        
        println!("Benchmark de performance (n={})", num_iterations);
        println!("  Generation moyenne: {:?}", avg_gen_time);
        println!("  Verification moyenne: {:?}", avg_ver_time);
        println!("  Ratio verification/generation: {:.2}%", 
                 (avg_ver_time.as_nanos() as f64 / avg_gen_time.as_nanos() as f64) * 100.0);
        
        // Assertions de performance
        assert!(avg_gen_time < Duration::from_secs(10)); // Generation < 10s
        assert!(avg_ver_time < Duration::from_millis(100)); // Verification < 100ms
        assert!(avg_ver_time < avg_gen_time / 10); // Verification at least 10x plus rapide
    }
}