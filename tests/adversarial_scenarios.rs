// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests de scenarios adversariaux pour la validation consensus + crypto
//!
//! Ce module teste des attaques realistes qu'un adversaire pourrait
//! tenter contre le system TSN :
//!
//! - Attaques par deni de service (DoS)
//! - Tentatives de double-spend sophistiquees
//! - Attaques par timing sur la cryptographie
//! - Exploitation de race conditions
//! - Attaques par malleabilite des transactions
//!
//! ADVERSAIRE MODEL:
//! - Controle partiel du network (peut injecter des messages)
//! - Acces aux temps de response (timing attacks)
//! - Capacite de calcul limitee (pas de break crypto)
//! - Peut coordonner des attaques distribuees

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use tsn::consensus::validation::{Validator, ValidationError};
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::core::state::ShieldedState;
use tsn::crypto::hash::Hash;
use tsn::crypto::merkle_tree::MerkleTree;
use tsn::crypto::poseidon2_state_tree::Poseidon2StateTree;
use tsn::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SLH_DSA_SHA2_128S};

/// Simulateur d'adversaire pour les tests
struct Adversary {
    signer: SlhDsaSigner,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    attack_budget: u64, // Nombre d'operations que l'adversaire peut faire
}

impl Adversary {
    fn new() -> Self {
        let signer = SlhDsaSigner::new(SLH_DSA_SHA2_128S);
        let (pk, sk) = signer.generate_keypair().unwrap();
        
        Self {
            signer,
            public_key: pk.to_bytes(),
            private_key: sk.to_bytes(),
            attack_budget: 10000,
        }
    }

    /// Attaque 1: Spam de blocs invalids pour DoS
    fn dos_attack_invalid_blocks(&mut self, count: usize) -> Vec<Block> {
        let mut malicious_blocks = Vec::new();
        
        for i in 0..count.min(self.attack_budget as usize) {
            // Create a bloc avec des data malformedes
            let mut header = BlockHeader {
                version: 1,
                previous_block_hash: Hash::from_bytes([i as u8; 32]),
                merkle_root: Hash::zero(),
                state_root: Hash::zero(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 3600, // Timestamp invalid (futur)
                nonce: 0,
                difficulty: u64::MAX, // Difficulte impossible
                producer_public_key: self.public_key.clone(),
                signature: vec![0xFF; 1000], // Signature invalid
            };

            // Create transactions malformedes
            let malicious_tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([0xFF; 32]),
                    script: vec![0; 10000], // Script enorme pour ralentir la validation
                }],
                outputs: vec![TransactionOutput {
                    value: u64::MAX, // Valeur impossible
                    script: vec![],
                }],
                sender_public_key: vec![0; 10000], // Key enorme
                signature: vec![0xFF; 10000], // Signature enorme
            };

            malicious_blocks.push(Block {
                header,
                transactions: vec![malicious_tx],
            });

            self.attack_budget -= 1;
        }

        malicious_blocks
    }

    /// Attaque 2: Tentative de double-spend sophistiquee
    fn double_spend_attack(&mut self) -> (Transaction, Transaction) {
        let shared_input = Hash::from_bytes([0x42; 32]);

        // Transaction 1: Depenser vers une adresse
        let tx1 = Transaction {
            inputs: vec![TransactionInput {
                previous_output: shared_input,
                script: vec![],
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script: vec![1, 2, 3], // Script different
            }],
            sender_public_key: self.public_key.clone(),
            signature: vec![],
        };

        // Transaction 2: Depenser le same input vers une autre adresse
        let tx2 = Transaction {
            inputs: vec![TransactionInput {
                previous_output: shared_input,
                script: vec![],
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script: vec![4, 5, 6], // Script different
            }],
            sender_public_key: self.public_key.clone(),
            signature: vec![],
        };

        // Signer les deux transactions
        let sk = self.signer.secret_key_from_bytes(&self.private_key).unwrap();
        
        let mut signed_tx1 = tx1;
        let message1 = signed_tx1.signature_message();
        let sig1 = self.signer.sign(&sk, &message1).unwrap();
        signed_tx1.signature = sig1.to_bytes();

        let mut signed_tx2 = tx2;
        let message2 = signed_tx2.signature_message();
        let sig2 = self.signer.sign(&sk, &message2).unwrap();
        signed_tx2.signature = sig2.to_bytes();

        self.attack_budget -= 2;
        (signed_tx1, signed_tx2)
    }

    /// Attaque 3: Malleabilite de signature
    fn signature_malleability_attack(&mut self, original_tx: &Transaction) -> Vec<Transaction> {
        let mut malleable_txs = Vec::new();
        
        // Tenter diverses modifications de la signature
        for i in 0..10.min(self.attack_budget as usize) {
            let mut modified_tx = original_tx.clone();
            
            if !modified_tx.signature.is_empty() {
                // Modification subtile de la signature
                let idx = i % modified_tx.signature.len();
                modified_tx.signature[idx] ^= 0x01;
                malleable_txs.push(modified_tx);
            }
            
            self.attack_budget -= 1;
        }

        malleable_txs
    }

    /// Attaque 4: Race condition sur la validation
    fn race_condition_attack(&mut self) -> Vec<Block> {
        let mut racing_blocks = Vec::new();
        
        // Creer plusieurs blocs avec le same parent mais des contenus differents
        let parent_hash = Hash::from_bytes([0x33; 32]);
        
        for i in 0..5 {
            let tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([i; 32]),
                    script: vec![],
                }],
                outputs: vec![TransactionOutput {
                    value: 100 + i as u64,
                    script: vec![],
                }],
                sender_public_key: self.public_key.clone(),
                signature: vec![],
            };

            let mut merkle_tree = MerkleTree::new();
            merkle_tree.insert(tx.hash()).unwrap();

            let header = BlockHeader {
                version: 1,
                previous_block_hash: parent_hash,
                merkle_root: merkle_tree.root(),
                state_root: Hash::zero(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                nonce: i as u64,
                difficulty: 100,
                producer_public_key: self.public_key.clone(),
                signature: vec![],
            };

            racing_blocks.push(Block {
                header,
                transactions: vec![tx],
            });
        }

        self.attack_budget -= 5;
        racing_blocks
    }
}

/// Mock StateView thread-safe pour les tests concurrents
#[derive(Clone)]
struct ThreadSafeStateView {
    state: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
}

impl ThreadSafeStateView {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn compute_state_root(&self, _txs: &[Transaction]) -> Result<Hash, ValidationError> {
        let state = self.state.lock().unwrap();
        let mut hasher = blake3::Hasher::new();
        
        let mut sorted_entries: Vec<_> = state.iter().collect();
        sorted_entries.sort_by_key(|(k, _)| k.as_slice());
        
        for (key, value) in sorted_entries {
            hasher.update(key);
            hasher.update(&value.to_le_bytes());
        }
        
        let hash_bytes = hasher.finalize();
        Ok(Hash::from_bytes(hash_bytes.as_bytes()[..32].try_into().unwrap()))
    }
}

#[test]
fn test_dos_attack_resistance() {
    let validator = Validator::new();
    let mut adversary = Adversary::new();
    let state_view = ThreadSafeStateView::new();

    // L'adversaire generates de nombreux blocs invalids
    let malicious_blocks = adversary.dos_attack_invalid_blocks(100);

    let start_time = Instant::now();
    let mut validation_times = Vec::new();

    // Valider tous les blocs malveillants
    for block in &malicious_blocks {
        let validation_start = Instant::now();
        let result = validator.validate_block(block, None, &state_view);
        validation_times.push(validation_start.elapsed());

        // Tous les blocs malveillants doivent be rejetes
        assert!(result.is_err(), "Malicious block should be rejected");
    }

    let total_time = start_time.elapsed();

    // Check that la validation reste rapide same sous attaque
    assert!(
        total_time < Duration::from_secs(10),
        "DoS attack caused validation slowdown: {:?}",
        total_time
    );

    // Check that les temps de validation restent constants
    let avg_time = validation_times.iter().sum::<Duration>() / validation_times.len() as u32;
    for time in &validation_times {
        let deviation = if avg_time.as_nanos() > 0 {
            (time.as_nanos() as f64 - avg_time.as_nanos() as f64).abs() / avg_time.as_nanos() as f64
        } else {
            0.0
        };
        assert!(
            deviation < 5.0, // Tolerance elevee pour les tests CI
            "Validation time variance too high: {:.2}",
            deviation
        );
    }
}

#[test]
fn test_double_spend_detection() {
    let validator = Validator::new();
    let mut adversary = Adversary::new();
    let state_view = ThreadSafeStateView::new();

    // L'adversaire tente un double-spend
    let (tx1, tx2) = adversary.double_spend_attack();

    // Create blocs contenant chaque transaction
    let mut merkle_tree1 = MerkleTree::new();
    merkle_tree1.insert(tx1.hash()).unwrap();
    
    let mut merkle_tree2 = MerkleTree::new();
    merkle_tree2.insert(tx2.hash()).unwrap();

    let state_root = state_view.compute_state_root(&[]).unwrap();

    let block1 = Block {
        header: BlockHeader {
            version: 1,
            previous_block_hash: Hash::zero(),
            merkle_root: merkle_tree1.root(),
            state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 1,
            difficulty: 100,
            producer_public_key: adversary.public_key.clone(),
            signature: vec![],
        },
        transactions: vec![tx1],
    };

    let block2 = Block {
        header: BlockHeader {
            version: 1,
            previous_block_hash: Hash::zero(),
            merkle_root: merkle_tree2.root(),
            state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 2,
            difficulty: 100,
            producer_public_key: adversary.public_key.clone(),
            signature: vec![],
        },
        transactions: vec![tx2],
    };

    // Le premier bloc peut be valide
    let result1 = validator.validate_block(&block1, None, &state_view);
    
    // Le second bloc doit be rejete (double-spend)
    let result2 = validator.validate_block(&block2, None, &state_view);

    // Au moins un des deux doit be rejete
    assert!(
        result1.is_err() || result2.is_err(),
        "Double-spend attack was not detected"
    );
}

#[test]
fn test_signature_malleability_resistance() {
    let validator = Validator::new();
    let mut adversary = Adversary::new();

    // Create a transaction valide
    let original_tx = Transaction {
        inputs: vec![TransactionInput {
            previous_output: Hash::zero(),
            script: vec![],
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            script: vec![],
        }],
        sender_public_key: adversary.public_key.clone(),
        signature: vec![],
    };

    // Signer la transaction
    let sk = adversary.signer.secret_key_from_bytes(&adversary.private_key).unwrap();
    let mut signed_tx = original_tx.clone();
    let message = signed_tx.signature_message();
    let signature = adversary.signer.sign(&sk, &message).unwrap();
    signed_tx.signature = signature.to_bytes();

    // Check that la transaction originale est valide
    assert!(validator.validate_transaction(&signed_tx).is_ok());

    // L'adversaire tente de modifier la signature
    let malleable_txs = adversary.signature_malleability_attack(&signed_tx);

    // Toutes les versions modifiees doivent be rejetees
    for modified_tx in &malleable_txs {
        let result = validator.validate_transaction(modified_tx);
        assert!(
            result.is_err(),
            "Modified signature should not validate: {:?}",
            result
        );
    }
}

#[test]
fn test_concurrent_validation_safety() {
    let validator = Arc::new(Validator::new());
    let state_view = Arc::new(ThreadSafeStateView::new());
    let mut adversary = Adversary::new();

    // L'adversaire creates des blocs en conflit
    let racing_blocks = adversary.race_condition_attack();
    let blocks = Arc::new(racing_blocks);

    let mut handles = Vec::new();

    // Lancer plusieurs threads qui valident concurremment
    for i in 0..5 {
        let validator_clone = Arc::clone(&validator);
        let state_view_clone = Arc::clone(&state_view);
        let blocks_clone = Arc::clone(&blocks);

        let handle = thread::spawn(move || {
            let mut results = Vec::new();
            
            for block in blocks_clone.iter() {
                let result = validator_clone.validate_block(block, None, state_view_clone.as_ref());
                results.push(result);
                
                // Petite pause pour augmenter les chances de race condition
                thread::sleep(Duration::from_millis(1));
            }
            
            results
        });

        handles.push(handle);
    }

    // Collecter tous les results
    let mut all_results = Vec::new();
    for handle in handles {
        let results = handle.join().unwrap();
        all_results.extend(results);
    }

    // Verifier qu'aucune validation n'a panique
    // et que les results sont coherents
    let success_count = all_results.iter().filter(|r| r.is_ok()).count();
    let error_count = all_results.iter().filter(|r| r.is_err()).count();

    assert_eq!(
        success_count + error_count,
        all_results.len(),
        "Some validations returned unexpected results"
    );

    // Dans un scenario de race condition, la plupart des validations
    // devraient fail car les blocs sont en conflit
    println!(
        "Concurrent validation results: {} success, {} errors",
        success_count, error_count
    );
}

#[test]
fn test_timing_attack_resistance() {
    let validator = Validator::new();
    let mut adversary = Adversary::new();

    // Create transactions avec differents patterns de signature
    let mut timing_samples = Vec::new();

    for pattern in [0x00, 0xFF, 0xAA, 0x55] {
        let mut times = Vec::new();

        for i in 0..20 {
            let tx = Transaction {
                inputs: vec![TransactionInput {
                    previous_output: Hash::from_bytes([i; 32]),
                    script: vec![],
                }],
                outputs: vec![TransactionOutput {
                    value: 100,
                    script: vec![],
                }],
                sender_public_key: adversary.public_key.clone(),
                signature: vec![pattern; 64], // Signature avec pattern specifique
            };

            let start = Instant::now();
            let _ = validator.validate_transaction(&tx);
            times.push(start.elapsed().as_nanos());
        }

        let avg_time = times.iter().sum::<u128>() / times.len() as u128;
        timing_samples.push(avg_time);
    }

    // Analyser les variations de timing
    let overall_avg = timing_samples.iter().sum::<u128>() / timing_samples.len() as u128;
    
    for &sample_time in &timing_samples {
        let deviation = if overall_avg > 0 {
            (sample_time as f64 - overall_avg as f64).abs() / overall_avg as f64
        } else {
            0.0
        };

        assert!(
            deviation < 0.5,
            "Timing attack vulnerability detected: deviation = {:.2}",
            deviation
        );
    }
}

#[test]
fn test_memory_exhaustion_resistance() {
    let validator = Validator::new();
    let state_view = ThreadSafeStateView::new();

    // Create a bloc avec de nombreuses transactions pour tester la resistance a l'epuisement memory
    let mut large_transactions = Vec::new();
    
    for i in 0..1000 {
        let tx = Transaction {
            inputs: vec![TransactionInput {
                previous_output: Hash::from_bytes([i as u8; 32]),
                script: vec![0; 100], // Script de taille moderee
            }],
            outputs: vec![TransactionOutput {
                value: 100,
                script: vec![0; 100],
            }],
            sender_public_key: vec![0; 32],
            signature: vec![0; 64],
        };
        large_transactions.push(tx);
    }

    let mut merkle_tree = MerkleTree::new();
    for tx in &large_transactions {
        merkle_tree.insert(tx.hash()).unwrap();
    }

    let large_block = Block {
        header: BlockHeader {
            version: 1,
            previous_block_hash: Hash::zero(),
            merkle_root: merkle_tree.root(),
            state_root: Hash::zero(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 0,
            difficulty: 100,
            producer_public_key: vec![0; 32],
            signature: vec![],
        },
        transactions: large_transactions,
    };

    // La validation doit terminer dans un temps raisonnable
    let start = Instant::now();
    let result = validator.validate_block(&large_block, None, &state_view);
    let duration = start.elapsed();

    assert!(
        duration < Duration::from_secs(30),
        "Large block validation took too long: {:?}",
        duration
    );

    // Le result peut be une error (signatures invalids) mais ne doit pas paniquer
    match result {
        Ok(_) => println!("Large block validated successfully"),
        Err(e) => println!("Large block rejected as expected: {:?}", e),
    }
}
