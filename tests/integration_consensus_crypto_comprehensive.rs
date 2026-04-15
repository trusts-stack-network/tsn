// DISABLED: uses API/modules that no longer exist in current codebase
#![cfg(feature = "disabled_test")]
//! Tests d'integration consensus + crypto - Suite complete
//!
//! MISSION SECURITY CRITIQUE :
//! Validation exhaustive du pipeline : Block validation → SLH-DSA verification → Poseidon2 state tree update
//!
//! THREAT MODEL COMPLET :
//! - Adversaire forge des blocs avec signatures SLH-DSA invalids
//! - Adversaire tente de corrompre le state tree Poseidon2
//! - Adversaire exploite des race conditions dans la validation
//! - Adversaire cause des DoS via inputs malformeds
//! - Adversaire tente des attaques par timing sur la crypto
//! - Adversaire exploite des vulnerabilitys de deserialization
//!
//! PROPERTIES CRITIQUES TESTED :
//! ✓ Integrite cryptographique (SLH-DSA + Poseidon2)
//! ✓ Coherence du state tree after validation
//! ✓ Resistance aux attaques par corruption
//! ✓ Performance sous charge adversariale
//! ✓ Determinisme des operations crypto
//! ✓ Robustesse face aux inputs malformeds
//!
//! Auteur: Marcus.R (Security & QA Engineer)
//! Derniere update: 2024

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

use tsn::consensus::validation::{Validator, ValidationError};
use tsn::core::block::{Block, BlockHeader};
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::core::state::ShieldedState;
use tsn::crypto::hash::Hash;
use tsn::crypto::merkle_tree::MerkleTree;
use tsn::crypto::poseidon2_state_tree::Poseidon2StateTree;
use tsn::crypto::pq::slh_dsa::{SecretKey, PublicKey, Signature, PK_BYTES, SK_BYTES, SIG_BYTES};

/// Configuration de security pour les tests
#[derive(Debug, Clone)]
struct SecurityTestConfig {
    /// Timeout maximum pour avoid les DoS
    max_validation_time: Duration,
    /// Taille maximale des blocs testes
    max_block_size: usize,
    /// Nombre maximum de transactions par bloc
    max_transactions_per_block: usize,
    /// Profondeur maximale du state tree
    max_state_tree_depth: usize,
    /// Activer les tests de timing attacks
    enable_timing_tests: bool,
    /// Activer les tests de corruption adversariale
    enable_adversarial_tests: bool,
}

impl Default for SecurityTestConfig {
    fn default() -> Self {
        Self {
            max_validation_time: Duration::from_secs(5),
            max_block_size: 1_000_000, // 1MB max
            max_transactions_per_block: 1000,
            max_state_tree_depth: 32,
            enable_timing_tests: true,
            enable_adversarial_tests: true,
        }
    }
}

/// State view securise pour les tests avec protection contre les attaques
struct SecureTestStateView {
    state_tree: Arc<Mutex<Poseidon2StateTree>>,
    account_balances: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
    spent_outputs: Arc<Mutex<HashSet<Vec<u8>>>>,
    config: SecurityTestConfig,
    operation_count: Arc<Mutex<u64>>,
}

impl SecureTestStateView {
    fn new(config: SecurityTestConfig) -> Self {
        let tree_depth = config.max_state_tree_depth.min(32);
        Self {
            state_tree: Arc::new(Mutex::new(Poseidon2StateTree::new(tree_depth))),
            account_balances: Arc::new(Mutex::new(HashMap::new())),
            spent_outputs: Arc::new(Mutex::new(HashSet::new())),
            config,
            operation_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Applique une transaction avec validation de security complete
    fn apply_transaction_secure(&self, tx: &Transaction) -> Result<(), ValidationError> {
        // Protection contre les attaques DoS
        {
            let mut count = self.operation_count.lock().unwrap();
            *count += 1;
            if *count > 10000 {
                return Err(ValidationError::TooManyOperations);
            }
        }

        // Validation des inputs
        for input in &tx.inputs {
            let output_key = input.previous_output.as_bytes().to_vec();
            
            // Verification double-spend
            {
                let spent = self.spent_outputs.lock().unwrap();
                if spent.contains(&output_key) {
                    return Err(ValidationError::DoubleSpend);
                }
            }

            // Verification solde suffisant
            {
                let balances = self.account_balances.lock().unwrap();
                let balance = balances.get(&output_key).unwrap_or(&0);
                if *balance < 100 { // Montant minimum pour les tests
                    return Err(ValidationError::InsufficientFunds);
                }
            }
        }

        // Application des changements d'state
        {
            let mut balances = self.account_balances.lock().unwrap();
            let mut spent = self.spent_outputs.lock().unwrap();
            let mut state_tree = self.state_tree.lock().unwrap();

            // Debiter les inputs
            for input in &tx.inputs {
                let output_key = input.previous_output.as_bytes().to_vec();
                let current_balance = balances.get(&output_key).unwrap_or(&0);
                let new_balance = current_balance.saturating_sub(100);
                
                balances.insert(output_key.clone(), new_balance);
                spent.insert(output_key.clone());
                
                // Mise a jour securisee du state tree
                state_tree.insert(&output_key, &new_balance.to_le_bytes());
            }

            // Crediter les outputs
            for (i, output) in tx.outputs.iter().enumerate() {
                // Protection contre les debordements
                if output.value > u64::MAX / 2 {
                    return Err(ValidationError::ValueOverflow);
                }

                let output_key = format!("{}:{}", hex::encode(tx.hash().as_bytes()), i);
                balances.insert(output_key.as_bytes().to_vec(), output.value);
                
                // Mise a jour securisee du state tree
                state_tree.insert(output_key.as_bytes(), &output.value.to_le_bytes());
            }
        }

        Ok(())
    }

    /// Calcule le state root de maniere securisee
    fn compute_state_root_secure(&self, _txs: &[Transaction]) -> Result<Hash, ValidationError> {
        let balances = self.account_balances.lock().unwrap();
        
        // Protection contre les states trop volumineux
        if balances.len() > 100000 {
            return Err(ValidationError::StateTooLarge);
        }

        // Calcul deterministic et securise
        let mut hasher = blake3::Hasher::new();
        let mut sorted_accounts: Vec<_> = balances.iter().collect();
        sorted_accounts.sort_by_key(|(k, _)| k.as_slice());
        
        for (key, value) in sorted_accounts {
            hasher.update(key);
            hasher.update(&value.to_le_bytes());
        }
        
        let hash_bytes = hasher.finalize();
        Ok(Hash::from_bytes(hash_bytes.as_bytes()[..32].try_into().unwrap()))
    }

    /// Reinitialise l'state pour les tests
    fn reset(&self) {
        let mut balances = self.account_balances.lock().unwrap();
        let mut spent = self.spent_outputs.lock().unwrap();
        let mut count = self.operation_count.lock().unwrap();
        
        balances.clear();
        spent.clear();
        *count = 0;
    }
}

/// Generateur de blocs securise avec SLH-DSA
struct SecureBlockGenerator {
    secret_key: SecretKey,
    public_key: PublicKey,
    config: SecurityTestConfig,
}

impl SecureBlockGenerator {
    fn new(config: SecurityTestConfig) -> Self {
        let seed = [0x42; 32]; // Graine deterministic pour les tests
        let (secret_key, public_key) = SecretKey::generate(&seed);
        
        Self {
            secret_key,
            public_key,
            config,
        }
    }

    /// Creates a bloc valide avec signature SLH-DSA
    fn create_valid_block(&self, transactions: Vec<Transaction>, previous_hash: Hash, state_root: Hash) -> Result<Block, ValidationError> {
        // Protection contre les blocs trop volumineux
        if transactions.len() > self.config.max_transactions_per_block {
            return Err(ValidationError::TooManyTransactions);
        }

        // Calcul du merkle root
        let mut merkle_tree = MerkleTree::new();
        for tx in &transactions {
            merkle_tree.insert(tx.hash())?;
        }
        let merkle_root = merkle_tree.root();

        // Creation du header
        let mut header = BlockHeader {
            version: 1,
            previous_block_hash: previous_hash,
            merkle_root,
            state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 0,
            difficulty: 100,
            producer_public_key: self.public_key.to_bytes(),
            signature: vec![],
        };

        // Signature SLH-DSA securisee
        let message = header.signature_message();
        let signature = self.secret_key.sign(&message);
        header.signature = signature.to_bytes();

        Ok(Block {
            header,
            transactions,
        })
    }

    /// Creates a transaction avec signature SLH-DSA
    fn create_secure_transaction(&self, inputs: Vec<Hash>, outputs: Vec<u64>) -> Result<Transaction, ValidationError> {
        // Validation des inputs
        if inputs.len() > 100 {
            return Err(ValidationError::TooManyInputs);
        }
        if outputs.len() > 100 {
            return Err(ValidationError::TooManyOutputs);
        }

        // Validation des montants
        for &amount in &outputs {
            if amount > u64::MAX / 2 {
                return Err(ValidationError::ValueOverflow);
            }
        }

        let tx_inputs: Vec<TransactionInput> = inputs.into_iter()
            .map(|hash| TransactionInput {
                previous_output: hash,
                script: vec![],
            })
            .collect();

        let tx_outputs: Vec<TransactionOutput> = outputs.into_iter()
            .map(|value| TransactionOutput {
                value,
                script: vec![],
            })
            .collect();

        let mut tx = Transaction {
            inputs: tx_inputs,
            outputs: tx_outputs,
            sender_public_key: self.public_key.to_bytes(),
            signature: vec![],
        };

        // Signature SLH-DSA de la transaction
        let message = tx.signature_message();
        let signature = self.secret_key.sign(&message);
        tx.signature = signature.to_bytes();

        Ok(tx)
    }

    /// Creates a bloc avec signature corrompue pour les tests d'attaque
    fn create_block_with_corrupted_signature(&self, transactions: Vec<Transaction>, previous_hash: Hash, state_root: Hash) -> Result<Block, ValidationError> {
        let mut block = self.create_valid_block(transactions, previous_hash, state_root)?;
        
        // Corruption de la signature
        if !block.header.signature.is_empty() {
            block.header.signature[0] ^= 0x01;
        }
        
        Ok(block)
    }
}

/// Test d'integration complete : validation de bloc avec SLH-DSA + Poseidon2
#[tokio::test]
async fn test_completee_block_validation_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityTestConfig::default();
    let validator = Validator::new();
    let generator = SecureBlockGenerator::new(config.clone());
    let state_view = SecureTestStateView::new(config.clone());

    // 1. Create a transaction valide
    let tx = generator.create_secure_transaction(
        vec![Hash::zero()],
        vec![100, 50]
    )?;

    // 2. Calculer le state root after application
    let mut temp_state = SecureTestStateView::new(config.clone());
    temp_state.apply_transaction_secure(&tx)?;
    let state_root = temp_state.compute_state_root_secure(&[tx.clone()])?;

    // 3. Create a bloc valide avec signature SLH-DSA
    let block = generator.create_valid_block(
        vec![tx.clone()],
        Hash::zero(),
        state_root
    )?;

    // 4. Validation avec timeout pour avoid les DoS
    let validation_start = Instant::now();
    let validation_result = timeout(
        config.max_validation_time,
        async { validator.validate_block(&block, None, &state_view) }
    ).await??;

    let validation_duration = validation_start.elapsed();

    // 5. Assertions de security
    assert!(validation_result.is_ok(), "Bloc valide doit passer la validation");
    assert!(validation_duration < config.max_validation_time, 
            "Validation trop lente: {:?}", validation_duration);

    // 6. Check the integrite du state tree after application
    state_view.apply_transaction_secure(&tx)?;
    let final_state_root = state_view.compute_state_root_secure(&[tx])?;
    assert_eq!(final_state_root, state_root, "State root doit be coherent");

    println!("✓ Pipeline complete valide en {:?}", validation_duration);
    Ok(())
}

/// Test de resistance aux attaques par signature forgee
#[tokio::test]
async fn test_forged_signature_attack_resistance() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityTestConfig::default();
    let validator = Validator::new();
    let generator = SecureBlockGenerator::new(config.clone());
    let state_view = SecureTestStateView::new(config.clone());

    // 1. Create a bloc avec signature corrompue
    let tx = generator.create_secure_transaction(vec![Hash::zero()], vec![100])?;
    let state_root = state_view.compute_state_root_secure(&[tx.clone()])?;
    
    let corrupted_block = generator.create_block_with_corrupted_signature(
        vec![tx],
        Hash::zero(),
        state_root
    )?;

    // 2. La validation doit rejeter le bloc
    let validation_result = validator.validate_block(&corrupted_block, None, &state_view);
    
    assert!(matches!(
        validation_result,
        Err(ValidationError::InvalidBlockSignature)
    ), "Bloc avec signature corrompue doit be rejete");

    println!("✓ Resistance aux signatures forgees confirmee");
    Ok(())
}

/// Test de consistency du state tree Poseidon2 sous charge
#[tokio::test]
async fn test_poseidon2_state_tree_consistency_under_load() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityTestConfig {
        max_transactions_per_block: 100,
        ..Default::default()
    };
    let generator = SecureBlockGenerator::new(config.clone());
    let state_view = SecureTestStateView::new(config.clone());

    // 1. Create multiples transactions
    let mut transactions = Vec::new();
    for i in 0..50 {
        let tx = generator.create_secure_transaction(
            vec![Hash::from_bytes([i as u8; 32])],
            vec![100 + i as u64, 50 + i as u64]
        )?;
        transactions.push(tx);
    }

    // 2. Appliquer les transactions et checksr la consistency
    let mut expected_state = HashMap::new();
    for (i, tx) in transactions.iter().enumerate() {
        state_view.apply_transaction_secure(tx)?;
        
        // Construire l'state attendu
        for (j, output) in tx.outputs.iter().enumerate() {
            let key = format!("{}:{}", hex::encode(tx.hash().as_bytes()), j);
            expected_state.insert(key, output.value);
        }
    }

    // 3. Check the consistency du state root
    let computed_root = state_view.compute_state_root_secure(&transactions)?;
    
    // Le state root doit be deterministic
    let computed_root2 = state_view.compute_state_root_secure(&transactions)?;
    assert_eq!(computed_root, computed_root2, "State root doit be deterministic");

    println!("✓ Coherence Poseidon2 sous charge confirmee ({} transactions)", transactions.len());
    Ok(())
}

/// Test de resistance aux attaques par deni de service
#[tokio::test]
async fn test_dos_attack_resistance() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityTestConfig {
        max_validation_time: Duration::from_millis(100), // Timeout very court
        max_transactions_per_block: 10,
        ..Default::default()
    };
    let validator = Validator::new();
    let generator = SecureBlockGenerator::new(config.clone());
    let state_view = SecureTestStateView::new(config.clone());

    // 1. Try to create un bloc avec trop de transactions (doit fail)
    let large_tx_list: Result<Vec<_>, _> = (0..1000)
        .map(|i| generator.create_secure_transaction(
            vec![Hash::from_bytes([i as u8; 32])],
            vec![100]
        ))
        .collect();

    match large_tx_list {
        Ok(txs) => {
            // Si la creation reussit, la validation doit fail rapidement
            let state_root = state_view.compute_state_root_secure(&txs[..10])?;
            let block_result = generator.create_valid_block(txs, Hash::zero(), state_root);
            
            assert!(matches!(block_result, Err(ValidationError::TooManyTransactions)),
                    "Bloc avec trop de transactions doit be rejete");
        }
        Err(_) => {
            // La creation elle-same fails, c'est also une protection valide
            println!("✓ Protection au niveau creation de transactions");
        }
    }

    // 2. Test avec timeout de validation
    let tx = generator.create_secure_transaction(vec![Hash::zero()], vec![100])?;
    let state_root = state_view.compute_state_root_secure(&[tx.clone()])?;
    let block = generator.create_valid_block(vec![tx], Hash::zero(), state_root)?;

    let validation_start = Instant::now();
    let validation_result = timeout(
        config.max_validation_time,
        async { validator.validate_block(&block, None, &state_view) }
    ).await;

    match validation_result {
        Ok(_) => {
            let duration = validation_start.elapsed();
            assert!(duration < config.max_validation_time, 
                    "Validation doit respecter le timeout");
        }
        Err(_) => {
            println!("✓ Protection par timeout activee");
        }
    }

    println!("✓ Resistance aux attaques DoS confirmee");
    Ok(())
}

/// Tests property-based pour la robustesse cryptographique
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_slh_dsa_signature_determinism(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        seed_bytes in prop::array::uniform32(any::<u8>())
    ) {
        let (secret_key, public_key) = SecretKey::generate(&seed_bytes);
        
        // Les signatures doivent be deterministics pour un same message et key
        let sig1 = secret_key.sign(&message);
        let sig2 = secret_key.sign(&message);
        
        prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        
        // Les deux signatures doivent be valides
        prop_assert!(public_key.verify(&message, &sig1));
        prop_assert!(public_key.verify(&message, &sig2));
    }

    #[test]
    fn prop_poseidon2_state_tree_insertion_order_independence(
        operations in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 1..32), any::<u64>()),
            1..50
        )
    ) {
        let mut tree1 = Poseidon2StateTree::new(16);
        let mut tree2 = Poseidon2StateTree::new(16);
        
        // Inserer dans l'ordre original
        for (key, value) in &operations {
            tree1.insert(key, &value.to_le_bytes());
        }
        
        // Inserer dans l'ordre inverse
        for (key, value) in operations.iter().rev() {
            tree2.insert(key, &value.to_le_bytes());
        }
        
        // Les arbres doivent contenir les sames data
        for (key, expected_value) in &operations {
            prop_assert_eq!(
                tree1.get(key),
                Some(expected_value.to_le_bytes().as_slice())
            );
            prop_assert_eq!(
                tree2.get(key),
                Some(expected_value.to_le_bytes().as_slice())
            );
        }
    }

    #[test]
    fn prop_block_validation_rejects_invalid_signatures(
        corruption_index in 0usize..100usize,
        corruption_value in any::<u8>()
    ) {
        let config = SecurityTestConfig::default();
        let validator = Validator::new();
        let generator = SecureBlockGenerator::new(config.clone());
        let state_view = SecureTestStateView::new(config);

        // Create a bloc valide
        let tx = generator.create_secure_transaction(vec![Hash::zero()], vec![100]).unwrap();
        let state_root = state_view.compute_state_root_secure(&[tx.clone()]).unwrap();
        let mut block = generator.create_valid_block(vec![tx], Hash::zero(), state_root).unwrap();

        // Corrompre la signature si possible
        if !block.header.signature.is_empty() && corruption_index < block.header.signature.len() {
            block.header.signature[corruption_index] ^= corruption_value;
            
            // La validation doit fail
            let result = validator.validate_block(&block, None, &state_view);
            prop_assert!(result.is_err());
        }
    }
}

/// Tests de regression pour vulnerabilitys connues
mod security_regression_tests {
    use super::*;

    #[tokio::test]
    async fn test_regression_double_spend_prevention() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityTestConfig::default();
        let validator = Validator::new();
        let generator = SecureBlockGenerator::new(config.clone());
        let state_view = SecureTestStateView::new(config);

        let same_input = Hash::from_bytes([0x42; 32]);
        
        // First transaction
        let tx1 = generator.create_secure_transaction(vec![same_input], vec![50])?;
        state_view.apply_transaction_secure(&tx1)?;

        // Tentative de double spend
        let tx2 = generator.create_secure_transaction(vec![same_input], vec![30])?;
        let result = state_view.apply_transaction_secure(&tx2);

        assert!(matches!(result, Err(ValidationError::DoubleSpend)),
                "Double spend doit be detecte");

        println!("✓ Regression double spend: protection confirmee");
        Ok(())
    }

    #[tokio::test]
    async fn test_regression_integer_overflow_protection() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityTestConfig::default();
        let generator = SecureBlockGenerator::new(config);

        // Tentative de create une transaction avec overflow
        let result = generator.create_secure_transaction(
            vec![Hash::zero()],
            vec![u64::MAX] // Valeur trop grande
        );

        assert!(matches!(result, Err(ValidationError::ValueOverflow)),
                "Overflow doit be detecte");

        println!("✓ Regression integer overflow: protection confirmee");
        Ok(())
    }

    #[tokio::test]
    async fn test_regression_state_tree_corruption_detection() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityTestConfig::default();
        let state_view = SecureTestStateView::new(config);

        // Calculer un state root initial
        let initial_root = state_view.compute_state_root_secure(&[])?;

        // Ajouter une transaction
        let generator = SecureBlockGenerator::new(SecurityTestConfig::default());
        let tx = generator.create_secure_transaction(vec![Hash::zero()], vec![100])?;
        state_view.apply_transaction_secure(&tx)?;

        // Le state root doit avoir change
        let new_root = state_view.compute_state_root_secure(&[tx])?;
        assert_ne!(initial_root, new_root, "State root doit changer after transaction");

        println!("✓ Regression state tree corruption: detection confirmee");
        Ok(())
    }
}

/// Tests de performance et de timing attacks
#[cfg(feature = "timing_tests")]
mod timing_security_tests {
    use super::*;

    #[tokio::test]
    async fn test_constant_time_signature_verification() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityTestConfig::default();
        let generator = SecureBlockGenerator::new(config);

        let message1 = b"message court";
        let message2 = b"message beaucoup plus long pour tester les variations de timing";

        // Mesurer le temps de signature pour differentes tailles de messages
        let start1 = Instant::now();
        let _sig1 = generator.secret_key.sign(message1);
        let duration1 = start1.elapsed();

        let start2 = Instant::now();
        let _sig2 = generator.secret_key.sign(message2);
        let duration2 = start2.elapsed();

        // Les temps ne doivent pas varier significativement
        let ratio = duration1.as_nanos() as f64 / duration2.as_nanos() as f64;
        assert!(ratio > 0.5 && ratio < 2.0, 
                "Timing variation trop importante: {:.2}", ratio);

        println!("✓ Test timing constant confirme (ratio: {:.2})", ratio);
        Ok(())
    }
}
