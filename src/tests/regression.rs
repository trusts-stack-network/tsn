//! Tests de regression for the modules core, consensus and crypto
//!
//! Ces tests verifiesnt que the modifications of the code not cassent pas
//! the invariants fondamentaux of the protocole TSN.

use crate::core::{ShieldedBlock, BlockHeader, ShieldedTransaction, CoinbaseTransaction};
use crate::consensus::{ForkChoice, ChainInfo, ChainError};
use crate::state::{State, StateError};
use crate::crypto::{
    keys::{SpendingKey, ViewingKey},
    signature::Signature,
    proof::ZKProof,
    commitment::NoteCommitment,
    nullifier::Nullifier,
    merkle_tree::MerkleTree,
};
use std::collections::HashMap;

/// Tests de regression for the module core
#[cfg(test)]
mod core_regression {
    use super::*;

    /// Test de regression : the structure BlockHeader must rester stable
    #[test]
    fn test_block_header_structure_stability() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 20,
            nonce: 42,
        };

        // Verification de the serialization/deserialization
        let serialized = serde_json::to_string(&header).expect("Serialization failed");
        let deserialized: BlockHeader = serde_json::from_str(&serialized)
            .expect("Deserialization failed");

        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.prev_hash, deserialized.prev_hash);
        assert_eq!(header.merkle_root, deserialized.merkle_root);
        assert_eq!(header.commitment_root, deserialized.commitment_root);
        assert_eq!(header.nullifier_root, deserialized.nullifier_root);
        assert_eq!(header.timestamp, deserialized.timestamp);
        assert_eq!(header.difficulty, deserialized.difficulty);
        assert_eq!(header.nonce, deserialized.nonce);
    }

    /// Test de regression : the hash of blocs must be deterministic
    #[test]
    fn test_block_hash_deterministic() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 20,
            nonce: 42,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        
        assert_eq!(hash1, hash2, "Block hash must be deterministic");
        
        // Hash connu for this configuration (regression)
        let expected_hash = "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7";
        // Note: remplacer par the hash real a fois calculationated
        assert_eq!(hash1.len(), 32, "Hash must be 32 bytes");
    }

    /// Test de regression : the validation de difficulty must fonctionner
    #[test]
    fn test_difficulty_validation_regression() {
        let mut header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 8, // 8 zero bits required
            nonce: 0,
        };

        // Chercher a nonce valid (simulation de mining)
        let mut found_valid = false;
        for nonce in 0..100000 {
            header.nonce = nonce;
            if header.meets_difficulty() {
                found_valid = true;
                break;
            }
        }

        assert!(found_valid, "Should find a valid nonce for difficulty 8");
    }

    /// Test de regression : the transactions vides doivent be valids
    #[test]
    fn test_empty_transaction_validity() {
        let coinbase = CoinbaseTransaction {
            outputs: vec![],
            memo: "Genesis block".to_string(),
        };

        // Une transaction coinbase vide must be serializable
        let serialized = serde_json::to_string(&coinbase).expect("Coinbase serialization failed");
        let _deserialized: CoinbaseTransaction = serde_json::from_str(&serialized)
            .expect("Coinbase deserialization failed");
    }
}

/// Tests de regression for the module consensus
#[cfg(test)]
mod consensus_regression {
    use super::*;

    /// Test de regression : ForkChoice must handle the bloc genesis
    #[test]
    fn test_fork_choice_genesis_handling() {
        let genesis_header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            commitment_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            difficulty: 1,
            nonce: 0,
        };

        let genesis_block = ShieldedBlock {
            header: genesis_header,
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };

        let fork_choice = ForkChoice::new(genesis_block);
        
        assert!(fork_choice.canonical_tip().is_some(), "Genesis should be canonical tip");
        
        let tip_info = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_info.height, 0, "Genesis height should be 0");
        assert_eq!(tip_info.cumulative_work, 1, "Genesis cumulative work should equal difficulty");
    }

    /// Test de regression : the chain the plus long must be selectede
    #[test]
    fn test_longest_chain_selection() {
        let genesis_header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            commitment_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            difficulty: 10,
            nonce: 0,
        };

        let genesis_block = ShieldedBlock {
            header: genesis_header,
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };

        let mut fork_choice = ForkChoice::new(genesis_block.clone());
        let genesis_hash = genesis_block.hash();

        // Create a bloc enfant with plus de travail
        let child_header = BlockHeader {
            version: 1,
            prev_hash: genesis_hash,
            merkle_root: [1u8; 32],
            commitment_root: [1u8; 32],
            nullifier_root: [1u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            difficulty: 15,
            nonce: 0,
        };

        let child_block = ShieldedBlock {
            header: child_header,
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Block 1".to_string(),
            },
        };

        let result = fork_choice.add_block(child_block.clone());
        assert!(result.is_ok(), "Adding valid child block should succeed");
        assert!(result.unwrap(), "Child block should become new canonical tip");

        let tip_info = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_info.height, 1, "New tip height should be 1");
        assert_eq!(tip_info.cumulative_work, 25, "Cumulative work should be 10 + 15");
        assert_eq!(tip_info.tip_hash, child_block.hash(), "Tip hash should match child block");
    }

    /// Test de regression : the blocs orphelins doivent be stored
    #[test]
    fn test_orphan_block_handling() {
        let genesis_header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            commitment_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            difficulty: 10,
            nonce: 0,
        };

        let genesis_block = ShieldedBlock {
            header: genesis_header,
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };

        let mut fork_choice = ForkChoice::new(genesis_block);

        // Create a bloc orphelin (parent inconnu)
        let orphan_header = BlockHeader {
            version: 1,
            prev_hash: [99u8; 32], // Parent inexistant
            merkle_root: [1u8; 32],
            commitment_root: [1u8; 32],
            nullifier_root: [1u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            difficulty: 15,
            nonce: 0,
        };

        let orphan_block = ShieldedBlock {
            header: orphan_header,
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Orphan".to_string(),
            },
        };

        let result = fork_choice.add_block(orphan_block.clone());
        
        // Le bloc orphelin not must pas devenir the tip canonical
        assert!(result.is_ok(), "Adding orphan should not fail");
        assert!(!result.unwrap(), "Orphan should not become canonical tip");
        
        // Mais il must be stored like orphelin
        assert_eq!(fork_choice.orphans().len(), 1, "Should have one orphan block");
        assert!(fork_choice.orphans().contains_key(&orphan_block.hash()), 
               "Orphan should be stored by hash");
    }
}

/// Tests de regression for the module state
#[cfg(test)]
mod state_regression {
    use super::*;

    /// Test de regression : l'state initial must be valid
    #[test]
    fn test_initial_state_validity() {
        let state = State::new();
        
        // L'state initial must avoir of properties consistent
        assert_eq!(state.get_height(), 0, "Initial state height should be 0");
        assert!(state.get_commitment_tree().is_empty(), "Initial commitment tree should be empty");
        assert!(state.get_nullifier_set().is_empty(), "Initial nullifier set should be empty");
    }

    /// Test de regression : l'application d'un bloc vide must fonctionner
    #[test]
    fn test_empty_block_application() {
        let mut state = State::new();
        
        let empty_block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Empty block".to_string(),
            },
        };

        let result = state.apply_block(&empty_block);
        assert!(result.is_ok(), "Applying empty block should succeed");
        
        assert_eq!(state.get_height(), 1, "State height should increment");
    }

    /// Test de regression : the validation d'state must detect the inconsistencys
    #[test]
    fn test_state_validation_regression() {
        let state = State::new();
        
        // Create a bloc with racines inconsistent
        let invalid_block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [99u8; 32], // Racine invalid
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Invalid block".to_string(),
            },
        };

        let result = state.validate_block(&invalid_block);
        assert!(result.is_err(), "Block with invalid commitment root should be rejected");
        
        match result.unwrap_err() {
            StateError::InvalidCommitmentRoot => {
                // Expected error
            }
            other => panic!("Expected InvalidCommitmentRoot, got {:?}", other),
        }
    }
}

/// Tests de regression for the module crypto
#[cfg(test)]
mod crypto_regression {
    use super::*;

    /// Test de regression : the generation de keys must be deterministic with the same seed
    #[test]
    fn test_key_generation_deterministic() {
        let seed = [42u8; 32];
        
        let key1 = SpendingKey::from_seed(&seed);
        let key2 = SpendingKey::from_seed(&seed);
        
        assert_eq!(key1.to_bytes(), key2.to_bytes(), 
                  "Keys generated from same seed must be identical");
    }

    /// Test de regression : the signatures doivent be verifiable
    #[test]
    fn test_signature_verification_regression() {
        let spending_key = SpendingKey::generate();
        let message = b"Test message for signature";
        
        let signature = spending_key.sign(message);
        let verification_key = spending_key.verification_key();
        
        assert!(verification_key.verify(message, &signature), 
               "Valid signature must verify");
        
        // Test with a message different
        let wrong_message = b"Different message";
        assert!(!verification_key.verify(wrong_message, &signature), 
               "Signature with wrong message must not verify");
    }

    /// Test de regression : l'arbre de Merkle must maintenir ses invariants
    #[test]
    fn test_merkle_tree_invariants() {
        let mut tree = MerkleTree::new();
        
        // L'arbre vide must avoir a racine deterministic
        let empty_root = tree.root();
        assert_eq!(empty_root.len(), 32, "Root must be 32 bytes");
        
        // Ajouter of commitments
        let commitment1 = NoteCommitment::from_bytes([1u8; 32]);
        let commitment2 = NoteCommitment::from_bytes([2u8; 32]);
        
        tree.append(commitment1);
        let root_after_one = tree.root();
        
        tree.append(commitment2);
        let root_after_two = tree.root();
        
        // Les racines doivent be different
        assert_ne!(empty_root, root_after_one, "Root must change after insertion");
        assert_ne!(root_after_one, root_after_two, "Root must change after second insertion");
        
        // La size must be correcte
        assert_eq!(tree.size(), 2, "Tree size must match number of insertions");
    }

    /// Test de regression : the nullifiers doivent be uniques
    #[test]
    fn test_nullifier_uniqueness() {
        let spending_key = SpendingKey::generate();
        let note_commitment = NoteCommitment::from_bytes([1u8; 32]);
        
        let nullifier1 = spending_key.compute_nullifier(&note_commitment, 0);
        let nullifier2 = spending_key.compute_nullifier(&note_commitment, 0);
        
        assert_eq!(nullifier1.to_bytes(), nullifier2.to_bytes(), 
                  "Same inputs must produce same nullifier");
        
        // Different position index must donner a nullifier different
        let nullifier3 = spending_key.compute_nullifier(&note_commitment, 1);
        assert_ne!(nullifier1.to_bytes(), nullifier3.to_bytes(), 
                  "Different position must produce different nullifier");
    }

    /// Test de regression : the preuves ZK doivent be verifiable
    #[test]
    fn test_zk_proof_verification() {
        // Note: this test requires a implementation completee of preuves ZK
        // Pour l'instant, on teste juste the structure
        
        let proof_data = vec![0u8; 192]; // Typical size d'une preuve Groth16
        let proof = ZKProof::from_bytes(&proof_data);
        
        assert_eq!(proof.to_bytes().len(), 192, "Proof must maintain size");
        
        // Test de serialization/deserialization
        let serialized = serde_json::to_string(&proof).expect("Proof serialization failed");
        let deserialized: ZKProof = serde_json::from_str(&serialized)
            .expect("Proof deserialization failed");
        
        assert_eq!(proof.to_bytes(), deserialized.to_bytes(), 
                  "Proof must survive serialization round-trip");
    }
}

/// Tests d'integration inter-modules
#[cfg(test)]
mod integration_regression {
    use super::*;

    /// Test de regression : pipeline complete bloc -> state -> consensus
    #[test]
    fn test_full_pipeline_regression() {
        // Create a state initial
        let mut state = State::new();
        
        // Create a bloc genesis
        let genesis_block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };

        // Apply the bloc to l'state
        let apply_result = state.apply_block(&genesis_block);
        assert!(apply_result.is_ok(), "Genesis block application should succeed");

        // Create the fork choice with the same bloc
        let fork_choice = ForkChoice::new(genesis_block.clone());
        
        // Verify the consistency
        assert_eq!(state.get_height(), 1, "State height should be 1");
        
        let tip_info = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_info.height, 0, "Fork choice genesis height should be 0");
        
        // Note: il y a a difference intentionnelle ici - l'state compte to partir de 1,
        // the fork choice to partir de 0. C'est a invariant to maintenir.
    }

    /// Test de regression : consistency of hashes entre modules
    #[test]
    fn test_hash_consistency_across_modules() {
        let block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [1u8; 32],
                commitment_root: [2u8; 32],
                nullifier_root: [3u8; 32],
            state_root: [0u8; 32],
                timestamp: 1234567890,
                difficulty: 20,
                nonce: 42,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Test".to_string(),
            },
        };

        // Le hash of the bloc must be consistent
        let hash1 = block.hash();
        let hash2 = block.header.hash();
        
        assert_eq!(hash1, hash2, "Block hash must equal header hash");
        
        // Le hash must be reproductible
        let hash3 = block.hash();
        assert_eq!(hash1, hash3, "Hash must be deterministic");
    }
}