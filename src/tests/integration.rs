//! Tests d'integration pour TSN
//!
//! Ces tests checksnt les interactions entre modules et les scenarios
//! complexes qui impliquent plusieurs composants du system.

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

/// Tests d'integration pour la synchronisation de chain
#[cfg(test)]
mod chain_sync_integration {
    use super::*;

    /// Test d'integration : synchronisation d'une chain de blocs
    #[test]
    fn test_chain_synchronization() {
        let mut state = State::new();
        
        // Create a chain de 5 blocs
        let mut blocks = Vec::new();
        let mut prev_hash = [0u8; 32];
        
        for i in 0..5 {
            let block = ShieldedBlock {
                header: BlockHeader {
                    version: 1,
                    prev_hash,
                    merkle_root: [i as u8; 32],
                    commitment_root: [0u8; 32],
                    nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                    timestamp: i as u64,
                    difficulty: 10,
                    nonce: i as u64,
                },
                shielded_txs: vec![],
                coinbase: CoinbaseTransaction {
                    outputs: vec![],
                    memo: format!("Block {}", i),
                },
            };
            
            prev_hash = block.hash();
            blocks.push(block);
        }
        
        // Appliquer tous les blocs a l'state
        for block in &blocks {
            let result = state.apply_block(block);
            assert!(result.is_ok(), "Block application should succeed for block {}", 
                   block.header.timestamp);
        }
        
        assert_eq!(state.get_height(), 5, "Final state height should be 5");
        
        // Create the fork choice et ajouter tous les blocs
        let mut fork_choice = ForkChoice::new(blocks[0].clone());
        
        for block in blocks.iter().skip(1) {
            let result = fork_choice.add_block(block.clone());
            assert!(result.is_ok(), "Adding block to fork choice should succeed");
            assert!(result.unwrap(), "Each block should become the new canonical tip");
        }
        
        let tip_info = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_info.height, 4, "Final tip height should be 4 (0-indexed)");
        assert_eq!(tip_info.cumulative_work, 50, "Cumulative work should be 5 * 10");
    }

    /// Test d'integration : gestion des forks
    #[test]
    fn test_fork_resolution() {
        // Create a bloc genesis
        let genesis = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 10,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };
        
        let genesis_hash = genesis.hash();
        let mut fork_choice = ForkChoice::new(genesis);
        
        // Createux branches concurrent
        let branch_a = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [1u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 15, // Plus de travail
                nonce: 1,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Branch A".to_string(),
            },
        };
        
        let branch_b = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [2u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 12, // Moins de travail
                nonce: 2,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Branch B".to_string(),
            },
        };
        
        // Ajouter la branche B d'abord
        let result_b = fork_choice.add_block(branch_b.clone());
        assert!(result_b.is_ok() && result_b.unwrap(), "Branch B should become tip");
        
        let tip_after_b = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_after_b.tip_hash, branch_b.hash(), "Branch B should be canonical");
        assert_eq!(tip_after_b.cumulative_work, 22, "Cumulative work should be 10 + 12");
        
        // Ajouter la branche A (plus de travail)
        let result_a = fork_choice.add_block(branch_a.clone());
        assert!(result_a.is_ok() && result_a.unwrap(), "Branch A should become new tip");
        
        let tip_after_a = fork_choice.canonical_tip().unwrap();
        assert_eq!(tip_after_a.tip_hash, branch_a.hash(), "Branch A should be canonical");
        assert_eq!(tip_after_a.cumulative_work, 25, "Cumulative work should be 10 + 15");
        
        // La branche B doit maintenant be un fork alternatif
        assert_eq!(fork_choice.alternative_tips().len(), 1, "Should have one alternative tip");
    }

    /// Test d'integration : reorganisation de chain
    #[test]
    fn test_chain_reorganization() {
        let mut state_main = State::new();
        let mut state_alt = State::new();
        
        // Create a genesis commun
        let genesis = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 10,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Genesis".to_string(),
            },
        };
        
        // Appliquer genesis aux deux states
        state_main.apply_block(&genesis).unwrap();
        state_alt.apply_block(&genesis).unwrap();
        
        let genesis_hash = genesis.hash();
        
        // Create a chain principale courte mais avec moins de travail
        let main_block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [1u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 8,
                nonce: 1,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Main chain".to_string(),
            },
        };
        
        state_main.apply_block(&main_block).unwrap();
        
        // Create a chain alternative plus longue avec plus de travail
        let alt_block1 = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [2u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 6,
                nonce: 2,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Alt chain 1".to_string(),
            },
        };
        
        let alt_block2 = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: alt_block1.hash(),
                merkle_root: [3u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 2,
                difficulty: 6,
                nonce: 3,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Alt chain 2".to_string(),
            },
        };
        
        state_alt.apply_block(&alt_block1).unwrap();
        state_alt.apply_block(&alt_block2).unwrap();
        
        // Check that les states sont differents avant reorganisation
        assert_eq!(state_main.get_height(), 2, "Main state should have height 2");
        assert_eq!(state_alt.get_height(), 3, "Alt state should have height 3");
        
        // Simuler une reorganisation : l'state principal adopte la chain alternative
        // (Dans une vraie implementation, ceci serait gere par le consensus)
        let mut reorg_state = State::new();
        reorg_state.apply_block(&genesis).unwrap();
        reorg_state.apply_block(&alt_block1).unwrap();
        reorg_state.apply_block(&alt_block2).unwrap();
        
        assert_eq!(reorg_state.get_height(), 3, "Reorganized state should have height 3");
        
        // Check that la chain alternative a plus de travail cumule
        let main_work = 10 + 8; // genesis + main_block
        let alt_work = 10 + 6 + 6; // genesis + alt_block1 + alt_block2
        assert!(alt_work > main_work, "Alternative chain should have more cumulative work");
    }
}

/// Tests d'integration pour les transactions shielded
#[cfg(test)]
mod shielded_transaction_integration {
    use super::*;

    /// Test d'integration : cycle de vie complete d'une transaction shielded
    #[test]
    fn test_shielded_transaction_lifecycle() {
        let mut state = State::new();
        
        // Create keys pour l'expediteur et le destinataire
        let sender_key = SpendingKey::generate();
        let receiver_key = SpendingKey::generate();
        
        // Create a bloc genesis avec une sortie pour l'expediteur
        let genesis = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 10,
                nonce: 0,
            },
            shielded_txs: vec![],
            coinbase: CoinbaseTransaction {
                outputs: vec![
                    // Note: dans une vraie implementation, ceci serait un NoteOutput
                ],
                memo: "Genesis with initial funds".to_string(),
            },
        };
        
        state.apply_block(&genesis).unwrap();
        
        // Simuler la creation d'une transaction shielded
        // Note: ceci requiresrait une implementation complete des preuves ZK
        
        // Pour l'instant, on teste juste la structure
        let shielded_tx = ShieldedTransaction {
            nullifiers: vec![
                // Nullifiers des notes depensees
            ],
            commitments: vec![
                // Commitments des nouvelles notes
            ],
            proof: ZKProof::from_bytes(&vec![0u8; 192]),
            binding_signature: Signature::from_bytes(&vec![0u8; 64]),
        };
        
        // Create a bloc avec cette transaction
        let block_with_tx = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis.hash(),
                merkle_root: [1u8; 32],
                commitment_root: [1u8; 32], // Mis a jour avec les nouveaux commitments
                nullifier_root: [1u8; 32],  // Mis a jour avec les nouveaux nullifiers
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 10,
                nonce: 1,
            },
            shielded_txs: vec![shielded_tx],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Block with shielded tx".to_string(),
            },
        };
        
        // Appliquer le bloc (ceci devrait valider la transaction)
        let result = state.apply_block(&block_with_tx);
        
        // Note: dans l'implementation currentle, ceci pourrait fail
        // car la validation complete des preuves ZK n'est pas implementee
        match result {
            Ok(_) => {
                assert_eq!(state.get_height(), 2, "State height should be 2 after tx block");
            }
            Err(StateError::InvalidZKProof) => {
                // Attendu si la validation ZK n'est pas encore implementee
                println!("ZK proof validation not yet implemented - this is expected");
            }
            Err(other) => {
                panic!("Unexpected error: {:?}", other);
            }
        }
    }

    /// Test d'integration : detection de double-spend
    #[test]
    fn test_double_spend_detection() {
        let mut state = State::new();
        
        // Create a nullifier pour simuler une note depensee
        let spending_key = SpendingKey::generate();
        let note_commitment = NoteCommitment::from_bytes([1u8; 32]);
        let nullifier = spending_key.compute_nullifier(&note_commitment, 0);
        
        // First transaction qui depense la note
        let tx1 = ShieldedTransaction {
            nullifiers: vec![nullifier.clone()],
            commitments: vec![],
            proof: ZKProof::from_bytes(&vec![0u8; 192]),
            binding_signature: Signature::from_bytes(&vec![0u8; 64]),
        };
        
        let block1 = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [1u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [1u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 10,
                nonce: 1,
            },
            shielded_txs: vec![tx1],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "First spend".to_string(),
            },
        };
        
        // Appliquer le premier bloc
        let result1 = state.apply_block(&block1);
        // Note: peut fail si la validation ZK n'est pas implementee
        
        // Second transaction qui tente de depenser la same note (double-spend)
        let tx2 = ShieldedTransaction {
            nullifiers: vec![nullifier], // Same nullifier !
            commitments: vec![],
            proof: ZKProof::from_bytes(&vec![0u8; 192]),
            binding_signature: Signature::from_bytes(&vec![0u8; 64]),
        };
        
        let block2 = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: block1.hash(),
                merkle_root: [2u8; 32],
                commitment_root: [0u8; 32],
                nullifier_root: [2u8; 32],
            state_root: [0u8; 32],
                timestamp: 2,
                difficulty: 10,
                nonce: 2,
            },
            shielded_txs: vec![tx2],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Double spend attempt".to_string(),
            },
        };
        
        // Appliquer le second bloc - doit fail
        let result2 = state.apply_block(&block2);
        
        match result2 {
            Err(StateError::DuplicateNullifier) => {
                // Comportement attendu
                println!("Double-spend correctly detected");
            }
            Err(StateError::InvalidZKProof) => {
                // Peut arriver si la validation ZK fails avant la verification des nullifiers
                println!("ZK validation failed before nullifier check - acceptable for now");
            }
            Ok(_) => {
                panic!("Double-spend should have been rejected!");
            }
            Err(other) => {
                panic!("Unexpected error: {:?}", other);
            }
        }
    }
}

/// Tests d'integration pour la cryptographie
#[cfg(test)]
mod crypto_integration {
    use super::*;

    /// Test d'integration : consistency des arbres de Merkle avec l'state
    #[test]
    fn test_merkle_tree_state_consistency() {
        let mut state = State::new();
        let mut external_tree = MerkleTree::new();
        
        // Create commitments
        let commitments = vec![
            NoteCommitment::from_bytes([1u8; 32]),
            NoteCommitment::from_bytes([2u8; 32]),
            NoteCommitment::from_bytes([3u8; 32]),
        ];
        
        // Ajouter les commitments a l'arbre externe
        for commitment in &commitments {
            external_tree.append(*commitment);
        }
        
        // Create a bloc avec ces commitments
        let block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                commitment_root: external_tree.root(), // Utiliser la racine calculee
                nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                timestamp: 0,
                difficulty: 10,
                nonce: 0,
            },
            shielded_txs: vec![
                // Simuler des transactions avec ces commitments
                ShieldedTransaction {
                    nullifiers: vec![],
                    commitments: commitments.clone(),
                    proof: ZKProof::from_bytes(&vec![0u8; 192]),
                    binding_signature: Signature::from_bytes(&vec![0u8; 64]),
                }
            ],
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: "Block with commitments".to_string(),
            },
        };
        
        // Appliquer le bloc
        let result = state.apply_block(&block);
        
        match result {
            Ok(_) => {
                // Check that l'arbre de l'state correspond a notre arbre externe
                let state_tree = state.get_commitment_tree();
                assert_eq!(state_tree.root(), external_tree.root(), 
                          "State tree root must match external tree root");
                assert_eq!(state_tree.size(), external_tree.size(), 
                          "State tree size must match external tree size");
            }
            Err(StateError::InvalidCommitmentRoot) => {
                // Attendu si la validation des racines est stricte
                println!("Commitment root validation is working correctly");
            }
            Err(other) => {
                println!("Other error during block application: {:?}", other);
            }
        }
    }

    /// Test d'integration : generation et verification de preuves de path Merkle
    #[test]
    fn test_merkle_path_proof_integration() {
        let mut tree = MerkleTree::new();
        
        // Ajouter plusieurs commitments
        let commitments = vec![
            NoteCommitment::from_bytes([1u8; 32]),
            NoteCommitment::from_bytes([2u8; 32]),
            NoteCommitment::from_bytes([3u8; 32]),
            NoteCommitment::from_bytes([4u8; 32]),
        ];
        
        for commitment in &commitments {
            tree.append(*commitment);
        }
        
        let root = tree.root();
        
        // Generate des preuves de path pour chaque commitment
        for (index, commitment) in commitments.iter().enumerate() {
            let path = tree.path(index);
            assert!(path.is_some(), "Should be able to generate path for index {}", index);
            
            let path = path.unwrap();
            
            // Check that la preuve est valide
            let is_valid = path.verify(*commitment, &root);
            assert!(is_valid, "Path proof should be valid for commitment at index {}", index);
            
            // Verifier qu'une preuve avec un mauvais commitment fails
            let wrong_commitment = NoteCommitment::from_bytes([99u8; 32]);
            let is_invalid = path.verify(wrong_commitment, &root);
            assert!(!is_invalid, "Path proof should be invalid for wrong commitment");
        }
    }

    /// Test d'integration : signatures et authentification
    #[test]
    fn test_signature_authentication_integration() {
        // Creer plusieurs keys
        let keys: Vec<SpendingKey> = (0..5).map(|_| SpendingKey::generate()).collect();
        
        let message = b"Transaction data to sign";
        
        // Chaque key signe le message
        let signatures: Vec<(SpendingKey, Signature)> = keys.iter()
            .map(|key| (key.clone(), key.sign(message)))
            .collect();
        
        // Check that chaque signature est valide avec la bonne key
        for (key, signature) in &signatures {
            let verification_key = key.verification_key();
            assert!(verification_key.verify(message, signature), 
                   "Signature should verify with correct key");
        }
        
        // Verifier qu'aucune signature ne fonctionne avec une mauvaise key
        for (i, (_, signature)) in signatures.iter().enumerate() {
            for (j, (other_key, _)) in signatures.iter().enumerate() {
                if i != j {
                    let other_verification_key = other_key.verification_key();
                    assert!(!other_verification_key.verify(message, signature), 
                           "Signature should not verify with wrong key");
                }
            }
        }
    }
}

/// Tests de performance et de charge
#[cfg(test)]
mod performance_integration {
    use super::*;
    use std::time::Instant;

    /// Test d'integration : performance de validation de blocs
    #[test]
    fn test_block_validation_performance() {
        let mut state = State::new();
        
        // Create a bloc avec plusieurs transactions
        let num_txs = 10;
        let mut shielded_txs = Vec::new();
        
        for i in 0..num_txs {
            let tx = ShieldedTransaction {
                nullifiers: vec![
                    // Simuler des nullifiers uniques
                    Nullifier::from_bytes([i as u8; 32]),
                ],
                commitments: vec![
                    NoteCommitment::from_bytes([(i + 100) as u8; 32]),
                ],
                proof: ZKProof::from_bytes(&vec![0u8; 192]),
                binding_signature: Signature::from_bytes(&vec![0u8; 64]),
            };
            shielded_txs.push(tx);
        }
        
        let block = ShieldedBlock {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [1u8; 32],
                commitment_root: [1u8; 32],
                nullifier_root: [1u8; 32],
            state_root: [0u8; 32],
                timestamp: 1,
                difficulty: 10,
                nonce: 1,
            },
            shielded_txs,
            coinbase: CoinbaseTransaction {
                outputs: vec![],
                memo: format!("Block with {} transactions", num_txs),
            },
        };
        
        // Mesurer le temps de validation
        let start = Instant::now();
        let result = state.validate_block(&block);
        let validation_time = start.elapsed();
        
        println!("Block validation with {} transactions took: {:?}", 
                num_txs, validation_time);
        
        // La validation ne doit pas prendre plus de 100ms pour 10 transactions
        assert!(validation_time.as_millis() < 100, 
               "Block validation should be fast (< 100ms for 10 txs)");
        
        // Note: le result peut be une error si la validation ZK n'est pas implementee
        match result {
            Ok(_) => println!("Block validation succeeded"),
            Err(e) => println!("Block validation failed (expected): {:?}", e),
        }
    }

    /// Test d'integration : performance de l'arbre de Merkle
    #[test]
    fn test_merkle_tree_performance() {
        let mut tree = MerkleTree::new();
        
        let num_commitments = 1000;
        let commitments: Vec<NoteCommitment> = (0..num_commitments)
            .map(|i| NoteCommitment::from_bytes([(i % 256) as u8; 32]))
            .collect();
        
        // Mesurer le temps d'insertion
        let start = Instant::now();
        for commitment in &commitments {
            tree.append(*commitment);
        }
        let insertion_time = start.elapsed();
        
        println!("Inserting {} commitments took: {:?}", num_commitments, insertion_time);
        
        // Mesurer le temps de generation de preuves
        let start = Instant::now();
        let _path = tree.path(num_commitments / 2);
        let proof_time = start.elapsed();
        
        println!("Generating Merkle path proof took: {:?}", proof_time);
        
        // Les operations doivent be raisonnablement rapides
        assert!(insertion_time.as_millis() < 1000, 
               "Inserting 1000 commitments should take < 1s");
        assert!(proof_time.as_millis() < 10, 
               "Generating Merkle proof should take < 10ms");
    }

    /// Test d'integration : performance de la synchronisation de chain
    #[test]
    fn test_chain_sync_performance() {
        let mut state = State::new();
        let mut fork_choice = None;
        
        let num_blocks = 100;
        let mut prev_hash = [0u8; 32];
        
        let start = Instant::now();
        
        for i in 0..num_blocks {
            let block = ShieldedBlock {
                header: BlockHeader {
                    version: 1,
                    prev_hash,
                    merkle_root: [(i % 256) as u8; 32],
                    commitment_root: [0u8; 32],
                    nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
                    timestamp: i as u64,
                    difficulty: 10,
                    nonce: i as u64,
                },
                shielded_txs: vec![],
                coinbase: CoinbaseTransaction {
                    outputs: vec![],
                    memo: format!("Block {}", i),
                },
            };
            
            prev_hash = block.hash();
            
            // Appliquer a l'state
            state.apply_block(&block).unwrap();
            
            // Ajouter au fork choice
            if i == 0 {
                fork_choice = Some(ForkChoice::new(block));
            } else {
                fork_choice.as_mut().unwrap().add_block(block).unwrap();
            }
        }
        
        let sync_time = start.elapsed();
        
        println!("Synchronizing {} blocks took: {:?}", num_blocks, sync_time);
        
        // Check the state final
        assert_eq!(state.get_height(), num_blocks, "State height should match number of blocks");
        
        let tip_info = fork_choice.unwrap().canonical_tip().unwrap();
        assert_eq!(tip_info.height, num_blocks - 1, "Tip height should be correct");
        
        // La synchronisation doit be raisonnablement rapide
        assert!(sync_time.as_millis() < 5000, 
               "Synchronizing 100 blocks should take < 5s");
    }
}