// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Checks that les epreuves non canoniques sont rejetees.

use tsn_crypto::merkle_tree::{compute_root, verify_proof, Hash};

#[test]
fn reject_non_canonical_proof() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = tsn_crypto::merkle_tree::MerkleTree::new(leaves.clone());
    let root = tree.root();

    // Proof canonique
    let (pos, proof) = tree.proof(0).unwrap();
    assert!(verify_proof(&root, &leaves[0], pos, &proof));

    // Proof non-canonique : on inverse l'ordre des peers
    let mut bad_proof = proof.clone();
    if let Some((left, right)) = bad_proof.first_mut() {
        std::mem::swap(left, right);
    }
    // Doit be rejetee
    assert!(!verify_proof(&root, &leaves[0], pos, &bad_proof));
}

proptest::proptest! {
    #[test]
    fn merkle_root_invariant(leaves: Vec<Hash>) {
        prop_assume!(!leaves.is_empty());
        let tree = tsn_crypto::merkle_tree::MerkleTree::new(leaves.clone());
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let (pos, proof) = tree.proof(i).unwrap();
            prop_assert!(verify_proof(&root, leaf, pos, &proof));
        }
    }
}
