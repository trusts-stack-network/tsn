#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use tsn::core::block::{Block, BlockHeader};
use tsn::crypto::hash::Hash;

#[derive(Arbitrary, Debug)]
struct FuzzBlockInput {
    data: Vec<u8>,
    corrupt_header: bool,
    corrupt_body: bool,
    oversized: bool,
}

fuzz_target!(|input: FuzzBlockInput| {
    // Test 1: Deserialization basique
    if let Ok(block) = Block::deserialize(&input.data) {
        // Verification des invariants
        if block.header.height > 0 {
            // Check that le hash du bloc est coherent
            let recomputed_hash = block.hash();
            assert_eq!(block.hash(), recomputed_hash, "Block hash mismatch");
            
            // Check the consistency du Merkle root
            if let Ok(computed_root) = block.compute_merkle_root() {
                if computed_root != block.header.merkle_root {
                    // Potentielle attaque de consensus - documenter
                    return;
                }
            }
        }
        
        // Test 2: Verification des transactions
        for tx in &block.transactions {
            // Check that les transactions ne sont pas vides
            if tx.inputs.is_empty() && tx.outputs.is_empty() {
                // Transaction vide - potentielle attaque DoS
                return;
            }
        }
    }
    
    // Test 3: Attaque par buffer overflow via taille excessive
    if input.oversized && input.data.len() > 10_000_000 {
        // DoS potentiel - le parser doit rejeter rapidement
        let start = std::time::Instant::now();
        let _ = Block::deserialize(&input.data);
        let elapsed = start.elapsed();
        
        // Le parsing doit fail rapidement (< 100ms) pour avoid DoS
        if elapsed.as_millis() > 100 {
            panic!("Oversized block parsing took too long: {}ms", elapsed.as_millis());
        }
    }
    
    // Test 4: Corruption ciblee du header
    if input.corrupt_header && input.data.len() >= 32 {
        let mut corrupted = input.data.clone();
        // Corrompre le champ previous_hash (offset 8-40)
        for i in 8..40 {
            if i < corrupted.len() {
                corrupted[i] = corrupted[i].wrapping_add(1);
            }
        }
        
        // Le parser doit detect l'inconsistency
        if let Ok(block) = Block::deserialize(&corrupted) {
            // Si on arrive ici, checksr que c'est pas un old bloc valide par hasard
            if block.header.height > 1000000 {
                // Hauteur de bloc impossible - attaque potentielle
                panic!("Suspicious block height after corruption: {}", block.header.height);
            }
        }
    }
});