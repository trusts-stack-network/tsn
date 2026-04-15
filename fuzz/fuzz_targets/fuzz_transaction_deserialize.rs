#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use tsn::core::transaction::{Transaction, TransactionInput, TransactionOutput};
use tsn::crypto::nullifier::Nullifier;

#[derive(Arbitrary, Debug)]
struct FuzzTxInput {
    data: Vec<u8>,
    zero_inputs: bool,
    duplicate_nullifiers: bool,
    overflow_outputs: bool,
}

fuzz_target!(|input: FuzzTxInput| {
    // Test 1: Deserialization avec validation
    if let Ok(tx) = Transaction::deserialize(&input.data) {
        // Verification: pas de transaction avec uniquement des outputs (sauf coinbase)
        if tx.inputs.is_empty() && !tx.outputs.is_empty() {
            // Doit be une transaction coinbase - checksr la hauteur
            if let Some(height) = tx.coinbase_height {
                if height == 0 {
                    panic!("Invalid coinbase height: 0");
                }
            } else {
                // Transaction non-coinbase sans inputs - double spend potentiel
                panic!("Non-coinbase transaction without inputs");
            }
        }
        
        // Test 2: Verification des nullifiers uniques (protection contre double spend)
        if input.duplicate_nullifiers && !tx.inputs.is_empty() {
            let mut nullifiers = std::collections::HashSet::new();
            for input in &tx.inputs {
                if let Some(nullifier) = &input.nullifier {
                    if !nullifiers.insert(nullifier.clone()) {
                        // Nullifier en double detecte - FAIL
                        panic!("Duplicate nullifier detected: {:?}", nullifier);
                    }
                }
            }
        }
        
        // Test 3: Verification des montants (prevention overflow)
        if input.overflow_outputs {
            let mut total_output: u64 = 0;
            for output in &tx.outputs {
                total_output = match total_output.checked_add(output.amount) {
                    Some(sum) => sum,
                    None => {
                        // Overflow detecte - FAIL
                        panic!("Output amount overflow detected");
                    }
                };
            }
            
            // Check that le total n'est pas deraisonnable
            if total_output > 21_000_000_000_000_000 { // 21M TSN avec 8 decimales
                panic!("Total output exceeds max supply: {}", total_output);
            }
        }
        
        // Test 4: Verification de la taille
        if tx.inputs.len() > 1000 || tx.outputs.len() > 1000 {
            // DoS potentiel - transaction trop grande
            panic!("Transaction too large: {} inputs, {} outputs", 
                   tx.inputs.len(), tx.outputs.len());
        }
    }
    
    // Test 5: Attaque par transaction ciculaire (output qui reference input)
    if input.data.len() > 64 {
        // Try to create une reference circulaire
        let mut circular_data = input.data.clone();
        // Copier les 32 premiers octets vers la fin
        let len = circular_data.len();
        for i in 0..32 {
            if len > 32 + i {
                circular_data[len - 32 + i] = circular_data[i];
            }
        }
        
        // Ne doit pas parser en transaction valide
        if let Ok(tx) = Transaction::deserialize(&circular_data) {
            // Si ca parse, checksr qu'il n'y a pas de reference circulaire
            for (i, input) in tx.inputs.iter().enumerate() {
                for (j, output) in tx.outputs.iter().enumerate() {
                    if i == j && input.nullifier.is_some() {
                        // Reference suspecte detectee
                        panic!("Potential circular reference in transaction");
                    }
                }
            }
        }
    }
});