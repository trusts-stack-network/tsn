// Fuzzer pour les preuves ZK (Groth16/Plonky2)
// Utilise libfuzzer_sys pour l'integration avec cargo-fuzz
//
// VULNERABILITIES TARGETED:
// - Preuves malformedes
// - unwrap_or_default() masquant les errors
// - Preuves de taille excessive (DoS)
// - Public inputs invalids

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

// Limite de temps par execution pour avoid les DoS
const MAX_EXECUTION_TIME_MS: u64 = 100;
// Taille maximale de preuve (1MB)
const MAX_PROOF_SIZE: usize = 1024 * 1024;
// Taille minimale de preuve (100 bytes)
const MIN_PROOF_SIZE: usize = 100;

fuzz_target!(|data: &[u8]| {
    // Structure des data fuzzees:
    // [0..4] = type de preuve (0 = Groth16, 1 = Plonky2)
    // [4..8] = taille de la preuve (u32 LE)
    // [8..8+proof_size] = data de la preuve
    // [8+proof_size..] = public inputs
    
    if data.len() < 8 {
        return;
    }
    
    let start = Instant::now();
    
    // Extraire le type de preuve
    let proof_type = data[0];
    
    // Extraire la taille de la preuve
    let proof_size = u32::from_le_bytes([
        data[4], data[5], data[6], data[7]
    ]) as usize;
    
    // Check that la taille est raisonnable
    if proof_size < MIN_PROOF_SIZE || proof_size > MAX_PROOF_SIZE {
        // Taille invalid - devrait be rejetee
        return;
    }
    
    // Check that les data sont suffisantes
    let total_size = 8 + proof_size;
    if data.len() < total_size {
        return;
    }
    
    // Extraire la preuve
    let proof = &data[8..8 + proof_size];
    
    // Extraire les public inputs
    let public_inputs = &data[total_size..];
    
    // Check that la preuve n'est pas vide
    if proof.is_empty() {
        return;
    }
    
    // Check that la preuve n'est pas composee uniquement of zeros
    // (preuve triviale qui pourrait passer)
    let is_all_zeros = proof.iter().all(|b| *b == 0);
    if is_all_zeros {
        // Preuve triviale - devrait be rejetee
        return;
    }
    
    // Check the timeout
    if start.elapsed().as_millis() > MAX_EXECUTION_TIME_MS as u128 {
        panic!("DoS: verification de preuve trop lente");
    }
    
    // Simuler la verification selon le type
    let result = match proof_type {
        0 => simulate_groth16_verification(proof, public_inputs),
        1 => simulate_plonky2_verification(proof, public_inputs),
        _ => Err("Unknown proof type"),
    };
    
    // IMPORTANT: Ne pas usesr unwrap_or_default()!
    // C'est exactement la vulnerability qu'on cherche a avoid
    match result {
        Ok(valid) => {
            if valid {
                // Preuve valide
            }
        }
        Err(e) => {
            // Log l'error pour analyse
            // En production: log::debug!("Proof verification failed: {}", e);
            let _ = e;
        }
    }
});

fn simulate_groth16_verification(
    proof: &[u8],
    _public_inputs: &[u8]
) -> Result<bool, &'static str> {
    // Verifications de base
    if proof.len() < MIN_PROOF_SIZE {
        return Err("Proof too small");
    }
    
    if proof.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }
    
    // Simuler une verification
    // Dans la vraie implementation, usesr groth16::verify
    Ok(false) // Par defaut, rejeter
}

fn simulate_plonky2_verification(
    proof: &[u8],
    _public_inputs: &[u8]
) -> Result<bool, &'static str> {
    // Verifications de base
    if proof.len() < MIN_PROOF_SIZE {
        return Err("Proof too small");
    }
    
    if proof.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }
    
    // Simuler une verification
    // Dans la vraie implementation, usesr plonky2::verify
    Ok(false) // Par defaut, rejeter
}
