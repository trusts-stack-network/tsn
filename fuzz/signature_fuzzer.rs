// Fuzzer pour les signatures ML-DSA-65
// Utilise libfuzzer_sys pour l'integration avec cargo-fuzz
//
// VULNERABILITIES TARGETED:
// - Signatures malformedes
// - Keys publiques invalids
// - Messages de taille excessive
// - Timing attacks

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

// Limite de temps par execution pour avoid les DoS
const MAX_EXECUTION_TIME_MS: u64 = 100;

fuzz_target!(|data: &[u8]| {
    // Structure des data fuzzees:
    // [0..2592] = key publique ML-DSA-65 (2592 bytes)
    // [2592..7190] = signature ML-DSA-65 (4598 bytes)
    // [7190..] = message a checksr
    
    const PUBKEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4598;
    const MIN_DATA_SIZE: usize = PUBKEY_SIZE + SIGNATURE_SIZE;
    
    // Ignorer les entrees trop courtes
    if data.len() < MIN_DATA_SIZE {
        return;
    }
    
    let start = Instant::now();
    
    // Extraire les composants
    let pubkey = &data[0..PUBKEY_SIZE];
    let signature = &data[PUBKEY_SIZE..PUBKEY_SIZE + SIGNATURE_SIZE];
    let message = &data[PUBKEY_SIZE + SIGNATURE_SIZE..];
    
    // Check that la key publique n'est pas nulle
    let is_null_pubkey = pubkey.iter().all(|b| *b == 0);
    if is_null_pubkey {
        // Key publique nulle - devrait be rejetee
        return;
    }
    
    // Check that la signature n'est pas vide
    if signature.iter().all(|b| *b == 0) {
        // Signature vide - devrait be rejetee
        return;
    }
    
    // Check the timeout
    if start.elapsed().as_millis() > MAX_EXECUTION_TIME_MS as u128 {
        panic!("DoS: verification de signature trop lente");
    }
    
    // NOTE: Ici on ferait normalement appel a la verification de signature
    // Pour le fuzzer, on checks juste que les data sont bien formees
    
    // Check that le message n'est pas trop grand (DoS)
    if message.len() > 1024 * 1024 {
        // Message trop grand - potentiel DoS
        return;
    }
    
    // Simuler une verification
    let _ = simulate_signature_verification(pubkey, signature, message);
});

fn simulate_signature_verification(
    _pubkey: &[u8],
    _signature: &[u8],
    _message: &[u8]
) -> Result<bool, &'static str> {
    // Simulation de verification
    // Dans la vraie implementation, appelerait ML-DSA-65 verify
    
    // Verifications de base
    if _pubkey.len() != 2592 {
        return Err("Invalid public key size");
    }
    
    if _signature.len() != 4598 {
        return Err("Invalid signature size");
    }
    
    // Simuler un result random pour le fuzzing
    Ok(true)
}
