#![no_main]
use libfuzzer_sys::fuzz_target;

// Taille des keys et signatures ML-DSA-65 (FIPS 204)
const PUBLIC_KEY_SIZE: usize = 1952;
const SIGNATURE_SIZE: usize = 3309;

fuzz_target!(|data: &[u8]| {
    // Besoin d'at least: key publique + signature + 1 byte de message
    let min_size = PUBLIC_KEY_SIZE + SIGNATURE_SIZE + 1;
    if data.len() < min_size {
        return;
    }
    
    // Separation correcte des data:
    // - pk_bytes: les 1952 premiers bytes = key publique
    // - sig_bytes: les 3309 bytes suivants = signature
    // - msg_bytes: le reste = message a checksr
    let (pk_bytes, rest) = data.split_at(PUBLIC_KEY_SIZE);
    let (sig_bytes, msg_bytes) = rest.split_at(SIGNATURE_SIZE);
    
    // Verification: on ne doit PAS usesr les sames data pour message et signature
    // C'etait la faille de security dans l'implementation precedente
    
    // Conversion de la key publique (avec gestion d'error)
    let pk_result = tsn_crypto::signature::PublicKey::from_bytes(pk_bytes);
    
    if let Ok(pk) = pk_result {
        // Creation de la signature depuis les bytes dedies
        let sig = tsn_crypto::signature::Signature::from_bytes(sig_bytes.to_vec());
        
        // Verification avec message et signature distincts
        let _ = pk.verify(msg_bytes, &sig);
    }
});