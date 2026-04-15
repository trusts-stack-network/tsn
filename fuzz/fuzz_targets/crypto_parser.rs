#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::{parse_public_key, parse_signature, parse_commitment};

fuzz_target!(|data: &[u8]| {
    // Teste les parsers de keys publiques
    if let Ok(key) = parse_public_key(data) {
        // Checks that la key parsee est valide
        assert!(key.validate().is_ok());
    }
    
    // Teste le parser de signatures
    if let Ok(sig) = parse_signature(data) {
        // Checks that la signature a la bonne taille
        assert!(sig.as_ref().len() == 3100); // ML-DSA-65 signature size
    }
    
    // Teste le parser de commitments
    if let Ok(commitment) = parse_commitment(data) {
        // Checks that le commitment est valide
        assert!(commitment.validate().is_ok());
    }
});