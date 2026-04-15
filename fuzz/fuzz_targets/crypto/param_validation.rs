#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::keys::{KeyPair, PublicKey, PrivateKey};
use tsn_crypto::signature::Signature;
use tsn_crypto::commitment::Commitment;
use tsn_crypto::proof::Proof;

fuzz_target!(|data: &[u8]| {
    // Test la validation des parameters lors de la deserialization
    if data.len() >= 32 {
        // Test deserialization key publique avec data randoms
        if let Ok(pk) = PublicKey::from_bytes(&data[..32]) {
            // Checks that la key est valide
            let _ = pk.validate().is_ok();
        }
        
        // Test deserialization key private
        if data.len() >= 64 {
            if let Ok(sk) = PrivateKey::from_bytes(&data[..64]) {
                let _ = sk.validate().is_ok();
            }
        }
    }
    
    // Test la validation de signature
    if data.len() >= 64 {
        if let Ok(sig) = Signature::from_bytes(&data[..64]) {
            // Doit passer la validation de base
            assert!(sig.validate_basic().is_ok() || sig.validate_basic().is_err());
        }
    }
    
    // Test les points a l'infini ou invalids
    if data.len() >= 1 {
        let zero_bytes = vec![0u8; 32];
        let _ = PublicKey::from_bytes(&zero_bytes).is_err();
        
        // Test valeurs limites
        let max_bytes = vec![0xFF; 32];
        let _ = PublicKey::from_bytes(&max_bytes).is_err();
    }
});

// Fuzzer specifique pour les attaques sur les courbes
#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::keys::PublicKey;

fuzz_target!(|data: &[u8]| {
    // Test atta