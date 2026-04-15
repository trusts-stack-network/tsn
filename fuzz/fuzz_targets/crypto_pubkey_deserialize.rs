#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::PublicKey;

/// Fuzzer pour la deserialization de key publique
/// Verifie qu'on ne peut pas faire panic le parser avec des data invalids
fuzz_target!(|data: &[u8]| {
    // Test de deserialization - ne doit pas panic
    let _ = PublicKey::from_bytes(data);
    
    // Test avec des prefixes connus pour bypasser des validations
    let mut prefixed_data = vec![0xFF, 0xFE, 0xFD];
    prefixed_data.extend_from_slice(data);
    let _ = PublicKey::from_bytes(&prefixed_data);
});