#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::Signature;

/// Fuzzer pour la deserialization de signature
/// Cherche des panics lors de la deserialization of data malformedes
fuzz_target!(|data: &[u8]| {
    // Ne doit jamais panic, same avec des data randoms
    let _ = Signature::from_bytes(data);
    
    // Test also avec des tailles specifiques qui causent souvent des problemes
    if data.len() == 64 || data.len() == 32 {
        let _ = Signature::from_bytes(data);
    }
});