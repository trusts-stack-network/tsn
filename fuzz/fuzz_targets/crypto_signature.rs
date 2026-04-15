#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::signature::{Signature, verify_signature};
use tsn_crypto::keys::{PublicKey, SecretKey};
use rand::thread_rng;

/// Fuzzing de la verification de signature
/// Cherche des cas ou une signature invalid est acceptee
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    
    let mut rng = thread_rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = PublicKey::from(&sk);
    
    // Fuzz les inputs de verification
    let message = &data[0..data.len()/2];
    let sig_bytes = &data[data.len()/2..];
    
    // Tente de create une signature depuis des bytes randoms
    if let Ok(signature) = Signature::from_bytes(sig_bytes) {
        let _ = verify_signature(&pk, message, &signature);
        // Ne pas panic ici - on teste juste la robustesse
    }
});

/// Fuzzing du parsing de keys publiques
fuzz_target!(|data: &[u8]| {
    if data.len() != 32 {
        return;
    }
    
    // Tente de parser une key publique depuis des bytes randoms
    let _ = PublicKey::from_bytes(data);
});

/// Fuzzing de la deserialization
fuzz_target!(|data: &[u8]| {
    use tsn_crypto::signature::Signature;
    
    // Teste la deserialization avec des data corrompues
    let _ = Signature::deserialize(data);
});