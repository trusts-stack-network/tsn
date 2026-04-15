#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::{
    keys::{PublicKey, PrivateKey, Signature},
    commitment::Commitment,
    nullifier::Nullifier,
    note::Note,
    address::Address,
    proof::Proof
};

/// Fuzzer pour la deserialization de structures cryptographiques
fuzz_target!(|data: &[u8]| {
    // Test deserialization key publique
    if data.len() >= 32 {
        let _ = PublicKey::from_bytes(&data[..32]);
    }
    
    // Test deserialization signature
    if data.len() >= 64 {
        let _ = Signature::from_bytes(&data[..64]);
    }
    
    // Test deserialization commitment
    if data.len() >= 32 {
        let _ = Commitment::from_bytes(&data[..32]);
    }
    
    // Test deserialization nullifier
    if data.len() >= 32 {
        let _ = Nullifier::from_bytes(&data[..32]);
    }
    
    // Test deserialization note
    if data.len() >= 128 {
        let _ = Note::from_bytes(&data[..128]);
    }
    
    // Test deserialization adresse
    if data.len() >= 20 {
        let _ = Address::from_bytes(&data[..20]);
    }
    
    // Test deserialization preuve
    if data.len() >= 192 {
        let _ = Proof::from_bytes(&data[..192]);
    }
});