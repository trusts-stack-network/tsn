//! Fuzzer pour SLH-DSA post-quantique - SECURITY CRITIQUE
//!
//! Ce fuzzer teste la robustesse de l'implementation SLH-DSA contre :
//! - Deserialization de keys/signatures malformedes
//! - Messages de taille arbitraire et contenu malveillant
//! - Attaques par corruption of data
//! - Cas limites et inputs extreme
//!
//! ⚠️  RULE ABSOLUE : Aucun panic, crash ou comportement indefini autorise
//! ⚠️  Toute vulnerability trouvee doit be documentee et corrigee

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsn::crypto::pq::slh_dsa::{SecretKey, PublicKey, Signature, PK_BYTES, SK_BYTES, SIG_BYTES};
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
enum SlhDsaOperation {
    /// Test de generation de key avec graine arbitraire
    KeygenFromSeed { seed: [u8; 32] },
    
    /// Test de deserialization de key publique
    DeserializePublicKey { pk_bytes: Vec<u8> },
    
    /// Test de deserialization de signature
    DeserializeSignature { sig_bytes: Vec<u8> },
    
    /// Test de signature avec message arbitraire
    SignMessage { 
        seed: [u8; 32],
        message: Vec<u8>,
    },
    
    /// Test de verification avec data arbitraires
    VerifySignature {
        pk_bytes: Vec<u8>,
        message: Vec<u8>,
        sig_bytes: Vec<u8>,
    },
    
    /// Test de serialization/deserialization roundtrip
    SerializationRoundtrip {
        seed: [u8; 32],
        message: Vec<u8>,
    },
    
    /// Test avec des tailles of data extreme
    ExtremeSizes {
        large_message: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    
    // Generate une operation arbitraire
    let operation = match SlhDsaOperation::arbitrary(&mut unstructured) {
        Ok(op) => op,
        Err(_) => return, // Pas assez of data pour generate une operation
    };
    
    // Executer l'operation de maniere securisee
    match operation {
        SlhDsaOperation::KeygenFromSeed { seed } => {
            fuzz_keygen_from_seed(seed);
        },
        
        SlhDsaOperation::DeserializePublicKey { pk_bytes } => {
            fuzz_deserialize_public_key(&pk_bytes);
        },
        
        SlhDsaOperation::DeserializeSignature { sig_bytes } => {
            fuzz_deserialize_signature(&sig_bytes);
        },
        
        SlhDsaOperation::SignMessage { seed, message } => {
            fuzz_sign_message(seed, &message);
        },
        
        SlhDsaOperation::VerifySignature { pk_bytes, message, sig_bytes } => {
            fuzz_verify_signature(&pk_bytes, &message, &sig_bytes);
        },
        
        SlhDsaOperation::SerializationRoundtrip { seed, message } => {
            fuzz_serialization_roundtrip(seed, &message);
        },
        
        SlhDsaOperation::ExtremeSizes { large_message } => {
            fuzz_extreme_sizes(&large_message);
        },
    }
});

/// Fuzzer pour la generation de keys a partir de graines arbitraires
fn fuzz_keygen_from_seed(seed: [u8; 32]) {
    // La generation de key ne doit jamais paniquer, same avec des graines malveillantes
    let result = std::panic::catch_unwind(|| {
        let (_sk, _pk) = SecretKey::generate(&seed);
    });
    
    assert!(result.is_ok(), "Panic lors de la generation de key avec graine: {:?}", seed);
}

/// Fuzzer pour la deserialization de keys publiques
fn fuzz_deserialize_public_key(pk_bytes: &[u8]) {
    // Test avec des tailles incorrectes
    if pk_bytes.len() != PK_BYTES {
        // La deserialization doit fail gracieusement pour des tailles incorrectes
        return;
    }
    
    // Try to deserialiser
    let result = std::panic::catch_unwind(|| {
        let pk_array: [u8; PK_BYTES] = match pk_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return, // Taille incorrecte
        };
        
        let _pk = PublicKey::from_bytes(&pk_array);
        
        // Tester la serialization roundtrip
        let serialized = _pk.to_bytes();
        assert_eq!(serialized, pk_array, "Serialization roundtrip echouee");
    });
    
    assert!(result.is_ok(), "Panic lors de la deserialization de key publique: {:?}", pk_bytes);
}

/// Fuzzer pour la deserialization de signatures
fn fuzz_deserialize_signature(sig_bytes: &[u8]) {
    // Test avec des tailles incorrectes
    if sig_bytes.len() != SIG_BYTES {
        return;
    }
    
    let result = std::panic::catch_unwind(|| {
        let sig_array: [u8; SIG_BYTES] = match sig_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        
        let _sig = Signature::from_bytes(&sig_array);
        
        // Tester la serialization roundtrip
        let serialized = _sig.to_bytes();
        assert_eq!(serialized, sig_array, "Serialization signature roundtrip echouee");
    });
    
    assert!(result.is_ok(), "Panic lors de la deserialization de signature: {:?}", sig_bytes);
}

/// Fuzzer pour la signature de messages arbitraires
fn fuzz_sign_message(seed: [u8; 32], message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Signer le message
        let sig = sk.sign(message);
        
        // Check that la signature est valide
        assert!(pk.verify(message, &sig), "Signature generee invalid");
        
        // Check that la signature est deterministic
        let sig2 = sk.sign(message);
        assert_eq!(sig.to_bytes(), sig2.to_bytes(), "Signature non deterministic");
        
        // Verifier qu'un message modifie invalid la signature
        if !message.is_empty() {
            let mut modified_message = message.to_vec();
            modified_message[0] ^= 0x01; // Flip 1 bit
            
            if modified_message != message {
                assert!(!pk.verify(&modified_message, &sig), "Signature valide sur message modifie");
            }
        }
    });
    
    assert!(result.is_ok(), "Panic lors de la signature: seed={:?}, message_len={}", seed, message.len());
}

/// Fuzzer pour la verification de signatures avec data arbitraires
fn fuzz_verify_signature(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) {
    // Check thes tailles
    if pk_bytes.len() != PK_BYTES || sig_bytes.len() != SIG_BYTES {
        return;
    }
    
    let result = std::panic::catch_unwind(|| {
        let pk_array: [u8; PK_BYTES] = pk_bytes.try_into().unwrap();
        let sig_array: [u8; SIG_BYTES] = sig_bytes.try_into().unwrap();
        
        let pk = PublicKey::from_bytes(&pk_array);
        let sig = Signature::from_bytes(&sig_array);
        
        // La verification ne doit jamais paniquer, same avec des data corrompues
        let _is_valid = pk.verify(message, &sig);
        
        // Tester la consistency : checksr deux fois doit donner le same result
        let is_valid2 = pk.verify(message, &sig);
        assert_eq!(_is_valid, is_valid2, "Verification incoherente");
    });
    
    assert!(result.is_ok(), "Panic lors de la verification: pk_len={}, msg_len={}, sig_len={}", 
            pk_bytes.len(), message.len(), sig_bytes.len());
}

/// Fuzzer pour les roundtrips de serialization
fn fuzz_serialization_roundtrip(seed: [u8; 32], message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Test roundtrip key publique
        let pk_bytes = pk.to_bytes();
        let pk_deserialized = PublicKey::from_bytes(&pk_bytes);
        assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes(), "Roundtrip key publique echoue");
        
        // Test roundtrip signature
        if !message.is_empty() {
            let sig = sk.sign(message);
            let sig_bytes = sig.to_bytes();
            let sig_deserialized = Signature::from_bytes(&sig_bytes);
            assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes(), "Roundtrip signature echoue");
            
            // Check that la signature deserializede est toujours valide
            assert!(pk.verify(message, &sig_deserialized), "Signature deserializede invalid");
        }
    });
    
    assert!(result.is_ok(), "Panic lors du roundtrip: seed={:?}, message_len={}", seed, message.len());
}

/// Fuzzer pour les tailles extreme
fn fuzz_extreme_sizes(large_message: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        // Tester avec un message very long (jusqu'a la limite du fuzzer)
        let seed = [0x42u8; 32]; // Graine fixe pour la reproductibilite
        let (sk, pk) = SecretKey::generate(&seed);
        
        // Signer le message long
        let sig = sk.sign(large_message);
        
        // Check the signature
        assert!(pk.verify(large_message, &sig), "Signature invalid pour message long");
        
        // Tester la performance : ne doit pas be trop lent
        let start = std::time::Instant::now();
        let _sig2 = sk.sign(large_message);
        let elapsed = start.elapsed();
        
        // Limite arbitraire : 10 secondes pour un message de n'importe quelle taille
        assert!(elapsed.as_secs() < 10, "Signature trop lente pour message de {} bytes: {:?}", 
                large_message.len(), elapsed);
    });
    
    assert!(result.is_ok(), "Panic avec message de taille extreme: {} bytes", large_message.len());
}

/// Tests de propertys invariantes pendant le fuzzing
#[cfg(test)]
mod fuzz_property_tests {
    use super::*;
    
    #[test]
    fn fuzz_property_deterministic_keygen() {
        let seed = [0x12u8; 32];
        let (sk1, pk1) = SecretKey::generate(&seed);
        let (sk2, pk2) = SecretKey::generate(&seed);
        
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }
    
    #[test]
    fn fuzz_property_signature_consistency() {
        let seed = [0x34u8; 32];
        let (sk, pk) = SecretKey::generate(&seed);
        let message = b"test message";
        
        let sig1 = sk.sign(message);
        let sig2 = sk.sign(message);
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        assert!(pk.verify(message, &sig1));
        assert!(pk.verify(message, &sig2));
    }
}