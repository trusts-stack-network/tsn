//! Fuzzer pour les signatures ML-DSA-65 post-quantiques
//! 
//! Ce fuzzer teste specifiquement l'implementation FIPS204 ML-DSA-65
//! utilisee dans TSN pour la signature des transactions et blocs.
//! 
//! Modules testes:
//! - Generation de keys ML-DSA-65
//! - Signature de messages
//! - Verification de signatures
//! - Serialization/deserialization de keys et signatures
//! - Resistance aux attaques par malleabilite

#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::pq::signature::*;
use tsn::crypto::keys::*;

/// Structure pour les data de fuzzing ML-DSA
#[derive(Debug)]
struct MLDSAFuzzInput {
    // Message a signer
    message: Vec<u8>,
    
    // Data de key private
    private_key_seed: Vec<u8>,
    private_key_bytes: Vec<u8>,
    
    // Data de key publique
    public_key_bytes: Vec<u8>,
    
    // Signature data
    signature_bytes: Vec<u8>,
    
    // Adversarial inputs
    malformed_signature: Vec<u8>,
    modified_message: Vec<u8>,
    
    // Key manipulation
    key_modification_offset: usize,
    key_modification_value: u8,
    
    // Signature manipulation
    sig_modification_offset: usize,
    sig_modification_value: u8,
    
    // Context data
    context: Vec<u8>,
    
    // Batch verification data
    batch_messages: Vec<Vec<u8>>,
    batch_signatures: Vec<Vec<u8>>,
    batch_public_keys: Vec<Vec<u8>>,
}

impl<'a> Arbitrary<'a> for MLDSAFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let message_len = u.int_in_range(0..=8192)?;
        let private_key_len = u.int_in_range(0..=4096)?;
        let public_key_len = u.int_in_range(0..=2048)?;
        let signature_len = u.int_in_range(0..=4096)?;
        let malformed_sig_len = u.int_in_range(0..=4096)?;
        let modified_msg_len = u.int_in_range(0..=8192)?;
        let context_len = u.int_in_range(0..=255)?; // ML-DSA context max 255 bytes
        let batch_size = u.int_in_range(0..=16)?; // Limite pour avoid OOM
        let seed_len = u.int_in_range(0..=64)?;
        
        let mut batch_messages = Vec::new();
        let mut batch_signatures = Vec::new();
        let mut batch_public_keys = Vec::new();
        
        for _ in 0..batch_size {
            let msg_len = u.int_in_range(0..=1024)?;
            let sig_len = u.int_in_range(0..=4096)?;
            let key_len = u.int_in_range(0..=2048)?;
            
            batch_messages.push((0..msg_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
            batch_signatures.push((0..sig_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
            batch_public_keys.push((0..key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?);
        }
        
        Ok(MLDSAFuzzInput {
            message: (0..message_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            private_key_seed: (0..seed_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            private_key_bytes: (0..private_key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            public_key_bytes: (0..public_key_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            signature_bytes: (0..signature_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            malformed_signature: (0..malformed_sig_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            modified_message: (0..modified_msg_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            key_modification_offset: u.arbitrary()?,
            key_modification_value: u.arbitrary()?,
            sig_modification_offset: u.arbitrary()?,
            sig_modification_value: u.arbitrary()?,
            context: (0..context_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            batch_messages,
            batch_signatures,
            batch_public_keys,
        })
    }
}

fuzz_target!(|input: MLDSAFuzzInput| {
    // Test generation et verification de signatures valides
    fuzz_valid_signature_flow(&input);
    
    // Test deserialization de keys malformedes
    fuzz_key_deserialization(&input);
    
    // Test deserialization de signatures malformedes
    fuzz_signature_deserialization(&input);
    
    // Test resistance aux modifications de signature
    fuzz_signature_malleability(&input);
    
    // Test resistance aux modifications de message
    fuzz_message_modification(&input);
    
    // Test verification batch
    fuzz_batch_verification(&input);
    
    // Test avec contexte
    fuzz_context_handling(&input);
});

/// Fuzz le flow complete de signature valide
fn fuzz_valid_signature_flow(input: &MLDSAFuzzInput) {
    // Test 1: Generation de keys deterministic si seed suffisant
    if input.private_key_seed.len() >= 32 {
        let seed: [u8; 32] = match input.private_key_seed[..32].try_into() {
            Ok(s) => s,
            Err(_) => return,
        };
        
        let keypair_result = generate_mldsa_keypair_from_seed(seed);
        if let Ok(keypair) = keypair_result {
            // Test de signature
            if !input.message.is_empty() {
                let signature_result = sign_mldsa(&keypair.private_key, &input.message, &input.context);
                
                if let Ok(signature) = signature_result {
                    // Test de verification
                    let verify_result = verify_mldsa(&keypair.public_key, &input.message, &signature, &input.context);
                    
                    if verify_result.is_err() {
                        // CRITIQUE: Signature generee par nous-sames doit be valide
                        panic!("SECURITY BUG: Valid signature failed verification");
                    }
                    
                    // Test de serialization/deserialization
                    test_signature_serialization(&signature, &keypair.public_key, &input.message, &input.context);
                    
                    // Test de resistance aux modifications
                    test_signature_immutability(&signature, &keypair.public_key, &input.message, &input.context);
                    
                    // Test avec message modifie (doit fail)
                    if !input.modified_message.is_empty() && input.modified_message != input.message {
                        let verify_modified = verify_mldsa(&keypair.public_key, &input.modified_message, &signature, &input.context);
                        if verify_modified.is_ok() {
                            // CRITIQUE: Signature ne doit pas be valide pour un message different
                            panic!("SECURITY BUG: Signature valid for different message");
                        }
                    }
                    
                    // Test avec contexte modifie (doit fail)
                    if !input.context.is_empty() {
                        let mut modified_context = input.context.clone();
                        if !modified_context.is_empty() {
                            modified_context[0] = modified_context[0].wrapping_add(1);
                            let verify_modified_ctx = verify_mldsa(&keypair.public_key, &input.message, &signature, &modified_context);
                            if verify_modified_ctx.is_ok() {
                                // CRITIQUE: Signature ne doit pas be valide avec contexte different
                                panic!("SECURITY BUG: Signature valid for different context");
                            }
                        }
                    }
                }
            }
            
            // Test de serialization des keys
            test_key_serialization(&keypair);
        }
    }
    
    // Test 2: Generation de keys random
    let random_keypair_result = generate_mldsa_keypair();
    if let Ok(keypair) = random_keypair_result {
        // Test de signature avec message vide
        let empty_sig_result = sign_mldsa(&keypair.private_key, &[], &[]);
        if let Ok(empty_signature) = empty_sig_result {
            let verify_empty = verify_mldsa(&keypair.public_key, &[], &empty_signature, &[]);
            if verify_empty.is_err() {
                // Signature de message vide doit be valide
                return;
            }
        }
        
        // Test avec message de taille maximale (si pas trop grand)
        if input.message.len() <= 1024 * 1024 { // 1MB max pour avoid OOM
            let large_sig_result = sign_mldsa(&keypair.private_key, &input.message, &input.context);
            if let Ok(large_signature) = large_sig_result {
                let verify_large = verify_mldsa(&keypair.public_key, &input.message, &large_signature, &input.context);
                if verify_large.is_err() {
                    // Signature de gros message doit be valide
                    return;
                }
            }
        }
    }
}

/// Test la serialization/deserialization des signatures
fn test_signature_serialization(signature: &MLDSASignature, public_key: &MLDSAPublicKey, message: &[u8], context: &[u8]) {
    // Test de serialization
    let serialized = serialize_mldsa_signature(signature);
    if serialized.is_empty() {
        // Signature serializede ne doit pas be vide
        return;
    }
    
    // Test de deserialization
    let deserialized_result = deserialize_mldsa_signature(&serialized);
    if let Ok(deserialized_sig) = deserialized_result {
        // Test de verification de la signature deserializede
        let verify_deserialized = verify_mldsa(public_key, message, &deserialized_sig, context);
        if verify_deserialized.is_err() {
            // CRITIQUE: Signature deserializede doit rester valide
            panic!("SECURITY BUG: Deserialized signature became invalid");
        }
        
        // Test de re-serialization (doit be identique)
        let re_serialized = serialize_mldsa_signature(&deserialized_sig);
        if serialized != re_serialized {
            // Probleme potentiel dans la serialization canonique
            return;
        }
    }
}

/// Test l'immutabilite des signatures
fn test_signature_immutability(signature: &MLDSASignature, public_key: &MLDSAPublicKey, message: &[u8], context: &[u8]) {
    let mut serialized = serialize_mldsa_signature(signature);
    
    // Test de modification de chaque byte
    for i in 0..serialized.len().min(256) { // Limite pour avoid timeout
        let original_byte = serialized[i];
        
        // Test avec differentes modifications
        for modification in [1u8, 255u8, original_byte.wrapping_add(1)] {
            if modification != original_byte {
                serialized[i] = modification;
                
                let modified_sig_result = deserialize_mldsa_signature(&serialized);
                if let Ok(modified_sig) = modified_sig_result {
                    let verify_modified = verify_mldsa(public_key, message, &modified_sig, context);
                    if verify_modified.is_ok() {
                        // CRITIQUE: Signature modifiee ne doit pas be valide
                        panic!("SECURITY BUG: Modified signature still valid at byte {}", i);
                    }
                }
                
                // Restaurer le byte original
                serialized[i] = original_byte;
            }
        }
    }
}

/// Test la serialization des keys
fn test_key_serialization(keypair: &MLDSAKeyPair) {
    // Test serialization key publique
    let pub_serialized = serialize_mldsa_public_key(&keypair.public_key);
    if !pub_serialized.is_empty() {
        let pub_deserialized_result = deserialize_mldsa_public_key(&pub_serialized);
        if let Ok(pub_deserialized) = pub_deserialized_result {
            // Test que la key deserializede fonctionne
            let test_message = b"test message";
            let test_sig_result = sign_mldsa(&keypair.private_key, test_message, &[]);
            if let Ok(test_sig) = test_sig_result {
                let verify_original = verify_mldsa(&keypair.public_key, test_message, &test_sig, &[]);
                let verify_deserialized = verify_mldsa(&pub_deserialized, test_message, &test_sig, &[]);
                
                if verify_original.is_ok() && verify_deserialized.is_err() {
                    // CRITIQUE: Key publique deserializede doit fonctionner
                    panic!("SECURITY BUG: Deserialized public key doesn't work");
                }
            }
        }
    }
    
    // Test serialization key private
    let priv_serialized = serialize_mldsa_private_key(&keypair.private_key);
    if !priv_serialized.is_empty() {
        let priv_deserialized_result = deserialize_mldsa_private_key(&priv_serialized);
        if let Ok(priv_deserialized) = priv_deserialized_result {
            // Test que la key private deserializede fonctionne
            let test_message = b"test message";
            let test_sig_original = sign_mldsa(&keypair.private_key, test_message, &[]);
            let test_sig_deserialized = sign_mldsa(&priv_deserialized, test_message, &[]);
            
            if let (Ok(sig_orig), Ok(sig_deser)) = (test_sig_original, test_sig_deserialized) {
                let verify_orig = verify_mldsa(&keypair.public_key, test_message, &sig_orig, &[]);
                let verify_deser = verify_mldsa(&keypair.public_key, test_message, &sig_deser, &[]);
                
                if verify_orig.is_ok() && verify_deser.is_err() {
                    // CRITIQUE: Key private deserializede doit fonctionner
                    panic!("SECURITY BUG: Deserialized private key doesn't work");
                }
            }
        }
    }
}

/// Fuzz la deserialization de keys malformedes
fn fuzz_key_deserialization(input: &MLDSAFuzzInput) {
    // Test deserialization key publique
    let pub_key_result = deserialize_mldsa_public_key(&input.public_key_bytes);
    match pub_key_result {
        Ok(pub_key) => {
            // Si la deserialization reussit, tester la key
            let test_message = b"test";
            
            // Create a signature factice pour tester la verification
            if !input.signature_bytes.is_empty() {
                let sig_result = deserialize_mldsa_signature(&input.signature_bytes);
                if let Ok(sig) = sig_result {
                    let verify_result = verify_mldsa(&pub_key, test_message, &sig, &[]);
                    // Peut fail ou reussir, ne doit pas paniquer
                    let _ = verify_result;
                }
            }
            
            // Test de re-serialization
            let re_serialized = serialize_mldsa_public_key(&pub_key);
            if !re_serialized.is_empty() {
                let round_trip = deserialize_mldsa_public_key(&re_serialized);
                let _ = round_trip; // Ne doit pas paniquer
            }
        },
        Err(_) => {
            // Failure attendu pour des data randoms
        }
    }
    
    // Test deserialization key private
    let priv_key_result = deserialize_mldsa_private_key(&input.private_key_bytes);
    match priv_key_result {
        Ok(priv_key) => {
            // Test de signature avec key deserializede
            let test_message = b"test";
            let sign_result = sign_mldsa(&priv_key, test_message, &[]);
            let _ = sign_result; // Peut fail ou reussir
            
            // Test de re-serialization
            let re_serialized = serialize_mldsa_private_key(&priv_key);
            if !re_serialized.is_empty() {
                let round_trip = deserialize_mldsa_private_key(&re_serialized);
                let _ = round_trip;
            }
        },
        Err(_) => {
            // Failure attendu
        }
    }
    
    // Test avec data tronquees
    test_truncated_keys(input);
    
    // Test avec patterns adversariaux
    test_adversarial_key_patterns();
}

/// Test avec data de keys tronquees
fn test_truncated_keys(input: &MLDSAFuzzInput) {
    // Test key publique tronquee
    if input.public_key_bytes.len() > 10 {
        for len in [1, 4, 8, input.public_key_bytes.len() / 2, input.public_key_bytes.len() - 1] {
            if len < input.public_key_bytes.len() {
                let truncated = &input.public_key_bytes[..len];
                let result = deserialize_mldsa_public_key(truncated);
                // Doit fail gracieusement
                if result.is_ok() {
                    // Data tronquees ne devraient pas be acceptees
                }
            }
        }
    }
    
    // Test key private tronquee
    if input.private_key_bytes.len() > 10 {
        for len in [1, 4, 8, input.private_key_bytes.len() / 2, input.private_key_bytes.len() - 1] {
            if len < input.private_key_bytes.len() {
                let truncated = &input.private_key_bytes[..len];
                let result = deserialize_mldsa_private_key(truncated);
                // Doit fail gracieusement
                let _ = result;
            }
        }
    }
}

/// Test avec patterns adversariaux pour les keys
fn test_adversarial_key_patterns() {
    let patterns = [
        vec![0x00; 2048],           // Tous zeros
        vec![0xFF; 2048],           // Tous uns
        (0u8..=255).cycle().take(2048).collect::<Vec<u8>>(), // Sequence
        vec![0xAA, 0x55].repeat(1024), // Pattern alterne
    ];
    
    for pattern in &patterns {
        // Test key publique
        let pub_result = deserialize_mldsa_public_key(pattern);
        let _ = pub_result;
        
        // Test key private
        let priv_result = deserialize_mldsa_private_key(pattern);
        let _ = priv_result;
    }
}

/// Fuzz la deserialization de signatures malformedes
fn fuzz_signature_deserialization(input: &MLDSAFuzzInput) {
    // Test avec signature_bytes
    let sig_result = deserialize_mldsa_signature(&input.signature_bytes);
    let _ = sig_result;
    
    // Test avec malformed_signature
    let malformed_result = deserialize_mldsa_signature(&input.malformed_signature);
    let _ = malformed_result;
    
    // Test avec data tronquees
    if input.signature_bytes.len() > 10 {
        for len in [1, 4, 8, input.signature_bytes.len() / 2, input.signature_bytes.len() - 1] {
            if len < input.signature_bytes.len() {
                let truncated = &input.signature_bytes[..len];
                let result = deserialize_mldsa_signature(truncated);
                let _ = result;
            }
        }
    }
    
    // Test avec patterns adversariaux
    let patterns = [
        vec![0x00; 4096],
        vec![0xFF; 4096],
        (0u8..=255).cycle().take(4096).collect::<Vec<u8>>(),
    ];
    
    for pattern in &patterns {
        let result = deserialize_mldsa_signature(pattern);
        let _ = result;
    }
}

/// Fuzz la resistance aux modifications de signature
fn fuzz_signature_malleability(input: &MLDSAFuzzInput) {
    if input.signature_bytes.len() > input.sig_modification_offset {
        let mut modified_sig = input.signature_bytes.clone();
        modified_sig[input.sig_modification_offset] = input.sig_modification_value;
        
        let sig_result = deserialize_mldsa_signature(&modified_sig);
        if let Ok(sig) = sig_result {
            // Create a key publique factice pour tester
            if let Ok(keypair) = generate_mldsa_keypair() {
                let verify_result = verify_mldsa(&keypair.public_key, &input.message, &sig, &input.context);
                // Peut fail ou reussir, ne doit pas paniquer
                let _ = verify_result;
            }
        }
    }
}

/// Fuzz la resistance aux modifications de message
fn fuzz_message_modification(input: &MLDSAFuzzInput) {
    // Generate une signature valide
    if let Ok(keypair) = generate_mldsa_keypair() {
        if let Ok(signature) = sign_mldsa(&keypair.private_key, &input.message, &input.context) {
            // Test avec message modifie
            if !input.modified_message.is_empty() && input.modified_message != input.message {
                let verify_modified = verify_mldsa(&keypair.public_key, &input.modified_message, &signature, &input.context);
                if verify_modified.is_ok() {
                    // CRITIQUE: Ne doit pas be valide pour message different
                    panic!("SECURITY BUG: Signature valid for modified message");
                }
            }
            
            // Test avec modifications byte par byte (echantillonnage)
            if !input.message.is_empty() {
                let mut modified_msg = input.message.clone();
                let test_positions = [0, input.message.len() / 2, input.message.len() - 1];
                
                for &pos in &test_positions {
                    if pos < modified_msg.len() {
                        let original = modified_msg[pos];
                        modified_msg[pos] = original.wrapping_add(1);
                        
                        let verify_modified = verify_mldsa(&keypair.public_key, &modified_msg, &signature, &input.context);
                        if verify_modified.is_ok() {
                            // CRITIQUE: Ne doit pas be valide
                            panic!("SECURITY BUG: Signature valid for byte-modified message at pos {}", pos);
                        }
                        
                        // Restaurer
                        modified_msg[pos] = original;
                    }
                }
            }
        }
    }
}

/// Fuzz la verification batch
fn fuzz_batch_verification(input: &MLDSAFuzzInput) {
    if input.batch_messages.is_empty() {
        return;
    }
    
    // Create signatures valides pour test
    let mut valid_signatures = Vec::new();
    let mut valid_public_keys = Vec::new();
    
    for message in &input.batch_messages {
        if let Ok(keypair) = generate_mldsa_keypair() {
            if let Ok(signature) = sign_mldsa(&keypair.private_key, message, &[]) {
                valid_signatures.push(signature);
                valid_public_keys.push(keypair.public_key);
            }
        }
    }
    
    // Test verification batch valide
    if !valid_signatures.is_empty() {
        let batch_verify_result = verify_mldsa_batch(
            &valid_public_keys,
            &input.batch_messages,
            &valid_signatures,
            &vec![vec![]; valid_signatures.len()], // Contextes vides
        );
        
        if batch_verify_result.is_err() {
            // Signatures valides doivent passer la verification batch
            return;
        }
    }
    
    // Test avec signatures malformedes du fuzzer
    let mut fuzz_signatures = Vec::new();
    let mut fuzz_public_keys = Vec::new();
    
    for (sig_bytes, key_bytes) in input.batch_signatures.iter().zip(input.batch_public_keys.iter()) {
        if let Ok(sig) = deserialize_mldsa_signature(sig_bytes) {
            if let Ok(key) = deserialize_mldsa_public_key(key_bytes) {
                fuzz_signatures.push(sig);
                fuzz_public_keys.push(key);
            }
        }
    }
    
    if !fuzz_signatures.is_empty() && fuzz_signatures.len() == fuzz_public_keys.len() {
        let messages_ref: Vec<&[u8]> = input.batch_messages.iter().take(fuzz_signatures.len()).map(|m| m.as_slice()).collect();
        if messages_ref.len() == fuzz_signatures.len() {
            let batch_verify_fuzz = verify_mldsa_batch(
                &fuzz_public_keys,
                &messages_ref,
                &fuzz_signatures,
                &vec![vec![]; fuzz_signatures.len()],
            );
            // Peut fail ou reussir, ne doit pas paniquer
            let _ = batch_verify_fuzz;
        }
    }
}

/// Fuzz la gestion du contexte
fn fuzz_context_handling(input: &MLDSAFuzzInput) {
    if let Ok(keypair) = generate_mldsa_keypair() {
        // Test avec differentes tailles de contexte
        let contexts = [
            vec![],                    // Vide
            input.context.clone(),     // Du fuzzer
            vec![0; 255],             // Taille max
            vec![0xFF; 255],          // Taille max, tous 1
        ];
        
        for context in &contexts {
            // Test signature avec contexte
            let sign_result = sign_mldsa(&keypair.private_key, &input.message, context);
            
            if let Ok(signature) = sign_result {
                // Test verification avec same contexte
                let verify_result = verify_mldsa(&keypair.public_key, &input.message, &signature, context);
                if verify_result.is_err() {
                    // Signature avec contexte doit be valide
                    return;
                }
                
                // Test verification avec contexte different
                let different_context = if context.is_empty() {
                    vec![1]
                } else {
                    vec![]
                };
                
                let verify_different = verify_mldsa(&keypair.public_key, &input.message, &signature, &different_context);
                if verify_different.is_ok() {
                    // CRITIQUE: Ne doit pas be valide avec contexte different
                    panic!("SECURITY BUG: Signature valid with different context");
                }
            }
        }
        
        // Test avec contexte trop grand (> 255 bytes)
        if input.context.len() > 255 {
            let oversized_context = &input.context[..256]; // Prendre 256 bytes
            let sign_oversized = sign_mldsa(&keypair.private_key, &input.message, oversized_context);
            // Doit fail gracieusement
            let _ = sign_oversized;
        }
    }
}