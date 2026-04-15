//! Fuzzer pour les operations de signature ML-DSA
//!
//! Ce fuzzer teste la robustesse des fonctions de signature et verification
//! ML-DSA contre des inputs malformeds et des attaques potentielles.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::pq::ml_dsa::{keygen_from_seed, sign, verify, PublicKey, SecretKey, Signature};

#[derive(Arbitrary, Debug)]
struct MLDSAFuzzInput {
    seed: [u8; 32],
    message: Vec<u8>,
    operation: FuzzOperation,
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    SignVerify,
    VerifyInvalidSignature { sig_bytes: Vec<u8> },
    VerifyInvalidPublicKey { pk_bytes: Vec<u8> },
    SignLargeMessage,
    VerifyWithWrongKey { wrong_seed: [u8; 32] },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    if let Ok(input) = MLDSAFuzzInput::arbitrary(&mut u) {
        match input.operation {
            FuzzOperation::SignVerify => {
                fuzz_sign_verify(&input.seed, &input.message);
            }
            
            FuzzOperation::VerifyInvalidSignature { sig_bytes } => {
                fuzz_verify_invalid_signature(&input.seed, &input.message, &sig_bytes);
            }
            
            FuzzOperation::VerifyInvalidPublicKey { pk_bytes } => {
                fuzz_verify_invalid_public_key(&input.message, &pk_bytes);
            }
            
            FuzzOperation::SignLargeMessage => {
                // Create a message very large pour tester les limites
                let large_message: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
                fuzz_sign_verify(&input.seed, &large_message);
            }
            
            FuzzOperation::VerifyWithWrongKey { wrong_seed } => {
                fuzz_verify_wrong_key(&input.seed, &wrong_seed, &input.message);
            }
        }
    }
});

fn fuzz_sign_verify(seed: &[u8; 32], message: &[u8]) {
    // Generation de keys ne doit jamais paniquer
    let keygen_result = std::panic::catch_unwind(|| {
        keygen_from_seed(seed)
    });
    
    let (sk, pk) = match keygen_result {
        Ok(Ok(keys)) => keys,
        Ok(Err(_)) => return, // Erreur de keygen, pas un panic
        Err(_) => panic!("keygen_from_seed a panique avec seed: {:?}", seed),
    };
    
    // Signature ne doit jamais paniquer
    let sign_result = std::panic::catch_unwind(|| {
        sign(&sk, message)
    });
    
    let signature = match sign_result {
        Ok(sig) => sig,
        Err(_) => panic!("sign a panique avec message de {} bytes", message.len()),
    };
    
    // Verification ne doit jamais paniquer
    let verify_result = std::panic::catch_unwind(|| {
        verify(&pk, message, &signature)
    });
    
    let is_valid = match verify_result {
        Ok(valid) => valid,
        Err(_) => panic!("verify a panique"),
    };
    
    // Une signature valide doit toujours be verifiede comme valide
    if !is_valid {
        panic!("Signature valide rejetee par verify()");
    }
}

fn fuzz_verify_invalid_signature(seed: &[u8; 32], message: &[u8], sig_bytes: &[u8]) {
    // Generate une key valide
    let keygen_result = keygen_from_seed(seed);
    let (_sk, pk) = match keygen_result {
        Ok(keys) => keys,
        Err(_) => return, // Erreur de keygen
    };
    
    // Essayer de create une signature a partir des bytes arbitraires
    // Note: On ne peut pas create directement une Signature depuis des bytes
    // dans l'API currentle, donc on teste indirectement
    
    // Create a signature valide puis la modifier
    if !message.is_empty() {
        let valid_sig = sign(&_sk, message);
        
        // Tester la verification avec un message different (doit be false)
        let modified_message = if message.len() > 1 {
            let mut mod_msg = message.to_vec();
            mod_msg[0] = mod_msg[0].wrapping_add(1);
            mod_msg
        } else {
            vec![0u8]
        };
        
        let verify_result = std::panic::catch_unwind(|| {
            verify(&pk, &modified_message, &valid_sig)
        });
        
        match verify_result {
            Ok(false) => {}, // Attendu: signature invalid
            Ok(true) => panic!("Signature acceptee pour un message modifie!"),
            Err(_) => panic!("verify a panique avec message modifie"),
        }
    }
}

fn fuzz_verify_invalid_public_key(message: &[u8], pk_bytes: &[u8]) {
    // Try to create une key publique a partir de bytes arbitraires
    // Note: L'API currentle ne allows pas de create directement une PublicKey
    // depuis des bytes arbitraires, donc on teste la robustesse indirectement
    
    // Generate une key valide pour avoir une signature valide
    let seed = [42u8; 32];
    if let Ok((sk, _pk)) = keygen_from_seed(&seed) {
        if !message.is_empty() {
            let signature = sign(&sk, message);
            
            // Generate une autre key (differente) et tester la verification
            let wrong_seed = [99u8; 32];
            if let Ok((_wrong_sk, wrong_pk)) = keygen_from_seed(&wrong_seed) {
                let verify_result = std::panic::catch_unwind(|| {
                    verify(&wrong_pk, message, &signature)
                });
                
                match verify_result {
                    Ok(false) => {}, // Attendu: signature invalid avec mauvaise key
                    Ok(true) => panic!("Signature acceptee avec une mauvaise key publique!"),
                    Err(_) => panic!("verify a panique avec une key publique differente"),
                }
            }
        }
    }
}

fn fuzz_verify_wrong_key(correct_seed: &[u8; 32], wrong_seed: &[u8; 32], message: &[u8]) {
    // Generate deux paires de keys differentes
    let correct_keys = keygen_from_seed(correct_seed);
    let wrong_keys = keygen_from_seed(wrong_seed);
    
    if let (Ok((sk, _pk)), Ok((_wrong_sk, wrong_pk))) = (correct_keys, wrong_keys) {
        if !message.is_empty() {
            // Signer avec la bonne key
            let signature = sign(&sk, message);
            
            // Verifier avec la mauvaise key (doit be false)
            let verify_result = std::panic::catch_unwind(|| {
                verify(&wrong_pk, message, &signature)
            });
            
            match verify_result {
                Ok(false) => {}, // Attendu
                Ok(true) => {
                    // Check that les keys sont vraiment differentes
                    if correct_seed != wrong_seed {
                        panic!("Signature acceptee avec une key differente!");
                    }
                }
                Err(_) => panic!("verify a panique lors du test de key incorrecte"),
            }
        }
    }
}