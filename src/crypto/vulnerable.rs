//! Implementations volontairement vulnerables pour demonstration
//! 
//! ⚠️ **ATTENTION : DEMONSTRATION MODULES ONLY** ⚠️
//! 
//! Ces implementations contiennent des vulnerabilitys cryptographiques intentionnelles
//! pour l'education et les tests de security. Elles ne doivent JAMAIS be utilisees
//! en production ou dans du code reel.
//! 
//! ## Activation
//! 
//! Ces modules ne sont compiles que si la feature `vulnerable-demo` est activee :
//! ```bash
//! cargo build --features vulnerable-demo
//! cargo test --features vulnerable-demo
//! ```
//! 
//! ## Vulnerabilites implementees
//! 
//! 1. **Timing Attacks** : Comparaisons non-constant-time
//! 2. **Nonce Reuse** : Reutilisation de nonces en mode CTR
//! 3. **RNG previsible** : Generateur pseudo-random seedable
//! 4. **Padding Oracle** : Verification PKCS#7 vulnerable
//! 5. **KDF naif** : Derivation de key sans sel ni iterations

// ⚠️ PROTECTION : Ce module ne compile QUE si la feature vulnerable-demo est activee
// compile_error deleted : le module est already cfg-gate dans mod.rs
// avec #[cfg(any(test, feature = "vulnerable-demo"))]

#[cfg(feature = "vulnerable-demo")]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(feature = "vulnerable-demo")]
use aes::Aes128;

/// VULNERABILITY: Comparaison non-constant-time (Timing Attack)
/// 
/// **Probleme** : Cette fonction revele des informations via le temps d'execution.
/// Un attaquant peut deviner la key ou le message byte par byte en mesurant
/// le temps de response.
/// 
/// **Attaque** : Mesurer le temps pour determiner combien de bytes sont corrects
/// avant le premier echec.
/// 
/// **Solution** : Utiliser `subtle::ConstantTimeEq` pour des comparaisons securisees.
#[cfg(feature = "vulnerable-demo")]
pub fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    // VULNERABILITY: Early return sur premier byte different
    // Timing leak : le temps d'execution revele la position du premier byte incorrect
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ Timing leak ici
        }
    }
    true
}

/// VULNERABILITY: Nonce reuse dans AES-CTR
/// 
/// **Probleme** : Reusesr le same nonce+key revele le XOR des plaintexts.
/// Si on chiffre P1 et P2 avec le same keystream K, alors :
/// C1 ⊕ C2 = P1 ⊕ P2 (le keystream s'annule)
/// 
/// **Attaque** : Recuperation de plaintext par analyse differentielle.
/// 
/// **Solution** : Generate un nonce random unique pour chaque chiffrement.
#[cfg(feature = "vulnerable-demo")]
pub struct InsecureCtrMode {
    key: [u8; 16],
    nonce: [u8; 16], // ⚠️ Nonce fixe = vulnerability
    counter: u64,
}

#[cfg(feature = "vulnerable-demo")]
impl InsecureCtrMode {
    pub fn new(key: [u8; 16], nonce: [u8; 16]) -> Self {
        Self { key, nonce, counter: 0 }
    }
    
    /// VULNERABILITY: Incrementation previsible et pas de verification de nonce
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        
        for (i, pt_byte) in plaintext.iter().enumerate() {
            let block_idx = (self.counter + i as u64) / 16;
            let block_offset = (self.counter + i as u64) % 16;
            
            // Generation du keystream (simplifie, vulnerable)
            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&self.nonce[0..8]);
            block[8..16].copy_from_slice(&block_idx.to_le_bytes());
            
            let mut aes_block = GenericArray::from_mut_slice(&mut block);
            cipher.encrypt_block(&mut aes_block);
            
            ciphertext.push(pt_byte ^ block[block_offset as usize]);
        }
        
        self.counter += plaintext.len() as u64;
        ciphertext
    }
}

/// VULNERABILITY: RNG previsible (seedable)
/// 
/// **Probleme** : Generateur deterministic allowstant la reproduction des keys
/// si le seed est devine ou connu.
/// 
/// **Attaque** : Prediction des keys futures si le seed ou l'state interne est compromis.
/// 
/// **Solution** : Utiliser `rand::thread_rng()` ou `OsRng` pour de l'entropie cryptographique.
#[cfg(feature = "vulnerable-demo")]
pub struct PredictableRng {
    state: u64,
}

#[cfg(feature = "vulnerable-demo")]
impl PredictableRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    
    /// Generateur lineaire congruentiel (LCG) - previsible
    pub fn next_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            // ⚠️ LCG previsible : state suivant = (a * state + c) mod m
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let bytes = self.state.to_le_bytes();
            let len = chunk.len().min(8);
            chunk.copy_from_slice(&bytes[..len]);
        }
    }
}

/// VULNERABILITY: Padding Oracle (PKCS#7 non verified en constant-time)
/// 
/// **Probleme** : La verification du padding revele des informations via le timing
/// ou les messages d'error, allowstant de dechiffrer sans connaitre la key.
/// 
/// **Attaque** : Padding Oracle Attack - modification systematique du dernier bloc
/// pour determiner le plaintext byte par byte.
/// 
/// **Solution** : Verification en constant-time et messages d'error uniformes.
#[cfg(feature = "vulnerable-demo")]
pub fn remove_pkcs7_padding(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let pad_len = data[data.len() - 1] as usize;
    
    // VULNERABILITY: Verification non-constant-time
    // Timing different selon la validite du padding
    if pad_len == 0 || pad_len > 16 {
        return None; // ⚠️ Early return = timing leak
    }
    
    // Verification des bytes de padding (court-circuit = timing leak)
    for i in 0..pad_len {
        if data[data.len() - 1 - i] != pad_len as u8 {
            return None; // ⚠️ Early return = timing leak
        }
    }
    
    Some(&data[..data.len() - pad_len])
}

/// VULNERABILITY: KDF naif (simple SHA256)
/// 
/// **Probleme** : Derivation de key sans sel, sans iterations, vulnerable aux
/// rainbow tables et aux attaques par dictionnaire.
/// 
/// **Attaque** : Precalcul de hashes pour mots de passe courants (rainbow tables).
/// 
/// **Solution** : Utiliser PBKDF2, scrypt, ou Argon2 avec sel random et iterations.
#[cfg(feature = "vulnerable-demo")]
pub fn naive_kdf(password: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password); // ⚠️ Pas de sel, pas d'iterations
    hasher.finalize().into()
}

#[cfg(all(test, feature = "vulnerable-demo"))]
mod tests {
    use super::*;

    #[test]
    fn test_timing_attack_vulnerability() {
        let secret = b"secret_key_12345";
        let guess1 = b"secret_key_12346"; // Dernier byte different
        let guess2 = b"wrong_key_123456"; // Premier byte different
        
        // Ces comparaisons devraient prendre des temps differents
        // (non teste automatiquement car dependant du timing)
        assert!(!insecure_compare(secret, guess1));
        assert!(!insecure_compare(secret, guess2));
    }

    #[test]
    fn test_nonce_reuse_vulnerability() {
        let key = [0u8; 16];
        let nonce = [1u8; 16];
        
        let mut cipher1 = InsecureCtrMode::new(key, nonce);
        let mut cipher2 = InsecureCtrMode::new(key, nonce); // ⚠️ Same nonce
        
        let plaintext1 = b"Hello World!";
        let plaintext2 = b"Secret Data!";
        
        let ciphertext1 = cipher1.encrypt(plaintext1);
        let ciphertext2 = cipher2.encrypt(plaintext2);
        
        // Verification de la vulnerability : C1 ⊕ C2 = P1 ⊕ P2
        let xor_ciphertexts: Vec<u8> = ciphertext1.iter()
            .zip(ciphertext2.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        let xor_plaintexts: Vec<u8> = plaintext1.iter()
            .zip(plaintext2.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        assert_eq!(xor_ciphertexts, xor_plaintexts);
    }

    #[test]
    fn test_predictable_rng() {
        let mut rng1 = PredictableRng::new(12345);
        let mut rng2 = PredictableRng::new(12345); // Same seed
        
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        
        rng1.next_bytes(&mut buf1);
        rng2.next_bytes(&mut buf2);
        
        // Same seed = same sortie (previsible)
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_padding_oracle_vulnerability() {
        let valid_data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x02\x02";
        let invalid_data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x02\x03";
        
        assert!(remove_pkcs7_padding(valid_data).is_some());
        assert!(remove_pkcs7_padding(invalid_data).is_none());
    }

    #[test]
    fn test_naive_kdf() {
        let password1 = b"password123";
        let password2 = b"password123";
        let password3 = b"different_pw";
        
        let key1 = naive_kdf(password1);
        let key2 = naive_kdf(password2);
        let key3 = naive_kdf(password3);
        
        // Same mot de passe = same key (pas de sel)
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}