//! Implementations volontairement vulnerables for demonstration
//! 
//! ⚠️ **ATTENTION : MODULES DE DEMONSTRATION UNIQUEMENT** ⚠️
//! 
//! Ces implementations contiennent of vulnerabilities cryptographiques intentionnelles
//! for education and the tests de security. Elles not doivent JAMAIS be used
//! in production or in of the code real.
//! 
//! ## Activation
//! 
//! Ces modules not are compiled que if the feature `vulnerable-demo` is enabled :
//! ```bash
//! cargo build --features vulnerable-demo
//! cargo test --features vulnerable-demo
//! ```
//! 
//! ## Vulnerabilities implementedes
//! 
//! 1. **Timing Attacks** : Comparaisons non-constant-time
//! 2. **Nonce Reuse**: Nonce reuse in CTR mode
//! 3. **Predictable RNG**: Seedable pseudo-random generator
//! 4. **Padding Oracle**: Vulnerable PKCS#7 verification
//! 5. **Naive KDF**: Key derivation without salt or iterations

// ⚠️ PROTECTION: This module only compiles if the vulnerable-demo feature is enabled
// compile_error removed : the module is already cfg-gated in mod.rs
// with #[cfg(any(test, feature = "vulnerable-demo"))]

#[cfg(feature = "vulnerable-demo")]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(feature = "vulnerable-demo")]
use aes::Aes128;

/// VULNERABILITY: Non-constant-time comparison (timing attack).
///
/// **Problem**: This function leaks information through its execution time.
/// An attacker can guess the key or the message one byte at a time by measuring
/// the response time.
///
/// **Attack**: Measure the response time to determine how many bytes are correct
/// before the first mismatch.
///
/// **Fix**: Use `subtle::ConstantTimeEq` for secure comparisons.
#[cfg(feature = "vulnerable-demo")]
pub fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    // VULNERABILITY: Early return sur first byte different
    // Timing leak : the temps d'execution reveals the position of the first byte incorrect
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ Timing leak ici
        }
    }
    true
}

/// VULNERABILITY: Nonce reuse in AES-CTR
/// 
/// **Problem** : Reuse the same nonce+key reveals the XOR of plaintexts.
/// Si on chiffre P1 and P2 with the same keystream K, alors :
/// C1 ⊕ C2 = P1 ⊕ P2 (le keystream s'annule)
/// 
/// **Attaque** : Retrieval de plaintext par analyse differentielle.
/// 
/// **Solution** : Generate a nonce random unique for each chiffrement.
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
    
    /// VULNERABILITY: Incrementation predictable and pas de verification de nonce
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        
        for (i, pt_byte) in plaintext.iter().enumerate() {
            let block_idx = (self.counter + i as u64) / 16;
            let block_offset = (self.counter + i as u64) % 16;
            
            // Generation of the keystream (simplified, vulnerable)
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

/// VULNERABILITY: RNG predictable (seedable)
/// 
/// **Problem** : Generator deterministic allowstant the reproduction of keys
/// if the seed is guessed or connu.
/// 
/// **Attaque** : Prediction of keys futures if the seed or l'state interne is compromis.
/// 
/// **Solution** : Utiliser `rand::thread_rng()` or `OsRng` for de l'entropie cryptographique.
#[cfg(feature = "vulnerable-demo")]
pub struct PredictableRng {
    state: u64,
}

#[cfg(feature = "vulnerable-demo")]
impl PredictableRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    
    /// Generator linear congruentiel (LCG) - predictable
    pub fn next_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            // ⚠️ LCG predictable : state suivant = (a * state + c) mod m
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let bytes = self.state.to_le_bytes();
            let len = chunk.len().min(8);
            chunk.copy_from_slice(&bytes[..len]);
        }
    }
}

/// VULNERABILITY: Padding Oracle (PKCS#7 non verified in constant-time)
/// 
/// **Problem** : La verification of the padding reveals of informations via the timing
/// or the messages d'error, allowstant de decrypt without know the key.
/// 
/// **Attaque** : Padding Oracle Attack - modification systematic of the last bloc
/// for determine the plaintext byte par byte.
/// 
/// **Solution**: Constant-time verification and uniform error messages.
#[cfg(feature = "vulnerable-demo")]
pub fn remove_pkcs7_padding(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let pad_len = data[data.len() - 1] as usize;
    
    // VULNERABILITY: Verification non-constant-time
    // Timing different selon the validity of the padding
    if pad_len == 0 || pad_len > 16 {
        return None; // ⚠️ Early return = timing leak
    }
    
    // Verification of bytes de padding (court-circuit = timing leak)
    for i in 0..pad_len {
        if data[data.len() - 1 - i] != pad_len as u8 {
            return None; // ⚠️ Early return = timing leak
        }
    }
    
    Some(&data[..data.len() - pad_len])
}

/// VULNERABILITY: KDF naive (simple SHA256)
/// 
/// **Problem** : Derivation de key without sel, without iterations, vulnerable aux
/// rainbow tables and aux attaques par dictionnaire.
/// 
/// **Attaque** : Precalculation de hashes for mots de passe courants (rainbow tables).
/// 
/// **Solution** : Utiliser PBKDF2, scrypt, or Argon2 with sel random and iterations.
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
        let guess1 = b"secret_key_12346"; // Last byte different
        let guess2 = b"wrong_key_123456"; // First byte different
        
        // Ces comparisons devraient prendre of temps different
        // (non tested automatically car dependsant of the timing)
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
        
        // Verification de the vulnerability : C1 ⊕ C2 = P1 ⊕ P2
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
        
        // Same seed = same sortie (predictable)
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