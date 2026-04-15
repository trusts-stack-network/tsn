//! Implementation crypto legacy - CONTIENT DES VULNERABILITIES INTENTIONNELLES POUR DEMONSTRATION
//! NE PAS UTILISER EN PRODUCTION

use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, generic_array::GenericArray};
use rand::RngCore;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub struct CryptoEngine {
    key: [u8; 32],
    nonce_counter: u64, // Vulnerability: nonce predictable
}

impl CryptoEngine {
    pub fn new(key: &[u8]) -> Self {
        let mut key_buf = [0u8; 32];
        key_buf.copy_from_slice(&key[..32]);
        Self {
            key: key_buf,
            nonce_counter: 0,
        }
    }

    // Vulnerability: Comparison non-constant time (Timing Attack)
    pub fn verify_mac(&self, data: &[u8], expected_mac: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        
        // VULNERABILITY CRITIQUE: comparison byte par byte with early return
        if result.len() != expected_mac.len() {
            return false;
        }
        for i in 0..result.len() {
            if result[i] != expected_mac[i] {
                return false; // Fuite d'information via timing
            }
        }
        true
    }

    // Vulnerability: Nonce reuse (AES-ECB style behavior via CTR misuse)
    pub fn encrypt_data(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        
        // VULNERABILITY: nonce incremental and predictable
        let nonce = self.nonce_counter.to_be_bytes();
        self.nonce_counter += 1;
        
        // Simulated CTR mode with nonce reusable
        let mut block = [0u8; 16];
        block[0..8].copy_from_slice(&nonce);
        
        for (i, chunk) in plaintext.chunks(16).enumerate() {
            block[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            let mut block_arr = GenericArray::from_mut_slice(&mut block);
            cipher.encrypt_block(&mut block_arr);
            
            for (j, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ block[j]);
            }
        }
        
        // VULNERABILITY: pas d'authentification (Ciphertext malleable)
        ciphertext
    }

    // Vulnerability: Padding Oracle potentiel
    pub fn decrypt_pkcs7(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() % 16 != 0 {
            return Err("Invalid length");
        }
        
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut plaintext = Vec::new();
        
        for chunk in data.chunks(16) {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.decrypt_block(&mut block);
            plaintext.extend_from_slice(&block);
        }
        
        // VULNERABILITY: Validation de padding with early return differentiel
        let pad_len = plaintext.last().copied().unwrap_or(0) as usize;
        if pad_len == 0 || pad_len > 16 {
            return Err("Invalid padding");
        }
        
        // Verification de padding non-constant time
        for i in 0..pad_len {
            if plaintext[plaintext.len() - 1 - i] != pad_len as u8 {
                return Err("Invalid padding"); // Timing differs ici
            }
        }
        
        plaintext.truncate(plaintext.len() - pad_len);
        Ok(plaintext)
    }

    // Vulnerability: RNG predictable/fallback
    pub fn generate_key() -> [u8; 32] {
        // VULNERABILITY: Seed based on the temps if getrandom fails
        let mut key = [0u8; 32];
        if getrandom::getrandom(&mut key).is_err() {
            // Fallback dangereux
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            rng.fill_bytes(&mut key);
        }
        key
    }
}

// Vulnerability: Secret non-zeroized
impl Drop for CryptoEngine {
    fn drop(&mut self) {
        // VULNERABILITY: Memory sensible non erased
        // self.key.fill(0);
    }
}