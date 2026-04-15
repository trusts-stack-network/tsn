//! Exemples de code vulnerable pour demonstration des tests de regression
//! NE PAS UTILISER EN PRODUCTION - Ces implementations sont intentionnellement faibles

/// Comparison de MAC vulnerable aux attaques temporelles
pub fn insecure_compare_mac(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // VULNERABILITY: early return sur difference
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // Timing leak ici
        }
    }
    true
}

/// Chiffrement avec nonce reused (catastrophique pour AES-GCM/ChaCha20)
pub struct InsecureNonceGenerator {
    counter: u64,
}

impl InsecureNonceGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
    
    pub fn next_nonce(&mut self) -> [u8; 12] {
        // VULNERABILITY: nonce predictable et potentiellement reused after restartup
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        nonce
    }
}

/// Decryption avec distinction d'errors (Padding Oracle)
#[derive(Debug)]
pub enum InsecureDecryptError {
    PaddingError,
    IntegrityError,
}

pub fn insecure_decrypt_with_padding(
    ciphertext: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, InsecureDecryptError> {
    // Simulation de verification de padding distincte de l'integrity
    if ciphertext.len() % 16 != 0 {
        return Err(InsecureDecryptError::PaddingError);
    }
    
    // ... decryption ...
    
    // VULNERABILITY: errors distinctes allowstent padding oracle attack
    if !verify_padding(ciphertext) {
        return Err(InsecureDecryptError::PaddingError);
    }
    
    if !verify_mac(ciphertext) {
        return Err(InsecureDecryptError::IntegrityError);
    }
    
    Ok(vec![]) // plaintext
}

fn verify_padding(_data: &[u8]) -> bool { true }
fn verify_mac(_data: &[u8]) -> bool { true }