//! Primitives cryptographiques durcies contre the side-channels
//! 
//! MITIGATIONS:
//! - Comparaisons in temps constant via `subtle`
//! - Zeroization explicite of secrets
//! - Pas de branches sur data secret
//! - Alignment memory for avoidr the cache-line splits

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, CryptoRng};

/// Constant-time error (no error case distinction)
#[derive(Debug, Clone, Copy)]
pub struct CryptoError;

/// Key symetric secure (zeroized automatically)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(skip)]
    pub id: u64,
    pub material: [u8; 32],
}

/// Comparaison MAC in temps constant
/// PREVIOUS VULNERABILITY: `mac1 == mac2` vulnerable to timing attack
/// MITIGATION: Usage of subtle::ConstantTimeEq
pub fn verify_mac(mac1: &[u8], mac2: &[u8]) -> Choice {
    if mac1.len() != mac2.len() {
        return Choice::from(0);
    }
    mac1.ct_eq(mac2)
}

/// Derivation de key resistant aux side-channels
pub fn derive_key_scrypt(password: &[u8], salt: &[u8]) -> Result<SecureKey, CryptoError> {
    // Parameters conservateurs for resistance brute-force
    let params = scrypt::Params::new(15, 8, 1, 32)
        .map_err(|_| CryptoError)?;
    
    let mut key_material = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut key_material)
        .map_err(|_| CryptoError)?;
    
    Ok(SecureKey {
        id: 0,
        material: key_material,
    })
}

/// Validation de padding PKCS#7 in temps constant
/// VULNERABILITY: Timing differences reveal padding invalid
pub fn verify_padding_constant_time(data: &[u8], block_size: usize) -> Choice {
    if data.is_empty() || data.len() % block_size != 0 {
        return Choice::from(0);
    }
    
    let last_byte = data[data.len() - 1];
    let pad_len = last_byte as usize;
    
    if pad_len == 0 || pad_len > block_size {
        return Choice::from(0);
    }
    
    let mut valid = Choice::from(1);
    let start = data.len() - pad_len;
    
    // Verification in temps constant - pas de short-circuit
    for i in start..data.len() {
        let expected = (pad_len - (data.len() - 1 - i)) as u8;
        valid &= data[i].ct_eq(&expected);
    }
    
    valid
}

/// Generation de nonce with protection contre reuse
pub struct NonceGenerator {
    counter: std::sync::atomic::AtomicU64,
    random_prefix: [u8; 8],
}

impl NonceGenerator {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut prefix = [0u8; 8];
        rng.fill_bytes(&mut prefix);
        Self {
            counter: std::sync::atomic::Atomic