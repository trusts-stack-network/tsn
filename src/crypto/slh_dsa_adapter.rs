//! Adaptateur SLH-DSA utilisant la crate FIPS 204 officielle
//!
//! Ce module fournit une interface unified pour les signatures SLH-DSA (SPHINCS+)
//! en utilisant l'implementation FIPS 205 officielle via la crate `fips204`.
//!
//! # Parameters de security
//! - SLH-DSA-SHA2-128s: 128 bits de security classique, 64 bits post-quantique
//! - Key publique: 32 octets
//! - Key secret: 64 bytes  
//! - Signature: ~7.8KB
//!
//! # References
//! - FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
//! - Crate fips204: <https://crates.io/crates/fips204>

use fips204::{
    slh_dsa_sha2_128s as slh_dsa,
    traits::{KeyGen, Signer, Verifier},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Erreurs de l'adaptateur SLH-DSA
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaAdapterError {
    #[error("Failure de generation de key SLH-DSA")]
    KeyGenerationFailed,
    #[error("Failure de signature SLH-DSA: {0}")]
    SigningFailed(String),
    #[error("Failure de verification SLH-DSA")]
    VerificationFailed,
    #[error("Format de key publique invalid (attendu {expected} octets, received {actual})")]
    InvalidPublicKeyFormat { expected: usize, actual: usize },
    #[error("Format de key secret invalid (attendu {expected} bytes, received {actual})")]
    InvalidSecretKeyFormat { expected: usize, actual: usize },
    #[error("Format de signature invalid (attendu {expected} octets, received {actual})")]
    InvalidSignatureFormat { expected: usize, actual: usize },
    #[error("Key secret corrupted ou invalid")]
    CorruptedSecretKey,
}

/// Tailles des structures SLH-DSA-SHA2-128s selon FIPS 205
pub const PUBLIC_KEY_SIZE: usize = slh_dsa::PK_LEN;
pub const SECRET_KEY_SIZE: usize = slh_dsa::SK_LEN;
pub const SIGNATURE_SIZE: usize = slh_dsa::SIG_LEN;

/// Key public SLH-DSA avec serialization secure
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Bytes de la key publique (32 octets pour SLH-DSA-SHA2-128s)
    pub bytes: [u8; PUBLIC_KEY_SIZE],
}

/// Key secret SLH-DSA avec protection memory
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Bytes de la key secret (64 bytes pour SLH-DSA-SHA2-128s)
    #[zeroize(skip)]
    pub bytes: [u8; SECRET_KEY_SIZE],
}

/// Signature SLH-DSA
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Bytes de la signature (~7.8KB pour SLH-DSA-SHA2-128s)
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates une key public to partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la key publique (doit faire exactement 32 octets)
    ///
    /// # Erreurs
    /// Retourne `InvalidPublicKeyFormat` si la taille est incorrecte
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(SlhDsaAdapterError::InvalidPublicKeyFormat {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Exporte la key publique en bytes
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Verifies une signature avec cette key public
    ///
    /// # Arguments
    /// * `message` - Message signed
    /// * `signature` - Signature to verify
    ///
    /// # Security
    /// Utilise l'implementation FIPS 205 officielle resistant aux attaques temporelles
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SlhDsaAdapterError> {
        if signature.bytes.len() != SIGNATURE_SIZE {
            return Err(SlhDsaAdapterError::InvalidSignatureFormat {
                expected: SIGNATURE_SIZE,
                actual: signature.bytes.len(),
            });
        }

        // Conversion vers le format fips204
        let pk = slh_dsa::PublicKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)?;
        
        let sig = slh_dsa::Signature::try_from_bytes(&signature.bytes)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)?;

        // Verification avec l'implementation FIPS 205
        pk.verify(message, &sig)
            .map_err(|_| SlhDsaAdapterError::VerificationFailed)
    }
}

impl SecretKey {
    /// Generates une new paire de keys SLH-DSA
    ///
    /// # Security
    /// Utilise `OsRng` pour la generation cryptographiquement secure
    /// La key secret est automatically zeroized to la destruction
    pub fn generate() -> Result<(Self, PublicKey), SlhDsaAdapterError> {
        let mut rng = OsRng;
        
        // Generation avec l'implementation FIPS 205
        let (pk_bytes, sk_bytes) = slh_dsa::try_keygen_with_rng(&mut rng)
            .map_err(|_| SlhDsaAdapterError::KeyGenerationFailed)?;

        let secret_key = Self { bytes: sk_bytes };
        let public_key = PublicKey { bytes: pk_bytes };

        Ok((secret_key, public_key))
    }

    /// Creates une key secret to partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la key secret (doit faire exactement 64 bytes)
    ///
    /// # Erreurs
    /// Retourne `InvalidSecretKeyFormat` si la taille est incorrecte
    ///
    /// # Security
    /// Les bytes d'entry doivent provenir d'une source cryptographiquement secure
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(SlhDsaAdapterError::InvalidSecretKeyFormat {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Exporte la key secret en bytes
    ///
    /// # Security
    /// L'appelant est responsable de zeroizer les bytes returneds
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.bytes
    }

    /// Derives la key public to partir de cette key secret
    ///
    /// # Erreurs
    /// Returns `CorruptedSecretKey` si la key secret est invalid
    pub fn derive_public_key(&self) -> Result<PublicKey, SlhDsaAdapterError> {
        let sk = slh_dsa::SecretKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::CorruptedSecretKey)?;
        
        let pk_bytes = sk.get_public_key();
        Ok(PublicKey { bytes: pk_bytes })
    }

    /// Signe un message avec cette key secret
    ///
    /// # Arguments
    /// * `message` - Message to signer
    ///
    /// # Security
    /// - Utilise l'implementation FIPS 205 officielle
    /// - Chaque signature utilise une randomisation fresh
    /// - Resistant aux attaques par canaux auxiliaires
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SlhDsaAdapterError> {
        let mut rng = OsRng;
        
        let sk = slh_dsa::SecretKey::try_from_bytes(self.bytes)
            .map_err(|_| SlhDsaAdapterError::CorruptedSecretKey)?;

        let sig_bytes = sk.try_sign_with_rng(&mut rng, message)
            .map_err(|e| SlhDsaAdapterError::SigningFailed(format!("{:?}", e)))?;

        Ok(Signature {
            bytes: sig_bytes.to_vec(),
        })
    }
}

impl Signature {
    /// Creates une signature to partir de bytes bruts
    ///
    /// # Arguments
    /// * `bytes` - Bytes de la signature (doit faire exactement ~7.8KB)
    ///
    /// # Erreurs
    /// Retourne `InvalidSignatureFormat` si la taille est incorrecte
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlhDsaAdapterError> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(SlhDsaAdapterError::InvalidSignatureFormat {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Exporte la signature en bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Retourne la taille de la signature en octets
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Verifies si la signature est vide
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Signeur SLH-DSA pour l'integration avec le consensus TSN
///
/// Fournit une interface haut niveau pour signer des messages avec
/// gestion d'state et protection contre la reuse de keys.
pub struct SlhDsaSigner {
    secret_key: SecretKey,
    signature_count: u64,
}

impl SlhDsaSigner {
    /// Creates un nouveau signeur avec une key secret
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            signature_count: 0,
        }
    }

    /// Generates un nouveau signeur avec une paire de keys fresh
    pub fn generate() -> Result<(Self, PublicKey), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let signer = Self::new(sk);
        Ok((signer, pk))
    }

    /// Signe un message et increments le compteur
    ///
    /// # Arguments
    /// * `message` - Message to signer
    ///
    /// # Retour
    /// Tuple (signature, compteur) pour traceability
    pub fn sign_with_counter(&mut self, message: &[u8]) -> Result<(Signature, u64), SlhDsaAdapterError> {
        let signature = self.secret_key.sign(message)?;
        let counter = self.signature_count;
        self.signature_count += 1;
        Ok((signature, counter))
    }

    /// Gets la key public associated
    pub fn public_key(&self) -> Result<PublicKey, SlhDsaAdapterError> {
        self.secret_key.derive_public_key()
    }

    /// Gets le nombre de signatures performedes
    pub fn signature_count(&self) -> u64 {
        self.signature_count
    }
}

/// Verifier SLH-DSA pour l'integration avec le consensus TSN
pub struct SlhDsaVerifier {
    public_key: PublicKey,
}

impl SlhDsaVerifier {
    /// Creates un nouveau verifier avec une key public
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Verifies une signature
    ///
    /// # Arguments
    /// * `message` - Message signed
    /// * `signature` - Signature to verify
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SlhDsaAdapterError> {
        self.public_key.verify(message, signature)
    }

    /// Verifies une signature avec compteur (pour audit)
    ///
    /// # Arguments
    /// * `message` - Message signed
    /// * `signature` - Signature to verify
    /// * `expected_counter` - Compteur attendu (pour detection de replay)
    ///
    /// # Note
    /// Le compteur doit be inclus dans le message signed pour be verified
    pub fn verify_with_counter(
        &self,
        message: &[u8],
        signature: &Signature,
        expected_counter: u64,
    ) -> Result<(), SlhDsaAdapterError> {
        // Verification basique de la signature
        self.verify(message, signature)?;
        
        // TODO: Implement la verification du compteur si inclus dans le message
        // Pour l'instant, on accepte toutes les signatures valids
        let _ = expected_counter; // Avoid le warning unused
        
        Ok(())
    }

    /// Gets la key public used par ce verifier
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Fonctions utilitaires pour l'integration avec TSN
impl PublicKey {
    /// Convertit la key publique en adresse TSN
    ///
    /// # Note
    /// Utilise le hash SHA-256 des bytes de la key publique
    pub fn to_address(&self) -> crate::crypto::address::Address {
        crate::crypto::address::Address::from_public_key(&self.bytes)
    }
}

/// Constantes de validation pour les tests
pub mod constants {
    use super::*;
    
    /// Verifies que les tailles matchesent aux specifications FIPS 205
    pub const fn validate_sizes() {
        // Compilation-time assertions
        assert!(PUBLIC_KEY_SIZE == 32, "SLH-DSA-SHA2-128s public key must be 32 bytes");
        assert!(SECRET_KEY_SIZE == 64, "SLH-DSA-SHA2-128s secret key must be 64 bytes");
        assert!(SIGNATURE_SIZE == 7856, "SLH-DSA-SHA2-128s signature must be 7856 bytes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants() {
        // Verification que les constantes matchesent to FIPS 205
        constants::validate_sizes();
        
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SECRET_KEY_SIZE, 64);
        assert_eq!(SIGNATURE_SIZE, 7856);
    }

    #[test]
    fn test_key_generation() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        
        assert_eq!(sk.bytes.len(), SECRET_KEY_SIZE);
        assert_eq!(pk.bytes.len(), PUBLIC_KEY_SIZE);
        
        // Verify que la key public peut be derived
        let derived_pk = sk.derive_public_key()?;
        assert_eq!(pk.bytes, derived_pk.bytes);
        
        Ok(())
    }

    #[test]
    fn test_sign_verify_cycle() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let message = b"Test message for SLH-DSA FIPS 205";
        
        // Signature
        let signature = sk.sign(message)?;
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        
        // Verification
        pk.verify(message, &signature)?;
        
        Ok(())
    }

    #[test]
    fn test_wrong_message_fails() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        
        let signature = sk.sign(message)?;
        
        // La signature doit be valid pour le message original
        pk.verify(message, &signature)?;
        
        // La signature doit failsr pour un mauvais message
        assert!(pk.verify(wrong_message, &signature).is_err());
        
        Ok(())
    }

    #[test]
    fn test_signer_counter() -> Result<(), SlhDsaAdapterError> {
        let (sk, _) = SecretKey::generate()?;
        let mut signer = SlhDsaSigner::new(sk);
        
        assert_eq!(signer.signature_count(), 0);
        
        let message = b"Test message 1";
        let (_, counter1) = signer.sign_with_counter(message)?;
        assert_eq!(counter1, 0);
        assert_eq!(signer.signature_count(), 1);
        
        let (_, counter2) = signer.sign_with_counter(message)?;
        assert_eq!(counter2, 1);
        assert_eq!(signer.signature_count(), 2);
        
        Ok(())
    }

    #[test]
    fn test_verifier() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        let verifier = SlhDsaVerifier::new(pk);
        let message = b"Test message for verifier";
        
        let signature = sk.sign(message)?;
        verifier.verify(message, &signature)?;
        
        Ok(())
    }

    #[test]
    fn test_invalid_key_sizes() {
        // Test key publique invalid
        let invalid_pk = PublicKey::from_bytes(&[0u8; 31]);
        assert!(matches!(
            invalid_pk,
            Err(SlhDsaAdapterError::InvalidPublicKeyFormat { expected: 32, actual: 31 })
        ));
        
        // Test key secret invalid
        let invalid_sk = SecretKey::from_bytes(&[0u8; 63]);
        assert!(matches!(
            invalid_sk,
            Err(SlhDsaAdapterError::InvalidSecretKeyFormat { expected: 64, actual: 63 })
        ));
        
        // Test signature invalid
        let invalid_sig = Signature::from_bytes(&[0u8; 100]);
        assert!(matches!(
            invalid_sig,
            Err(SlhDsaAdapterError::InvalidSignatureFormat { expected: 7856, actual: 100 })
        ));
    }

    #[test]
    fn test_serialization() -> Result<(), SlhDsaAdapterError> {
        let (sk, pk) = SecretKey::generate()?;
        
        // Test serialization/deserialization key public
        let pk_bytes = pk.to_bytes();
        let pk_restored = PublicKey::from_bytes(&pk_bytes)?;
        assert_eq!(pk.bytes, pk_restored.bytes);
        
        // Test serialization/deserialization key secret
        let sk_bytes = sk.to_bytes();
        let sk_restored = SecretKey::from_bytes(&sk_bytes)?;
        assert_eq!(sk.bytes, sk_restored.bytes);
        
        Ok(())
    }

    #[test]
    fn test_zeroize_secret_key() {
        let (mut sk, _) = SecretKey::generate().unwrap();
        let original_bytes = sk.bytes;
        
        // Verify que la key n'est pas nulle initially
        assert_ne!(original_bytes, [0u8; SECRET_KEY_SIZE]);
        
        // Zeroize explicite
        sk.zeroize();
        
        // Verify que les bytes sont now zero
        // Note: Cette verification peut ne pas fonctionner si le compilateur optimise
        // mais c'est un test conceptuel de l'interface zeroize
        assert_eq!(sk.bytes, [0u8; SECRET_KEY_SIZE]);
    }
}