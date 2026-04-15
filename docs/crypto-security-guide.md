# TSN Cryptographic Security Guide

## Overview

This guide presents les bonnes pratiques cryptographics for the development sur Trust Stack Network (TSN). Il couvre les implementations securees, les vulnerabilities courantes, and the modules de demonstration educational.

## 🛡️ Modules de Production (Secures)

### Cryptographie Post-Quantum

```rust
// ✅ CORRECT : Signature ML-DSA-65 (FIPS 204)
use fips204::ml_dsa_65;

let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)?;
let signature = ml_dsa_65::try_sign_with_rng(&mut OsRng, &sk, &message, &context)?;
let is_valid = ml_dsa_65::try_verify(&pk, &message, &signature, &context)?;
```

### Secure Hashing

```rust
// ✅ CORRECT : Poseidon2 for ZK proofs
use light_poseidon::Poseidon;

let mut poseidon = Poseidon::new();
poseidon.hash(&inputs)?;

// ✅ CORRECT : SHA-256 pour usage general
use sha2::{Sha256, Digest};

let mut hasher = Sha256::new();
hasher.update(data);
let hash = hasher.finalize();
```

### Authenticated Encryption

```rust
// ✅ CORRECT : ChaCha20-Poly1305 (AEAD)
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};

let key = ChaCha20Poly1305::generate_key(&mut OsRng);
let cipher = ChaCha20Poly1305::new(&key);
let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
```

### Secure Random Generation

```rust
// ✅ CORRECT : Cryptographic entropy
use rand::{rngs::OsRng, RngCore};

let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);

// ✅ CORRECT : Pour les reprodutarget tests
use rand::{rngs::StdRng, SeedableRng};
let mut rng = StdRng::seed_from_u64(42); // Tests only
```

### Constant-Time Comparisons

```rust
// ✅ CORRECT : Secure comparison
use subtle::ConstantTimeEq;

fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
```

### Key Derivation (KDF)

```rust
// ✅ CORRECT : PBKDF2 with sel
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

let salt = b"unique_random_salt_16_bytes_min";
let mut key = [0u8; 32];
pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
```

## ⚠️ Modules de Demonstration (Vulnerables)

### Activation of the Modules Vulnerables

The modules de demonstration ne are availables qu'avec la feature `vulnerable-demo` :

```bash
# Compilation with modules vulnerables (TESTS/EDUCATION UNIQUEMENT)
cargo build --features vulnerable-demo
cargo test --features vulnerable-demo

# Compilation normale (modules vulnerables EXCLUS)
cargo build
cargo test
```

### Protection par Compilation Conditionnelle

```rust
// Protection automatic - prevents la compilation accidentelle
#[cfg(not(feature = "vulnerable-demo"))]
compile_error!(
    "❌ ACCESS REFUSED : Modules vulnerables disabled\n\
     Pour les activer (TESTS/EDUCATION UNIQUEMENT) :\n\
     cargo build --features vulnerable-demo"
);
```

## 🚨 Vulnerabilities Demonstrated

### 1. Timing Attacks

**Problem** : Comparaisons non-constant-time revealsnt of the informations via le timing.

```rust
// ❌ VULNERABLE : Early return = timing leak
fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ Timing reveals la position de l'error
        }
    }
    true
}

// ✅ SECURED : Constant-time
use subtle::ConstantTimeEq;
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
```

### 2. Nonce Reuse

**Problem** : Nonce reuse en mode CTR reveals le XOR of the plaintexts.

```rust
// ❌ VULNERABLE : Nonce fixe
let nonce = [0u8; 12]; // Always le same
let ciphertext = cipher.encrypt(&nonce, plaintext)?;

// ✅ SECURED : Nonce unique
let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
let ciphertext = cipher.encrypt(&nonce, plaintext)?;
```

### 3. Predictable RNG

**Problem** : Generators deterministics permettent la prediction of the keys.

```rust
// ❌ VULNERABLE : Seed connu = sequence predictable
let mut rng = StdRng::seed_from_u64(12345);

// ✅ SECURED : Entropie of the system
let mut rng = OsRng;
```

### 4. Padding Oracle

**Problem** : Verification de padding non-constant-time reveals of the informations.

```rust
// ❌ VULNERABLE : Early return sur padding invalid
fn remove_padding(data: &[u8]) -> Option<&[u8]> {
    let pad_len = data[data.len() - 1] as usize;
    if pad_len > 16 { return None; } // ⚠️ Timing leak
    // ...
}

// ✅ SECURED : Verification constant-time
use subtle::{Choice, ConditionallySelectable};
fn secure_remove_padding(data: &[u8]) -> Option<&[u8]> {
    // Implementation constant-time complete
}
```

### 5. Naive KDF

**Problem** : Derivation without sel ni iterations, vulnerable to rainbow tables.

```rust
// ❌ VULNERABLE : Hash simple without sel
fn naive_kdf(password: &[u8]) -> [u8; 32] {
    Sha256::digest(password).into()
}

// ✅ SECURED : PBKDF2 with sel and iterations
use pbkdf2::pbkdf2_hmac;
fn secure_kdf(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
    key
}
```

## 🧪 Tests de Security

### Tests de Timing Attack

```bash
# Benchmark of the vulnerabilities de timing
cargo test --features vulnerable-demo timing_attack_benchmark
```

### Tests de Non-Regression

```bash
# Verify que the modules vulnerables are bien blocked
cargo build  # Doit failsr si vulnerable.rs is imported without feature

# Verify que la feature fonctionne
cargo build --features vulnerable-demo  # Doit succeed
```

## 📋 Checklist of Review Crypto

Before merging of the code cryptographic :

- [ ] **Entropie** : Utilise `OsRng` for keys/nonces production
- [ ] **Constant-time** : Comparaisons sensibles utilisent `subtle::ConstantTimeEq`
- [ ] **AEAD** : Encryption authenticated (ChaCha20-Poly1305, AES-GCM)
- [ ] **Post-quantum** : Signatures ML-DSA-65, hashes Poseidon2 pour ZK
- [ ] **KDF secure** : PBKDF2/scrypt/Argon2 with sel random
- [ ] **Nonce unique** : Never de reuse de nonce
- [ ] **Tests** : Couverture of the cas d'error and edge cases
- [ ] **Documentation** : Justification of the choix cryptographics

## 🔗 References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
- [RFC 8439](https://tools.ietf.org/html/rfc8439) - ChaCha20-Poly1305
- [Plonky2 Paper](https://github.com/0xPolygonZero/plonky2) - STARKs post-quantums
- [Timing Attack Prevention](https://github.com/dalek-cryptography/subtle)
- [OWASP Crypto Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**⚠️ RAPPEL IMPORTANT** : The modules `src/crypto/vulnerable.rs` ne doivent JAMAIS be useds in production. Ils are exclusivement intendeds to education and to tests de security.