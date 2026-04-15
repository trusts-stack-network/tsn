# Security Analysis - Vulnerable Crypto Modules

## Overview

This document analysis les vulnerabilities intentionnelles presentss in `src/crypto/vulnerable.rs` and leurs mitigations in `src/crypto/secure_impl.rs`. Ces modules servent d'examples pedagogical and de tests de security.

⚠️ **ATTENTION**: The functions in `vulnerable.rs` MUST NEVER be useof the in production.

## Identified Vulnerabilities

### 1. Timing Attack - Comparaison Non Constant-Time

**Fonction vulnerable**: `insecure_compare()`
**Localisation**: `src/crypto/vulnerable.rs:7`

#### Description
```rust
pub fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false; // ⚠️ VULNERABILITY: Sortie early
        }
    }
    true
}
```

#### Vulnerability
- **Type**: Timing Side-Channel Attack
- **Mechanism**: The function retourne from le premier byte different
- **Impact**: Un attacker can deduce la position de l'error en mesurant le temps d'execution
- **Severity**: HAUTE (for verification de tokens/passwords)

#### Exploitation
```rust
// Timing attack pour deviner un secret
let secret = b"supersecret";
let mut guess = b"aaaaaaaaaaaa".to_vec();

for pos in 0..secret.len() {
    for byte_val in 0..=255 {
        guess[pos] = byte_val;
        let start = Instant::now();
        insecure_compare(secret, &guess);
        let elapsed = start.elapsed();
        
        // Plus le temps is long, more on is proche of the bon byte
        if elapsed > threshold {
            // Byte correct found to la position pos
            break;
        }
    }
}
```

#### Mitigation
**Fonction securee**: `secure_compare()` in `src/crypto/secure_impl.rs`
```rust
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
```

### 2. Mode CTR with IV Predictable

**Fonction vulnerable**: `InsecureCtrMode`
**Localisation**: `src/crypto/vulnerable.rs:20`

#### Description
```rust
pub struct InsecureCtrMode {
    key: [u8; 16],
    counter: u64, // ⚠️ VULNERABILITY: Compteur predictable
}
```

#### Vulnerability
- **Type**: IV/Nonce Reuse Attack
- **Mechanism**: The accountur commence always to 0 pour each instance
- **Impact**: Reuse d'IV permet de recover XOR of the plaintexts
- **Severity**: CRITICAL

#### Exploitation
```rust
let key = [0u8; 16];
let ctr1 = InsecureCtrMode::new(key);
let ctr2 = InsecureCtrMode::new(key);

let msg1 = b"Secret message 1";
let msg2 = b"Secret message 2";

let cipher1 = ctr1.encrypt(msg1);
let cipher2 = ctr2.encrypt(msg2);

// XOR of the ciphertexts reveals XOR of the plaintexts
let xor_result: Vec<u8> = cipher1.iter()
    .zip(cipher2.iter())
    .map(|(a, b)| a ^ b)
    .collect();
// xor_result == msg1 XOR msg2
```

#### Mitigation
Utiliser `SecureAead` with nonces randoms uniques.

### 3. Generator de Nombres Pseudo-Randoms Predictable

**Fonction vulnerable**: `PredictableRng`
**Localisation**: `src/crypto/vulnerable.rs:45`

#### Description
```rust
pub struct PredictableRng {
    state: u64, // ⚠️ VULNERABILITY: State simple, predictable
}
```

#### Vulnerability
- **Type**: Weak Random Number Generation
- **Mechanism**: LFSR simple with seed predictable
- **Impact**: Sequences randoms predictables for cryptographie
- **Severity**: CRITICAL (pour generation de keys/nonces)

#### Exploitation
```rust
// Si on observe quelques valeurs, on can predict les followinges
let mut rng = PredictableRng::new(known_seed);
let observed_values = vec![rng.next(), rng.next(), rng.next()];

// Un attacker can now predict all les valeurs futures
let predicted_next = rng.next();
```

### 4. Padding Oracle - PKCS#7

**Fonction vulnerable**: `remove_pkcs7_padding()`
**Localisation**: `src/crypto/vulnerable.rs:65`

#### Description
```rust
pub fn remove_pkcs7_padding(data: &[u8]) -> Option<&[u8]> {
    // Validation basique qui can leak of the informations via timing
}
```

#### Vulnerability
- **Type**: Padding Oracle Attack
- **Mechanism**: Differents temps de traitement selon la validity of the padding
- **Impact**: Decryption de messages without know la key
- **Severity**: HAUTE

#### Exploitation
L'attack padding oracle permet de decrypt of the messages en observant si le padding is valide or non.

### 5. Key Derivation Function Low

**Fonction vulnerable**: `naive_kdf()`
**Localisation**: `src/crypto/vulnerable.rs:85`

#### Description
```rust
pub fn naive_kdf(password: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.finalize().into() // ⚠️ VULNERABILITY: Pas de salt, vulnerable to rainbow tables
}
```

#### Vulnerability
- **Type**: Weak Key Derivation
- **Mechanism**: Pas de salt, une seule iteration de hash
- **Impact**: Vulnerable to rainbow tables and attacks par dictionnaire
- **Severity**: HAUTE

#### Exploitation
```rust
// Precomputation de rainbow table
let common_passwords = ["password", "123456", "admin"];
let mut rainbow_table = HashMap::new();

for pwd in common_passwords {
    let hash = naive_kdf(pwd.as_bytes());
    rainbow_table.insert(hash, pwd);
}

// Attack instant si le password is in la table
if let Some(password) = rainbow_table.get(&stolen_hash) {
    println!("Password found: {}", password);
}
```

#### Mitigation
**Fonction securee**: `strong_kdf()` with salt and PBKDF2.

## Security Tests

### Tests Unitaires
- **File**: `tests/crypto_vulnerable_test.rs`
- **Couverture**: Toutes les vulnerabilities with tests de regression
- **Property-based tests**: Invariants cryptographics verifieds

### Fuzzing
- **File**: `fuzz/fuzz_targets/crypto_vulnerable.rs`
- **Target**: Enputs malformeof the and adversariales
- **Execution**: `cargo fuzz run crypto_vulnerable`

### Tests de Timing
```bash
# Execution of the tests de timing attack
cargo test test_insecure_compare_timing_leak -- --nocapture
cargo test test_secure_compare_constant_time -- --nocapture
```

## Recommendations de Security

### 1. Audit de Code
- [ ] Verify the absence of use of the fonctions vulnerables in production
- [ ] Rechercher les patterns similaires in the codebase
- [ ] Valider que all les sensitive comparisons utilisent `subtle::ConstantTimeEq`

### 2. Tests Automated
- [ ] Integrate the tests de timing in la CI
- [ ] Execute le fuzzing regularly
- [ ] Monitorer les regressions de security

### 3. Formation Team
- [ ] Sensibiliser to timing attacks
- [ ] Former on bonnes pratiques crypto
- [ ] Documenter les patterns to avoid

## References

### Standards
- [RFC 3447 - PKCS #1](https://tools.ietf.org/html/rfc3447)
- [RFC 5652 - PKCS #7](https://tools.ietf.org/html/rfc5652)
- [NIST SP 800-108 - KDF](https://csrc.nist.gov/publications/detail/sp/800-108/final)

### Attacks Documentedes
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/TimingAttacks.pdf)
- [Padding Oracle Attacks](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [The Security Impact of a New Cryptographic Library](https://cr.yp.to/highspeed/naclcrypto-20090310.pdf)

### Outils de Security
- [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [subtle](https://github.com/dalek-cryptography/subtle)

## Security Changelog

| Date | Version | Change | Severity |
|------|---------|------------|----------|
| 2024-01-XX | v0.1.0 | Ajout of the modules vulnerables pour tests | INFO |
| 2024-01-XX | v0.1.1 | Ajout of the mitigations securees | MEDIUM |
| 2024-01-XX | v0.1.2 | Timing tests automated | HIGH |

---

**Responsable Security**: Marcus.R  
**Last revision**: 2024-01-XX  
**Next revision**: 2024-02-XX