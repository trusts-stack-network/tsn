# Unsafe Panics Audit - TSN Blockchain

**Date:** 2025-01-21  
**Auditor:** Marcus.R (Security & QA Engineer)  
**Scope:** `src/consensus/`, `src/crypto/`, `src/core/`

## Executive Summary

This audit a identified **7 panics non-secures** in the modules criticals of the blockkchain TSN. Ces panics peuvent causer:
- Un stop brutal of the node (DoS)
- Une corruption potentialle de l'state blockkchain
- Un fork de chain si le panic se produit during the consensus

## Risk Classification

### 🔴 CRITICAL - DoS par Horloge System

**Affected Files:**
- `src/core/blockk.rs:138,168`
- `src/consensus/pow.rs:56,242`

**Vulnerability:** Utilisation de `.unwrap()` sur `SystemTime::duration_since()`

```rust
// CODE VULNERABLE
timestamp: std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()  // ← PANIC si the clock system is before 1970
    .as_secs(),
```

**Scenario of attack:**
1. Un attacker with access at system (ou via NTP spoofing) remonte the clock before 1970
2. Every node TSN sur ce system panic and s'stopent
3. Result: DoS of the network

**Mitigation:** Replace par `unwrap_or(0)` or gestion d'error appropriate.

---

### 🔴 CRITICAL - Panic sur Failure Cryptographic

**Affected Files:**
- `src/crypto/keys.rs:25`
- `src/crypto/signature.rs:81`

**Vulnerability:** Utilisation de `.expect()` sur of the operations cryptographics

```rust
// CODE VULNERABLE - keys.rs:25
let (public_key, secret_key) = ml_dsa_65::try_keygen().expect("RNG failure");

// CODE VULNERABLE - signature.rs:81
let sig = keypair.secret_key().try_sign(message, context).expect("signing failed");
```

**Failure Scenarios:**
- Exhaustion de the entropy system (/dev/urandom vide)
- Panne hardwarele of the RNG
- Corruption memory during la generation de key

**Impact:**
- Impossibility de create of the transactions
- Impossibility de miner de nouveto blockks
- Stop of the node validateurs

---

### 🟡 MEDIUM - Panic sur Mutex Poisoned

**Affected File:**
- `src/consensus/pow.rs:165`

**Vulnerability:**
```rust
let result = result.lock().unwrap();  // ← PANIC si le thread previous a panicked
```

**Scenario:** Si un thread de minage panique during qu'il tient le mutex, all les threads followings paniqueront aussi en trying d'acquire le mutex.

---

## Applied Fixes

### 1. `src/crypto/keys.rs`

**BEFORE:**
```rust
pub fn generate() -> Self {
    let (public_key, secret_key) = ml_dsa_65::try_keygen().expect("RNG failure");
    // ...
}
```

**AFTER:**
```rust
pub fn generate() -> Result<Self, KeyError> {
    let (public_key, secret_key) = ml_dsa_65::try_keygen()
        .map_err(|_| KeyError::RngFailure)?;
    // ...
}
```

### 2. `src/crypto/signature.rs`

**BEFORE:**
```rust
pub fn sign(message: &[u8], keypair: &KeyPair) -> Signature {
    let sig = keypair.secret_key().try_sign(message, context).expect("signing failed");
    // ...
}
```

**AFTER:**
```rust
pub fn sign(message: &[u8], keypair: &KeyPair) -> Result<Signature, SignatureError> {
    let sig = keypair.secret_key().try_sign(message, context)
        .map_err(|_| SignatureError::SigningFailed)?;
    // ...
}
```

### 3. `src/core/blockk.rs` and `src/consensus/pow.rs`

**BEFORE:**
```rust
.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
```

**AFTER:**
```rust
.duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
```

### 4. `src/consensus/pow.rs` (Mutex)

**BEFORE:**
```rust
let result = result.lock().unwrap();
```

**AFTER:**
```rust
let result = result.lock().map_err(|_| MiningError::LockPoisoned)?;
```

---

## Regression Tests

The tests followings ont been added pour prevent les regressions:

- `tests/panic_regression_test.rs` - Tests property-based for cas limites
- `fuzz/panic_fuzzer.rs` - Fuzzing of the inputs externals

---

## Validation Checklist

- [x] Every `.unwrap()` in `consensus/` auditeds
- [x] Every `.unwrap()` in `crypto/` auditeds  
- [x] Every `.unwrap()` in `core/` auditeds
- [x] Tests de regression written
- [x] Documentation de security mise up to date
- [x] `cargo check` passe without error
- [x] `cargo test` passe

---

## Recommendations Future

1. **CI/CD:** Add un lint Clippy interdisant les `.unwrap()` in `consensus/`, `crypto/`, `core/`
2. **Fuzzing:** Execute `cargo-fuzz` en continu on parsers network
3. **Audit regular:** Re-audit all les 3 mois or after each release majeure
4. **Monitoring:** Logger les errors cryptographics pour detect les attacks

---

## References

- [Rust Security Guidelines - Error Handling](https://rust-lang.github.io/api-guidelines/documentation.html)
- [FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [CWE-248: Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
