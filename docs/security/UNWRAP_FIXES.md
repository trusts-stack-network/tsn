# Critical Unwraps/Expects Fixes

**Date:** March 2026  
**Auteur:** Marcus.R (Security & QA Engineer)  
**Status:** IN PROGRESS  
**Severity:** CRITICAL

## Executive Summary

This document suit the fixes of the unwraps/expects criticals identified in the codebase TSN. These fixes are essentielles pour garantir la stability of the node in production and prevent les attacks DoS.

## Identified and Fixed Unwraps/Expects

### 1. src/consensus/validation.rs:64

**Problematic Code:**
```rust
let current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
```

**Risk:** Si the clock system is before l'epoch Unix (1970), le code panique.

**Proposed Fix:**
```rust
let current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or(Duration::from_secs(0))
    .as_secs();
```

**Status:** ⏳ PENDING FIX

---

### 2. src/crypto/poseidon.rs:41

**Problematic Code:**
```rust
let poseidon = Poseidon::<Fr>::new_circom(n_inputs)
    .expect("Poseidon init failed");
```

**Risk:** Panique si le nombre of inputs is invalid.

**Proposed Fix:**
```rust
let poseidon = Poseidon::<Fr>::new_circom(n_inputs)
    .map_err(|e| ValidationError::PoseidonInitFailed(e))?;
```

**Status:** ⏳ PENDING FIX

---

### 3. src/crypto/poseidon.rs:47

**Problematic Code:**
```rust
let hash = poseidon.hash(&all_inputs)
    .expect("Poseidon hash failed");
```

**Risk:** Panique si the hash fails.

**Proposed Fix:**
```rust
let hash = poseidon.hash(&all_inputs)
    .map_err(|e| ValidationError::PoseidonHashFailed(e))?;
```

**Status:** ⏳ PENDING FIX

---

### 4. src/crypto/poseidon.rs:90

**Problematic Code:**
```rust
let inv = sum.inverse()
    .expect("Cauchy matrix construction");
```

**Risk:** Panique si l'inverse n'existe pas (sum = 0).

**Proposed Fix:**
```rust
let inv = sum.inverse()
    .ok_or(ValidationError::CauchyMatrixConstructionFailed)?;
```

**Status:** ⏳ PENDING FIX

---

### 5. src/crypto/keys.rs:20

**Problematic Code:**
```rust
let (pk, sk) = ml_dsa_65::try_keygen()
    .expect("RNG failure");
```

**Risk:** Panique si le RNG fails.

**Proposed Fix:**
```rust
let (pk, sk) = ml_dsa_65::try_keygen()
    .map_err(|e| KeyError::RngFailed(e))?;
```

**Status:** ⏳ PENDING FIX

---

### 6. src/network/api.rs:67

**Problematic Code:**
```rust
let rate_limiter = RateLimiter::new(config)
    .expect("Failed to build rate limiter config");
```

**Risk:** Panique si la config is invalid.

**Proposed Fix:**
```rust
let rate_limiter = RateLimiter::new(config)
    .unwrap_or_else(|_| create_default_rate_limiter());
```

**Status:** ⏳ PENDING FIX

---

## Regression Tests

The tests followings ont been createds pour verify the fixes:

1. `tests/panic_regression_test.rs` - Tests unitaires pour each unwrap fixed
2. `fuzz/fuzz_targets/critical_unwrap_fuzzer.rs` - Fuzzer dedicated to unwraps criticals

## Validation Checklist

- [ ] Correction appliede to src/consensus/validation.rs:64
- [ ] Correction appliede to src/crypto/poseidon.rs:41
- [ ] Correction appliede to src/crypto/poseidon.rs:47
- [ ] Correction appliede to src/crypto/poseidon.rs:90
- [ ] Correction appliede to src/crypto/keys.rs:20
- [ ] Correction appliede to src/network/api.rs:67
- [ ] Tests de regression passent
- [ ] Fuzzer critical_unwrap passe without panic
- [ ] cargo check passe without errors
- [ ] cargo test passe without errors

## Security Notes

1. **Ne never utiliser unwrap() or expect() in the code network**
2. **Always prefer Result<T, E> for operations that can failsr**
3. **Utiliser unwrap_or(), unwrap_or_else(), or ? for propagation d'errors**
4. **Documenter les invariants qui justifient un unwrap with SAFETY comments**

## References

- [PANIC_AUDIT.md](./PANIC_AUDIT.md) - Audit complete of the panics
- [UNWRAP_AUDIT.md](./UNWRAP_AUDIT.md) - Audit of the unwraps
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Model de threats TSN
