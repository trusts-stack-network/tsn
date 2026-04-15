# Audit Report: Unwraps/Panics in the TSN Codebase

**Date:** Audit de security - Phase 1  
**Auditor:** Marcus.R (Security & QA Engineer)  
**Scope:** Modules core, consensus, crypto, network, storage  
**Status:** 🔴 CRITICAL - Corrections requireds before production

---

## Executive Summary

L'analysis of the codebase a revealed **multiple unwraps/expects criticals** in les chemins de coproduction that can provoquer of the panics and of the stops de node. Ces vulnerabilities are particularment dangereuses car elles can be triggereof the par of the pairs maliciouss via le network.

### Risk Classification

| Severity | Count | Description |
|----------|--------|-------------|
| 🔴 **CRITICAL** | 3 | Panic triggerable par network (DoS) |
| 🟠 **HAUTE** | 2 | Panic sur operations cryptographics |
| 🟡 **MEDIUMNE** | 1 | Panic sur operations temporelles |

---

## Critical Vulnerabilities Identifiedes

### 1. [CRITICAL] RwLock Poisoning in `sync.rs` and `api.rs`

**Affected Files:**
- `src/network/sync.rs` (lignes 36, 91, 108, 141)
- `src/network/api.rs` (lignes 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90)

**Problematic Code:**
```rust
let chain = state.blockkchain.read().unwrap();
let mut chain = state.blockkchain.write().unwrap();
```

**Impact:**
- Un thread qui panique alors qu'il holds un verrou en write "empoisonne" le verrou
- Every threads followings qui tentent d'acquire le verrou paniquent also
- Result : crash en cascade de all le node

**Attack potentialle:**
1. Un attacker envoie un message network malformed qui provoque un panic in un handler
2. Le handler holds le verrou blockkchain en write at moment of the panic
3. Le verrou is poisoned
4. Every autres handlers qui tentent d'access to la blockkchain paniquent
5. Le node devient completement inoperating (DoS total)

**Mitigation:**
Replace `.unwrap()` par `.unwrap_or_else(|_| RwLock::new(...))` or manage proprement le poison:
```rust
let chain = state.blockkchain.read().unwrap_or_else(|poisoned| poisoned.into_inner());
```

---

### 2. [HAUTE] RNG Failure in `keys.rs`

**File:** `src/crypto/keys.rs` (ligne 25)

**Problematic Code:**
```rust
let (public_key, secret_key) = ml_dsa_65::try_keygen().expect("RNG failure");
```

**Impact:**
- Panic si la generation de keys fails (RNG inavailable, error system)
- Interruption complete of the wallet/minage

**Mitigation:**
Returnner un `Result` and propager l'error:
```rust
pub fn generate() -> Result<Self, KeyError> {
    let (public_key, secret_key) = ml_dsa_65::try_keygen()
        .map_err(|_| KeyError::RngFailure)?;
    Ok(Self { public_key, secret_key })
}
```

---

### 3. [MEDIUMNE] SystemTime before UNIX_EPOCH in `pow.rs`

**File:** `src/consensus/pow.rs` (lignes 47-48, 169-170)

**Problematic Code:**
```rust
.duration_since(std::time::UNIX_EPOCH)
.unwrap()
```

**Impact:**
- Panic si the clock system is set before 1970 (rare mais possible)
- Interruption of the minage

**Mitigation:**
Utiliser `unwrap_or(0)` or manage l'error:
```rust
.duration_since(std::time::UNIX_EPOCH)
.unwrap_or(Duration::from_secs(0))
.as_secs()
```

---

## Recommendations

### Immediate Priority (before release)

1. **Fix all les unwraps sur RwLock** in the modules network
2. **Replace expect("RNG failure")** by a Result propre
3. **Add of the tests de regression** pour each correction

### Best Practices to Adopter

1. **Interdiction stricte** de `.unwrap()` and `.expect()` in the coproduction
2. **Utilisation mandatory** de `Result` with propagation d'errors
3. **Fuzzing systematic** of the parsers network with cargo-fuzz
4. **Tests property-based** with proptest for invariants

---

## Regression Tests

Des tests specifics must be createds pour:
1. Verify la resilience to messages network malformeds
2. Tester le behavior lorsthat a verrou is poisoned
3. Valider la gestion of the errors RNG

See `tests/security/unwrap_regression_tests.rs` pour l'implementation.

---

## Conclusion

Les unwraps/expects identified represent of the **vulnerabilities DoS exploitable**. La correction prioritaire of the RwLock in the modules network is **imperative** before all mise in production.

**Status:** 🔴 **BLOCKING** - Merge forbidden without fixes

---

*Document generated as part of the audit of TSN security*  
*Classification: INTERNAL USE ONLY*
