# Security Audit Report - src/crypto/

## Executive Summary
Date: 2024-01-15
Auditeur: Security Research Team
Scope: Cryptographie symetric and key derivations

## Enddings

### [CRITICAL] F-001: Nonce Generation Non-Atomic
**File**: `src/crypto/aead.rs:45`
**Description**: La generation de nonce utilise `rand::thread_rng()` without verrou atomique, risk de collision under forte charge.
**Proof**: See `tests/regression_tests.rs::test_nonce_collision_resistance`
**Correction**: Utiliser `AtomicU64` + random 128-bit

### [HIGH] F-002: MAC Comparison Variable-Time
**File**: `src/crypto/aead.rs:89`
**Description**: Comparaison de tag via `==` standard (optimized par LLVM)
**Impact**: Timing attack possible on 16 premiers octets
**Correction**: `subtle::ConstantTimeEq` required

### [HIGH] F-003: Secret Key Material in Swap
**File**: `src/crypto/kdf.rs`
**Description**: Keys derived storedes en `Vec<u8>` without `mlock`
**Impact**: Extraction via swap/partition de swap
**Correction**: Utiliser `secrets::SecretBox` or `memsec::mlock`

### [MEDIUM] F-004: Insufficient KDF Iterations
**File**: `src/crypto/kdf.rs:23`
**Description**: Argon2 configured with m=8KB, trop low pour resistance GPU
**Correction**: m >= 64MB, t >= 3

### [LOW] F-005: RNG Seed Reuse in Tests
**File**: `tests/` (multiples)
**Description**: Tests utilisent seed fixe, masque potentiallement of the bugs
**Correction**: Proptest with seeds randoms + replay

## Recommendations

1. **Hardening Constant-Time**: Verify assembly generated pour comparaisons
2. **Fuzzing Continu**: Integrate `cargo-fuzz` in CI/CD
3. **Formal Verification**: Consider `saw` or `cryptol` pour primitives criticals
4. **Documentation**: Add warnings de security sur all les exports publics