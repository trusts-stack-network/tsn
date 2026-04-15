# Cryptographic Inter-Module Consistency Audit

**Date:** 2024  
**Auditor:** Elena.M - Cryptography Engineer  
**Scope:** `src/crypto/`, `src/wallet/` (71 files, ~16k lines)  

## Executive Summary

The analysis reveals **several critical inconsistencies** between TSN cryptographic modules. These inconsistencies mainly concern :
- The simultaneous use of two schemes de signature post-quantum differents (ML-DSA-65 and SLH-DSA)
- Incompatible key and signature sizes between modules
- Duplicated and divergent validation interfaces

**Risk Level:** HIGH - Type inconsistencies can lead to silent validation errors.

---

## 1. Inconsistencys Identifiedes

### 1.1 Post-Quantum Signature Scheme Duality

#### Problem
Two post-quantum signature schemes are used simultaneously without a clear migration strategy :

| Module | Scheme | Public Key Size | Signature Size | Standard |
|--------|--------|---------------------|------------------|----------|
| `signature.rs` | ML-DSA-65 | 1952 bytes | 3293 bytes | FIPS 204 |
| `pq/slh_dsa.rs` | SLH-DSA-SHA2-128s | 64 bytes | 7856 bytes | FIPS 205 |
| `signature_validator.rs` | SLH-DSA | 32 bytes* | 7808 bytes* | FIPS 205 |

*Sizes incorrects in `signature_validator.rs` : PK_BYTES=32 and SIG_BYTES=7808 alors que SLH-DSA-SHA2-128s utilise 64 bytes for public key.

#### Impact
- Inability to validate ML-DSA signatures with the SLH-DSA validator
- Confusion about the signature algorithm "officiel" de TSN
- Risk of silent validation errors

#### References
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final

---

### 1.2 Size Constants Inconsistency

#### `pq/slh_dsa.rs`
```rust
pub const SLH_PUBLIC_KEY_SIZE: usize = 64;   // ✓ Correct pour SLH-DSA-SHA2-128s
pub const SLH_SECRET_KEY_SIZE: usize = 128;
pub const SLH_SIGNATURE_SIZE: usize = 7856;  // ✓ Correct
```

#### `signature_validator.rs`
```rust
pub const PK_BYTES: usize = 32;      // ✗ INCORRECT - Devrait be 64
pub const SIG_BYTES: usize = 7808;   // ✗ INCORRECT - Devrait be 7856
```

#### Impact
- Failure systematic of the validation of the signatures SLH-DSA
- Errors `MalformedSignature` and `MalformedPublicKey` incorrects

---

### 1.3 Validation Module Duplication

Two modules implement signature validation :
- `signature_validation.rs` : System de haut niveat with cache, rate limiting, batch validation
- `signature_validator.rs` : Validateur bas-niveat with metrics

#### Problems
1. **Error type divergence** :
   - `signature_validation.rs` : `ValidationSystemError`
   - `signature_validator.rs` : `ValidationError`

2. **Result structure inconsistency** :
   - `signature_validation.rs` : `ValidationResult` (champs partiels)
   - `signature_validator.rs` : `ValidationResult` (champs completes with metrics)

3. **Functional redundancy** : Both modules manage performance metrics

---

### 1.4 Inconsistency of the Types de ZK Proofs

| Module | Proof System | Status |
|--------|-------------------|--------|
| `proof.rs` | Circom/snarkjs (Groth16) | Legacy |
| `halo2_prover.rs` | Halo2 PLONK | Nouveat |

#### Problems
- `proof.rs` utilise Groth16 with BN254 (requires trusted setup)
- `halo2_prover.rs` utilise Halo2 (sans trusted setup)
- No documented migration strategy
- Circom and Halo2 circuits are not compatible

---

### 1.5 Commitment Type Inconsistency

#### `commitment.rs`
```rust
pub struct NoteCommitment(pub [u8; 32]);  // Poseidon hash
pub struct ValueCommitment {               // Pedersen sur BN254
    pub commitment: G1,
    pub randomness: Fr,
}
```

#### Problems
- `NoteCommitment` utilise Poseidon (ZK-friendly)
- `ValueCommitment` utilise Pedersen sur BN254 (homomorphique)
- No common trait for both types de commitments
- Type conversions are not standardized

---

## 2. Interfaces Non Standardized

### 2.1 Module `secure_impl.rs`

**Single public function :**
```rust
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool
```

**Problem:** N'utilise pas `subtle::ConstantTimeEq` correctly - retourne `bool` at lieu de `Choice`, permettant of the branches sur le result secret.

### 2.2 Module `halo2_prover.rs`

**Structures publics :**
- `CommitmentCircuit`
- `CommitmentConfig`

**Problem:** No common interface with `proof.rs` for proof verification.

---

## 3. Recommendations

### 3.1 Short Term (Critical)

1. **Fix the constants in `signature_validator.rs`** :
   ```rust
   pub const PK_BYTES: usize = 64;    // SLH-DSA-SHA2-128s
   pub const SIG_BYTES: usize = 7856; // SLH-DSA-SHA2-128s
   ```

2. **Unify signature schemes** : Choisir ML-DSA-65 (FIPS 204) comme standard TSN car :
   - Signatures more compactes (3.3KB vs 7.8KB)
   - Plus fast to verify
   - Recommended par NIST for plupart of the applications

3. **Create a standardized interfaces module** (`crypto_interfaces.rs`)

### 3.2 Medium Term (High)

1. **Merge `signature_validation.rs` and `signature_validator.rs`**
2. **Implement an abstraction layer for ZK proofs**
3. **Standardize traits for commitments**

### 3.3 Long Term (Medium)

1. **Fully migrate to Halo2** and deprecate Circom/snarkjs
2. **Implement inter-module integration tests**
3. **Formally document cryptographic interfaces**

---

## 4. Interfaces Standardized Proposed

### 4.1 Trait `SignatureScheme`

```rust
pub trait SignatureScheme: Send + Sync {
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;
    
    type PublicKey: Serialize + DeserializeOwned + Clone;
    type SecretKey: Serialize + DeserializeOwned + Zeroize + Clone;
    type Signature: Serialize + DeserializeOwned + Clone;
    
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::SecretKey, Self::PublicKey);
    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Self::Signature;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool;
}
```

### 4.2 Trait `ProofSystem`

```rust
pub trait ProofSystem {
    type Proof: Serialize + DeserializeOwned;
    type VerifyingKey: Clone;
    type PublicInputs;
    
    fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
        vk: &Self::VerifyingKey,
    ) -> Result<bool, ProofError>;
}
```

### 4.3 Trait `CommitmentScheme`

```rust
pub trait CommitmentScheme {
    type Commitment: AsRef<[u8]> + Eq + Clone;
    type Opening: Zeroize;
    
    fn commit<R: RngCore>(value: &[u8], rng: &mut R) -> (Self::Commitment, Self::Opening);
    fn verify(commitment: &Self::Commitment, value: &[u8], opening: &Self::Opening) -> bool;
}
```

---

## 5. Verification of the Constantes

| Constant | Current Value | Expected Value | Status |
|-----------|-----------------|-----------------|--------|
| `PK_BYTES` (SLH) | 32 | 64 | ❌ INCORRECT |
| `SIG_BYTES` (SLH) | 7808 | 7856 | ❌ INCORRECT |
| `SLH_PUBLIC_KEY_SIZE` | 64 | 64 | ✅ CORRECT |
| `SLH_SIGNATURE_SIZE` | 7856 | 7856 | ✅ CORRECT |
| ML-DSA-65 PK | 1952 | 1952 | ✅ CORRECT |
| ML-DSA-65 SIG | 3293 | 3293 | ✅ CORRECT |

---

## 6. Conclusion

Les inconsistencys identifieof the represent un risk significatif for security and l'interoperability of the system TSN. La correction immediatee of the constants incorrects in `signature_validator.rs` is **critical**.

La creation of a module d'interfaces standardized permettra de :
- Ensure consistency between implementations
- Facilitate future algorithm migrations
- Improve cryptographic code testability

**Next Step:** Implementation of the module `crypto_interfaces.rs` and correction of the constants.

---

*Document generated as part of the audit of TSN inter-module consistency.*
*Classification: Internal Use - Cryptography Team*
