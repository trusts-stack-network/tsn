# Security Documentation - Post-Quantum Cryptographic Modules

## Overview

This document described les considerations de security pour the modules cryptographics post-quantums de TSN.

## Architecture

```
src/crypto/pq/
├── ml_dsa.rs          # Signatures ML-DSA (FIPS 204)
├── slh_dsa.rs         # Signatures SLH-DSA (FIPS 205)
├── slh_dsa_batch.rs   # Verification batch SLH-DSA
├── slh_dsa_ops.rs     # Operations internals SLH-DSA
├── proof_pq.rs        # Proofs Plonky2 STARK
├── commitment_pq.rs   # Engagements post-quantums
├── verify_pq.rs       # Verification de transactions V2
├── circuit_pq.rs      # Circuits Plonky2
└── mod.rs             # Module principal
```

## Threats identifieof the (STRIDE)

### Spoofing (Identity Falsification)

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| ml_dsa.rs | Public key malformede | Validation de format ML-DSA | ✅ Implemented |
| slh_dsa.rs | Public key malformede | Validation de format SLH-DSA | ✅ Implemented |
| verify_pq.rs | Transaction with key invalid | Verification de signature | ✅ Implemented |

### Tampering (Alteration)

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| commitment_pq.rs | Alteration de l'engagement | Hash cryptographic | ✅ Implemented |
| proof_pq.rs | Alteration of the proof | Verification STARK | ✅ Implemented |
| verify_pq.rs | Alteration of the transaction | Signature + proof | ✅ Implemented |

### Repudiation

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| ml_dsa.rs | Signature non traceable | Signatures deterministics | ✅ Implemented |
| slh_dsa.rs | Signature non traceable | Signatures deterministics | ✅ Implemented |

### Information Disclosure

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| commitment_pq.rs | Valeur revealede | Randomness unique | ✅ Implemented |
| proof_pq.rs | Witness revealed | Zero-knowledge | ✅ Implemented |

### Denial of Service

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| slh_dsa_batch.rs | Batch trop grand | Limite size | ✅ Implemented |
| circuit_pq.rs | Circuit trop complex | Limite de profondeur | ✅ Implemented |
| verify_pq.rs | Transaction malformede | Validation d'input | ✅ Implemented |

### Elevation of Privilege

| Component | Threat | Mitigation | Status |
|-----------|--------|------------|--------|
| verify_pq.rs | Double spend | Nullifier unique | ✅ Implemented |
| proof_pq.rs | Proof invalid acceptede | Verification STARK | ✅ Implemented |

## Fuzzing Tests

### Fuzzers availables

| Fuzzer | Target | Propertys testedes |
|--------|-------|-------------------|
| `commitment_pq_fuzzer.rs` | Engagements | Determinism, verification |
| `proof_pq_fuzzer.rs` | Proofs Plonky2 | Generation, verification |
| `verify_pq_fuzzer.rs` | Transactions V2 | Validation, consistency |
| `slh_dsa_batch_fuzzer.rs` | Verification batch | Limites, consistency |
| `circuit_pq_fuzzer.rs` | Circuits Plonky2 | Construction, limites |

### Execution of the fuzzers

```bash
# Commitment PQ
cargo fuzz run commitment_pq_fuzzer

# Proof PQ
cargo fuzz run proof_pq_fuzzer

# Verify PQ
cargo fuzz run verify_pq_fuzzer

# SLH-DSA Batch
cargo fuzz run slh_dsa_batch_fuzzer

# Circuit PQ
cargo fuzz run circuit_pq_fuzzer
```

## Property Tests

The tests de property (`tests/crypto_pq_proptest.rs`) verify:

1. **Determinism**: Sames inputs → same outputs
2. **Verification**: Engagement valide → verification successful
3. **Binding**: Impossible d'ouvrir towards une valeur differente
4. **Hiding**: Engagements de valeurs differentes are differents
5. **Consistency**: Verification batch = verification individuelle

## Security Checklist pre-release

### Before Each Release

- [ ] Every fuzzers passent without crash
- [ ] Tests de property passent
- [ ] Pas de `unwrap()`/`expect()` in the code network
- [ ] Validation of the inputs complete
- [ ] Documentation of the errors up to date
- [ ] Audit de dependencys

### Code Review

- [ ] Pas de panics in les parsers
- [ ] Arithmetic checked partout
- [ ] Constant-time comparisons pour crypto
- [ ] Gestion of the errors appropriate
- [ ] Pas de fuites of information in les logs

## Known Vulnerabilities

### No Known Vulnerabilities currently

In case of discovery, follow the responsible disclosure process.

## References

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA
- [Plonky2](https://github.com/0xPolygonZero/plonky2) - STARKs
- [STRIDE](https://owasp.org/www-community/Threat_Modeling_Process) - Threat modeling

## Contact security

To report a vulnerability: security@truststack.network

---

Last Updated: 2024
