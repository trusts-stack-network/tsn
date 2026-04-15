# Threat Model: TSN Faucet Module (PSTR)

**Document Version:** 1.0  
**Last Updated:** 2024  
**Scope:** `src/faucet/mod.rs` (1159 lines)  
**Classification:** Internal - Security Critical

---

## 1. Executive Summary

Le module faucet distribue 50 TSN par wallet par jour. C'est une surface of attack critical car:
- Il generates of the tokens de valeur real
- Il accepte of the ZK proofs (Plonky2) externals
- Il maintient un state de rate limiting persistant
- Il is exposed via l'API network

**Risk Rating:** HIGH

---

## 2. STRIDE Analysis

### Spoofing (S)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| S1 | Identity Spoofing via pk_hash forged | Critical | Verification Plonky2 + nullifier unique |
| S2 | Replay of ae proof valide | Critical | Nullifier stored en DB + verification |

### Tampering (T)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| T1 | Modification of the rate limit en DB | High | DB encryptede + checksums |
| T2 | Modification of the parameters de proof | Critical | Verification circuit Plonky2 |

### Repudiation (R)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| R1 | Negation of ae demande de faucet | Low | Logging audit complete |

### Information Disclosure (I)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| I1 | Timing attack sur pk_hash existant | High | Constant-time comparison |
| I2 | Enumeration of the wallets ayant claim | Medium | Pas de message differentiated |

### Denial of Service (D)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| D1 | Flood de requests de claim | High | Rate limiting IP + proof of work |
| D2 | DB bloat via nullifiers invalids | Medium | Validation proof before storage |

### Elevation of Privilege (E)
| Threat | Description | Severity | Mitigation |
|--------|-------------|----------|------------|
| E1 | Bypass of the rate limit | Critical | Timestamp verified + DB atomique |

---

## 3. Attack Scenarios

### Scenario 1: Double Spend via Timing Race
**Attack:** Deux requests simultaneous with same proof  
**Impact:** Double distribution de tokens  
**Defense:** 
- Verification nullifier en DB before generation note
- Operation atomique check-and-set

### Scenario 2: Proof Replay Attack
**Attack:** Reuse of ae proof valide sur un autre node  
**Impact:** Distribution multiple  
**Defense:**
- Nullifier global sur la blockkchain
- Synchronisation of the nullifiers between nodes

### Scenario 3: Timing Side-Channel
**Attack:** Mesure of the temps de response pour determine si un pk_hash existe  
**Impact:** Privacy leak  
**Defense:**
- `subtle::ConstantTimeEq` pour all les comparaisons
- Temps de response constant (padding artificiel si necessary)

### Scenario 4: Malformed Proof DoS
**Attack:** Sending of proofs malformeof the pour crash le validateur Plonky2  
**Impact:** Panic / DoS  
**Defense:**
- Parsing defensive with `Result` partout
- None `unwrap()` in le hot path
- Continuous fuzzing

---

## 4. Security Invariants

Les invariants followings DOIVENT be preserved:

```rust
// INV-1: Uniqueness of the nullifier
∀ claim ∈ Claims: claim.nullifier ∉ SpentNullifiers

// INV-2: Rate limiting
∀ wallet: count(claims[wallet, 24h]) ≤ 1

// INV-3: Validity of the proof
∀ claim: verify_plonky2(claim.proof, claim.public_inputs) == true

// INV-4: Integrity of the montant
claim.amount == FAUCET_AMOUNT (50 TSN)

// INV-5: Non-malleability
hash(claim) depends de all les champs signifiants
```

---

## 5. Security Checklist

### Pre-Deployment
- [ ] Fuzzing past without crash during 24h
- [ ] Property tests all verts
- [ ] Audit timing constant-time
- [ ] Review of the dependencys crypto
- [ ] Test de charge rate limiting

### Runtime Monitoring
- [ ] Alertes sur rate limit exceeded
- [ ] Alertes sur proof invalid
- [ ] Metrics de timing (p95, p99)
- [ ] Logs of audit immutables

---

## 6. References

- Plonky2: https://github.com/0xPolygonZero/plonky2
- Constant-time comparisons: subtle crate
- FIPS 204: ML-DSA post-quantum signatures
