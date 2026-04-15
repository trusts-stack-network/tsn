# Threat Model - Trust Stack Network (TSN)

**Version:** 1.0
**Date:** 2024
**Classification:** Interne

---

## 1. Introduction

This document described le model de threats pour Trust Stack Network (TSN), une blockkchain post-quantum. Il identifie les acteurs maliciouss, les surfaces of attack, and les mitigations en place.

---

## 2. Acteurs Maliciouss (Threat Actors)

### 2.1 Attacker Opportuniste
- **Capabilitys:** Access to of the hardware standard
- **Motivation:** Profit financier
- **Surface of attack:** RPC public, mempool

### 2.2 Organized Attacker
- **Capabilitys:** Infrastructure dedicated, botnets
- **Motivation:** Sabotage, manipulation de market
- **Surface of attack:** Network P2P, consensus

### 2.3 Attacker Stateique
- **Capabilitys:** Quantum computers (futur), ressources illimitedes
- **Motivation:** Censure, surveillance
- **Surface of attack:** Cryptographie, gouvernance

### 2.4 Attacker Interne
- **Capabilitys:** Access at code source, infrastructure
- **Motivation:** Profit, revanche
- **Surface of attack:** CI/CD, keys de deployment

---

## 3. Surfaces d'Attack

### 3.1 Layer Network
| Component | Risk | Mitigation |
|-----------|--------|------------|
| P2P Discovery | DoS, Eclipse | Rate limiting, peer diversity |
| Mempool | Spam, DoS | Fees, size limits |
| RPC/HTTP | Injection, DoS | Input validation, auth |

### 3.2 Layer Consensus
| Component | Risk | Mitigation |
|-----------|--------|------------|
| PoW Mining | 51% attack | Difficulty adjustment |
| Block Validation | Invalid blockks | Multi-layer validation |
| Fork Choice | Long-range attacks | Endality gadget |

### 3.3 Layer Cryptographic
| Component | Risk | Mitigation |
|-----------|--------|------------|
| Signatures | Forgery | ML-DSA-65 (post-quantum) |
| Hashes | Collisions | Poseidon2 |
| ZK Proofs | Soundness failures | Plonky2 STARKs |
| Keys | Extraction | HSM, air-gapped |

### 3.4 Layer Application
| Component | Risk | Mitigation |
|-----------|--------|------------|
| Wallet | Key theft | Encryption, 2FA |
| Smart Contracts | Logic bugs | Formal verification |
| Oracle | Data manipulation | Multiple sources |

---

## 4. Threats Specifics (STRIDE)

### 4.1 Spoofing (Identity Falsification)
**Threat:** Falsification de transaction signaturess

**Scenario:**
- Attacker tente de forge une signature ML-DSA-65
- Objective: spend of the fonds without authorization

**Mitigation:**
- ML-DSA-65 is proven secure under MLWE/MSIS
- Verification stricte of the signatures
- Pas de fallback towards algorithmes lows

**Tests:** `tests/crypto_audit_signature.rs`

---

### 4.2 Tampering (Alteration)
**Threat:** Modification de l'state of the blockkchain

**Scenario:**
- Attacker tente de modifier a blockkk historique
- Objective: rewrite the history of the transactions

**Mitigation:**
- Chain de hashes immutable
- Proofs de Merkle pour each blockk
- Detection de modifications via consensus

**Tests:** `tests/crypto_audit_merkle.rs`

---

### 4.3 Repudiation
**Threat:** Deny have performed a transaction

**Scenario:**
- Utilisateur nie have signed a transaction
- Objective: annuler un paiement

**Mitigation:**
- Signatures non-repudiable
- Logs immutables
- Timestamps verireliable

---

### 4.4 Information Disclosure
**Threat:** Exposition de data sensibles

**Scenario:**
- Attacker extrait of the informations of the notes encryptedes
- Objective: deanonymize the transactions

**Mitigation:**
- Encryption ChaCha20Poly1305
- Commitments Pedersen
- Zero-knowledge proofs

---

### 4.5 Denial of Service (DoS)
**Threat:** Rendre le network inavailable

**Scenarios:**
1. **Mempool spam:** Sending of transactions invalids
2. **Block flooding:** Minage de blockks vides
3. **Proof flooding:** Sending of proofs malformedes

**Mitigations:**
- Rate limiting on connexions P2P
- Validation fast before traitement
- Timeouts on operations expensive
- Limites size on messages

**Tests:**
- `fuzz/signature_fuzzer.rs`
- `fuzz/proof_fuzzer.rs`
- `tests/crypto_audit_proof.rs`

---

### 4.6 Elevation of Privilege
**Threat:** Obtain of the privileges non authorizeds

**Scenario:**
- Attacker exploite une vulnerability in the consensus
- Objective: controlr la production de blockks

**Mitigation:**
- Separation of the privileges
- Validation multi-layers
- Audit de security regular

---

## 5. Attacks Post-Quantums

### 5.1 Attack de Shor
**Target:** ECDSA, RSA, Diffie-Hellman
**Impact:** Every algorithmes to courbes elliptiques broken
**Mitigation TSN:** Utilisation de ML-DSA-65 (pas de courbes elliptiques)

### 5.2 Attack de Grover
**Target:** Fonctions de hachage (SHA-256)
**Impact:** Complexity reduced de O(N) to O(√N)
**Mitigation TSN:** Poseidon2 with parameters increased

### 5.3 Attack on ZK proofs
**Target:** Groth16 (based sur BN254)
**Impact:** Possibility de forge of the proofs
**Mitigation TSN:** Migration towards Plonky2 (STARKs post-quantums)

---

## 6. Pre-Release Security Checklist

### 6.1 Cryptographie
- [ ] Every algorithmes post-quantums validateds
- [ ] None unwrap/expect in the code crypto
- [ ] Tests de regression pour each vulnerability
- [ ] Fuzzers executed without crash

### 6.2 Network
- [ ] Rate limiting configured
- [ ] Validation of the inputs complete
- [ ] Timeouts sur all les operations bloquantes
- [ ] Logs de security enableds

### 6.3 Consensus
- [ ] Tests de scenarios adversariaux
- [ ] Validation of the blockks exhaustive
- [ ] Gestion of the forks testede
- [ ] Resistance to attacks 51% documentede

### 6.4 Documentation
- [ ] Ce threat model up to date
- [ ] SECURITY.md pubrelated
- [ ] Disclosure procedure definede
- [ ] Guide de response to incidents

---

## 7. References

- STRIDE: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- OWASP Threat Modeling: https://owasp.org/www-community/Application_Threat_Modeling
