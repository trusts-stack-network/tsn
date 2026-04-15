# Threat Model: TSN Faucet Module

## Overview

Le module faucet distribue 50 TSN par wallet par jour. C'est une surface of attack critical car il creates of the valeur (tokens) to partir de rien.

**Document Version:** 1.0  
**Last Updated:** 2024  
**Owner:** Security & QA Team

---

## Assets

| Asset | Value | Protection Level |
|-------|-------|------------------|
| Faucet balance | TSN tokens | Critical |
| Claim rate limit state | DoS prevention | High |
| Nullifier set | Replay protection | Critical |
| Plonky2 verification key | Proof validation | Critical |
| Merkle root | Commitment integrity | Critical |

---

## Threat Actors

### 1. Opportunist (Low Sophistication)
- **Capabilities:** Scripts basiques, multiples wallets
- **Motivation:** Tokens gratuits
- **Attack:** Creation massive de wallets, claims automated

### 2. Organized Abuser (Medium Sophistication)
- **Capabilities:** Botnets, CAPTCHA solving, proxy rotation
- **Motivation:** Revente of the tokens
- **Attack:** Sybil attacks, geo-distribution of the requests

### 3. Advanced Attacker (High Sophistication)
- **Capabilities:** Reverse engineering, cryptanalysis
- **Motivation:** Exploitation technique, briser les garanties de security
- **Attack:** Falsification de proofs Plonky2, timing attacks, race conditions

### 4. Insider Threat
- **Capabilities:** Access at code source, infrastructure
- **Motivation:** Sabotage, vol
- **Attack:** Backdoors, manipulation of the parameters

---

## STRIDE Analysis

### Spoofing (S)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Identity Spoofing wallet | High | pk_hash binding cryptographic | ✅ Implemented |
| Falsification de proof Plonky2 | Critical | Verification complete of the circuit | ✅ Implemented |
| Replay de claims valiof the | High | Nullifier unique par claim | ✅ Implemented |

### Tampering (T)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Modification of the montant de claim | Critical | Montant constant (50 TSN), non configurable par l'utilisateur | ✅ Implemented |
| Modification of the timestamp | Medium | Validation side server, tolerance limitede | ✅ Implemented |
| Manipulation Merkle root | Critical | Verification contre root canonique | ✅ Implemented |
| Race condition double-spend | High | Atomicity of the operations de claim | ⚠️ At verify |

### Repudiation (R)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Negation of a claim | Low | Logging immutable, nullifier registered | ✅ Implemented |
| Negation d'abus | Medium | Metrics detailedes, alerting | ✅ Implemented |

### Information Disclosure (I)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Timing attack sur pk_hash | Medium | Constant-time comparisons via `subtle` crate | ✅ Implemented |
| Timing attack sur nullifier check | Medium | Recherche constant-time in le set | ⚠️ At verify |
| Fuite of the solde faucet | Low | Information public par design | ✅ Accepted |
| Fuite of the wallets ayant claim | Low | Data on-chain publics | ✅ Accepted |

### Denial of Service (D)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Exhaustion memory (grosses proofs) | High | Limites size strictes (64KB max) | ✅ Implemented |
| CPU exhaustion (verification proof) | High | Rate limiting global, timeouts | ✅ Implemented |
| Remplissage of the nullifier set | Medium | Cost de claim, purge periodic | ⚠️ At surveiller |
| Slowloris sur endpoint faucet | Medium | Timeouts de connexion, limites de requests | ✅ Implemented |

### Elevation of Privilege (E)

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Bypass rate limiting | Critical | Atomicity, validation side server only | ✅ Implemented |
| Bypass verification proof | Critical | Circuit Plonky2 fixe, VK hardcoded | ✅ Implemented |
| Modification parameters faucet | Critical | Pas de configuration runtime of the parameters criticals | ✅ Implemented |

---

## Attack Scenarios

### Scenario 1: Proof Plonky2 Falsified

**Description:** Un attacker generates une proof Plonky2 invalid qui passe la validation.

**Impact:** Creation illimitede de tokens.

**Steps of attack:**
1. Analysis of the circuit Plonky2 used
2. Tentative de generation de proof without witness valide
3. Soumission at faucet

**Mitigations:**
- Circuit Plonky2 audited and fixe
- Verification key hardcoded
- Tests de regression pour proofs invalids

**Test de security:** `test_plonky2_proof_verification_rejects_invalid`

---

### Scenario 2: Timing Attack sur pk_hash

**Description:** Un attacker mesure le temps de response pour deduce of the informations on pk_hash valides.

**Impact:** Enumeration of the wallets eligible, preparation of attacks targetedes.

**Steps of attack:**
1. Mesure of the temps de response pour differents pk_hash
2. Detection de patterns (early exit vs full validation)
3. Exploitation of the difference

**Mitigations:**
- Utilisation de `subtle::ConstantTimeEq` pour all les comparaisons
- Temps de response constant quel que soit le result
- Padding of the responses for aiformiser la size

**Test de security:** `test_pk_hash_comparison_is_constant_time`

---

### Scenario 3: Race Condition Double-Claim

**Description:** Deux requests simultaneous for the same wallet passent all les deux.

**Impact:** Double paiement, perte de fonds faucet.

**Steps of attack:**
1. Envoi simultaneous de deux claims from le same wallet
2. Timing precise pour interleaving of the threads
3. Les deux validations passent before l'enledgerment

**Mitigations:**
- Atomicity of the operations de claim
- Verrouillage par wallet during le traitement
- Verification finale before emission of the token

**Test de security:** `test_concurrent_claims_are_atomic`

---

### Scenario 4: Sybil Attack Massive

**Description:** Un attacker creates of the milliers de wallets pour maximiser les claims.

**Impact:** Exhaustion fast of the faucet.

**Steps of attack:**
1. Generation automatede de wallets
2. Distribution geographic of the requests
3. Rotation d'IP pour avoid le rate limiting

**Mitigations:**
- Per-IP rate limiting (en more of the wallet)
- Detection de patterns anormaux
- CAPTCHA pour claims suspects
- Cooldown exponentiel pour IPs suspectes

**Test de security:** `test_rate_limiting_enforced`

---

### Scenario 5: Memory Exhaustion

**Description:** Un attacker envoie of the proofs enormouss pour causer un OOM.

**Impact:** Crash of the node, inavailability of the service.

**Steps of attack:**
1. Creation of ae proof de multiple GB
2. Soumission at endpoint faucet
3. Allocation memory excessive

**Mitigations:**
- Limite size stricte before parsing (64KB)
- Streaming of the data si possible
- Limites de memory par connexion

**Test de security:** `test_large_input_handling`

---

## Security Checklist

### Before Each Release:

- [ ] Tous the tests de security passent
- [ ] Fuzzers executed without crash during >24h
- [ ] No `unwrap()` or `expect()` in le hot path network
- [ ] Comparaisons cryptographics en temps constant
- [ ] Validations d'input completes (size, format, plage)
- [ ] Arithmetic verifiede (pas de underflow/overflow)
- [ ] Tests de concurrence passent (miri si possible)
- [ ] Documentation of the changements de security

---

## Vulnerability Registry

| ID | Description | Severity | Status | Discovered | Mitigated |
|----|-------------|----------|--------|------------|-----------|
| FAU-001 | Timing attack potential sur pk_hash | Medium | ✅ Fixed | Audit internal | v1.0 |
| FAU-002 | Limite size manquante sur proofs | High | ✅ Fixed | Fuzzing | v1.0 |
| FAU-003 | Race condition theoretical double-claim | Medium | ⚠️ Monitoring | Review code | - |

---

## References

- [Plonky2 Documentation](https://github.com/0xPolygonZero/plonky2)
- [Subtle Crate - Constant-Time Operations](https://docs.rs/subtle)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
