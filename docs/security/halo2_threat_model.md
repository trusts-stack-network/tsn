# Halo2 Threat Model - Trust Stack Network

## Overview

This document described le model de threats for the system de proofs Halo2 de TSN, incluant les circuits ZK, le validateur de proofs, and les mechanisms de protection.

## Architecture Halo2 TSN

### Components Principaux

1. **halo2_proofs.rs** - Implementation of the circuits and proofs Halo2
2. **halo2_validator.rs** - Validation securee of the proofs
3. **halo2_shielded_proofs.rs** - Proofs pour transactions shielded
4. **halo2_circuit.rs** - Definition of the circuits

### Flux de Data

```
Transaction Shielded → Circuit Halo2 → Proof ZK → Validation → Inclusion Block
```

## Adversary Model

### Capabilitys de l'Adversary

| Niveat | Capabilitys | Examples |
|--------|-----------|----------|
| Opportuniste | Network public, observation | Timing attacks, fingerprinting |
| Actif | Injection de messages, DoS | Proofs malformedes, flood |
| Advanced | Connaissance cryptographic | Proofs fausses sophisticated |
| Insider | Access internal, keys compromiseddedof the | Fausse proof with vk legitimate |

### Objectives de l'Adversary

1. **Falsification de proof** - Create une proof valide without know le witness
2. **Double-spend** - Reuse une proof pour deux transactions
3. **DoS** - Crasher le validateur with of the inputs malformedes
4. **Extraction of information** - Deduce of the data privates of the proofs
5. **Malleability** - Modifier une proof without invalidr la verification

## STRIDE Analysis

### Spoofing (Identity Spoofing)

**Threat:** Usurpation of a circuit Halo2 legitimate

**Scenario:**
- Attacker creates un fto verifying key
- Usurpe l'identity of a circuit approven

**Mitigation:**
- Hash of the verifying key stored on-chain
- Verification systematic of the vk_hash
- Registre de circuits approvens

**Status:** ✅ Mitigated

### Tampering (Alteration)

**Threat:** Modification of ae proof after generation

**Scenario:**
- Attacker intercepte une proof valide
- Modifie les inputs publics
- Soumet la proof modifiede

**Mitigation:**
- Binding cryptographic proof → inputs publics
- Verification de consistency of the commitments
- Non-malleability of the scheme de proof

**Status:** ✅ Mitigated

### Repudiation

**Threat:** Deny have performed a transaction

**Scenario:**
- Utilisateur nie have created a transaction shielded
- Pas de traceability public

**Mitigation:**
- Nullifiers publics and uniques
- Proofs relateds to nullifiers
- Audit trail cryptographic

**Status:** ✅ Mitigated

### Information Disclosure

**Threat:** Extraction of informations privates of the proofs

**Scenario:**
- Analysis of the proofs pour deduce les montants
- Correlation of the nullifiers
- Timing analysis

**Mitigation:**
- Zero-knowledge property of the circuit
- Padding constant-time
- Randomisation of the proofs

**Status:** ✅ Mitigated

### Denial of Service

**Threat:** Crash or ralentissement of the validateur

**Scenarios:**
- Proof size excessive (10GB+)
- Nombre of inputs publics enormous
- Points de courbe invalids
- Boucles infinies in la verification

**Mitigations:**
- Limites strictes size (proof < 10MB, inputs < 1000)
- Timeouts de verification
- Circuit breaker sur errors repbeenes
- Validation structurelle before verification cryptographic

**Status:** ✅ Mitigated

### Elevation of Privilege

**Threat:** Contournement of the rules de consensus

**Scenario:**
- Proof valide mais pour montant superior to inputs
- Contournement of the verifications de solde

**Mitigation:**
- Verification of the contraintes arithmetics
- Range checks sur all les montants
- Verification of the Merkle roots

**Status:** ✅ Mitigated

## Attack Surfaces

### 1. Interface de Validation

**Enputs:**
- Proof binaire (bytes)
- Enputs publics (Vec<Vec<u8>>)
- Verifying key hash ([u8; 32])

**Risks:**
- Deserialization panic
- Buffer overflow
- Integer overflow on sizes

**Tests:** `halo2_proof_validation_test.rs`, `halo2_property_tests.rs`

### 2. Circuit Halo2

**Components:**
- Contraintes arithmetics
- Lookup tables
- Permutation arguments

**Risks:**
- Underconstrained circuit
- Malicious witness
- Side-channel via lookup tables

**Tests:** `halo2_circuit_test.rs`

### 3. Verifying Key

**Risks:**
- VK malformed
- VK compromiseddedd
- VK substitution

**Mitigation:**
- Hash verification
- On-chain registry
- Multi-sig pour VK updates

## Security Checklist Pre-Deployment

### Validation of the Proofs

- [ ] Size de proof limitede (min: 32 bytes, max: 10MB)
- [ ] Nombre of inputs publics limited (max: 1000)
- [ ] Size individuelle of the inputs limitede (max: 1MB)
- [ ] Size totale of the inputs limitede (max: 100MB)
- [ ] Patterns maliciouss rejecteds (PWN!, etc.)
- [ ] Points de courbe invalids rejecteds
- [ ] Timeout de verification configured

### Circuit Security

- [ ] Circuit audited for aderconstrained constraints
- [ ] Lookup tables verifiedes
- [ ] Random oracle model validated
- [ ] Fiat-Shamir transform secure

### Operationnel

- [ ] Circuit breaker enabled
- [ ] Rate limiting configured
- [ ] Monitoring of the errors de validation
- [ ] Alertes sur tto d'failure anormal

## References

- [Halo2 Book](https://zcash.github.io/halo2/)
- [PLONK Paper](https://eprint.iacr.org/2019/953)
- [Halo Paper](https://eprint.iacr.org/2019/1021)
- TSN Security Guidelines

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|-------------|
| 1.0 | 2024-01-15 | Security Team | Creation initiale |
| 1.1 | 2024-02-20 | Security Team | Ajout DoS scenarios |
