# Threat Model - TSN Cryptographic Module

## Overview
This document described le model de threats for the module cryptographic de Trust Stack Network.

## Actors
- **Utilisateur legitimate**: Owns of the keys valides
- **Attacker passif**: Peut observer le traffic
- **Attacker actif**: Peut modifier messages and timing
- **Attacker physique**: Access limited to l'appareil

## Attack Surfaces

### 1. Timing side channels
**Threat**: Attacker mesure le temps d'execution pour extraire of the keys
**Impact**: Compromission complete of the private keys
**Mitigation**: 
  - Constant-time comparisons
  - Blindage of the operations criticals

### 2. Invalid curve attacks
**Threat**: Sending of points non valiof the sur la courbe
**Impact**: Private keys compromiseddeddes
**Mitigation**:
  - Validation rigoureuse of the points
  - Rejet of the points to l'infini

### 3. Entropy failures
**Threat**: RNG predictable
**Impact**: Keys devinables
**Mitigation**:
  - RNG system + mixur cryptographic
  - Tests d'entropie continus

## Required Security Properties

1. **Confidentiality**: Private keys never exposedes
2. **Integrity**: Nonee modification non detectede
3. **Authenticity**: Signatures verireliable
4. **Non-repudiation**: Signature = proof
5. **Post-quantum resistance**: Security same contre QC

## Specific Attack Vectors

### Attacks sur ML-DSA-65
- **Key reuse**: Never signer deux messages differents
- **Side channel**: Timing sur la generation de nonce
- **Fault injection**: Failure lors of the signature

### Attacks sur Plonky2
- **Invalid proofs**: Verification incomplete
- **Soundness gap**: Parameters mal configureds
- **Side channel**: Timing sur FFT

## Security Checklist
- [ ] No direct comparisons on secrets
- [ ] Cryptographic input validation
- [ ] Sensitive memory cleanup
- [ ] Fault injection attack protection
- [ ] Continuous integrity tests