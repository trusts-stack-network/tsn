# Threat Model - TSN Cryptographic Module

## Overview
This document definedt le model de threats for the module cryptographic de Trust Stack Network, incluant les assumptions de security, les capabilitys de l'adversary, and les mitigations en place.

## Assumptions de Threat

### Adversary Model
- **Capabilitys**: L'adversary peut:
  - Observer all les messages network
  - Mesurer les temps d'execution with precision microseconde
  - Soumettre of the inputs maliciouss via l'API
  - Access at code source (model white-box)

- **Limitations**: L'adversary ne can pas:
  - Access to private keys storedes en memory securee
  - Modifier le code in production
  - Forcer of the reboots arbitrarys

### Surfaces d'Attack

#### 1. Timing Attacks
**Vecteur**: Comparaison non-constant-time in verify_signature()
**Impact**: Recovery de private key via analysis temporelle
**State**: VULNERABLE - See test `test_signature_timing_attack_resistance`
**Mitigation: Implement `constant_time_eq()` pour all les comparaisons cryptographics

#### 2. Side-Channel Attacks
**Vecteur**: Cache-timing on operations de hash
**Impact**: Inference of information on inputs secrets
**State**: PARTIELLEMENT PROTECTED - See test `test_cache_timing_resistance`
**Mitigation**: Utiliser of the operations constant-time, add of the bruit

#### 3. Fault Injection
**Vecteur**: Inputs malformeds in les parsers
**Impact**: Panic, DoS, potentiallement execution arbitrary
**State**: PARTIELLEMENT PROTECTED - Fuzzing en place
**Mitigation**: Validation stricte of the inputs, tests de robustsse

## Vulnerabilities Actives

### CRITICAL-001: Timing Attack sur Signature
**File**: `src/crypto/signature.rs:127`
**Description**: La comparaison de signature utilise `==` at lieu de `constant_time_eq`
**CVSS**: 7.5 (High)
**Status**: Non patched
**Test**: `tests/crypto/timing_attacks_test.rs`

### HIGH-001: Validation de Key Public
**File**: `src/crypto/keys.rs:89`
**Description**: Nonee validation que le point is sur la courbe
**Impact**: Attack de key invalid pouvant mener to of the signatures forgedes
**Status**: Non patched
**Test**: `tests/crypto/invalid_key_test.rs`

### MEDIUM-001: Entropie PRNG
**File**: `src/crypto/pq/dilithium.rs`
**Description**: Utilisation de `thread_rng()` at lieu de `OsRng` for generation de keys
**Impact**: Potentialle predictability of the keys
**Status**: Non patched

## Recommendations

### Immediate (1 semaine)
1. Replace all les comparaisons cryptographics par `constant_time_eq`
2. Add la validation de points de courbe for public keys
3. Passer to `OsRng` pour all generation de keys cryptographics

### At court terme (1 mois)
1. Implement of the compteurs de protection contre les timing attacks
2. Add of the bruit artificiel in les operations sensibles
3. Documenter all les algorithmes non-constant-time

### At long terme (3 mois)
1. Audit external of the module crypto par of the experts en side-channels
2. Certification FIPS 140-3 of the module de signature
3. Implementation of a HSM logiciel for protection of the keys