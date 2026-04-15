# Threat Model - Cryptographic Module

## Scope
Module `src/crypto/` : symmetric encryption, MAC, key derivations, gestion de secrets.

## Actors and Assets
- **Assets**: Private keys, mots de passe, data encryptedes, nonces/IVs
- **Attackers**: 
  - Local (access memory, cache, timing)
  - Network (manipulation ciphertexts)
  - Physique (cold boot, DMA)

## Vecteurs d'Attack Identifieds

### 1. Timing Attacks (HIGH)
- **Description**: Mesure of the temps d'execution pour derive of the secrets
- **Targets**: Comparaison de HMACs, boucles sur secrets, lookup tables
- **Mitigations**: Operations constant-time (`subtle`), pas de branchement sur secrets

### 2. Memory Side-Channels (HIGH)
- **Description**: Exposition of the keys en memory (swap, core dumps, heap inspection)
- **Mitigations**: `zeroize`, allocation locked (memsec), minimisation temps de vie

### 3. Padding Oracle (CRITICAL)
- **Description**: Decryption CBC with validation de padding information leak
- **Mitigations**: Utiliser AEAD (AES-GCM/ChaCha20-Poly1305), pas de padding manuel

### 4. Nonce Reuse (CRITICAL)
- **Description**: Reuse de IV with CTR/GCM mode
- **Mitigations**: Generation random 96-bit (GCM) or compteur atomique

### 5. RNG Predictability (CRITICAL)
- **Description**: Mauvaise source d'entropie pour generation keys
- **Mitigations**: `getrandom` / `rand::rngs::OsRng` only

### 6. Cache Timing via Lookup Tables (MEDIUM)
- **Description**: Tables S-box indexed par secret (AES software impl)
- **Mitigations**: Implementations constant-time or hardware AES-NI

## Assumptions de Security
- Le system d'exploitation protects l'espace memory of the processus
- `getrandom` fournit de the entropy system genuine
- L'attacker ne can pas lire les ledgers CPU during l'execution (mais can mesurer le temps)

## Checklist d'Audit
- [ ] Nonee comparaison de secrets with `==`
- [ ] Pas de `if secret[index] == value`
- [ ] Zeroization explicite of the keys
- [ ] Verification of the bounds before operations crypto
- [ ] RNG seeding non manuel (pas de `FromEntropy` predictable)