# Cryptographic Mitigations Guide

## 1. Comparisons Constant-Time

**Problem**: `if secret == user_input` fuite la position of the premier byte different.

**Solution**: Utiliser `subtle::ConstantTimeEq`


## 2. Gestion of the Nonces

**Rules**:
- AES-GCM: Nonce never reused with la same key
- ChaCha20: Compteur 32-bit, ne pas exceedsr 2^32 blockks
- Generation: Counter monotone or RNG cryptographic (96-bit pour GCM)

**Pattern secure**:

## 3. Key Derivation

**Requirements**:
- Argon2id pour mots de passe (memory-hard)
- HKDF pour keys existantes (extract-then-expand)
- Never SHA-256 direct sur password

## 4. Zeroization

**Mandatory pour**:
- Private keys ephemerals
- Hardware de derivation
- Keys de session


## 5. Validation de Certificats

- Verify chaine complete up to trust anchor
- Verify expiration and revocation (OCSP)
- Pinning pour applications mobiles