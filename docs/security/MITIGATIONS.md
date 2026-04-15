# Cryptographic Mitigations Guide

## 1. Constant-Time Operations

### Principe
Les operations sur data sensibles (keys, plaintexts internals) doivent s'execute en temps constant independently of the valeurs.

### Implementation Rust


### Verification

Utiliser `dudect` (Distinguishing Attack using Differential Testing) :


## 2. RSA Blinding

Protection contre timing attacks sur decryption RSA.


## 3. ECDSA Nonce Reuse Prevention


## 4. Memory Zeroization
