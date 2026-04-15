# TSN v0.1 - Technical Whitepaper
## Trustless Secure Network Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024  
**Status:** Draft Specification  
**Classification:** Technical Documentation / Research

---

## Table of Contents

1. [Executive Summary](#1-summary-executive)
2. [Architecture System](#2-architecture-system)
3. [Primitives Cryptographics](#3-primitives-cryptographics)
   - 3.1 [SLH-DSA (SPHINCS+)](#31-slh-dsa-sphincs)
   - 3.2 [Poseidon2 Hash Function](#32-poseidon2-hash-function)
   - 3.3 [Halo2 ZK Framework](#33-halo2-zk-framework)
4. [MIK - Modular Integrity Kernel](#4-mik---modular-integrity-kernel)
5. [Mechanism de Consensus](#5-mechanism-de-consensus)
6. [Layer P2P](#6-layer-p2p)
7. [Flux de Protocole](#7-flux-de-protocole)
8. [Analysis de Security](#8-analysis-de-security)
9. [References](#9-references)

---

## 1. Executive Summary

TSN (Trustless Secure Network) is une infrastructure distributede post-quantum combining of the primitives cryptographics to security provene with of the zero-knowledge proofs (ZK). The architecture integrates :

- **SLH-DSA** (NIST FIPS 205) for signature post-quantum stateless
- **Halo2** for proofs recursives and composition de circuits
- **Poseidon2** for the hachage optimized en arithmetic ZK
- **MIK** for gestion d'state authenticatede par Merkle
- Un consensus BFT asynchrone quantum attack resistant
- Une layer P2P with routage anonymized

---

## 2. Architecture System

```mermaid
graph TB
    subgraph "Layer Application"
        APP[Smart Contracts / State Transitions]
    end
    
    subgraph "Layer ZK / Proof"
        HALO[Halo2 Prover/Verifier]
        MIK[MIK State Manager]
    end
    
    subgraph "Layer Cryptographic"
        SLH[SLH-DSA Signer]
        POS[Poseidon2 Hasher]
        PQ_Crypto[Post-Quantum Primitives]
    end
    
    subgraph "Layer Consensus"
        CONS[BFT Consensus Engine]
        ST[State Replication]
    end
    
    subgraph "Layer Network"
        P2P[P2P Transport]
        DISC[Peer Discovery]
        ENCR[Noise Framework + PQ KEM]
    end
    
    APP --> HALO
    HALO --> MIK
    MIK --> POS
    HALO --> SLH
    SLH --> CONS
    CONS --> P2P
    MIK --> CONS
    P2P --> ENCR

### 2.1 Stack Technique

| Component | Implementation | Specification |
|-----------|---------------|---------------|
| Signature | SLH-DSA-SHAKE-256s | NIST FIPS 205 |
| Hash ZK | Poseidon2 | Cryptology ePrint 2023/323 |
| Proof ZK | Halo2 | Zcash Protocol Spec |
| Consensus | MIK-BFT | TSN-CONS-001 |
| Transport | QUIC + Noise IK | IETF RFC 9000 / Noise Protocol |

---

## 3. Primitives Cryptographics

### 3.1 SLH-DSA (SPHINCS+)

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) fournit la post-quantum resistance via of the hash functions cryptographics standard, without dependency of the structure algebraic.

#### Parameters TSN

# Configuration SLH-DSA-SHAKE-256s (Small, Security 128 bits NIST Level 1)
PARAMETERS = {
    "n": 16,          # Longueur de security (bytes)
    "h": 63,          # Height de l'hypertree
    "d": 7,           # Nombre of theyers
    "a": 12,          # Size of the arbres XMSS
    "k": 14,          # Nombre de chains FORS
    "w": 16,          # Parameter Winternitz
    
    # Derived
    "h_prime": 9,     # h // d
    "m": 30,          # Longueur of the message digest (FORS)
    "len": 35         # Nombre de blockks Winternitz
}

#### Structure of the Signature

Signature SLH-DSA (7,856 bytes pour SHAKE-256s):
├── Randomness (n bytes)
├── FORS Signature (k(1+a)n bytes)
│   ├── k indices de selection
│   └── k proofs d'authentication (a+1 node chacune)
└── Hypertree Signature (d × XMSS)
    └── d × (len + h/d) × n bytes

#### Integration TSN

Les keys are derived via un HD-wallet post-quantum (BIP32-PQ) :

Master Seed (256 bits)
    └── CKD-PQ(index):
        ├── SLH-DSA SK 
        ├── SLH-DSA PK
        └── Chain de hachage BLAKE2b pour derivation deterministic

### 3.2 Poseidon2 Hash Function

Poseidon2 is une primitive de hachage designed specificment for circuits ZK (low arithmetic de contraintes R1CS/Plonkish).

#### Parameters Arithmetics

- **Corps fini :** GF(p) where p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001 (BN254 scalar field)
- **Tto (t) :** 3 (2 elements de capability, 1 de taux)
- **Nombre de tours :** 8 full rounds + 56 partial rounds (rounds to mi-chemin