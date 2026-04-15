# TSN Technical Whitepaper v0.1
## Trustless Secure Network Architecture

**Version:** 0.1.0-draft  
**Date:** 2024-01-15  
**Status:** Draft Specification  
**Authors:** TSN Protocol Team  

---

## Table of Contents

1. [Abstract](#abstract)
2. [Introduction](#introduction)
3. [Architecture Overview](#architecture-overview)
4. [Cryptographic Primitives](#cryptographic-primitives)
   - 4.1 [SLH-DSA (SPHINCS+)](#slh-dsa-sphincs)
   - 4.2 [Poseidon2 Hash Function](#poseidon2-hash-function)
   - 4.3 [Halo2 Proof System](#halo2-proof-system)
5. [Identity Layer: MIK](#identity-layer-mik)
6. [Consensus Protocol](#consensus-protocol)
7. [Networking Layer](#networking-layer)
8. [Security Considerations](#security-considerations)
9. [References](#references)

---

## Abstract

TSN (Trustless Secure Network) is une infrastructure blockkchain post-quantum integrating of the primitives cryptographics resistantes to quantum computers with of the zero-knowledge proofs (ZKP) recursive. This document specifies the architecture v0.1 combining SLH-DSA for signature post-quantum, Halo2 for recursive proofs, and Poseidon2 comme hash function arithmetizede.

---

## Introduction

Les networkx distributeds actuels font face to deux threats majeures :
1. **Supremacy quantique** : The algorithm de Shor threat ECDSA and RSA
2. **Scalability** : Les ZK proofs existantes souffrent de temps de verification highs

TSN v0.1 propose une architecture hybride :
- **Post-quantum** : SLH-DSA (NIST FIPS 205) pour all the signatures
- **ZK-Rollup natif** : Halo2 without trusted setup
- **Hachage algebraic** : Poseidon2 optimized for circuits R1CS/PLONK

---

## Architecture Overview

### Technical Stack

```mermaid
graph TB
    A[Application Layer] --> B[ZK-Rollup Layer<br/>Halo2 Circuits]
    B --> C[Consensus Layer<br/>BFT + MIK]
    C --> D[Cryptographic Layer<br/>SLH-DSA + Poseidon2]
    D --> E[P2P Network Layer<br/>Noise Protocol]
    
    subgraph "Post-Quantum Security"
    D
    end
    
    subgraph "Zero-Knowledge"
    B
    end

### Flux de Transaction

sequenceDiagram
    participant U as User
    participant W as Wallet/MIK
    participant V as Validator
    participant C as Halo2 Circuit
    participant N as P2P Network
    
    U->>W: Sign(Tx, SK_SLH)
    W->>C: Generate Witness
    C->>C: Poseidon2(Tx_hash)
    C->>C: Create Proof π
    W->>V: Submit(Tx, π, PK_SLH)
    V->>V: Verify SLH-DSA Sig
    V->>C: Verify π
    V->>N: Broadcast Proposal
    N->>V: Consensus Round

---

## Cryptographic Primitives

### SLH-DSA (SPHINCS+)

TSN utilise **SLH-DSA-SHA2-128s** comme scheme de signature par default, compliant to NIST FIPS 205.

#### Parameters

| Parameter | Valeur | Description |
|-----------|--------|-------------|
| `n` | 16 | Security parameter (128-bit security) |
| `h` | 63 | Hypertree height |
| `d` | 7 | Hypertree layers |
| `a` | 12 | FORS trees |
| `k` | 14 | FORS leafs |
| `w` | 16 | Winternitz parameter |

#### Integration

The addresses TSN are derived of the public keys SLH-DSA via :

address = Poseidon2(PK_SLH || version_byte || checksum)

**Sizes:**
- Private key : 64 octets (seed)
- Public key : 32 octets
- Signature : 7 856 octets (compacted with compression de Winternitz)

### Poseidon2 Hash Function

Remplacement de SHA-256/Keccak par Poseidon2 pour all les operations arithmetics.

#### Parameters TSN-P2

# Prime field: BLS12-381 scalar field
p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# Permutation configuration
t = 3          # State size (2 inputs + 1 capacity)
R_F = 8        # Full rounds
R_P = 56       # Partial rounds (optimized for t=3)

#### Sponge Construction

graph LR
    I[Input Blocks] --> S[Sponge<br/>t=3]
    S -->|Absorb| P[Permutation<br/>R_F=8, R_P=56]
    P -->|Squeeze| O[Output<br/>256-bit]
    
    style P fill:#f9f,stroke:#333,stroke-width:2px

### Halo2 Proof System

Utilisation de Halo2 pour :
1. **Rollup validation** : Aggregation of the signatures SLH-DSA
2. **State transitions** : Proofs de transition d'state valides
3. **Recursive composition** : Proof de proof pour scalability infinie

#### Circuit Architecture

graph TD
    A[Transaction Circuit] --> D[Recursive Verifier]
    B[State Circuit] --> D
    C[Signature Circuit<br/>SLH-DSA verification] --> D
    D --> E[Aggregation Circuit]
    E --> F[Endal Proof<br/>~200 bytes]

**Contraintes keys :**
- Lookup tables pour Poseidon2 (optimisation 40% vs hash direct)
- Custom gates pour verification WOTS+ (Winternitz)
- Recursive depth max : 32 niveaux

---

## Identity Layer: MIK

### Merkle Identity Key (MIK)

System de derivation hierarchical post-quantum.

#### Structure

MIK-Tree (