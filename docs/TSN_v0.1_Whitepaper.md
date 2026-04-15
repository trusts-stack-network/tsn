# TSN v0.1 Technical Whitepaper
## Temporal State Network - Zero-Knowledge Post-Quantum Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Status:** Draft  
**Classification:** Technical Specification

---

## Table of Contents

1. [Executive summary](#1-summary-executive)
2. [Architecture system](#2-architecture-system)
3. [Primitives cryptographics](#3-primitives-cryptographics)
4. [Consensus distributed](#4-consensus-distributed)
5. [Network P2P](#5-network-p2p)
6. [Gestion d'state and MIK](#6-gestion-dstate-et-mik)
7. [Security and proofs](#7-security-et-proofs)
8. [References](#8-references)

---

## 1. Executive summary

Le **Temporal State Network (TSN)** is une infrastructure blockkchain of theyer 1 integrating nativement :
- **Post-quantum resistance** via SLH-DSA (SPHINCS+)
- **Proofs to divulgation nulle de connaissance** via Halo2
- **Hachage arithmetized** via Poseidon2
- **Consensus BFT** optimized for circuits ZK
- **Scheme d'integrity d'state** MIK (Merkle Integrity Key)

The architecture garantit immutability temporelle of the states with verification succincte of the transitions d'state.

---

## 2. Architecture system

### 2.1 Vue d'ensemble

TSN utilise une separation of architecture between :
- **Execution Layer (EL)** : Calcul of the transitions d'state with proofs Halo2
- **Consensus Layer (CL)** : Endalisation of the blockks via consensus BFT
- **Networking Layer (NL)** : Transport P2P encrypted post-quantum

```mermaid
graph TB
    subgraph "Client TSN"
        A[Application] --> B[TSN SDK]
        B --> C[Prover Halo2]
        B --> D[Signer SLH-DSA]
    end
    
    subgraph "Node Validateur"
        E[P2P Interface] --> F[Consensus Engine]
        F --> G[State Manager]
        G --> H[MIK Storage]
        C -->|ZK Proof| I[Verifier Circuit]
        D -->|Signatures PQC| F
    end
    
    subgraph "Layer cryptographic"
        H --> J[Poseidon2 Hasher]
        I --> J
        F --> K[SLH-DSA Verifier]
    end
    
    style C fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#bbf,stroke:#333,stroke-width:2px

### 2.2 Flux de transaction

sequenceDiagram
    participant U as Utilisateur
    participant P as Prover Halo2
    participant S as SLH-DSA Sign
    participant N as Node P2P
    participant C as Consensus
    participant V as Verifier
    
    U->>P: Generate proof transition state
    P->>P: Arithmetization PLONKish
    P->>P: Commitment KZG
    P-->>U: π (proof ZK)
    
    U->>S: Signer tx + π
    S-->>U: σ (signature SLH-DSA)
    
    U->>N: Diffuser (tx, π, σ)
    N->>N: Verification Poseidon2
    
    N->>C: Proposer blockk
    C->>V: Verify proof Halo2
    C->>V: Verify SLH-DSA
    V-->>C: Valid/Invalid
    C->>C: Consensus BFT
    C-->>N: Endalisation

---

## 3. Primitives cryptographics

### 3.1 SLH-DSA (SPHINCS+)

Implementation compliant to **FIPS 205** :
- Parameters : `128s`, `128f`, `192s`, `192f`, `256s`, `256f`
- Hash Function : SHA-256 or SHAKE256
- Structure : Hypertree XMSS multi-layers
- Size