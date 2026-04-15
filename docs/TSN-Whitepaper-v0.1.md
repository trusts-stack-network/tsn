# TSN Protocol v0.1 Technical Whitepaper
## Trustless Secure Network - Post-Quantum Ledger Architecture

**Version:** 0.1.0-alpha  
**Date:** 2024-11  
**Status:** Draft Specification  
**Classification:** Technical Reference

---

## Table of Contents

1. [Executive summary](#1-summary-executive)
2. [Architecture system](#2-architecture-system)
3. [Layer cryptographic](#3-layer-cryptographic)
   - 3.1 [SLH-DSA (FIPS 205)](#31-slh-dsa-fips-205)
   - 3.2 [Poseidon2 Hash Function](#32-poseidon2-hash-function)
4. [Layer Zero-Knowledge](#4-layer-zero-knowledge)
   - 4.1 [Halo2 Proof System](#41-halo2-proof-system)
   - 4.2 [Recursive Composition](#42-recursive-composition)
5. [Protocole de consensus MIK](#5-protocole-de-consensus-mik)
   - 5.1 [Specification of the protocole](#51-specification-du-protocole)
   - 5.2 [State and transitions](#52-state-et-transitions)
6. [Layer network P2P](#6-layer-network-p2p)
7. [Pipeline de transaction](#7-pipeline-de-transaction)
8. [Model de security](#8-model-de-security)
9. [Performances](#9-performances)
10. [References](#10-references)

---

## 1. Executive summary

TSN (Trustless Secure Network) is une infrastructure de ledger distributed resistante to attacks quantiques, combining primitives cryptographics post-quantums (SLH-DSA), zero-knowledge proofs recursive (Halo2), and consensus byzantin tolerant to fautes optimized pour l'state (MIK).

**Fundamental Properties:**
- **Security post-quantum:** Signatures stateful SLH-DSA compliants NIST FIPS 205
- **Scalability horizontale:** Proofs recursive Halo2 without trusted setup
- **Finality fast:** Consensus MIK to finality instant (≤3s)
- **Confidentiality optionnelle:** Circuits ZK pour transactions privates
- **Interoperability:** Compatibility EVM via proofs de validity

---

## 2. Architecture system

The architecture TSN adopte une separation stricte of the layers :

```mermaid
flowchart TB
    subgraph Application["Layer Application"]
        SC[Smart Contracts]
        ZKApp[ZK Applications]
    end
    
    subgraph Execution["Layer Execution (Halo2)"]
        PC[Proof Circuits]
        RV[Recursive Verifier]
        Poseidon[Poseidon2 Hasher]
    end
    
    subgraph Consensus["Layer Consensus (MIK)"]
        BFT[MIK BFT Engine]
        SMR[State Machine Replication]
        SLH[SLH-DSA Signatures]
    end
    
    subgraph Network["Layer Network (P2P)"]
        Gossip[Gossipsub v1.2]
        Noise[Noise Protocol]
        Discovery[mDNS/DHT]
    end
    
    Application -->|Transactions| Execution
    Execution -->|Batch Proofs| Consensus
    Consensus -->|Committed Blocks| Network
    Network -->|Block Propagation| Consensus

**Principes architecturaux:**
1. **Se