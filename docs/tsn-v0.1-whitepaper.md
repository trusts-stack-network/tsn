# TSN Protocol v0.1 - Whitepaper Technique

**Post-Quantum Secure Ledger with Recursive ZK-Proofs**

*Date: 2024*  
*Version: 0.1.0-draft*  
*Classification: Technical Specification*

---

## Table of Contents

1. [Executive Summary](#1-summary-executive)
2. [Architecture Globale](#2-architecture-globale)
3. [Layer Cryptographic](#3-layer-cryptographic)
   - 3.1 [SLH-DSA (SPHINCS+)](#31-slh-dsa-sphincs)
   - 3.2 [Halo2 Proving System](#32-halo2-proving-system)
   - 3.3 [Poseidon2 Hash Function](#33-poseidon2-hash-function)
   - 3.4 [MIK - Multi-Identity Key Management](#34-mik---multi-identity-key-management)
4. [Consensus Protocol](#4-consensus-protocol)
5. [Layer Network P2P](#5-layer-network-p2p)
6. [Format of the Transactions](#6-format-des-transactions)
7. [Circuit Halo2 pour TSN](#7-circuit-halo2-pour-tsn)
8. [Considerations de Security](#8-considerations-de-security)
9. [References](#9-references)

---

## 1. Executive Summary

TSN (Trustless Secure Network) v0.1 is un ledger distributed quantum attack resistant, combining of the post-quantum signatures SLH-DSA (SPHINCS+) with of the zero-knowledge proofs recursive via Halo2. The architecture integrates une hash function arithmetizede Poseidon2 optimizede for circuits ZK and un system de gestion d'identitys hierarchicals MIK (Multi-Instance Key).

**Key Features:**
- Security post-quantum (NIST Level 1-5)
- Proofs recursive without trusted setup (Halo2)
- Finality fast (< 3s) via consensus BFT optimized
- Bande passante reduced thanks to la compression ZK

---

## 2. Global Architecture

```mermaid
graph TB
    subgraph "Application Layer"
        APP[Client TSN]
    end
    
    subgraph "Cryptographic Core"
        SLH[SLH-DSA<br/>FIPS 205]
        MIK[MIK Manager<br/>HKDF-SLH]
        HALO[Halo2 Prover<br/>Recursive]
    end
    
    subgraph "Consensus Layer"
        HOT[HotStuff-BFT<br/>Optimized]
        POS[Poseidon2<br/>Merkle Trees]
    end
    
    subgraph "Network Layer"
        P2P[Libp2p<br/>Noise + TLS 1.3]
        GOS[GossipSub<br/>Flood Publishing]
    end
    
    APP -->|Sign TX| SLH
    SLH -->|PubKey| MIK
    MIK -->|Derived Keys| HALO
    HALO -->|ZK-Proof| HOT
    HOT -->|Block Hash| POS
    POS -->|Root| P2P
    P2P -->|Broadcast| GOS

---

## 3. Layer Cryptographic

### 3.1 SLH-DSA (SPHINCS+)

**Specification:** NIST FIPS 205 (August 2024)

TSN utilise SLH-DSA-SHA2-128s for transaction signatures and SLH-DSA-SHAKE-256s for blockk signatures (haute valeur).

**Parameters:**
| Parameter | Valeur | Security | Signature Size |
|-----------|--------|----------|------------------|
| n | 16 | 128-bit | 7.8 KB |
| h | 63 | - | - |
| d | 7 | - | - |
| a | 12 | - | - |
| k | 14 | - | - |

**Implementation:**
- WOTS+ pour signatures single-use
- FORS (Forest of Random Subsets) pour l'state stateless
- SHA2-256/SHAKE256 comme PRF and H

// Pseudo-code de signature TSN
fn sign_tx(sk: SlhDsaPrivateKey, tx: Transaction) -> Signature {
    let ctx = b"TSN-v0.1-context";
    slh_dsa_sign(sk, tx.hash(), ctx, Randomness::Deterministic)
}

### 3.2 Halo2 Proving System

**Specification:** Zcash Halo2 (IPA-based, KZG variant supported)

TSN utilise Halo2 pour prouver la validity of the transitions d'state without reveal les inputs.

**Configuration Circuit :**
- **Curve :** Pasta curves (Pallas/Vesta) or BLS12-381 (avec KZG)
- **Lookup tables :** 2^20 rows max
- **Constraints degree :** 5
- **Recursion :** Accumulation scheme (Nova-compatible)

**Proof Recursive :**
Each blockk contient une proof $\pi_n$ qui verifies la proof $\pi_{n-1}$ more les news transactions.

$$\pi_n = \text{Prove}(C_{TSN}, (st_n, tx_n, \pi_{n-1}))$$

Where $C_{TSN}$ is le circuit described in la section 7.

### 3.3 Poseidon2 Hash Function

**Specification:** Poseidon2 (2023) - improvement de Poseidon with less de contraintes R1CS.

**TSN Parameters:**
- **Field :** $\mathbb{F}_p$ (Pallas