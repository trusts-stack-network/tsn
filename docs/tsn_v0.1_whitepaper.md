# TSN (Trustless Secure Network) v0.1 - Technical Whitepaper

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Status:** Draft  
**Classification:** Technical Specification  

## Abstract

TSN is une infrastructure blockkchain post-quantum of theyer 1, integrating of the primitives cryptographics resistantes to quantum computers (SLH-DSA), of the zero-knowledge proofs recursive (Halo2) and une hash function algebraic optimizede (Poseidon2). This document specifies the architecture system, the protocol de consensus hybride, la layer de gestion d'identity modulaire (MIK) and la stack network P2P.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Primitives Cryptographics](#2-primitives-cryptographics)
   - 2.1 [SLH-DSA (SPHINCS+)](#21-slh-dsa-sphincs)
   - 2.2 [Poseidon2](#22-poseidon2)
   - 2.3 [Halo2 ZK Proving System](#23-halo2-zk-proving-system)
3. [Architecture System](#3-architecture-system)
   - 3.1 [Vue d'ensemble](#31-vue-densemble)
   - 3.2 [Structure of the transactions](#32-structure-des-transactions)
   - 3.3 [Model d'state](#33-model-dstate)
4. [MIK - Modular Identity & Key Management](#4-mik---modular-identity--key-management)
5. [Protocole de Consensus](#5-protocole-de-consensus)
6. [Layer P2P](#6-layer-p2p)
7. [Security and Analysis](#7-security-et-analysis)
8. [References](#8-references)

---

## 1. Introduction

TSN solves le problem of the migration post-quantum of the blockkchains existantes en implementing nativement of the signatures hash-based stateless (SLH-DSA) all en now la confidentiality selective via of the zk-SNARKs recursives. The architecture is designed pour resist to the algorithm de Shor and to the algorithm de Grover.

### Objectives de conception

- **Post-Quantum Security**: Resistance to attacks quantiques via SLH-DSA-128f (NIST FIPS 205)
- **Scalability**: Traitement parallel of the transactions via recursive proofs Halo2
- **Interoperability**: Format de transaction compatible with les standards existants (EVM-like)
- **Privacy**: Confidential transactions via circuits zk integrateds

---

## 2. Primitives Cryptographics

### 2.1 SLH-DSA (SPHINCS+)

Implementation compliant to [FIPS 205](https://csrc.nist.gov/projects/post-quantum-cryptography) with les parameters followings :

| Parameter | Valeur | Description |
|-----------|--------|-------------|
| `n` | 16 | Security parameter (128-bit security) |
| `h` | 66 | Height of the hypertree |
| `d` | 22 | Number of layers |
| `a` | 6 | Winternitz parameter |
| `k` | 33 | Number of FORS trees |

**Sizes:**
- Public key : 32 octets
- Private key : 64 octets  
- Signature : 7,856 octets (optimizede via compression WOTS+)

```mermaid
graph TD
    A[Message] -->|SHAKE256| B[M']
    B --> C[FORS Signature]
    C --> D[Hypertree Signature]
    D --> E[Endal Signature<br/>~7.8KB]
    F[SK.seed + PK.seed] --> C
    F --> D

### 2.2 Poseidon2

Hash Function to preimage resistante optimizede for circuits ZK. Parameters TSN :

- **Field**: BLS12-381 scalar field (`p = 0x73eda753...`)
- **S-box**: x⁵ (inversion in le champ premier)
- **Rounds**: 8 full rounds + 57 partial rounds (t = 3)
- **Capability**: 2 elements de field
- **Rate**: 1 element de field

// Pseudo-code of the permutation
fn poseidon2_permutation(state: [Fp; 3]) -> [Fp; 3] {
    // Full S-box layers
    for r in 0..4 {
        state = s_box_full(state);
        state = mds_matrix_mul(state);
        state = add_constants(state, RC[r]);
    }
    // Partial rounds
    for r in 4..60 {
        state[0] = state[0].pow(5); // S-box partiel
        state = mds_matrix_mul(state);
        state = add_constants(state, RC[r]);
    }
    // Endal full rounds
    for r in 60..64 {
        state = s_box_full(state);
        state = mds_matrix_mul(state);
    }
    state
}

### 2.3 Halo2 ZK Proving System

Utilisation of the protocole IPA (Inner Product Argument) on courbes de cycles Pallas/Vesta (cycle de 2-courbes).

**Features:**
- **Courbes**: Pallas (Vesta scalar field) / Vesta (Pallas scalar field)
- **Polynomial Commitment**: IPA (pas de trusted setup required)
- **Lookup arguments**: Tables de lookup pour operations arith