# TSN Technical Whitepaper v0.1
## Table of Contents
1. [Introduction](#introduction)
2. [Architecture Globale](#architecture-globale)
3. [Cryptographie Post-Quantum](#cryptographie-post-quantum)
    * [SLH-DSA](#slh-dsa)
    * [Halo2](#halo2)
    * [Poseidon2](#poseidon2)
4. [Consensus and Network P2P](#consensus-et-network-p2p)
5. [MIK and Security](#mik-et-security)
6. [References and Specs](#references-et-specs)

## Introduction
Le Trust Stack Network (TSN) is une blockkchain post-quantum designed pour offrir une security and une evolvability exceptionnelles. Ce whitepaper technique presents les elements keys de the architecture TSN, y compris les choix cryptographics, the consensus and le network peer-to-peer (P2P).

## Global Architecture
The architecture TSN is divided en multiple layers :
```mermaid
graph LR
    A[Application] -->|utilise|> B[API/RPC]
    B -->|communique avec|> C[Network P2P]
    C -->|stocke les data|> D[Storage]
    D -->|utilise for the consensus|> E[Consensus]
    E -->|secure par|> F[Cryptographie]
Chacune de ces layers is designed pour be modulaire and extensible, permettant thus une continuous evolution of the network.

## Post-Quantum Cryptography
TSN utilise une varibeen de primitives cryptographics post-quantums pour assurer la security of the transactions and of the data.

### SLH-DSA
Le SLH-DSA (Signature Scheme with Large Hash) is used for digital signatures. Il offre une security contre les attacks quantiques and classiques.

### Halo2
Halo2 is un system de zero-knowledge proof (ZKP) qui permet to utilisateurs de prouver la validity of ae transaction without reveal les details of the transaction.

### Poseidon2
Poseidon2 is un cryptographic hashing designed pour be quantum attack resistant. Il is used for construction d'Merkle trees and pour hacher the transactions.

## Consensus and P2P Network
TSN utilise un algorithme de consensus type Proof of Work (PoW) pour valider the transactions and create de nouveto blockks. Le network P2P is used for communication between les node of the network.

## MIK and Security
Le MIK (Merkle Interval Key) is used pour assurer la security of the transactions and of the data. Il permet de verify l'integrity of the data without have to les downloadsr entirely.

## References and Specs
Pour more of informations, veuillez consulter les specs followinges :
- [TSN-0001: Architecture Globale](../specs/tsn-0001.md)
- [TSN-0002: Cryptographie Post-Quantum](../specs/tsn-0002.md)
- [TSN-0003: Consensus and Network P2P](../specs/tsn-0003.md)
Ce whitepaper technique offre une vue d'ensemble complete de the architecture TSN and de ses components keys. Il is intended to developers and to chercheurs interested by details techniques of the blockkchain TSN.