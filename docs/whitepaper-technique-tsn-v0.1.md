# TSN Technical Whitepaper v0.1
## Table of Contents
1. [Introduction](#introduction)
2. [Architecture Generale](#architecture-generale)
3. [Cryptographie Post-Quantum](#cryptographie-post-quantum)
    * [SLH-DSA](#slh-dsa)
    * [Halo2](#halo2)
    * [Poseidon2](#poseidon2)
4. [Consensus and Network P2P](#consensus-et-network-p2p)
5. [Mechanisms de Security](#mechanisms-de-security)
6. [References and Specifications](#references-et-specifications)

## Introduction
Le projet Trust Stack Network (TSN) vise to create une blockkchain post-quantum securee and performante. Ce whitepaper technique presents les fondements architecturto and cryptographics de TSN, thus que les mechanisms de consensus and de network peer-to-peer (P2P).

## Architecture Generale
The architecture de TSN is designed pour be modulaire and scalable. Elle se compose de multiple layers :
```mermaid
graph LR
    A[Application] --> B[Network]
    B --> C[Consensus]
    C --> D[Cryptographie]
    D --> E[Storage]
Ces layers travaillent ensemble pour assurer la security, la transparence and l'efficiency of the blockkchain.

## Post-Quantum Cryptography
TSN utilise multiple algorithmes cryptographics post-quantums pour assurer la security of the transactions and of the data.

### SLH-DSA
Le SLH-DSA (Short Lattice-based Hash-based Digital Signature Algorithm) is used for digital signatures. Il offre une security highe contre les attacks quantiques.

### Halo2
Halo2 is un protocole de zero-knowledge proof (ZKP) used for transactions privates. Il permet to utilisateurs de prouver la validity of ae transaction without reveal les details of the transaction.

### Poseidon2
Poseidon2 is un algorithme de cryptographic hashing used for construction de l'Merkle tree. Il offre une security highe contre les attacks de collision.

## Consensus and P2P Network
TSN utilise un algorithme de consensus hybride qui combine les beforeages of the proof de travail (PoW) and of the proof d'enjeu (PoS). Le network P2P is designed pour be decentralized and resilient.

## Security Mechanisms
TSN met en oeuvre multiple mechanisms de security pour protect la blockkchain contre les attacks. Ces mechanisms incluent la cryptographie post-quantum, les proofs to connaissance zero and les mechanisms de detection d'intrusion.

## References and Specifications
Pour more de details on specifications techniques de TSN, veuillez consulter les documents followings :
* [TSN-0001: Specification of the cryptographie post-quantum](docs/tsn-0001.md)
* [TSN-0002: Specification of the consensus and of the network P2P](docs/tsn-0002.md)
Ce whitepaper technique fournit une vue d'ensemble de the architecture and of the mechanisms de security de TSN. Pour more de details, veuillez consulter les specifications techniques and les documents associateds.