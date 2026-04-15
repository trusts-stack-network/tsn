# Trust Stack Network — Whitepaper Technique v0.1

**Revision** : 0.1.0  
**Date** : 2024-06-XX  
**Auteurs** : Laila.H, Kai.V, dev-crypto-tsn  
**Status** : Draft  

## Table of Contents
1. [Vue d’ensemble](#vue-densemble)  
2. [Architecture modulaire](#architecture-modulaire)  
3. [Layer cryptographic post-quantum](#layer-cryptographic-post-quantum)  
4. [Consensus Nakamoto with proofs MIK](#consensus-nakamoto-avec-proofs-mik)  
5. [Network P2P & synchronisation](#network-p2p--synchronisation)  
6. [Protection of the vie private](#protection-de-la-vie-private)  
7. [Threats post-quantums & contre-mesures](#threats-post-quantums--contre-mesures)  
8. [Roadmap & versions futures](#roadmap--versions-futures)  
9. [References](#references)

---

## Vue d’ensemble

Trust Stack Network (TSN) is une blockkchain of theyer 1 designed pour survivre to the post-quantum era.  
Elle combine :

- **SLH-DSA (FIPS 204)** for blockk signatures and de transactions.  
- **Halo2 + KZG (Plonky2)** for ZK proofs quantum-safe.  
- **Poseidon2** comme primitive de arithmetic hashing.  
- **MIK (Merkle Interval Keeps)** pour replace la proof de travail by ae proof de storage/d’intervalle.  
- **ChaCha20-Poly1305** for the encryption of the payloads network.

Objectives : decentralization, confidentiality optionnelle, low latency (< 3 s), 1 000 tps sur 200 validateurs.

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] -->|RPC| B[API Layer Axum]
    B --> C[Consensus MIK]
    B --> D[Mempool]
    C --> E[Block Builder]
    D --> E
    E --> F[Crypto Service]
    F -->|SLH-DSA| G[Keys]
    F -->|Plonky2| H[Proofs]
    F -->|Poseidon2| I[Hash]
    E --> J[Storage Sled]
    C --> K[P2P Sync]

Each module is librement replaceable (cf. ADR-0003 « Boundaries & Crates »).

---

## Post-Quantum Cryptographic Layer

### 1. Signatures
- **Algorithme** : SLH-SHA2-65s (parameters « e »)  
- **Contexte** : `b"TSN-v0.1-PQ"` (domain-separation)  
- **Randomiser** : RFC 9381 § 4.2 (sig-rnd)  
- **Size clef public** : 32 B  
- **Size signature** : 2 460 B

### 2. Primitives de hachage
| Primitive     | Usage                     | Security (bits PQ) |
|---------------|---------------------------|--------------------|
| Poseidon2     | Commitments, Merkle, ZK | 128                |
| SHA-3-256     | Block headers             | 256                |
| BLAKE3        | Networking checksum       | 256                |

### 3. ZK Proofs
- **Halo2 + KZG** sur BLS12-381 (Plonky2 fork)  
- **Recursion** : 2 levels max (aggregation de 128 tx)  
- **Size proof** : 192 kB (compressed)  
- **Temps generation** : 1.4 s (Apple M3)

---

## Nakamoto Consensus with MIK Proofs

### 1. Rappel MIK
MIK = Merkle Interval Keep  
Un « keep » is un tuple `(C, i, j)` where :
- `C` : racine Poseidon2 d’un arbre binaire de hauteur 30  
- `i, j` : intervalle `[i, j]` de 64 bits

Pour produire a blockkk :
1. The miner prouve possession d’un keep valide sur `[H-Δ, H]`  
2. Il solves un mini-puzzle VDF (verif_delay = 2 s)  
3. Il emits le blockk with proof SLH-DSA

### 2. Difficulty adjustment
next_diff = prev_diff * (target_time / actual_time).sqrt()
Window : 120 blockks, target : 3 s (ADR-0007)

### 3. Fork-choice
- Rule : « MIK-heaviest » = more grand `Σ keep.weight`  
- Pas de slashing ; reorg max 30 blockks (cf. TSN-0002)

---

## P2P Network & synchronisation

### Transport
- QUIC v1 + TLS 1.3 (draft-34)  
- Identity ephemeral : clef X25519 (post-quantum transition)  

### Main Messages
| Type        | Max Payload | Typ. Frequency |
|-------------|-------------|---------------|
| Ping        | 64 B        | 30 s          |
| BlockHeader | 1 kB        | 3 s           |
| BlockBody   | 1 MB        | 3 s           |
| TX          | 2 kB        | random     |

### Fast Synchronization
- Snap-sync : downloads 512 blockks parallels + proof MIK aggregated  
- Verification : 300 ms/blockk (Ryzen 9)

---

## Privacy Protection

### 1. Notes & Commitments
- Note = `(pk, v, ρ, r)`  
- Commit : `Com = Poseidon2(pk∥v∥ρ∥r)`  
- Nullifier : `nf = Poseidon2(ρ∥sk)` prevents la double-depense

### 2. Pool anonyme
- Mix de 16 notes par default (ring-size)  
- Pas de trusted-setup (Halo2)  
- Size tx private : 4.2 kB

### 3. Auditability regulatory
- Vue en clair possible via clef de vue `vk` (diffie-hellman) – cf. TSN-0005

---

## Threats post-quantums & contre-mesures

| Threat                | Impact     | Countermeasure TSN |
|-----------------------|------------|--------------------|
| Shor sur ECDSA        | Signature forged | SLH-DSA (EU-CMA) |
| Grover sur SHA-256    | 128 bits   | Poseidon2 (256 bits) |
| Attack de migration  | Key-harvest | Flag `PQ_MIGRATE_TX` interdit les clefs ECDSA |
| Quantum-networking    | MITM       | Authenticity via SLH-DSA sur each handshake QUIC |

---

## Roadmap & Future Versions

- **v0.2** : migration complete SLH-DSA-44 (plus petit)  
- **v0.3** : rollup ZK natif (Halo2 recursion 3 niveaux)  
- **v0.4** : support hardware wallets Ledger PQ  
- **v1.0** : mainnet stable, audit NCC + TrailOfBits

---

## References

1. TSN-0001 – Poseidon2 Parameter Selection  
2. TSN-0002 – Fork-choice & Reorg Limits  
3. TSN-0003 – SLH-DSA Context & Randomiser  
4. ADR-0003 – Modular Crates Boundaries  
5. FIPS 204 (draft) – Stateless Hash-Based Digital Signature Standard  
6. Plonky2 – Polygon Labs (commit 3f5c1a9)  
7. RFC 9381 – SIG-RND for SLH-DSA  
