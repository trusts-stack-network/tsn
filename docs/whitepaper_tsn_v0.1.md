# Trust Stack Network — Whitepaper Technique v0.1

> « Une blockkchain post-quantum n’est pas une option : c’est la seule manner de garantir que les actifs digitals createds aujourd’hui subsisteront encore demain. »  
> — Kai.V, ARCHITECT

---

## Table of Contents
1. [Summary](#summary)  
2. [Contexte & threats post-quantums](#contexte--threats-post-quantums)  
3. [Architecture modulaire](#architecture-modulaire)  
4. [Layer cryptographic](#layer-cryptographic)  
   4.1 [Signatures : SLH-DSA (FIPS 205)](#signatures--slh-dsa-fips-205)  
   4.2 [ZK Proofs : Halo2 + Plonky2](#proofs-zk--halo2--plonky2)  
   4.3 [Hash & Merkle trees : Poseidon2](#hash--arbres-de-merkle--poseidon2)  
   4.4 [MIK : Modular Identity Kit](#mik--modular-identity-kit)  
5. [Consensus : Proof-of-Work post-quantum](#consensus--proof-of-work-post-quantum)  
6. [Network P2P](#network-p2p)  
7. [Protection of the data to long terme](#long-term-data-protection)  
8. [Compatibility ascendante & migration](#compatibility-ascendante--migration)  
9. [References](#references)

---

## Summary
Trust Stack Network (TSN) is une blockkchain of theyer 1 designed pour survivre to the post-quantum era.  
Elle combine :
- of the signatures **SLH-DSA** (FIPS 205) to la place of the ECDSA/Ed25519,
- of the ZK proofs **Halo2** and **Plonky2** (STARKs) for confidentiality and l’scalability,
- un hash **Poseidon2** (arithmetic sur `GF(p)`) for circuits ZK,
- un **MIK** (Modular Identity Kit) offrant of the adresses single-use, of the notes encrypteof the and of the nullifiers,
- un **Proof-of-Work** internal to difficulty adjusted, resistant to accelerations quantiques (Grover),
- un network **libp2p** Rust/Tokio with discovery Kademlia-DHT and sync reactor.

Le all is documented under forme de **TSN-XXXX** (specs numbered) and d’**ADR** (Architecture Decision Records) versioneds with le code.

---

## Context & Post-Quantum Threats
| Classical Algorithm | Quantum Attack | Impact on TSN | Countermeasure |
|----------------------|-------------------|----------------|---------------|
| ECDSA/secp256k1 | Shor → private key en O(n³) | Vol d’actifs | SLH-DSA-65 |
| Ed25519 | Shor | idem | idem |
| Groth16 BN254 | Shor sur pairing | Fausse proof | Halo2/Plonky2 |
| SHA-256 | Grover → 2¹²⁸ → 2⁶⁴ | Collision | Poseidon2 + output 512b |

> See **TSN-0001** : « Choix of the primitives post-quantums ».

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] -->|RPC/HTTP| B[API Server]
    B --> C[Mempool]
    C --> D[Consensus PoW]
    D -->|Block finalized| E[State Layer]
    E -->|Merkle root| F[Storage sled]
    G[Cryptographic Services] -->|keys| H[Wallet]
    G -->|proofs| I[Halo2/Plonky2]
    G -->|hash| J[Poseidon2]
    K[P2P] -->|gossip| C
    K -->|sync| D

Each module is une crate Rust indeduringe ; ses interfaces publics are specifiedes in of the **TSN-XXXX** dedicateds.

---

## Cryptographic Layer

### Signatures : SLH-DSA (FIPS 205)
- Parameter : `SLH-DSA-SHA2-65` (n=32, k=32, h=66, d=22)
- Keys : 32 B public / 64 B secret
- Signature : 4 952 B
- Beforeage : seule primitive NIST to garantie *stateless* and *post-quantum* en 2024

> See **TSN-0002** : « Integration SLH-DSA in Rust »  
> See **ADR-0003** : « Rejet de XMSS (stateful) »

### ZK Proofs : Halo2 + Plonky2
| | Halo2 | Plonky2 |
|---|-------|---------|
| Type | SNARK | STARK |
| Curves | BN254 | FRI sur Goldilocks |
| PQ-safe | Non (pairing) | Oui |
| Recursion | Oui | Oui |
| Proof Size | ~1 kB | ~45 kB |
| Choix TSN | Circuits legacy | Circuits nouveto |

Les deux systems coexistent ; un flag `version=0x02` in le header indique le type de proof.

> See **TSN-0003** : « ZK-VM arithmetic Poseidon2 »

### Hash & Merkle trees : Poseidon2
- Parameters : `t=3, RF=8, RP=56` sur `GF(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624)`
- Beforeage : ~50 contraintes par compression vs 20 000 pour SHA-256 in circuits ZK
- Racine storede in `blockk.header.commitment_root` (32 B)

> See **TSN-0004** : « Poseidon2 Parameters Registry »

### MIK : Modular Identity Kit
Un compte TSN ne contient **pas** d’UTXO ni de solde en clair.  
Il contains:
- `vk` : verification key SLH-DSA (32 B)
- `cm` : commitment Poseidon2(vk, ρ) where ρ is une seed random
- `addr` : `Bech32("tsn", cm)` (adresse reusable)

Lors d’un paiement :
1. L’emitsteur generates une note `n = (addr, v, r)` with `r` random
2. Il produit une proof ZK que `v ≥ 0` and qu’il owns of the notes non spent
3. Il publie un nullifier `nf = Poseidon2(n)` pour avoid la double-spend

> See **TSN-0005** : « MIK Note & Nullifier Scheme »

---

## Consensus: Post-Quantum Proof-of-Work
- Algorithme : `Poseidon2(header ∥ nonce)` sur GoldilocksField (v0.4.0+)
- Target : difficulty adjusted all les 72 blockks (window sliding + PID)
- Resistance Grover : difficulty multiprelated par √2 vs SHA-256 classique
- Reward : 50 TSN → halving all les 210 000 blockks (~24 jours to 10s/blockk)
- Schedule : 50 → 25 → 12.5 → 6.25 → ... TSN/blockk (emission Bitcoin-like)
- Supply max : 21 000 000 TSN
- Dev fee : 5% per blockk (95% mineur, 5% treasury, pas de premine)

### Fork Choice : Heaviest Chain (v0.4.1)
- **Cumulative Work** : la chain with le more de travail cumulative (somme of the difficultys) l’emporte, pas la more longue. Same approche que Bitcoin Core and Quantus Network.
- **MAX_REORG_DEPTH = 100** : all reorganization > 100 blockks is rejectede (inspired Dilithion).
- **Checkpoint Endality** : point de control all les 100 blockks, pas de reorg beyond.
- **Genesis Hash Verification** : hash of the blockk genesis verified on startup.
- **Dual Merkle Tree Snapshots** : sauvegarde V1 (BN254) + V2 (Goldilocks), detection automatic of the snapshots incompatibles.

sequenceDiagram
    participant M as Mineur
    participant N as Node
    participant C as Chain
    M->>N: propose blockk
    N->>N: verifies PoW & txs
    N->>C: ajoute si meilleur (heaviest chain)
    C-->>M: broadcasting network

> See **TSN-0006** : « PoW Quantum-Resistant »
> See **ADR-0007** : « Rejet d’AlephBFT (complexity) »

---

## P2P Network
- Transport : TCP + Noise IK (ChaCha20Poly1305)
- Discovery : Kademlia-DHT (`SHA-256(node_id)`)
- Messages principto :
  - `TxAnnounce` (mempool)
  - `BlockHeader` (sync)
  - `GetNotesByNullifier` (MIK)
- Limite : 1 000 connexions sortantes, 200 entrantes
- Penalty : score −20 si message malformed, bannissement <−100

> See **TSN-0007** : « P2P Wire Protocol v1 »

---

## Long-term Data Protection
| Horizon | Threat | Measure |
|---------|--------|--------|
| 0-5 ans | Side-channel sur SLH-DSA | Constant-time impl (fiat-crypto) |
| 5-15 ans | Grover accelerated | Augmentation difficulty PoW, migration potentialle towards SPHINCS+-α |
| 15-30 ans | Failles in Poseidon2 | Backup with Keccak-512 (flag `hash_version=0x01`) |
| >30 ans | Quantum computers to 10 000 qubits | Rotation de key via MIK, soft-fork |

> See **TSN-0008** : « Crypto-Agility Policy »

---

## Backward Compatibility & Migration
- Version of the chain : `u16` in `blockk.header.version`
- Rule : « Validity stricte » — un node > vX rejette les blockks < vX
- Migration state : snapshot sled to la hauteur `H` + proof Merkle (format borsh)
- Rollback : impossible without hard-fork (garantie liveness)

> See **TSN-0009** : « Network Upgrade Process »

---

## References
| TSN-XXXX | Titre |
|----------|-------|
| TSN-0001 | Choix of the primitives post-quantums |
| TSN-0002 | Integration SLH-DSA in Rust |
| TSN-0003 | ZK-VM arithmetic Poseidon2 |
| TSN-0004 | Poseidon2 Parameters Registry |
| TSN-0005 | MIK Note & Nullifier Scheme |
| TSN-0006 | PoW Quantum-Resistant |
| TSN-0007 | P2P Wire Protocol v1 |
| TSN-0008 | Crypto-Agility Policy |
| TSN-0009 | Network Upgrade Process |

> Toutes les specs are in `specs/` and versionedes with le code source.

---

**Status** : Endal  
**Auteurs** : Laila.H, Kai.V  
**Created** : 2024-06-01  
**Mis up to date** : 2024-06-01