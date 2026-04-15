# Trust Stack Network v0.1 — Whitepaper Technique

> “Post-quantum, ZK-native, scalable : la blockkchain of the confiance distributede”

---

## Table of Contents
1. [Vue d’ensemble](#vue-densemble)  
2. [Architecture modulaire](#architecture-modulaire)  
3. [Layer cryptographic post-quantum](#layer-cryptographic-post-quantum)  
4. [Consensus Proof-of-Work adaptatif](#consensus-proof-of-work-adaptatif)  
5. [Network peer-to-peer](#network-peer-to-peer)  
6. [Layer d’execution and MIK-VM](#layer-dexecution-et-mik-vm)  
7. [Protection de vie private](#protection-de-vie-private)  
8. [Scalability and sharding](#scalability-et-sharding)  
9. [References](#references)  

---

## Vue d’ensemble

Trust Stack Network (TSN) is une blockkchain of theyer 1 post-quantum designed pour offrir security, confidentiality and scalability native.  
Elle combine :

- **SLH-DSA (FIPS 204)** : digital signature resistante to attacks quantiques.  
- **Halo2** : ZK proofs recursive without setup trust.  
- **Poseidon2** : hash arithmetic optimized for circuits ZK.  
- **MIK-VM** : machine virtuelle instruction-set zero-knowledge.  
- **PoW adaptatif** : consensus set en temps real, ASIC-resistant.  

Objectives :  
- Security post-quantum from le genesis.  
- Confidentiality opt-in par default.  
- Latency < 1 s, throughput > 5 k tx/s sur shard unique.  

---

## Architecture modulaire

```mermaid
graph TD
    A[Application] --> B[RPC/REST]
    B --> C[MIK-VM]
    C --> D[Halo2 ZK]
    D --> E[Poseidon2 Hash]
    E --> F[SLH-DSA Sig]
    F --> G[Ledger Sled]
    G --> H[P2P Layer]
    H --> I[PoW Consensus]

Modules keys :  
| Module | Crate | Responsibility | Spec |
|--------|-------|----------------|--------|
| `tsn_crypto` | `src/crypto` | Keys, signatures, commitments | TSN-0001 |
| `tsn_consensus` | `src/consensus` | PoW + difficulty | TSN-0002 |
| `tsn_network` | `src/network` | Discovery, mempool, sync | TSN-0003 |
| `tsn_vm` | `src/vm` | MIK-VM & circuits | TSN-0004 |
| `tsn_storage` | `src/storage` | Sled persistence | TSN-0005 |

---

## Post-Quantum Cryptographic Layer

### 1. Signatures : SLH-DSA-65 (FIPS 204)

- `PublicKey = 32 B`, `SecretKey = 64 B`, `Sig = 2 459 B`.  
- None state de session → parallelization totale.  
- Randomiser le message with ChaCha20Rng (avoids les collisions multi-utilisateurs).  

### 2. Commits & Merkle

pub struct Commitment([u8; 32]); // Output Poseidon2

- Arbre de hauteur 32 → 4 G feuilles.  
- Feuille = `hash(addr ∥ amount ∥ blinding)`.  
- Root stored in `BlockHeader::commitment_root`.  

### 3. Nullifiers & Vie private

See [TSN-0006](specs/TSN-0006-nullifier-privacy.md) for the scheme anonymous-spending.

---

## Adaptive Proof-of-Work Consensus

### Algorithme : SHA-3-512 (Keccak) sur header

struct BlockHeader {
    prev: Hash,
    height: u64,
    timestamp: u64,
    target: u32,
    commitment_root: Hash,
    sig: SLHSignature,
}

### Difficulty Adjustment (ADR-0003)

- Window sliding de 60 blockks.  
- Target : 1 blockk / 5 s.  
- Formule :  
  next_target = prev_target * (ΔT_ideal / ΔT_real)

### Validity Rules

1. `timestamp > median(last 11) && < now + 2 h`.  
2. `hash(header) ≤ target`.  
3. Signature SLH-DSA valide sur hash.  

---

## Peer-to-Peer Network

sequenceDiagram
    participant N1 as Node-1
    participant N2 as Node-2
    N1->>N2: Ping(nonce, height)
    N2->>N1: Pong(nonce, height)
    N1->>N2: GetBlocks(from,height)
    N2->>N1: Blocks([Block])

- Transport : QUIC + Noise IK.  
- Discovery : Kademlia-like (Node-ID = hash(pubkey)).  
- Mempool : CRDT set, max 50 k tx.  
- Sync : Fast-Sync + Header-First + State-Sync (zk-proof).  

---

## Layer d’execution and MIK-VM

### Minimal Instruction Set

| Opcode | Description | Circuit |
|--------|-------------|---------|
| `TRANSFER` | envoi UTXO | Halo2 |
| `CALL` | appel contrat | Halo2 |
| `RET` | retourne valeur | Halo2 |

### Circuit Compilation

1. ASM MIK → AST.  
2. AST → contraintes Halo2 (custom gates).  
3. Proof generated side client, verified en 3 ms (Intel i7).  

### Gas & Fees

- Prix fixe par instruction (table TSN-0004).  
- Fees burned → rendre le token deflationary.  

---

## Privacy Protection

1. **UTXO anonyme** : commitments hidden, nullifiers uniques.  
2. **View-key** : partage opt-in de key de read.  
3. **Pool unified** : all les tx passent by the same contrat shielded → avoids les “anonymity set” fractioned.  
4. **Rapport d’audit** : cf. [ADR-0007](specs/ADR-0007-privacy-tradeoffs.md).

---

## Scalability and Sharding

### Phase 0 (actuelle)

- Shard unique : ~5 k tx/s.  
- State ~50 GB/an.  

### Phase 1 (v0.2)

- 64 shards, assignation par `account[0..6 bits]`.  
- Cross-shard : zk-rollup internal, confirmation 12 s.  
- Security : histogramme de rand. beacon + VDF.  

### Phase 2 (v0.3)

- Data-availability sampling (DAS) via Reed-Solomon.  
- Recursive proofs : 1 proof = N shards.  

---

## References

- FIPS 204 : *Sloth-Half-Domain Signature Standard*, NIST, 2024.  
- Bowe and al. : *Halo : Recursive Proof Composition*, 2019.  
- Grassi and al. : *Poseidon2 : A Faster Hash Function*, 2023.  
- TSN Improvement Proposals : [specs/](specs/)  
- Code source : [src/](src/)

---

> Status : Endal pour v0.1  
> Auteurs : Laila.H, Kai.V, J. Smith  
> Last updated : 2024-06-XX