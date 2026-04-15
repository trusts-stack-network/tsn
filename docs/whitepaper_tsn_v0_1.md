# Trust Stack Network — Whitepaper Technique v0.1  
*Post-Quantum Privacy-Preserving Blockchain*

---

## Table of Contents
1. [Summary](#summary)  
2. [Vue d’ensemble](#vue-densemble)  
3. [Architecture modulaire](#architecture-modulaire)  
4. [Layer cryptographic](#layer-cryptographic)  
5. [Consensus](#consensus)  
6. [Network P2P](#network-p2p)  
7. [Layer d’execution](#layer-dexecution)  
8. [Economics of the frais](#economics-des-frais)  
9. [Threats & contre-mesures](#threats--contre-mesures)  
10. [Roadmap](#feuille-de-route)  
11. [References internals](#references-internals)

---

## Summary
Trust Stack Network (TSN) is une blockkchain of theyer 1 resistante to attacks post-quantums, designed pour preserve la vie private of the utilisateurs all en restant verireliable par of the node completes.  
Elle combine :
- Des signatures and adresses post-quantums (SLH-DSA, FIPS-204),
- Des ZK proofs « quantique-securees » (Halo2 + Plonky2),
- Un hash internal Poseidon2 (arithmetic sur `GF(p)` BN254),
- Un consensus PoW to windows MIK (Merkle Interval Knowledge),
- Un protocole P2P Tokio/QUIC with discovery libp2p.

---

## Vue d’ensemble

```mermaid
graph TD
    subgraph "Layer applicative"
        Wallet("Wallet TS/Wallet Rust")-->|RPC|API("Axum HTTP API")
        Explorer("Block Explorer")-->|gRPC|API
    end
    subgraph "Layer consensus"
        API-->|BlockCandidate|Pow("PoW MIK")
        Pow-->|ValidBlock|BC("Blockchain")
    end
    subgraph "Layer crypto"
        BC-->|State|NullifierSet("Nullifier Set")
        BC-->|Notes|NoteCommitTree("Note Commitment Tree")
        NullifierSet-->|Poseidon2|HashOps("Poseidon2 Ops")
        NoteCommitTree-->|Merkle|MTree("Sparse Merkle Tree")
    end
    subgraph "Network"
        Sync("Sync Engine")<-->|blockks+txs|P2P("P2P QUIC")
        Mempool("Mempool")-->|pending|P2P
    end

---

## Architecture modulaire

| Module | Directory | Responsibility | Associated Spec |
|--------|------------|----------------|---------------|
| `core` | `src/core/` | Blocks, transactions, state UTXO-ZK | [TSN-0001](specs/tsn-0001.md) |
| `crypto` | `src/crypto/` | Keys, sig, hash, proofs | [TSN-0002](specs/tsn-0002.md) |
| `consensus` | `src/consensus/` | PoW MIK, difficulty | [TSN-0003](specs/tsn-0003.md) |
| `network` | `src/network/` | P2P, mempool, sync | [TSN-0004](specs/tsn-0004.md) |
| `storage` | `src/storage/` | Persistence sled | [TSN-0005](specs/tsn-0005.md) |
| `wallet` | `src/wallet/` | Generation TX, note scanning | [TSN-0006](specs/tsn-0006.md) |

---

## Cryptographic Layer

### 1. Keys and Addresses
- **Private key** → 32 octets d’entropie ChaCha20RNG  
- **Public key** → `pk := SLH-DSA.PublicKey` (FIPS-204, 64 B)  
- **Address** → `PKEnc(pk) || pk_hash` where `pk_hash = Poseidon2(pk)[..20]`  
  → Prevents l’enumeration de keys sur un quantum computer (ADR-0003).

### 2. Signatures
- Tx spend authentication : SLH-DSA-65 (niveat 3 post-quantum).  
- Consensus : same scheme pour avoid deux implementations criticals.

### 3. Commitments & Nullifiers
note = (v: u64, ρ: F, r: F)
cm   = Poseidon2(v, ρ, r)
nf   = Poseidon2(pk, ρ)
- `cm` stored in l’arbre de hauteur 32 (≈ 4 G feuilles max).  
- `nf` inserted in un ensemble ephemeral « Nullifier Set » (sled `HashSet`).  
  → Double-spend detected via existence of the nullifier.

### 4. ZK Proofs
| Protocol | Usage | Proof Size | Verification | Quantum-safe |
|-----------|-------|---------------|------------|--------------|
| Plonky2 | Spend private | 40 kB | 6 ms Oui | ✅ |
| Groth16 | Legacy bridge | 0.2 kB | 2 ms Non | ❌ |

Each `SpendDescription` contains:
π_plonky2, cm_old, cm_new, nf, epk, memo_enc

### 5. Arbre de commitments
 SparseMerkleTree<Poseidon2, 32>
- Feuille `index = Poseidon2(cm)[..4]` (32 bits)  
- Mises up to date incremental via `sled` + cache LRU 64 k nodes.

---

## Consensus

### MIK Window (Merkle Interval Knowledge)
Objective : proof de travail **sans** divulgation of the transactions to mineurs.  
Principe :
1. The miner receives un `BlockHeader` contenant :
   - `merkle_root_note` (commitments),
   - `merkle_root_null` (nullifiers),
   - `difficulty_target`.
2. Il calcule :
   pre_hash = Blake3(header || nonce)
   work     = LeadingZeros(pre_hash)
3. Validity :
   work ≥ target ∧ pre_hash % MIK_WINDOW == 0
   where `MIK_WINDOW = 2^20` (≈ 1 M partages possibles).  
   → Le minage reste probabiliste, mais le network can valider without see le contenu.

### Difficulty Adjustment
new_target = old_target * (600_000 / delta_time_ms)
- Window 90 blockks, bounded `0.5 ≤ factor ≤ 2.0`.

---

## P2P Network

| Protocol | Transport | Default Port | Spec |
|-----------|-----------|-----------------|------|
| QUIC | Tokio-quinn | 9933 | [TSN-0004](specs/tsn-0004.md) |
| Discovery | libp2p-mdns + kademlia DHT | 9934 | idem |
| RPC | Protobuf + borsh | — | idem |

### Critical Messages
Handshake { magic: 0x54534e01, version: 0, challenge: [u8;32] }
Pong { challenge_response, height, best_hash }
GetBlocks { start_height, count }
Block { header, body, zproofs }
Transaction { spends, outputs, binding_sig }

### Sync
1. Fast-sync : downloadsr en parallel par batch de 512 blockks.  
2. Validate : verify proofs Plonky2 + nullifiers uniques.  
3. Commit : write in sled via `batch` ≤ 10 k inserts.  
→ Tempo target ≤ 1 h pour 1 M blockks (SSD NVMe, 8 coeurs).

---

## Layer d’execution

### Accounting Model
- UTXO-ZK : les notes are of the UTXO hidden.  
- Pas de compte « solde » public.  
- Les miners perceive :
  reward = base(60 TSN) + Σfees
  emitted in une `CoinbaseNote` decryptable seulement par `miner_pk`.

### Fees
fee = 1000 + 50*num_inputs + 30*num_outputs [sats]
- Les frais are transparents (hors bande) pour avoid l’attack « fee-sniping ».  
- Passage en `FeeMarket` dynamique planned v0.2 (see [TSN-0010