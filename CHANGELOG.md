# TSN Changelog

All notable changes to Trust Stack Network are documented here.

---

## [2.9.15] — 2026-05-02

### Changed
- `MINIMUM_VERSION` bumped to `2.9.15` — nodes below this version are rejected at handshake
- Full English-only codebase: all French strings, comments and doc-strings replaced

### Removed
- Stray file with invalid name (`pow.rs et block.rs`) containing only placeholder comments

---

## [2.9.14] — 2026-05-01

### Fixed
- Backport W1 + W1B + H-G + FIX-D stability patches
- Auto-recovery timeout extended to 180s to handle slow-sync seeds

---

## [2.9.13] — 2026-05-01

### Changed
- `--role` flag defaults to `relay` when role cannot be detected from binary name
- Full auto-recovery cycle triggered on lost consensus

---

## [2.9.11 / 2.9.10 / 2.9.9] — 2026-04-30

### Added
- Background backfill of historical blocks missing after fast-sync
- Descending walk so seeds catch up to the chain tip
- `[0u8;32]` placeholder entries treated as missing (triggers re-fetch)

---

## [2.9.8] — 2026-04-29

### Changed
- `CHECKPOINT_QUORUM` dynamic 80% with warmup
- Plonky3 circuit warm-up limited to common shapes to prevent RAM exhaustion

---

## [2.9.7] — 2026-04-28

### Added
- Persistent libp2p identity key (survives restarts)
- `network_name` field in `/version.json`
- Checkpoint history endpoint `/chain/checkpoint_history`
- Phase C HTTP fallback for block relay

---

## [2.9.6 / 2.9.5 / 2.9.3] — 2026-04-27

### Fixed
- `checkpoint_vote`: anchor candidate scan starts at `fast_sync_base`
- Shallow fallback window for post-fast-sync transition
- Snapshot always published on checkpoint tick

---

## [2.9.2] — 2026-04-26

### Changed
- `CHECKPOINT_QUORUM` raised to 4 (was 3)

### Added
- `/chain/quorum_status` endpoint
- Explorer quorum halo badge

---

## [2.9.1] — 2026-04-25

### Changed
- Sled cache: 1 GB → 256 MB
- Block LRU: 1,000 → 200 entries
- Fast-sync anchor recomputed on load

### Fixed
- Anchor-retry timeout prevents infinite block fetch loop

---

## [2.9.0] — 2026-04-24

### Fixed
- BIP-152 RAM fix: filter mempool by short_id before cloning full transactions

---

## [2.8.9] — 2026-04-23

### Added
- Trusted-quorum checkpoint vote (4+ seeds must agree every 100 blocks)

### Changed
- BIP-152 DoS protections: max announces per peer, dedup window, rate limit

---

## [2.8.8] — 2026-04-22

### Fixed
- Invalid anchor retry with exponential backoff (Phase 1 hardening)

---

## [2.8.7] — 2026-04-21

### Added
- Full **Compact Block Relay** (BIP-152 inspired)
  - `cmpctblock` / `getblocktxn` / `blocktxn` message types
  - Short IDs via SipHash-2-4 keyed on nonce + block hash
  - Mempool-based transaction reconstruction (avoids redundant transfers)
  - Up to 98% bandwidth savings on well-connected peers

---

## [2.8.6] — 2026-04-20

### Changed
- Proactive tip-pull: nodes pull latest tip on GossipSub announcement (Phase 0.2)

---

## [2.8.5] — 2026-04-19

### Added
- **Iron Fish wallet integration** (BIP44 derivation path `m/44'/990'/0'/0/i`)
- **Anchored mempool**: transactions anchored to a recent block hash to prevent replays after reorgs

### Fixed
- Cumulative work drift: recalculates `cumulative_work` from DB on snapshot import

---

## [2.8.1] — 2026-04-18

### Fixed
- Phase A pipeline fixes (block relay ordering)
- `MAX_SPENDS` raised from 25 to 50

---

## [2.8.0] — 2026-04-17

### Added
- Phase C wallet bootstrap
- Signed fast-sync snapshot (Ed25519)
- Auto-consolidate wallet notes ON by default

---

## [2.7.4] — 2026-04-16

### Fixed
- Anti-freeze HTTP timeouts on RPC calls during high load
- Lock-free chain reads (reduces contention on the canonical tip)
- Explorer aggregate block stats fixes

---

## [2.5.0] — 2026-04-14

### Added
- **Cortex node** Phase 1: WASM runtime for dApp service modules (NetherSwap, Whispr, ZST)
  - Fees come from dApps, NOT coinbase
  - `./tsn cortex` — new node role
- 4 fork-choice fixes improving convergence on testnet

### Changed
- Testnet-v9 reset with fresh genesis

---

## [2.4.3] — 2026-04-13

### Added
- `wallet-cleanup` command: removes spent/orphaned notes
- `/leaves/bulk` endpoint for wallet pre-validation batch fetch
- Testnet-v8 reset

### Changed
- `balance` command shows spendable notes only (excludes locked/unconfirmed)

### Fixed
- `calculate_chain_work` fast-path verifies parent is canonical
- Seed PeerID dedup in peer info tracking (key on libp2p PeerID)
- Persist `cumulative_work` in DB on snapshot import + recompute

---

## [2.4.2] — 2026-04-12

### Changed
- Testnet-v7 reset (private test build, not shipped externally)

---

## [2.4.1] — 2026-04-11

### Added
- DNS-aware P2P bootstrap: nodes resolve `seed1-4.tsnchain.com` at startup

### Changed
- `MINIMUM_VERSION` bumped to 2.4.1

---

## [2.4.0] — 2026-04-10

### Added
- **Relay pool payouts**: 3% of block reward distributed to relay nodes
  - Scored by per-block participation (signed or unsigned presence)
  - Snapshot confirmation: relay must be active at the payout block
- Miner attribution in explorer (correct labeling of mining nodes)
- V2 shielded TX inclusion enforced at consensus level

### Changed
- Testnet-v6 reset with fresh genesis

---

## [2.3.9] — 2026-04-09

### Fixed
- LWMA fast-sync fix (eliminates the post-fast-sync fork loop)
- Seeds migrated from hardcoded IPs to DNS (`nexus.tsnchain.com`, `seed1-4.tsnchain.com`)

### Added
- Explorer: typed traffic particles, `/stats/activity`, SSE event stream
- Snapshot GitHub dedup
- Watchdog logs in distinct color

---

## [2.3.6] — 2026-04-08

### Added
- Anti-spam middleware with escalating IP bans (1h → 6h → 24h)
- Keyed on `X-TSN-Version` / `X-TSN-Network` / `X-TSN-Genesis` headers

### Fixed
- Fork-work recovery via `prefix_estimate`
- Snapshot cache stale protection (500-block gap guard)

---

## [2.3.5] — 2026-04-07

### Added
- Testnet-v5 reset with genesis hash derived from `NETWORK_NAME`
- Auto-wipe at boot on genesis mismatch
- Signed GitHub snapshot mirror + retention pruning

### Fixed
- HTTP `CLOSE_WAIT` leak fix

---

## [2.3.4] — 2026-04-06

### Fixed
- P2P `NewBlock` mempool cleanup runs in `spawn_blocking`
- Snapshot persistence to disk with 24h retention
- `cmd_balance` orphan-aware display

---

## [2.3.3] — 2026-04-05

### Fixed
- Pre-validate orphan notes before `cmd_send` to avoid retry loops after chain reorgs

---

## [2.3.2] — 2026-04-04

### Fixed
- Wallet rescan correctly deletes DB rows (was only marking as spent)
- Metrics port auto-fallback: tries 9090..9099
- `WalletLock::try_acquire` returns actionable error message

---

## [2.3.1] — 2026-04-03

### Added
- Admin `/mempool/purge` endpoint

### Fixed
- HTTP 429 backoff: 1s → 32s on witness fetch and tx submit
- Auto-consolidation multi-round orchestration

---

## [2.3.0] — 2026-04-02

### Added
- LRU dedup for tip / block / fork-recovery paths
- Snapshot auto-trigger from miner path
- `agent_version` height hint in libp2p Identify

### Fixed
- Wallet `resolve_pq_commitment` fallback on server leaf

---

## [2.0.0] — 2026-03-28

**Breaking:** New network identity, protocol magic, and genesis — all previous versions are incompatible.

### Added
- Genesis HTTP check: peer genesis block hash verified via REST before any sync
- `EXPECTED_GENESIS_HASH`: hardcoded and verified at startup
- Sync stability patches A+B+D (validated across 20-miner EPYC stress test)
- Headers-first sync with fast-sync blind zone detection
- Open network: IP whitelist removed, compatibility enforced via version + magic + genesis

### Changed
- Protocol magic: `TSN1` → `TSN2` (old nodes cannot parse messages)
- Network identity: `tsn-testnet-v2`
- `MINIMUM_VERSION`: bumped to `2.0.0`
- node-1 converted from miner to relay-only

---

## [1.4.0] — 2026-03-20

### Changed
- Fork choice always uses `cumulative_work` (was height-based for short forks)
- `MINIMUM_VERSION`: bumped to `1.4.0`

### Fixed
- 19 consensus bugs in fork resolution, snapshot validation, and self-healing
- Persistent `cumulative_work` in sled (survives LRU eviction)
- PoW validation in trusted mode
- Graduated difficulty tolerance post fast-sync

---

## [1.3.0] — 2026-03-12

### Added
- P2P Auto-Update: nodes detect, download, verify, and self-update

### Changed
- Halving interval: 210,000 → 4,200,000 blocks (~10 year supply schedule)
- `MINIMUM_VERSION`: bumped to `1.3.0`

---

## [0.8.0] — 2026-03-05

### Added
- Working V2 shielded transactions (create, sign, broadcast, validate)
- Interactive wallet menu with BIP39 recovery (24 words)
- `MAX_REORG_DEPTH = 100`, Fork ID verification, anchor block filtering

---

## [0.7.1] — 2026-02-28

Full security audit: 29 findings, 23 fixes applied. Score: **5.4/10 → 8.1/10**. Zero critical vulnerabilities remaining.

---

## [0.7.0] — 2026-02-20

### Added
- LWMA per-block difficulty adjustment (N=45 window)
- GossipSub mesh P2P (replaced flood protocol)
- Cryptographic random nonces

---

## [0.6.0] — 2026-02-10

### Added
- Numeric difficulty system with 512-bit nonce
- Poseidon2 PoW (Plonky3)
- Fast sync (~2 seconds)
- BIP39 wallet recovery
- DNS seed discovery
- Chain Watchdog monitoring
