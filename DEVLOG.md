# Devlog — Trust Stack Network

Every TSN release, chronological (newest first). Mirrors the site version at
https://www.tsnchain.com/devlog.html.

Network: **tsn-testnet-v9** (genesis reset with v2.5.0 on April 14, 2026).
Minimum protocol version required to peer: **2.9.15**.

---

## v2.9.15 — English-only codebase, minimum version gate
*May 2, 2026 — network-private*

- **MINIMUM_VERSION** bumped to `2.9.15` — nodes below this version are rejected at handshake with an escalating IP ban on repeat offenders.
- **Full English-only codebase.** Every French string, comment, and doc-string across 71 source files replaced with English equivalents. Zero accented characters remain in any `.rs` or `.toml` file.
- **Stray file removed.** A file with an invalid name (`pow.rs et block.rs`) containing only placeholder comments was deleted.

---

## v2.9.14 — Stability backports, auto-recovery timeout
*May 1, 2026 — network-private*

- Backport W1 + W1B + H-G + FIX-D patches from the internal stability branch.
- Auto-recovery timeout extended to 180s to handle slow-sync seeds without false-positive wipes.

---

## v2.9.13 — Default relay role, full auto-recovery
*May 1, 2026 — network-private*

- `--role` defaults to `relay` when the role cannot be detected from the binary name.
- Full auto-recovery cycle triggered on lost consensus (wipe + fast-sync + restart).

---

## v2.9.9–v2.9.11 — Background backfill
*April 30, 2026 — network-private*

- New background goroutine backfills historical blocks that are missing after a fast-sync. The node continues mining immediately while the backfill walks the chain descending from the tip, so seeds that joined via snapshot still serve historical data within minutes.
- `[0u8;32]` placeholder entries in the block DB are now treated as missing and trigger a re-fetch.

---

## v2.9.8 — Dynamic checkpoint quorum, RAM fix
*April 29, 2026 — network-private*

- `CHECKPOINT_QUORUM` is now dynamically set to 80% of connected seeds (minimum 4) to handle partial outages gracefully.
- Plonky3 circuit warm-up limited to the 5 most-common transaction shapes, preventing the OOM crash on 4 GB seeds.

---

## v2.9.7 — Persistent identity, checkpoint history
*April 28, 2026 — network-private*

- The libp2p identity key is now persisted to disk so a node keeps the same PeerID across restarts. This improves relay scoring stability and reduces "new peer" churn in the explorer.
- `network_name` added to `/version.json` — lets the explorer verify it is talking to the correct testnet.
- `/chain/checkpoint_history` endpoint exposes the last 10 signed checkpoints.
- Phase C HTTP fallback: if GossipSub delivery fails, the node falls back to direct HTTP push to known peers.

---

## v2.9.2–v2.9.6 — Checkpoint voting stabilization
*April 26–27, 2026 — network-private*

- `checkpoint_vote` anchor candidate scan now starts at `fast_sync_base` — prevents false finality on placeholder heights.
- Shallow fallback window added for the post-fast-sync transition (the first LWMA_WINDOW blocks after import).
- Checkpoint snapshot always published on tick, even if quorum was already reached, so late-joining nodes can catch up.
- `CHECKPOINT_QUORUM` raised to 4 (was 3). Added `/chain/quorum_status` endpoint and explorer quorum halo badge.

---

## v2.9.0–v2.9.1 — BIP-152 RAM fix, memory diet
*April 24–25, 2026 — network-private*

- **RAM diet.** Sled cache capped at 256 MB (was 1 GB). Block LRU reduced to 200 entries. Fast-sync anchor recomputed from DB on load rather than held in memory.
- **BIP-152 RAM fix.** The compact block relay was cloning the entire mempool before filtering by short_id. Now filters first, clones only matching entries — peak RAM during block relay drops from ~800 MB to ~30 MB on a full mempool.

---

## v2.8.9 — Trusted-quorum checkpoints, BIP-152 hardening
*April 23, 2026 — network-private*

- **Trusted-quorum checkpoint vote.** Every 100 blocks, the 4+ seed nodes sign a checkpoint. A node that receives a checkpoint signed by quorum finalizes that height — no reorg can go below it. This provides Byzantine-fault-tolerant finality without a separate consensus round.
- **BIP-152 DoS protections.** Added per-peer max announces, dedup window (60s), and rate limit (10 `cmpctblock` per minute). Prevents a rogue peer from flooding the relay pool.

---

## v2.8.7 — Compact Block Relay (BIP-152)
*April 21, 2026 — network-private*

- **Full Compact Block Relay** inspired by Bitcoin's BIP-152.
  - When a miner finds a block, it sends a `cmpctblock` message containing only short IDs (8-byte SipHash-2-4 keyed on a nonce + block hash) instead of full transactions.
  - Receiving nodes reconstruct the block from their mempool. Only missing transactions trigger a `getblocktxn` / `blocktxn` round-trip.
  - Bandwidth savings: **up to 98%** on peers with a well-filled mempool (typical case: 0 missing transactions).

---

## v2.8.5 — Iron Fish wallet, anchored mempool, cumulative work drift fix
*April 19, 2026 — network-private*

- **Iron Fish wallet integration.** HD key derivation via BIP44 path `m/44'/990'/0'/0/i`. Compatible with external signers that implement the same derivation standard.
- **Anchored mempool.** Transactions now include an anchor block hash. After a reorg deeper than the anchor, the transaction is evicted from the mempool and must be resubmitted. Prevents replay attacks after chain reorganizations.
- **Cumulative work drift fix.** `cumulative_work` is now recalculated from actual block difficulties on snapshot import, eliminating the drift that built up over long-running nodes and caused incorrect fork-choice decisions.

---

## v2.8.0–v2.8.1 — Pipeline fixes, signed snapshots
*April 17–18, 2026 — network-private*

- Block relay pipeline ordering fixed (Phase A).
- `MAX_SPENDS` raised from 25 to 50 per transaction.
- Fast-sync snapshots are now signed with the node's Ed25519 identity key and verified by the importing node.
- Auto-consolidate wallet notes is ON by default.

---

## v2.7.4 — Anti-freeze HTTP, lock-free chain reads
*April 16, 2026 — network-private*

- Added timeouts on all outbound HTTP calls (block fetch, peer probe, snapshot download) to prevent the node from hanging when a peer is unresponsive.
- Chain reads in the HTTP API layer are now lock-free (replaced `RwLock<Chain>` with an `Arc<ArcSwap<Chain>>`), eliminating the latency spike that occurred when a miner was writing a new block.

---

## v2.5.0 — Cortex node, fork-choice fixes, testnet-v9
*April 14, 2026 — network-private*

- **Cortex node Phase 1.** New node role (`./tsn cortex`) that runs a WASM runtime for dApp service modules. Cortex nodes earn fees from dApps (NetherSwap, Whispr, ZST) — not from coinbase. This separates the service layer from the mining layer, keeping mining rewards fully decentralized.
- 4 fork-choice fixes improving convergence when two miners find blocks within the same second.
- Testnet-v9 reset with a fresh genesis (`tsn-testnet-v9`).

---

## v2.4.3 — Wallet cleanup, bulk leaf fetch, testnet-v8
*April 13, 2026 — network-private*

- `wallet-cleanup` command: removes spent and orphaned notes from the local wallet DB.
- `balance` now shows spendable notes only (excludes locked and unconfirmed outputs).
- `/leaves/bulk` endpoint: fetches multiple Merkle leaves in one HTTP call. The wallet uses it before a send to pre-validate witness availability, reducing "missing witness" errors.
- Testnet-v8 reset. `cumulative_work` persisted to DB on snapshot import.

---

## v2.4.1 — DNS bootstrap, MINIMUM_VERSION bump
*April 11, 2026 — network-private*

- P2P bootstrap now resolves `seed1-4.tsnchain.com` via DNS at startup. Rotating a seed's IP no longer requires a binary update.
- `MINIMUM_VERSION` bumped to 2.4.1.

---

## v2.4.0 — Relay pool payouts, V2 TX inclusion, testnet-v6
*April 10, 2026 — network-private*

- **Relay pool payouts.** 3% of each block reward is distributed to relay nodes. Score is based on per-block participation — a relay earns credit for every block it is present for (signed or unsigned), not on a sliding window threshold. Snapshot confirmation: the relay must be present at the payout block height.
- V2 shielded transactions now enforced at consensus level (V1 format rejected by default).
- Miner attribution in the explorer correctly labels which node mined a given block.
- Testnet-v6 reset.

---

## v2.3.9 — Mining unstuck, DNS seeds, live explorer telemetry
*April 20, 2026 — network-private*

- **LWMA post-fast-sync fix.** Validators and freshly-synced miners now compute the exact same next-block difficulty. The node fetches the last `LWMA_WINDOW + 1` compact headers from the snapshot peer at import time and stores them locally; `next_difficulty()` falls back to that buffer for any block-height the fast-sync placeholder overwrote. Closes the loop where post-fast-sync miners produced blocks at the wrong difficulty, got rejected for "Invalid difficulty", the watchdog wiped them, they resynced, and repeated.
- **Wallet incremental scan marks spent notes.** Two related issues silently left "spent" notes as unspent in the SQLite wallet: an early-return skipped `/nullifiers/check` when no new blocks had arrived, and only post-quantum nullifiers were checked (legacy V1 notes were not). The incremental scan now sweeps both V1 and V2 nullifiers every run and persists whenever any note flipped to spent.
- **Seeds moved from hardcoded IPs to DNS.** `nexus.tsnchain.com`, `seed1.tsnchain.com` through `seed4.tsnchain.com`. Rotating a seed's hosting no longer requires a new binary; a DNS A-record edit is enough.
- **Live explorer telemetry.** Two read-only endpoints — `/stats/activity` (cumulative counters) and the Server-Sent Events stream `/events/stream` — let the explorer animate real traffic instead of a simulation. Tip announcements, block broadcasts, V2 transactions, sync requests, snapshot transfers, peer handshakes and rejected blocks are now distinct typed particles on screen.
- **Watchdog Check 2d — stuck-behind auto-recovery.** Symmetric counterpart to the solo-fork-ahead guard. When the local chain is behind consensus by more than 20 blocks AND peer-sync can't rollback (because the common ancestor sits below finalization), the watchdog now wipes and fast-syncs. Same smart guards as the ahead-case: ≥3 peers agree, 1h cooldown, kill switch at 3 wipes/24h, 120s grace to rule out transient lag.
- **Ghost peer filter in /network/status.** A peer briefly accepted by libp2p but rejected by the TSN HTTP middleware no longer shows up as a 2-second flicker on the explorer graph. A peer must present a well-formed `tsn/<version>/<role>` protocol, meet `MINIMUM_VERSION`, and have exchanged at least one height before it is surfaced.
- **/wallet/address disambiguation.** `address` now aliases `pk_hash` (the 32-byte Blake2s256 of the ML-DSA-65 public key — the one mining rewards land on). The 20-byte legacy V1 identifier is moved to `legacy_address_v1` with an explicit note that it is back-compat only. Closes a source of confusion where users were copying the wrong value.
- **Watchdog logs in cyan.** Operator-facing alerts stand out in `journalctl` output.
- **Cleanup.** 14 outdated v0.1 whitepaper duplicates removed from the repo (the fresh English whitepaper will live in a dedicated repository). Residual mixed-language strings swept out of 11 source files. In-source comments no longer reference server-local private-key paths.

No consensus change. `MINIMUM_VERSION` stays at 2.3.7. Validated on live testnet-v5 across 5 seeds + 1 miner with unanimous consensus at h=2916+.

---

## v2.3.8 — Tighter solo-fork threshold, tip downgrade accept, stale cache guard
*April 20, 2026 — network-private*

- **Solo-fork threshold tightened 20 → 5.** The smart auto-wipe's multi-peer guards proved reliable enough under load that the height-gap cutoff could be lowered by a factor of four. A miner that silently drifts off the network now triggers a supervised resync almost immediately instead of accumulating dozens of rejected blocks first.
- **`tip_topic` accepts downgrades.** Previously a peer that wiped its chain and came back at a lower height was invisible to us — the libp2p tip cache only accepted monotonically increasing values, so a node recovering from a reset looked frozen in the explorer for minutes. The handler now always records the broadcast value; stale caches are no longer a source of confusion during incidents.
- **Snapshot cache gap invalidation.** A 500-block gap between the cached snapshot height and the current tip now invalidates the cache proactively. Used to be that a stuck seed kept serving fast-sync data from its last good state while the rest of the network moved on.
- **Persistent `last_snapshot_auto_trigger`.** Snapshot auto-trigger height is now persisted to disk so a restart does not re-fire a snapshot at the current (non-interval-aligned) tip — this used to pollute the snapshot mirror with near-duplicate releases every time the service cycled.

Follow-up to v2.3.7, focused on the stability surface around real-network recoveries.

---

## v2.3.7 — Solo-fork guard, ghost peer TTL, HUD consensus view
*April 20, 2026 — network-private*

- **Smart solo-fork detection.** The self-healing watchdog now fires only when ≥3 peers agree on a consensus height and the local node is more than 5 blocks ahead. Three independent guards — a 1-hour cooldown, a 3-wipe-per-24-hour kill switch, and the multi-peer agreement threshold — close the cascade path that could wipe a chain indefinitely in older builds.
- **Consensus height in `/network/status`.** The explorer used to render whichever seed polled fastest, causing nodes to bob up and down by a block. The endpoint now returns a median over online seeds, a `quorum` count, and a `solo_fork` flag — the UI can colour an outlier node in red the instant it drifts.
- **Ghost peer TTL.** libp2p sometimes keeps connections that no longer exchange messages. Peers silent for longer than 120 seconds are now evicted from the public peer list instead of lingering in the explorer long after they stopped being reachable.
- **/wallet/address enrichment.** The endpoint surfaces the mining address, a legacy V1 address for back-compat, and a note about which form the user should share.
- **`MINIMUM_VERSION` bumped to 2.3.7.** Community nodes on 2.3.6 or earlier are rejected at the HTTP sync layer.

Still focused on the stability surface a testnet uncovers but a local unit test never sees.

---

## v2.3.6 — Anti-spam middleware, fork-work recovery, auto-wipe disabled
*April 19, 2026 — GitHub release, https://github.com/trusts-stack-network/tsn/releases/tag/v2.3.6*

- **Anti-spam middleware on sync routes.** Per-IP escalating ban (1h → 6h → 24h) for peers announcing an outdated `X-TSN-Version`, wrong `X-TSN-Network`, or wrong `X-TSN-Genesis` header. Triggered after 3 offenses in a sliding window. WARN log is deduplicated per IP on a 5-minute window, so a community node stuck on an old version no longer floods seed journals.
- **Fork-work recovery fix.** `calculate_chain_work` now adds a bounded prefix estimate drawn from our own cumulative work when the walk back from a fork tip cannot reach a known-work ancestor. Previously, valid longer chains were rejected as `REJECT LESS_WORK` because the accumulated difficulty was grossly under-counted. Guarded by `MAX_REORG_DEPTH`, so long-range attacks stay rejected.
- **Auto-wipe removed from the watchdog.** Height-stuck, peers-far-ahead, solo-fork, and resync-loop signals are now log-only. The destructive pattern of wiping on transient mesh instability is gone — operators trigger re-sync manually via `/admin/force-resync`.
- **No wipe on rollback-below-finalization.** When a peer proposes a fork that would require rolling past our finalized height, we reject the peer instead of wiping our chain. Finalized blocks are canonical; the peer is wrong.
- **Snapshot auto-trigger fixed.** The first snapshot now fires at h=1100 as intended, not at h=2100. Off-by-one boundary guards corrected; atomic `last_snapshot_auto_trigger` is now the single source of truth.
- **Snapshot cache staleness.** The HTTP snapshot cache is now invalidated both ahead-of-chain and when more than 500 blocks behind the tip. Stops stale-cache diffusion through fast-syncing peers.
- **`MINIMUM_VERSION` = 2.3.6.**

394 library tests pass. End-to-end validated on testnet-v5 (rolling deploy, snapshot cross-confirmation, GitHub mirror publish).

---

## v2.3.5 — Testnet reset (testnet-v5)
*April 19, 2026 — GitHub release*

Chain reset to `tsn-testnet-v5`. All nodes v2.3.4 and earlier are rejected. Old data is auto-wiped on boot. Wallets preserved (same address) but their pre-reset notes are archived.

- **Why the reset.** We deliberately drove the testnet into two parallel chains (internally labeled Chain A and Chain B) as part of our fork-handling and reorg-resilience tests for the v2.3.x iteration cycle. The tests produced exactly the diverging state we wanted to exercise, and they are now done. v2.3.5 closes that testing phase by rolling out a new genesis so every node restarts from h=0 on a single, clean chain.
- **Network identity.** `NETWORK_NAME` bumped `tsn-testnet-v4` → `tsn-testnet-v5`. `MINIMUM_VERSION` bumped to `2.3.5`. New genesis hash derived automatically from the network name.
- **Auto-wipe + wallet obsolescence.** Nodes with obsolete `blockchain/` data wipe it on boot. Wallets detect the new testnet via `scan_state.network_name` and archive pre-reset notes; keys preserved.
- **CLOSE-WAIT fix.** The v2.3.4 P2P mempool cleanup held locks inline on the gossip event loop and starved axum's accept loop under `/tip` polling. Cleanup now runs on `spawn_blocking` and short-circuits on empty mempool. 0 leaks at 12k rps in stress test.
- **`./tsn balance` 429 fix.** Bail after 2 consecutive rate-limit errors instead of minutes of backoff; 100ms pacing between position queries.
- **Snapshot GitHub mirror.** Seeds with `TSN_SNAPSHOT_GH_TOKEN` now publish signed snapshots to `trusts-stack-network/tsn-snapshots`. Last 10 kept.

---

## v2.3.4 — P2P mempool cleanup + snapshot disk persistence + wallet orphan visibility
*April 18, 2026 — GitHub release*

- **P2P mempool cleanup.** Blocks arriving via GossipSub now correctly drop confirmed transactions and spent nullifiers from the mempool. Miners that ingest blocks only via P2P no longer loop on `Nullifier already spent` while the chain moves forward under them.
- **Snapshot disk persistence.** Auto-snapshots are written to `<data_dir>/snapshots/` (compressed blob + signed manifest) with 24h retention. Process restarts no longer leave fast-sync peers without a snapshot to download until the next interval.
- **Wallet orphan visibility.** `tsn balance` now pre-validates each unspent note witness against the node and shows Total / Spendable / Stuck. Orphan notes from prior reorgs are visible before any send.
- **Web wallet honesty.** `wallet.html` no longer shows a stale `0.00 TSN`. It states plainly that the web wallet does not decrypt on-chain notes and points users at the CLI.

No consensus change. No schema change. `MINIMUM_VERSION` unchanged at 2.2.0. 394 library tests + 13 binary tests green.

---

## v2.3.3 — Pre-validate unspent note witnesses before send
*April 18, 2026 — GitHub release*

`tsn send` now calls `/witness/verify` on every candidate note before signing and submitting. Orphan notes (whose witness no longer verifies because of a reorg) are skipped automatically instead of producing a rejected transaction.

---

## v2.3.2 — Wallet rescan actually deletes rows + metrics port auto-fallback + actionable wallet-lock error
*April 18, 2026 — GitHub release*

- **Wallet rescan deletes rows.** The destructive path of `tsn wallet rescan` was silently a no-op because the notes table was never cleared. It now deletes all rows under the rescan flag, so a rescan actually starts from a clean slate.
- **Metrics port auto-fallback.** If port 9334 is taken (second node on the same machine), the metrics listener now tries 9335, 9336, 9337 in order instead of crashing.
- **Wallet-lock error clarity.** When another process holds the wallet lock, the error now prints the PID and how to resolve it, instead of a cryptic `Resource temporarily unavailable`.

---

## v2.3.1 — Wallet Merkle witness orphan detection + HTTP 429 backoff
*April 17, 2026 — GitHub release*

- Merkle witnesses that no longer match the current commitment tree are marked orphan in the wallet DB; `tsn balance` shows them under `Stuck` instead of including them in `Spendable`.
- HTTP client backoff on 429 uses `Retry-After` when present, otherwise exponential up to 30 s.

---

## v2.3.0 — V2 tx propagation + fork/reorg hardening
*April 17, 2026 — GitHub release*

- Fix: V2 transactions gossiped via P2P now land in miner mempools (earlier path routed them only to seed nodes).
- Phase 1–3 fixes across sync, fork recovery, and dedup; see commit series `2cb0fe9 → 6201a22` for details.
- Wallet: fall back to server-provided leaf when `pq_commitment` is missing (fixes send from pre-v2.0 notes).
- Expose startup height via libp2p Identify `agent_version`.
- Snapshot auto-trigger wired into the local miner path.
- Downgrade `COMMITMENT_ROOT_MISMATCH` warn to debug (false-positive during reorg).

---

## v2.2.1 — Wallet auto-detection after SQLite migration
*April 16, 2026 — GitHub release*

Hotfix: after the `wallet.json` → `wallet.db` migration, `tsn wallet`-family commands failed to locate the wallet when launched from a directory other than the one containing the file. Auto-detection now scans `$TSN_WALLET`, the current directory, and the binary directory in that order.

---

## v2.2.0 — Wallet SQLite rewrite, atomic writes, file locking, testnet-v4
*April 16, 2026 — GitHub release*

- **Wallet moved from `wallet.json` to `wallet.db` (SQLite, WAL mode).** Five tables: `wallet_keys`, `notes`, `tx_history`, `scan_state`, `schema_version`. Automatic one-time migration on first run; `wallet.json` is renamed to `wallet.json.migrated`.
- **Atomic writes.** `write(tmp) → rename(final)` replaces truncate-in-place. A crash between the two steps can no longer lose data.
- **File locking.** `libc::flock` advisory lock blocks concurrent access from a second process (the bug that caused mysterious balance resets when the miner and a CLI wallet were open at the same time).
- **Network identity locked.** `NETWORK_NAME = tsn-testnet-v4`, genesis hash pinned in config. Cross-testnet mixing rejected at the header layer.

---

## v2.1.6 — Sync recovery, block confirmation, wallet address command
*April 15, 2026*

- Removed all auto-reset code from `reorganize_to_block` (dangerous legacy path).
- Removed dangerous startup sanity check that could wipe a valid chain on a cold boot.
- Sync recovery: resume from last-known-good block instead of restarting from genesis.
- Block confirmation count surfaced in `/tip` and CLI.
- `tsn wallet address` command surfaces the mining address + legacy form.

---

## Older (v2.1.x, v2.0.x, v0.1.x)

Earlier history is preserved in the git log and on the site:
https://www.tsnchain.com/devlog.html
