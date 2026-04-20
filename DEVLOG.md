# Devlog — Trust Stack Network

Every TSN release, chronological (newest first). Mirrors the site version at
https://www.tsnchain.com/devlog.html.

Network: **tsn-testnet-v5** (genesis reset with v2.3.5 on April 19, 2026).
Minimum protocol version required to peer: **2.3.7**.

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
