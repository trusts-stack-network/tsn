# Network profile — testnet-v12

This file is the authoritative reference for `tsn-testnet-v12`. Any
release shipping for this network MUST match every value below. The CI
preflight (`scripts/release-safety/verify-release.sh`) reads this file
directly and refuses the release if any field disagrees with the binary
or the manifest.

## Identity

| Field | Value |
|-------|-------|
| `network_name` | `tsn-testnet-v12` |
| `genesis_hash` | `007870623724127ccf467b74041c3fed0e3569f02c66414a3018d7c04856e38d` |
| `chain_started` | 2026-04-24 |
| `purpose` | Public testnet, real community participation, intentionally lossy (forks acceptable, wipe/resync legitimate) |

The genesis hash is **non-empty and pinned**. A binary that ships an
empty `EXPECTED_GENESIS_HASH` for this network is rejected at CI.

## Network topology

| Role | Identifier | Public address | Internal port | P2P port |
|------|------------|----------------|---------------|----------|
| Authoritative seed | seed-1 | `seed1.tsnchain.com` (151.240.19.253) | 9333 | 9334 |
| Authoritative seed | seed-2 | `seed2.tsnchain.com` (45.145.164.76) | 9333 | 9334 |
| Authoritative seed | seed-3 | `seed3.tsnchain.com` (146.19.168.71) | 9333 | 9334 |
| Authoritative seed | seed-4 | `seed4.tsnchain.com` (45.132.96.141) | 9333 | 9334 |
| Authoritative relay | node-1 | `nexus.tsnchain.com` (45.145.165.223) | 9333 | 9334 |

Seeds list above is the **only** acceptable set of canonical-truth
sources for this network. A snapshot served by a host outside this list
is treated as untrusted (community node — useful, but not source of
truth).

Community nodes use ports 9333 (HTTP API) and 9334 (P2P). Other ports
seen in the wild: 9335 (relay), 9337 (cortex), 9339 (default miner),
9340 (legacy P2P) — these are valid roles but not canonical seed ports.

## Version policy

| Field | Value |
|-------|-------|
| Latest release | `v2.9.20` (post-incident 2026-05-02) |
| `MINIMUM_VERSION` enforced by middleware | `2.9.15` |
| Reason for keeping minimum at 2.9.15 | Transitional compatibility — community nodes upgraded from 2.9.15 are still allowed during the upgrade window. Will tighten to 2.9.20 once auto-update propagation is observed >95%. |

Bumping `MINIMUM_VERSION` to a new value means:
- Any node running below it is rejected at handshake by the version
  gate middleware.
- The bump must be paired with a working auto-update path so locked-out
  nodes can upgrade.
- The bump cannot precede the release of the version it points at.

## Snapshot policy

- Snapshots are produced every 500 blocks at finalized heights.
- Stored in `/opt/tsn/data/snapshots/snapshot-NNNN.json.gz`.
- Served via HTTP `/snapshot` endpoint and via P2P GossipSub.
- A node MAY serve a snapshot only if its tip has progressed monotonically
  for ≥ 2 minutes (avoids serving a tip from a stuck or reset node).
  This rule is documented as a normative requirement in
  `docs/KNOWN_FAILURES.md` (failure type "toxic snapshot") but not yet
  enforced in code as of 2026-05-02 — see Spec 4 in
  `incident-2026-05-02/specs/P4-self-repair-specs.md`.

## Wipe / resync strategy

A `data_dir` wipe is acceptable on testnet without a chain reset
ceremony, because:
- The chain is intentionally lossy.
- All wallet state is recoverable from BIP39 mnemonic + chain replay.
- Confirmed transactions remain visible in any healthy node.

Procedure:
1. `systemctl stop tsn-node` (or `kill -9` for nohup).
2. Rename `data/` → `data.broken-$(date +%s)` (don't delete — needed for
   forensics if a problem repeats).
3. Restart service. Node fast-syncs from a canonical seed.
4. **Use `/admin/force-resync` HTTP endpoint** instead of manual wipe
   when the node is still up — preserves binary and config, just resets
   the chain state.

`/admin/force-resync` was tested as functional in incident 2026-05-02
on seed-1 and on epyc1-miner.

## Transitional compatibility rules

Currently active (as of v2.9.20):

1. **Empty `X-TSN-Genesis` header is treated as "not declared"**
   (passes through without ban). Reason: pre-v2.9.19 nodes were
   configured with `EXPECTED_GENESIS_HASH=""` and emit `""` in their
   request headers. Without this rule the network self-segregates
   between upgraded and pre-upgrade peers.

   This rule is **temporary** and must be removed once auto-update
   propagation is observed >95% (target: 14 days after v2.9.20
   release). Removal requires a new release and a `RELEASE_DECISIONS.md`
   entry.

2. **MINIMUM_VERSION lag policy**: `MINIMUM_VERSION` is held one minor
   version below the latest release for at least the duration of
   transitional compatibility, so a peer that is exactly one upgrade
   behind is never locked out.

## Handshake refusal criteria

A peer is rejected by the version gate middleware (`/src/network/api.rs::version_gate_middleware`)
if **any** of the following holds:

- `X-TSN-Version` is present **and** `version_meets_minimum()` returns false.
- `X-TSN-Network` is present **and** `!= "tsn-testnet-v12"`.
- `X-TSN-Genesis` is present **and non-empty** **and** `!= "007870623724127c..."`.
- IP is currently in the version-ban map AND the peek-headers check
  detects the peer is still out of compliance.

Missing headers (not present at all) are tolerated — they're internal
explorer/snapshot tooling that historically did not set them.

## Refusal at startup (chain-side)

A node refuses to start (returns `BlockchainError::StorageError`) if:
- Stored `height_index[0]` is **non-zero** AND `!= EXPECTED_GENESIS_HASH`.
  (Zero is treated as "fast-sync placeholder, OK".)

This is the genesis check at boot in `src/core/blockchain.rs:560-577`.

## Operational invariants

- `EXPECTED_GENESIS_HASH` MUST be `007870623724127c...` for any binary
  built for testnet-v12. CI rejects empty.
- `NETWORK_NAME` MUST be `tsn-testnet-v12`. CI rejects mismatch.
- A binary built from a commit not on the `backport-10k` branch (or
  successor branch tagged for testnet-v12) is invalid.
- Testnet-v12 binaries MUST NOT be deployed on a future mainnet host
  and vice-versa.
