# Network profile — mainnet-v1

Status: **NOT YET LIVE**. This file is normative for the future mainnet
launch. Every value below MUST be filled with a concrete, signed,
documented decision before mainnet genesis is produced. Empty fields are
not acceptable launch state — the launch is blocked until they are set.

## Identity

| Field | Value | Locked? |
|-------|-------|---------|
| `network_name` | `tsn-mainnet-v1` | RESERVED |
| `genesis_hash` | _to be produced at genesis ceremony_ | NO — see ceremony below |
| `chain_started` | _to be set at launch_ | NO |
| `purpose` | Production cryptocurrency network. Real value at risk. Forks are not acceptable, wipes are not acceptable, downtime is severely limited. |

The `genesis_hash` field MUST NOT be empty at launch. CI MUST reject any
mainnet binary that ships an empty `EXPECTED_GENESIS_HASH`. The exact
value comes from the genesis ceremony described below.

## Genesis ceremony (one-time, before launch)

A mainnet genesis is not generated implicitly — it requires a deliberate
ceremony:

1. Final pre-genesis review of `src/config/mod.rs` constants:
   - `NETWORK_NAME = "tsn-mainnet-v1"`
   - `EXPECTED_GENESIS_HASH = ""` (placeholder, becomes pinned at step 5)
   - `MINIMUM_VERSION` set to the launch release version
   - All testnet-specific flags removed
2. Build the launch binary in CI (signed Ed25519, registered in
   `RELEASE_DECISIONS.md` as `mainnet-genesis-candidate`).
3. Run on a single dedicated bootstrap host with no peers, role=relay,
   data dir empty. Capture `block 0` hash from `/block/height/0`.
4. Verify ≥ 2 independent operators reproduce the same `genesis_hash`
   from the same binary (two separate machines, same checksum binary,
   same source code commit).
5. Commit the genesis hash to `mainnet-v1.md` AND to
   `EXPECTED_GENESIS_HASH` in `src/config/mod.rs`. Tag a release.
6. Re-run the launch binary build with the now-pinned constant.
7. Compare new binary checksum against step-2 binary — they will differ
   by exactly the hash bytes. This difference is documented in
   `RELEASE_DECISIONS.md`.

The release used at step 6 is the **mainnet launch binary**. Steps 1–5
produce throwaway artifacts that MUST NOT be served from any public URL.

## Network topology

The seed list MUST be defined before launch and MUST NOT be the same
hosts as testnet seeds. Reusing testnet hosts for mainnet is forbidden
because:
- Testnet seeds run with permissive transitional rules (e.g. empty
  genesis header tolerated). Mainnet rules are stricter and incompatible.
- Testnet history sits on disk and would contaminate mainnet via
  fast-sync if not isolated.

| Role | Identifier | Public address | Internal port | P2P port |
|------|------------|----------------|---------------|----------|
| _to be set_ | _to be set_ | _to be set_ | 9333 | 9334 |

A minimum of 5 geographically distributed seeds with documented
operators is required before launch.

## Version policy

| Field | Value |
|-------|-------|
| Launch release | _to be set_ — pin commit, sha256, signature in `RELEASE_DECISIONS.md` |
| `MINIMUM_VERSION` at launch | equal to launch release (no transitional compatibility window — there is no "previous" mainnet to be compatible with) |

After launch, version bumps follow the testnet model (transitional
window of 1 minor version), but the bump cadence is much slower
(months, not days) and each bump is gated by `RELEASE_CHECKLIST.md`.

## Snapshot policy

- Snapshots are produced every 500 blocks at finalized heights.
- Mainnet snapshots MUST be served only from authoritative seeds for
  the first 30 days. Community-served snapshots are tolerated only
  after 30 days of stable canonical chain operation.
- Snapshots MUST be Ed25519-signed by the seed that produced them.
  The signing key is per-seed, registered in this document at launch,
  and rotatable via signed migration message.
- A node receiving a snapshot from a non-authoritative source MUST
  cross-check the tip hash with at least 3 authoritative seeds before
  importing. This is the **majority-vote fast-sync** rule (Spec 1 in
  `incident-2026-05-02/specs/P4-self-repair-specs.md`) — for mainnet
  it is **not optional**.

## Wipe / resync strategy

**Wipes are not acceptable on mainnet** under normal operation. Wipes
on a mainnet seed require:

1. Written incident declaration in `POSTMORTEMS.md`.
2. Signed approval from ≥ 2 operators not running the affected seed.
3. The seed is taken out of the authoritative list during the wipe
   (clients should not consider it canonical until re-validated).
4. Post-wipe, the seed must reproduce the canonical tip hash for ≥ 24h
   before being re-added to the authoritative list.

`/admin/force-resync` HTTP endpoint MUST be authenticated on mainnet
seeds. The current testnet implementation accepts unauthenticated
requests on localhost — this MUST be replaced before mainnet launch
with bearer-token auth. Tracked as a launch blocker.

## Transitional compatibility rules

**None.** Mainnet has no transitional compatibility for older versions
because:
- There is no pre-launch mainnet network to be compatible with.
- The launch binary defines the ground truth.
- Any peer below `MINIMUM_VERSION` at launch is genuinely a wrong
  network (testnet, dev, attacker) and MUST be rejected.

The "treat empty genesis header as not declared" rule from testnet
v2.9.20 MUST NOT be carried over to mainnet. Empty header on mainnet
means malformed peer or attack — reject hard.

## Handshake refusal criteria

A peer is rejected by mainnet seeds if **any** of:
- `X-TSN-Version` < `MINIMUM_VERSION` (no transitional grace).
- `X-TSN-Network` != `tsn-mainnet-v1` (no auto-detect).
- `X-TSN-Genesis` != mainnet genesis hash (no empty-tolerant fallback).
- All four headers MUST be present — any missing header is rejected
  (mainnet does not tolerate "internal tooling without headers" — all
  internal tooling MUST set them).

This is stricter than testnet on purpose.

## Operational invariants

- The mainnet binary, manifest, signature, and tag MUST be unique. CI
  rejects republication of any of these under a different hash. (See
  `RELEASE_DECISIONS.md` for the canonical record.)
- A mainnet binary MUST NOT be served from the testnet manifest URL
  (`tsnchain.com/releases/latest.json`) and vice-versa. Mainnet uses a
  separate manifest URL pinned in code.
- Mainnet hardening on hosts: in addition to the testnet `hardening.conf`
  drop-in (KillMode=mixed, StartLimitBurst, ExecStartPre DB-lock check),
  mainnet seeds MUST also have:
  - SSH access restricted to a hardware-key-authenticated jump host.
  - File-system level immutability on `/opt/tsn/bin/tsn` between releases
    (chattr +i / signed package).
  - Off-host snapshot backup every 100 blocks (not every 500).
  - Anomaly alerting on `cumulative_work` regression, hash divergence,
    DB-lock contention, and auto-update failure.

## Launch blockers (must all be GREEN before launch)

- [ ] `genesis_hash` produced via ceremony and committed to source.
- [ ] 5+ seeds documented in this file with operator identity.
- [ ] `/admin/force-resync` requires authentication.
- [ ] Majority-vote fast-sync rule is enforced in code (not just docs).
- [ ] Snapshot-quarantine rule enforced (no serving from a stuck node).
- [ ] Mempool reorg invariants test passing in CI.
- [ ] Per-seed snapshot signing keys registered.
- [ ] At least one full end-to-end auto-update test from launch release
      to a hypothetical launch+1 release, validating the upgrade path.
- [ ] Postmortems for testnet incidents reviewed; matching CI tests
      added; `KNOWN_FAILURES.md` items all have a corresponding bloc
      ker in CI.
- [ ] No empty / placeholder values remain in any field of this file.

The mainnet launch is blocked until all checkboxes above are GREEN.
