# TSN Postmortems

Append-only ledger of incidents. Each entry documents a real failure
that happened on a real network with real impact. New entries go at
the **top** (most recent first). Old entries are never deleted or
edited — corrections come as a follow-up entry that references the
original.

Each postmortem MUST contain:
1. Date (UTC)
2. Symptoms — what was observed externally
3. Root cause — the actual technical reason
4. Impact — what users / network experienced
5. Error type — human / code / process (often combinations)
6. Correction — what was fixed and how it was deployed
7. Test added — the regression test or guardrail that now blocks the same
   class of failure from recurring (this is the "executable memory" layer)

If a postmortem has no entry under "Test added", the incident is
considered insufficiently mitigated and the corresponding item in
`KNOWN_FAILURES.md` stays in the unblocked list.

---

## 2026-05-02 — Auto-update + fork cascade + cluster fragmentation

### Symptoms
- Community testnet reopened the morning of 2026-05-02. Within hours,
  the explorer was showing multiple peers labelled "SOLO FORK" with
  heights 500–1500 blocks above the seed cluster's consensus height.
- A user-operated miner (`epyc2`) booted v2.9.15 and immediately
  observed `REJECT REORG_DEEP block=... depth=1124 max=100` for every
  block received from the seeds. Mining produced blocks that were
  accepted locally but never confirmed by the network.
- node-1 was crash-looping at 17,709 restarts; seed-4 at 25,585
  restarts. Both were "active" in systemd output but their actual
  process was either an orphan from a previous boot (holding the Sled
  DB lock) or a freshly-started process that exited immediately on
  lock contention.
- The fallback auto-update manifest at
  `https://tsnchain.com/releases/latest.json` either did not exist,
  had the wrong asset key, or had no Ed25519 signature, depending on
  when in the day the request was made. Pre-existing community nodes
  on v2.9.15 saw `Ed25519 signature verification FAILED for v2.9.20.
  Aborting update.`
- After deploying v2.9.19 with `EXPECTED_GENESIS_HASH` pinned,
  upgraded seeds began rejecting every v2.9.15 peer with
  `Rejected peer X.X.X.X (genesis="" != 007870..., offense ...)`,
  isolating the upgraded seeds from the rest of the network.

### Root cause

Three superposed bugs that interacted multiplicatively:

1. **Manifest asset key mismatch.** The `auto_update::check_fallback()`
   client-side code looks up `manifest.assets[get_platform_asset_name(version)]`,
   which produces `tsn-{VERSION}-linux-x86_64.tar.gz` (no `v` prefix).
   The first manifest deployed used `tsn-v{VERSION}-linux-x86_64.tar.gz`
   (with `v`) because that matches the actual GitHub release filename.
   Result: `manifest.assets.get(&asset_name)` returned `None`,
   `check_fallback()` returned `None`, the auto-update silently fell
   through to `check_github()` which was rate-limited at 60 req/h
   without an authenticated token. No node could update.

2. **Manifest missing Ed25519 signature.** The `verify_signature()`
   function in `auto_update.rs` rejects updates with empty signature
   (returning `false` and logging
   `"No Ed25519 signature provided — REJECTING unsigned update"`).
   The first manifest deployed had `signature: ""`. SHA256 verified
   fine, then the binary was discarded.

3. **Genesis hash pin without transitional grace period.** v2.9.19
   pinned `EXPECTED_GENESIS_HASH = "007870623724127c..."` and the
   `version_gate_middleware` rejected peers whose `X-TSN-Genesis`
   header didn't match — including the empty string emitted by all
   pre-v2.9.19 nodes (whose own `EXPECTED_GENESIS_HASH` was empty by
   configuration). v2.9.19 seeds therefore refused HTTP traffic from
   the entire pre-v2.9.19 community until v2.9.20 added an
   "empty header = not declared" exemption.

A fourth contributing condition: `epyc1-miner` was running v2.9.15
in `nohup` since 2026-05-01, in a LAN where reorg_lock latency was
zero, so the v2.9.16 mining-orphan bug never manifested for it. It
silently accumulated a private chain ~600 blocks tall by the time the
testnet was reopened. Any node in the same LAN that fast-synced
(notably `epyc2`) inherited this fork — and `max_reorg_depth = 100`
made the divergence permanent.

### Impact
- Public testnet split into 3+ parallel chains, each with similar but
  distinct cumulative work. No clear canonical chain by Nakamoto rule
  for a window of several hours.
- Community auto-update was completely non-functional for ~6 hours.
  Users could not move off v2.9.15 even though v2.9.16 / v2.9.17 /
  v2.9.18 were tagged on GitHub.
- 5 of 5 seeds required manual intervention (force-resync, restart,
  or wipe) to recover.
- `epyc2` user-machine hash power was wasted mining on a fork that no
  seed ever accepted.

### Error type
- **Human**: deploying the manifest by hand (in a hurry, during the
  incident) without running a checksum + asset-key + signature
  validation script. Pinning the genesis hash without thinking through
  the v2.9.15 → v2.9.19 transition window.
- **Code**: `auto_update::check_fallback()` does not log the asset
  key it is looking up — silent `None` made the bug invisible to
  operators. `version_gate_middleware` did not distinguish "missing
  header" from "empty header"; treating them the same would have
  prevented the transitional break.
- **Process**: no pre-publication checklist, no isolated smoke-test of
  the auto-update path before announcement, no canary rollout, no CI
  validation of the manifest before pushing.

### Correction
- Manifest republished with corrected asset key (`tsn-2.9.20-...`,
  no `v`), full SHA256, and valid Ed25519 signature against the
  hardcoded pubkey `8abd0a68...`. Verified from end-to-end on a
  freshly-booted v2.9.15 node in isolation.
- v2.9.20 shipped with the empty-genesis-as-not-declared rule in the
  version gate middleware.
- GitHub Actions `release.yml` workflow extended with an Ed25519
  signing step driven by the `RELEASE_SIGNING_KEY_PEM` secret. Future
  releases auto-publish a signed manifest.
- 5/5 seeds + node-1 received an `ExecStartPre` drop-in that runs
  `/usr/local/bin/tsn-pre-start-check.sh /opt/tsn/data` to detect an
  orphan `tsn` process holding the Sled DB lock and exit cleanly with
  a diagnostic instead of crash-looping.
- All 5 hosts have `KillMode=mixed`, `TimeoutStopSec=10s`,
  `StartLimitIntervalSec=120`, `StartLimitBurst=5` so any future
  crash-loop now stops after 5 attempts in 2 minutes instead of
  running indefinitely.
- `epyc1-miner` stopped to remove the silent solo-fork source.
- All affected nodes brought back to canonical chain via
  `/admin/force-resync` HTTP endpoint or, in one case, data-dir wipe.

### Test added (executable memory)
- `scripts/release-safety/validate-manifest.sh` — fails the build if
  asset key does not match `tsn-{version}-linux-x86_64.tar.gz`, if
  SHA256 doesn't match the actual tarball, if signature is empty, or
  if signature does not verify against the embedded pubkey. Wired
  into CI for every tag push (workflow
  `.github/workflows/release-safety.yml`).
- `scripts/release-safety/auto-update-smoketest.sh` — boots an
  isolated node on the previous supported version, points it at the
  proposed manifest, waits for the auto-update tick, asserts that
  the node ends up on the new version with a working chain. Required
  to pass before any tag is allowed to publish a public manifest.
- `scripts/release-safety/verify-release.sh` — checks that the
  `EXPECTED_GENESIS_HASH` constant in the binary matches the network
  profile (`docs/network-profiles/{network}.md`), and that the
  binary is reproduced from the same commit as the tag claims.
  Refuses to publish a binary whose constants disagree with the target
  network profile.
- `KNOWN_FAILURES.md` entries `KF-001` through `KF-005` (manifest
  asset-key mismatch, missing signature, genesis pin no grace, DB
  lock crash-loop, toxic snapshot serving) each link back to this
  postmortem and to the test that now blocks them.

### Long-tail follow-ups (not blocking, tracked separately)

- Spec 1 (majority-vote fast-sync) — **DONE 2026-05-03**, see
  `KF-007` BLOCKED.
- Spec 3 (auto-trigger reset_for_snapshot_resync on SOLO FORK) —
  **DONE 2026-05-03**, see `KF-009` BLOCKED at watchdog level
  (with cum_work guard against false positives on a legitimate
  faster miner).
- Spec 4 (snapshot-publication quarantine) — **DONE 2026-05-03**,
  see `KF-006` BLOCKED at first level.

- `cumulative_work` drift root cause confirmed and partially
  fixed 2026-05-03 (`KF-008` MITIGATED + DETECTED): the seed
  value at `fast_sync_base` is inherited from the snapshot
  publisher and never reconciled. KF-007's quorum check stops
  propagation at import; a runtime monitor detects existing
  drift and increments a metric; an opt-in env var allows
  operator-controlled correction. True determinism (recompute
  from genesis, or signed-checkpoint cum_work) is a mainnet
  launch blocker, not a testnet blocker.

### Follow-up entry — 2026-05-03 — KF-006/007/008/009 implementation

After the original incident postmortem (above), the four
"NOT YET BLOCKED" failure modes were addressed in code on
2026-05-03 — same branch (`backport-10k`), same testnet-v12
profile, no public release. See `KNOWN_FAILURES.md` for the
exact runtime guardrail per item. Files modified:

- `src/network/cum_work_consensus.rs` (new, ~280 lines, 5 unit
  tests passing): pure-data module providing `observe_peers()`
  and `detect_local_discrepancy()`; serves KF-007/008/009.
- `src/network/sync.rs:~1390` — KF-007 wired into snapshot
  import: cross-checks `cum_work` against peer median.
- `src/network/api.rs::quarantine_reason()` — KF-006 wired into
  `snapshot_info()` and `snapshot_download()` HTTP endpoints.
- `src/main.rs:~5824 watchdog` — KF-009 wired with 4-condition
  trigger (height + persistence + cum_work + kill switch).
- `src/main.rs:~5822 runtime monitor` — KF-008 detection task,
  120s tick.
- `src/core/blockchain.rs:730` —
  `set_cumulative_work_for_drift_correction()` for opt-in
  correction.

Live verification on isolated test node:
- KF-007: log line _"Snapshot cum_work cross-check OK:
  snap_work=32011825153 within 5% of 3 peers' median 32011825153
  (delta=0)"_ during fast-sync.
- KF-006: log line _"snapshot_info: refusing — quarantine: local
  height 0 below 10 (just reset?)"_ after `/admin/force-resync`.
- KF-008: 5 unit tests pass; runtime monitor wired and silent
  (cluster has no detectable drift in this test session).
- KF-009: code paths compile and `test_chainwork_deterministic`
  unit test passes (no consensus regression).

**No public release.** The new binary
(`sha256:1b9603367df8b471049de8017abb527e1de1895a986184e5c3ec1586f9634f6c`)
is held as an RC for staged Ring 0 deploy after operator
review. Per the 2026-05-02 rules, `RELEASE_DECISIONS.md` will
get its entry only after Ring 0 soak.

---

<!-- Append new postmortems above this line. Most recent first. -->
