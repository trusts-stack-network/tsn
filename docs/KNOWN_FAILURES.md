# Known failure modes

Catalog of failures that have already happened on a TSN network, with
- the signature that lets us detect a recurrence,
- a reproduction recipe,
- the fix that was applied,
- and the **current guardrail** that blocks recurrence.

A failure entry is "BLOCKED" only when there is a CI test or a script
that would fail if the same condition were re-introduced. Until then
it is "MITIGATED" (we know the fix, but a future operator could still
re-introduce it).

---

## KF-001 — Two different binaries shipped under the same version label

**Detected when:** a node reports `tsn 2.9.20` but its `/opt/tsn/bin/tsn`
sha256 does not match the sha256 in the public manifest. Auto-update
signature verification will fail at the next tick.

**Reproduction:** build the binary on machine A, deploy via SCP. Build
again on machine B (or same machine after `cargo clean`), deploy via
GitHub Actions. Both binaries report `--version` as `2.9.20`. They
will have different SHA256 because of build environment differences
(timestamps, host name embedded in debug info, parallel codegen
ordering, etc.). The Ed25519 signature in the manifest only covers
ONE of the two SHA256 values. Nodes running the unsigned binary
cannot prove provenance.

**Real occurrence:** 2026-05-02 — seed-1 and node-1 ended up running
`51483cd89682...` (built locally on epyc1) while seed-2 / seed-3 /
seed-4 / epyc1-miner ran `1e0f1d4ea38d...` (built by GitHub Actions).
Both functionally equivalent, but only the second was signed.

**Fix:** declare exactly one canonical binary per version. The
GitHub Actions build is the canonical one. Local builds are for
development and MUST NOT reach a host serving real network traffic.

**Guardrail (BLOCKED):** `scripts/release-safety/verify-release.sh`
fetches the public manifest, downloads the canonical binary, and
compares its SHA256 against any binary the operator wants to deploy.
Refuses to install a non-canonical binary on a registered host.
Wired into the deployment script as a hard gate.

---

## KF-002 — Manifest with wrong asset key (off-by-`v` prefix)

**Detected when:** `auto_update::check_fallback()` logs
`New release found on fallback manifest current=X available=Y` but
no download follows, then on the next tick the same line repeats.
Or the log is silent — the function returns `None` without
logging which key it failed to find.

**Reproduction:** publish a manifest with
`assets: { "tsn-v2.9.20-linux-x86_64.tar.gz": {...} }`
while the client computes the lookup key as
`tsn-2.9.20-linux-x86_64.tar.gz` (no `v`). `HashMap::get()` returns
`None`. Client falls through to GitHub API, which is rate-limited
to 60 req/h unauthenticated.

**Real occurrence:** 2026-05-02 — the first manifest deployed during
incident response had the `v`-prefixed key. Discovered when
`tail -f miner.log` showed the auto-update detect a new release but
fail to apply, with the log line that does NOT include the missing
key (a logging gap that itself is a sub-bug, see
`auto_update.rs:312`).

**Fix:** manifest asset key MUST be `tsn-{VERSION}-linux-x86_64.tar.gz`
where `{VERSION}` has no `v` prefix. The download URL inside the
asset entry can still be the v-prefixed GitHub release file — the
two are independent.

**Guardrail (BLOCKED):** `scripts/release-safety/validate-manifest.sh`
parses the manifest JSON, derives the expected asset key from the
`version` field, and asserts that the assets map contains exactly
that key. Pipeline fails otherwise. Run by the
`.github/workflows/release-safety.yml` workflow on every tag.

---

## KF-003 — Manifest published without Ed25519 signature

**Detected when:** node logs
`No Ed25519 signature found in manifest — signature check SKIPPED`
followed by
`No Ed25519 signature provided — REJECTING unsigned update.
All releases must be signed with the release signing key.`
The download succeeded, SHA256 matched, the binary is on disk in a
temp directory — but the swap is aborted.

**Reproduction:** deploy a manifest with `"signature": ""` or with no
`signature` field at all. The client `verify_signature()` returns
`false` for the empty case (with the explicit error message above).

**Real occurrence:** 2026-05-02 — when the manifest was first
deployed during incident response, the signing step was forgotten.
Multiple auto-update attempts on community nodes downloaded
13 MB tarballs and discarded them. Wasted bandwidth + 6 hours of
zero-progress on rollout.

**Fix:** every manifest published to a public URL MUST include a
non-empty `signature` field that is the hex Ed25519 signature of the
SHA256 of the binary tarball, signed with the private key whose
public counterpart is `RELEASE_SIGNING_PUBKEY = 0x8abd0a68...` in
`auto_update.rs:37-42`.

**Guardrail (BLOCKED):** `validate-manifest.sh` cryptographically
verifies the signature against the embedded pubkey. Empty signature
or invalid signature both fail the pipeline. The
`.github/workflows/release.yml` workflow runs the signing step
unconditionally and uses the `RELEASE_SIGNING_KEY_PEM` GitHub secret
— if the secret is missing, the workflow itself errors out instead
of producing an unsigned manifest.

---

## KF-004 — Genesis hash pinned without transitional grace period

**Detected when:** seed logs spam
`Rejected peer X.X.X.X (genesis="" != 007870..., offense N/3)` for
every previously-known community peer, and seed traffic suddenly
drops because the seed has banned the entire previous-version
network.

**Reproduction:** in a release that bumps `EXPECTED_GENESIS_HASH`
from `""` to a non-empty value, **without** adding the special case
`Some(g) if !g.is_empty() => g != EXPECTED_GENESIS_HASH` in the
`bad_genesis` check. All pre-bump peers send `X-TSN-Genesis: ""`
(because their own constant was empty), which the seed reads as
"declared genesis = empty string", which is `!= "007870..."`, which
is `bad_genesis = true`, which is a 403 ban with escalating
`offense_count`. Net effect: every old peer gets banned within
seconds.

**Real occurrence:** 2026-05-02 — v2.9.19 introduced the genesis pin
without the empty-tolerant fallback. Seeds began rejecting all
v2.9.15-v2.9.18 community traffic. Fixed in v2.9.20.

**Fix:** any future bump of `EXPECTED_GENESIS_HASH` from one value
to another (including from `""`) MUST be paired with a transitional
rule that tolerates the previous value (or empty). The transitional
rule is a temporary marker — it lives in the source with a
removal-by date and a comment explaining why.

**Guardrail (MITIGATED, not yet BLOCKED):** the transitional rule is
in v2.9.20 source. There is no automated check that future versions
preserve the rule. **TODO**: add a regression test in `tests/` that
boots a node with the previous-version's exact header set and asserts
the request succeeds. Without this test, a future cleanup PR can
silently re-introduce the bug.

---

## KF-005 — DB lock held by orphan process triggers infinite restart loop

**Detected when:** `systemctl status tsn-node` shows `NRestarts: 17000+`
or similar, the journal repeats
`Error: Storage error: Sled error: IO error: could not acquire lock
on "/opt/tsn/data/blockchain/db": Os { code: 11, kind: WouldBlock }`,
and `lsof /opt/tsn/data/blockchain/db | grep tsn` returns a PID that
is NOT the systemd `MainPID`.

**Reproduction:** start a `tsn` process under systemd, then run
another `tsn` process pointed at the same data dir (e.g. via `nohup`
during a rushed deploy). Stop the systemd service. Sled's lock is
held by the orphan, not by the systemd-tracked process. systemd
`Restart=always` immediately spawns a new `tsn`, which fails to
acquire the lock and exits. systemd respawns. The orphan continues
serving (or doesn't). Loop runs indefinitely with `RestartSec=5`.

**Real occurrence:** 2026-05-02 — node-1 at 17,709 restarts; seed-4
at 25,585. Discovered while diagnosing the explorer's "no height"
display.

**Fix:** systemd hardening drop-in:
- `KillMode=mixed` ensures child threads are killed on stop, no
  orphans.
- `Restart=on-failure` (not `always`) avoids respawning after a
  clean shutdown.
- `StartLimitIntervalSec=120` + `StartLimitBurst=5` cap the loop
  at 5 attempts in 2 minutes, after which the service is marked
  `failed` and stays down for human inspection.
- `ExecStartPre=/usr/local/bin/tsn-pre-start-check.sh /opt/tsn/data`
  detects an orphan tsn process holding the lock at boot, lists its
  PID and command line in the journal, and exits 1 to prevent the
  start. Refuses to enter the loop in the first place.

**Guardrail (BLOCKED):** the drop-in is committed at
`scripts/systemd/hardening.conf` and `scripts/systemd/db-lock-check.conf`,
the pre-start script at `scripts/systemd/tsn-pre-start-check.sh`. The
deployment script (`scripts/deploy/install-host.sh`) installs all
three on every host. The CI `release-safety.yml` includes a job that
boots the binary on the runner with a fake orphan and asserts the
pre-start check exits 1.

---

## KF-006 — Toxic snapshot served by a stuck or freshly-reset node

**Detected when:** a node that just appears to recover
(`/admin/force-resync` or wipe + restart) ends up at h=2 or h=4 with
a clearly-wrong tip hash, AND other nodes in the cluster start
ending up at the same wrong tip soon after. The first node was
serving its bad snapshot via HTTP/P2P during recovery.

**Reproduction:** stop a seed, wipe its data, start it. Before it
fast-syncs to a real height, another peer asks it for a snapshot.
The struggling seed serves the snapshot it has on disk (its own
genesis-only state at h=0 or h=2). The peer imports it and now
believes that's the canonical tip.

**Real occurrence:** 2026-05-02 — during the cascade, seed-1 served
its own h=2 snapshot to seed-2 and seed-3 while it was itself in
recovery. Both seeds picked it up and ended up at h=2.

**Fix:** a node MUST NOT serve a snapshot while it is in any of
these states:
- Local height is more than 5 blocks behind the consensus seen from
  other peers.
- Tip hash hasn't progressed monotonically for at least 2 minutes.
- Last `STARTUP CONSISTENCY CHECK FAILED` was within the last 60
  seconds.
- `cumulative_work` is more than 5% below the consensus seen from
  other peers.

**Guardrail (NOT YET BLOCKED — tracked as Spec 4):** the rule is
documented in `incident-2026-05-02/specs/P4-self-repair-specs.md`
as Spec 4 (snapshot-publication quarantine). Not yet enforced in
code. Until enforced, the manual rule is: do not run
`/admin/force-resync` and serve other peers in the same window.
This is one of the launch blockers for mainnet
(`docs/network-profiles/mainnet-v1.md`).

---

## KF-007 — Fast-sync from a single source contaminates the new node

**Detected when:** a freshly-booted node reports a tip that no other
seed can verify. Its `/block/height/N` for canonical N returns a
hash different from every other seed.

**Reproduction:** boot a fresh node with `--peer http://X` where X is
itself on a fork. The node fast-syncs from X and inherits the fork.
With `max_reorg_depth = 100`, if the divergence at the snapshot
height is more than 100 blocks below the canonical tip, the node
will never converge to canonical.

**Real occurrence:** 2026-05-02 — `epyc2` user-machine fast-synced
from `epyc1-miner` (closest LAN peer) which was on a 600-block solo
fork. epyc2 inherited the fork and then mined extending it.

**Fix:** Spec 1 — fast-sync majority-vote. Before importing a
snapshot from peer X, the client polls `/chain/info` on at least
N=3 peers and only proceeds if the (height_band, tip_hash, cum_work)
triple from X matches a cluster of ≥ ⌈N/2⌉+1 peers. If not, the
client enters quarantine mode and retries.

**Guardrail (NOT YET BLOCKED — tracked as Spec 1):** documented in
the spec. Not yet in code. Mainnet launch blocker.

---

## KF-008 — `cumulative_work` drift between same-chain peers

**Detected when:** two nodes with identical tip hash report different
`cumulative_work` values via `/chain/info`. Sometimes after a recent
fast-sync, the freshly-synced node reports a different cum_work than
the node it synced from.

**Reproduction:** boot node A from snapshot at height H1; boot node
B from snapshot at height H2 (H1 != H2). Let both advance to the
same tip. Their `cumulative_work` will differ because the seed value
at H1 vs H2 in the snapshot can be different (one of them was
generated by a node that had its own drift), and v2.9.15's drift
repair logic uses the on-disk seed as ground truth.

**Real occurrence:** 2026-05-02 — seed-1 reported cw=34.3G at the
same hash where node-1 reported cw=32.0G. The difference (~2.3G)
corresponds to ~1100 blocks worth of work — meaningful but
not affecting chain selection in this specific case (because the tip
hash matched).

**Fix:** v2.9.15 fixed one class of drift (consensus-critical drift
between nodes on the same on-disk chain). The remaining drift comes
from snapshots themselves having internally-inconsistent
`cumulative_work` values that propagate via fast-sync.

**Guardrail (NOT YET BLOCKED):** open investigation. Tracked
separately from `incident-2026-05-02`. Not currently a launch
blocker for mainnet because mainnet snapshots will be
seed-signed (KF-006 fix) and seeds will be authoritative on
their own cum_work values.

---

## KF-009 — `epyc1-miner` solo fork from local hashpower asymmetry

**Detected when:** a single internal miner produces blocks faster
than the rest of the network combined; its chain extends past
`max_reorg_depth` from the rest of the network; the rest of the
network can never reorg to it (or vice versa); permanent split.

**Reproduction:** start a miner with `-t 16` (or higher) on a fast
LAN node, while the rest of the network has < 4 threads of mining
power. The single miner's per-block time will be faster than the
network average, so it accumulates a longer chain, but its
difficulty will be lower → cum_work per block lower. Over enough
blocks the cum_work crosses but never within `max_reorg_depth`.

**Real occurrence:** 2026-05-02 — `epyc1-miner` running `-t 16` since
2026-05-01 produced ~600 blocks of solo fork that infected `epyc2`
via LAN fast-sync.

**Fix:** never run a single internal miner with disproportionate
hashpower vs the rest of the network. Either run multiple miners
across hosts, or limit `-t` to a value that doesn't dominate, or
run the host as `--role relay` only.

**Guardrail (MITIGATED, partially BLOCKED):**
- `RELEASE_CHECKLIST.md` step "verify epyc1-miner is in relay role
  or has -t ≤ network-balanced value" — manual.
- A future automated guardrail would have the cluster monitor compute
  cluster-total hashpower and alert when one host exceeds 30% of it.
  Not currently implemented.

---

## Conventions for new entries

When adding a new known failure:
1. Pick the next free `KF-NNN` number.
2. Write the **detected when** signature with concrete log lines or
   command outputs an operator can grep for.
3. The reproduction MUST be runnable in a test harness or sandbox.
4. The guardrail status (BLOCKED / MITIGATED / NOT YET BLOCKED)
   determines if this failure is closed for mainnet purposes.
5. NOT YET BLOCKED items appear in the mainnet launch blocker list
   in `docs/network-profiles/mainnet-v1.md`.
