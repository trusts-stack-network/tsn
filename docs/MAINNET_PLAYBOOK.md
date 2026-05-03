# Mainnet launch playbook

This document is the only authorized procedure for launching
TSN mainnet. Any deviation requires a written approval signed by the
operator and recorded in `RELEASE_DECISIONS.md`.

The mainnet is **not** an upgrade of the testnet. It is a brand new
network with:
- A different `network_name` (`tsn-mainnet-v1` — already reserved).
- A genesis hash produced at launch ceremony, not implicitly.
- A different seed set with documented operators.
- A different manifest URL (NOT the testnet's
  `tsnchain.com/releases/latest.json`).
- Stricter handshake rules (no transitional grace period, no
  empty-header tolerance).
- Authenticated admin endpoints.

## Phase 0 — Launch blockers must all be GREEN

Before any other phase begins, every checkbox in
`docs/network-profiles/mainnet-v1.md` "Launch blockers" section MUST
be GREEN. As of 2026-05-02 they include:

- [ ] `genesis_hash` produced via ceremony and committed to source.
- [ ] 5+ seeds documented with operator identity.
- [ ] `/admin/force-resync` requires authentication.
- [ ] Majority-vote fast-sync rule enforced in code.
- [ ] Snapshot-quarantine rule enforced.
- [ ] Mempool reorg invariants test passing in CI.
- [ ] Per-seed snapshot signing keys registered.
- [ ] End-to-end auto-update test from launch release to launch+1
      passing in CI.
- [ ] All postmortems for testnet incidents reviewed; matching CI
      tests added.
- [ ] No empty / placeholder values in `mainnet-v1.md`.

**No phase below begins until all of the above are checked.**

## Phase 1 — Genesis ceremony

This phase produces the immutable genesis hash that every mainnet
node will check against. It happens once, never repeats.

### Pre-ceremony

1. Create a dedicated branch `mainnet-v1-launch` from the latest
   audited release branch.
2. In `src/config/mod.rs`:
   - `NETWORK_NAME = "tsn-mainnet-v1"`.
   - `EXPECTED_GENESIS_HASH = ""` (to be filled at step 5 of
     ceremony).
   - `MINIMUM_VERSION = "<launch version>"`.
   - Remove any testnet-specific feature flags or transitional
     compatibility rules. In particular:
     - The "empty `X-TSN-Genesis` header is treated as not declared"
       rule (`api.rs:514-518`) MUST be removed.
     - Any `--no-seeds` permissive defaults MUST be tightened.
3. Build a candidate binary in CI on that branch (signed Ed25519,
   recorded in `RELEASE_DECISIONS.md` as `vX.Y.Z-mainnet-genesis-candidate`).
   This candidate is **not** publishable yet.

### Ceremony

4. On a dedicated bootstrap host, with no peers, role=relay, empty
   data dir:
   ```
   tsn node --role relay --port 9333 --data-dir /var/lib/tsn-genesis \
     --no-seeds
   ```
5. Read genesis hash from the API:
   ```
   curl -s http://localhost:9333/block/height/0 | jq -r .hash
   ```
6. Reproduce on a second independent machine with the **same binary
   sha256**. Genesis hash MUST match. If not, halt the ceremony.
7. Commit the genesis hash:
   - Update `EXPECTED_GENESIS_HASH` in `src/config/mod.rs`.
   - Update `genesis_hash` in `docs/network-profiles/mainnet-v1.md`.
   - Tag a new release `vX.Y.Z+1-mainnet-launch` (note the bump:
     the launch binary is NOT the genesis-candidate binary, because
     the constant changed). Commit recorded in
     `RELEASE_DECISIONS.md`.
8. Build the launch binary in CI. New SHA256, new tarball, new
   signature. Recorded in `RELEASE_DECISIONS.md`.

### Post-ceremony

9. Verify on a third machine by replaying the launch binary against
   an empty data dir — the produced genesis MUST match the now-pinned
   constant. (The check is automated by
   `verify-release.sh <launch-tag> mainnet-v1` which extracts the
   constant from the binary and compares it to the profile.)
10. Destroy the genesis-candidate artifacts. Only the launch binary
    is canonical.

## Phase 2 — Mainnet seeds bring-up

Mainnet seeds MUST NOT reuse testnet hosts. The ports, the binary,
the data_dir, the systemd unit, and the SSH access are all
mainnet-specific.

For each of the ≥ 5 mainnet seeds:

1. Provision a dedicated host (NOT a host already running testnet).
2. Install the launch binary at `/opt/tsn/bin/tsn`. The SHA256 MUST
   match `RELEASE_DECISIONS.md` for the launch tag.
3. Install the systemd unit + drop-ins from `scripts/systemd/`.
4. Install `tsn-pre-start-check.sh` at `/usr/local/bin/`.
5. **Mainnet-only hardening**:
   - SSH access via hardware-key-authenticated jump host only.
   - `chattr +i /opt/tsn/bin/tsn` between releases.
   - Off-host snapshot backup every 100 blocks (cron job).
   - Anomaly alerting on `cumulative_work` regression, hash
     divergence, DB-lock contention, auto-update failure.
6. Per-seed snapshot signing key generated, public key registered in
   `docs/network-profiles/mainnet-v1.md`, private key held in HSM
   or similar.
7. Authenticated `/admin/force-resync` endpoint configured (bearer
   token in EnvironmentFile, separate per-seed, rotatable).

Seeds boot one at a time. The first seed starts with empty data dir
and produces block 0 = the genesis (should match the pinned hash).
The next seeds bootstrap from the previous via P2P.

After all seeds are running and synced to the same genesis, the
manifest URL is configured (per-network mainnet manifest URL — NOT
the testnet URL).

## Phase 3 — Mainnet release-safety CI

The release-safety workflow runs the mainnet-specific job
`no-empty-genesis-on-mainnet`. This job blocks any tag pointing at
the mainnet profile if `genesis_hash` is empty or placeholder. It is
the first line of defense against accidentally launching with a
zero-hash mainnet.

`scripts/release-safety/verify-release.sh <tag> mainnet-v1` runs the
same checks as testnet, plus:
- Refuses to validate if the profile has placeholder genesis.
- Cross-checks the binary's `EXPECTED_GENESIS_HASH` literal against
  the profile.

The auto-update smoketest for mainnet uses the launch binary itself
as the "previous version" for the first release after launch (there
is no pre-launch version to upgrade from).

## Phase 4 — Operational rules at and after launch

### No wipes

A wipe on a mainnet seed requires a written incident declaration in
`POSTMORTEMS.md`, signed approval from ≥ 2 operators not running
the affected seed, and a 24-hour re-validation period before the seed
re-enters the authoritative list.

### No transitional compatibility

The "empty X-TSN-Genesis = not declared" rule from testnet v2.9.20 is
**not** in mainnet binaries. Mainnet rejects empty-genesis peers
hard. Any old testnet-only behavior that was tolerated as a
transitional rule MUST be re-audited and removed before mainnet.

### Strict version gate

`MINIMUM_VERSION` on mainnet is bumped only after the new release
has been live in Ring 2 for at least 30 days, with > 95% community
adoption observed.

### No public auto-update tick on day 1

For the first 7 days, the mainnet manifest is held at the launch
version. No auto-update is published, even if a fix is identified.
Hot fixes during the first 7 days are deployed to Ring 0 only,
manually, and require an incident declaration. This avoids the
2026-05-02 pattern of cascading patches that themselves introduced
new bugs.

After day 7, normal release cadence resumes (with the rings, the
checklist, the smoke test).

### Snapshot trust

For the first 30 days, only authoritative seeds may serve snapshots
to fresh nodes. Community nodes can serve snapshots to each other,
but a fresh node MUST cross-check with ≥ 3 authoritative seeds before
accepting a community-served snapshot. This is the majority-vote
fast-sync rule (Spec 1) made non-optional for mainnet.

## Phase 5 — Mainnet-specific incident response

If a postmortem-worthy incident happens on mainnet:

1. **Stop the bleeding first.** If the incident is actively losing
   funds or splitting the chain, restore service from the last
   known-good snapshot. Authoritative seeds may halt and restart
   coordinatedly.
2. **Open a postmortem entry** in `POSTMORTEMS.md` with the
   `[MAINNET P0]` prefix. This entry takes priority over all
   testnet work.
3. **Pause Ring 2.** No new community releases until the postmortem
   has a "Test added" line that demonstrably blocks recurrence.
4. **Communicate.** Public Discord + tsnchain.com banner explaining
   the issue, scope, and ETA.

A mainnet incident that ships an unsigned manifest, an empty genesis
binary, or a release without a `RELEASE_DECISIONS.md` entry is, by
definition, an operator process failure — and the postmortem must
identify which of the gates was bypassed and how to re-tighten it.

## Pre-launch dry run (mandatory)

Before the actual mainnet launch, the entire playbook above MUST be
rehearsed end-to-end on a throwaway "mainnet-rehearsal-1" network:
1. Run the genesis ceremony with throwaway constants.
2. Bring up 5 throwaway seeds.
3. Issue 3 releases using the full RELEASE_CHECKLIST + ring
   promotion process.
4. Stage one synthetic incident (e.g. introduce KF-005 manually on
   one seed) and verify the recovery procedure works.

The rehearsal is documented in `POSTMORTEMS.md` as a routine drill
entry. Only after a clean rehearsal pass does the real mainnet
launch proceed.
