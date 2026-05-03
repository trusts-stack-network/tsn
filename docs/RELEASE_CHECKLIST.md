# Release Checklist

Mandatory pre-publication checklist. Every TSN release MUST satisfy
**every** item below before the manifest is pushed to a public URL.
Any unchecked item is a publication blocker.

This checklist is **executable, not aspirational**: each item maps to
a script in `scripts/release-safety/` or a CI job in
`.github/workflows/release-safety.yml`. The release-safety workflow
runs on every tag push and rejects publication on any failure.

## When to use

- Cutting a new TSN version (e.g. `v2.9.21` after `v2.9.20`).
- Republishing a manifest (e.g. correcting a metadata error — but
  remember that the binary itself MUST NOT change for the same tag,
  see KF-001).
- Deploying a release to a new ring (Ring 0 → Ring 1 → Ring 2).

## Pre-tag (decision phase)

- [ ] **Network profile target identified.** Either `testnet-v12` or
      `mainnet-v1`. Cross-network releases are forbidden.
- [ ] **Source code committed.** Working tree clean (`git status`
      shows no uncommitted changes). All new logic on a named branch.
- [ ] **Constants in `src/config/mod.rs` match the target profile.**
      For `testnet-v12`: `NETWORK_NAME = "tsn-testnet-v12"`,
      `EXPECTED_GENESIS_HASH = "007870623724127c..."`. For
      `mainnet-v1`: see `docs/network-profiles/mainnet-v1.md`
      (placeholder values forbid release).
- [ ] **`MINIMUM_VERSION` policy reviewed.** Is the bump to a value
      that an existing peer can satisfy via auto-update? If pre-bump
      auto-update is broken, fix it BEFORE bumping `MINIMUM_VERSION`.
- [ ] **Transitional compatibility considered.** If this release
      introduces a new constant value (genesis pin, network name,
      protocol version), is there a transitional rule for peers
      running the previous value? Document the removal-by date for
      the rule in the source comment.
- [ ] **`docs/RELEASE_DECISIONS.md` entry drafted.** All required
      fields filled except `binary_sha256`, `tarball_sha256`, and
      `signature` (those come from the build).

## Build phase

- [ ] **Build via GitHub Actions.** Local builds are forbidden for
      release artifacts (KF-001). The CI build is the single
      canonical artifact.
- [ ] **CI build pulls the exact tagged commit.** Verified via
      `git rev-parse <tag>` matches `commit` in
      `RELEASE_DECISIONS.md`.
- [ ] **Tarball created.** Check size is reasonable (~13 MB
      compressed for v2.9.20).
- [ ] **SHA256 of tarball recorded.** This is the value the manifest
      will sign over.
- [ ] **SHA256 of binary inside tarball recorded.** This is the value
      `verify-release.sh` checks against.

## Manifest phase

- [ ] **Manifest JSON well-formed.** One asset entry. Asset key is
      `tsn-{VERSION}-linux-x86_64.tar.gz` (no `v` prefix). Asset URL
      points at the GitHub release file (which DOES use a `v` prefix).
- [ ] **SHA256 in manifest matches the actual tarball.**
- [ ] **Ed25519 signature present and valid.** Signs SHA256 of the
      tarball with the release private key. Verifies against
      `RELEASE_SIGNING_PUBKEY = 0x8abd0a68...` embedded in the
      binary.
- [ ] **Manifest URL not yet pushed to the public CDN.** Push happens
      only at the end of this checklist.

Run: `scripts/release-safety/validate-manifest.sh ./latest.json <VERSION>`

## Verification phase

- [ ] **`verify-release.sh` passes.** Confirms tarball SHA256, binary
      SHA256, embedded `NETWORK_NAME` string, embedded
      `EXPECTED_GENESIS_HASH` string, and KF-001 dedup (no prior
      version uses the same SHA).
- [ ] **`auto-update-smoketest.sh` passes.** Boots an isolated node
      on the previous supported version, points it at the new
      manifest, asserts the upgrade succeeds end-to-end with a
      working chain after re-exec.
- [ ] **All 5 release-safety CI jobs green.** No skipped jobs unless
      explicitly documented in `RELEASE_DECISIONS.md` for this entry.

Run: `scripts/release-safety/verify-release.sh <TAG> <PROFILE>`
Run: `scripts/release-safety/auto-update-smoketest.sh /path/to/prev-binary <NEW_VERSION>`

## Ring 0 deployment (private cluster)

- [ ] **Backup all 5 seeds + node-1 data_dirs.** Tar.gz pre-deploy.
      Size and checksum recorded in deploy log.
- [ ] **Backup current binary** on each host (`tsn.bak-pre-<TAG>`).
- [ ] **Deploy binary via signed auto-update**, NOT via SCP.
      Confirms KF-001 cannot recur (the canonical signed binary is
      what reaches every host).
- [ ] **Verify version reported on each host** matches the new tag.
- [ ] **Verify chain hash agreement.** All 6 hosts must show the
      same hash at a height where they all have the block (cross-
      verification via `/block/height/N` API).
- [ ] **Verify systemd hardening intact.** `KillMode=mixed`,
      `StartLimitBurst=5`, ExecStartPre `tsn-pre-start-check.sh`
      operational and reachable. `NRestarts` near 0.
- [ ] **24-hour observation window.** Cluster runs without:
      - height divergence > 50 blocks between any two hosts
      - `cumulative_work` regression on any host
      - `STARTUP CONSISTENCY CHECK FAILED` in journal
      - `SOLO FORK confirmed` in journal
      - `NRestarts` > 2 on any host

Document outcome in `RELEASE_DECISIONS.md` as the Ring 0 promotion
line.

## Ring 1 deployment (internal community-facing)

- [ ] **Ring 0 24h soak passed without incident.**
- [ ] **No new postmortem opened during the soak.**
- [ ] **Manifest published to the public URL.** This makes the
      release visible to every community node's auto-update tick.
- [ ] **48-hour Ring 1 observation window**, monitoring:
      - Auto-update tick coverage: how many community peers reach
        new version within 48h. Target: ≥ 80%.
      - Public bug reports, Discord alerts, explorer "solo fork"
        labels.

Document outcome in `RELEASE_DECISIONS.md` as the Ring 1 promotion
line.

## Ring 2 deployment (community broadcast)

- [ ] **Ring 1 48h soak passed.**
- [ ] **Discord announcement posted** in the release channel,
      English, with: version, manifest URL, summary of changes, link
      to the changelog.
- [ ] **Tsnchain.com release page updated** with the new release
      entry.

Document outcome in `RELEASE_DECISIONS.md` as the Ring 2 promotion
line.

## Wipe-resync regression test (run once per cycle, not per release)

To verify that the network's self-recovery rules still work end-to-end:

- [ ] **Wipe one Ring 0 host's data_dir** (preferably seed-3, smallest
      data_dir).
- [ ] **Restart the service.** The pre-start check passes, fast-sync
      starts.
- [ ] **Within 10 minutes**, the node reaches `(height, hash, cum_work)`
      that matches the rest of the cluster.
- [ ] **No toxic snapshot served during recovery** (KF-006 check):
      verify that no Ring 0 peer reset to a low height during the
      recovery window.

Document the run in `docs/POSTMORTEMS.md` as a routine drill (yes,
even routine drills go in the ledger — this is the executable
memory of "we tested this").

## Refusal criteria — DO NOT publish if any apply

- The CI release-safety pipeline has any failed job, even one.
- `RELEASE_DECISIONS.md` is missing the entry for this version.
- The binary `binary_sha256` matches a different version's
  `binary_sha256` from any prior entry (KF-001).
- The manifest signature is empty or does not verify against the
  embedded pubkey.
- The asset key in the manifest has a `v` prefix.
- The genesis hash in `src/config/mod.rs` is empty or different from
  the network profile.
- A mainnet release with any unchecked item in
  `docs/network-profiles/mainnet-v1.md` "Launch blockers".

If any of the above is true and the release is pushed anyway, the
event is a P0 incident and a postmortem MUST be opened.
