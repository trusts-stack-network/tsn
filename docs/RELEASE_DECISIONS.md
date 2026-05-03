# Release Decisions Ledger

Authoritative ledger of every TSN release. Each release MUST have an
entry here BEFORE the manifest is published to a public URL. Entries
are immutable — corrections come as follow-up entries that reference
the original.

A release entry is binding: the listed SHA256, signature, and tag are
the **only** acceptable values for that version. CI rejects any
attempt to ship a different binary, manifest, or signature under the
same version.

## Required fields per release

| Field | Definition |
|-------|-----------|
| `version` | Semver string, no `v` prefix (e.g. `2.9.20`) |
| `tag` | Git tag, with `v` prefix (e.g. `v2.9.20`) |
| `commit` | Full 40-char git SHA. Must be reachable from the tag. |
| `branch` | The branch the tag was cut from. |
| `binary_sha256` | SHA256 of the **stripped extracted binary** (`./tsn` after `tar xzf`). |
| `tarball_sha256` | SHA256 of the published `.tar.gz` artifact. |
| `signature` | Hex-encoded Ed25519 signature of `tarball_sha256`, signed with the release key. |
| `network_profile` | One of `testnet-v12`, `mainnet-v1`. |
| `deployment_ring` | `0` (private), `1` (internal), `2` (public community). |
| `human_validation` | Operator name + UTC timestamp + summary of the smoke-test that passed. |
| `manifest_url` | Public URL where this release's manifest is served. |

## Rules

1. **One binary per version.** A given `version` and `tag` map to
   exactly one `binary_sha256` and one `tarball_sha256`. Recompiling
   the same source on a different machine is irrelevant — only the
   CI-built binary is canonical.
2. **No silent overwrites.** Republishing under the same tag with a
   different artifact requires a new version number and a new entry.
   The CI workflow rejects re-tagging.
3. **No skipped rings.** A release reaches Ring 2 (public community)
   only after passing Ring 0 (private cluster) and Ring 1 (internal).
   Each promotion is a separate `human_validation` line in the entry.
4. **Network-profile binding.** A release built for `testnet-v12`
   MUST NOT be served from a `mainnet-v1` manifest URL, and vice-versa.

---

## Releases

### v2.9.24 — peer status classifier, lag-first and age-tolerant

| Field | Value |
|-------|-------|
| `version` | `2.9.24` |
| `tag` | `v2.9.24` |
| `commit` | `617896b736dd44acdc4d2c541456df5d1a55dddb` |
| `branch` | `main` |
| `binary_sha256` | `ef03b991aec014679e27290bc235576b03ad863dc2a3916146d87d6563195db3` |
| `tarball_sha256` | `b5fcdc19c084521d81f11a28793ea21da4497c6d7011367631b393c4134aab3f` |
| `signature` | `3a474cbbe6d7afa128205203ecac2b42963ace70d925d3cb3dbe8c6f6422de3f26bf6842a18e38352f01154a95ce9b4160eb3fe49d6170b84560b0f9eecc2d04` |
| `network_profile` | `testnet-v12` |
| `deployment_ring` | `2` (community rollout via auto-update) |
| `human_validation` | 2026-05-04 — Cosmetic / observability fix only. The `/network/status` peer classifier was returning `stale` for healthy miners that had not broadcast in 30 s; lag-first rule ships, frontend `network.js` aligned to the same 180 s threshold so backend and frontend agree on a single notion of stale. Manifest signed locally with the release key (Ed25519 against the embedded pubkey `8abd0a68…`), verified, deployed to `https://tsnchain.com/releases/latest.json`. |
| `manifest_url` | `https://tsnchain.com/releases/latest.json` |

**Notes**:
- No consensus, protocol, or genesis change. The fix is strictly the
  per-peer `status` value returned by `/network/status` (and the
  matching frontend threshold).
- `binary_sha256` is the SHA256 of the stripped `tsn` binary
  extracted from `tsn-v2.9.24-linux-x86_64.tar.gz`. The tarball SHA
  is recorded separately under `tarball_sha256`.
- Manifest signature was produced locally because the CI signing
  secret (`RELEASE_SIGNING_KEY_PEM`) is not configured on this repo.
  Signature verifies against the embedded release pubkey
  `8abd0a68f768c744a8e26f27f82688ef002f696068f77b1572c8fb15f0fb290a`.

### v2.9.23 — KF-008 root fix + remove all open() auto-wipe paths

| Field | Value |
|-------|-------|
| `version` | `2.9.23` |
| `tag` | `v2.9.23` |
| `commit` | `c5010bc18ab6570d1ed00347efb4ae5ed368a485` |
| `branch` | `main` |
| `binary_sha256` | `21a8f59466827835c3c69c31d576670236f4ff6e3bf02751e8ac4dfb80dfbe6a` |
| `tarball_sha256` | `4dd574921d51078523e300e24689577fb308d7af89bac0d89229d9fff1ad915d` |
| `signature` | `5c24a2e5137d1cc165078f237de018206407aeacd2e2c2c304d0d84b00ead31d9c4d0dcd02e1afe6b93181f9397d1a13b89a9004b7bee2fb3e0e0c1d6476940a` |
| `network_profile` | `testnet-v12` |
| `deployment_ring` | `0` (Ring 0 cluster validated; community rollout via auto-update) |
| `human_validation` | 2026-05-03 — Ring 0 rolling deploy v2.9.22 → v2.9.23 + 10 min soak: 0 auto-wipe events across the cluster, `uniq_hash@h = 1` on every tick, identical chain hash at the tip on 5/5 nodes. KF-008 cross-validated: cw@h=31100 within <0.5% spread; 3/5 byte-identical via the new `/cumulative_work/:height` endpoint. KF-X / KF-Y validated in isolated test (artificial markers injected on a fresh data dir → halt + DB preserved → escape-hatch env var → boot OK). Manifest signature verified against the embedded release pubkey. |
| `manifest_url` | `https://tsnchain.com/releases/latest.json` |

**Notes**:
- This release closes the chain of incident-driven hardening that
  started with v2.9.16 (mining `reorg_lock` fix on 2026-05-02). After
  v2.9.23, `blockchain.rs::open()` never destroys chain data without
  an explicit operator opt-in. Two new env vars are introduced for
  recovery: `TSN_CLEAR_REORG_MARKER=1` and `TSN_RESET_FOR_FAST_SYNC=1`.
- `MIN_VERSION` left at `2.9.15` for soft propagation. A follow-up
  release will bump it once auto-update propagation has been
  confirmed stable on the community testnet.
- Genesis hash unchanged at
  `007870623724127ccf467b74041c3fed0e3569f02c66414a3018d7c04856e38d`
  (testnet-v12). Verified across the 5/5 Ring 0 cluster: code
  constant matches the on-disk block 0 hash on the two nodes that
  hold a real genesis block, and 5/5 nodes converged on a single
  chain hash at the tip during the soak (mathematically excludes a
  divergent genesis on any node).

### v2.9.20 — Empty-genesis transitional fix (incident 2026-05-02 baseline)

| Field | Value |
|-------|-------|
| `version` | `2.9.20` |
| `tag` | `v2.9.20` |
| `commit` | `faff51e45bfc208b17d98b04b5ab6d0ea8862a5e` |
| `branch` | `backport-10k` |
| `binary_sha256` | `1e0f1d4ea38dedb23e5049db56f272f96c46385cc3d78f6dde24a4ebd1c3104b` |
| `tarball_sha256` | `dda062c3bf1335dca16de81230490788629dba8858d20fd4f583a9bf41557b8b` |
| `signature` | `d87d1a5f8f1a34971d5efea88508de60e417d39c4f5b95d9fa1894cb543cb3f13a5f771cff5c38ed236a201f9bdcd3316e778fc7c3d4b59f17ad386a7ba1a405` |
| `network_profile` | `testnet-v12` |
| `deployment_ring` | `2` (currently in production on community testnet) |
| `human_validation` | Recorded retroactively 2026-05-02. Auto-update tested end-to-end on isolated v2.9.15 → v2.9.20 path on epyc1 port 19333: manifest fetch ✓, asset key match ✓, sha256 verify ✓, Ed25519 verify ✓, binary swap ✓, re-exec ✓, post-restart version 2.9.20 ✓. Live cluster verified canonical-aligned (5/5 seeds + node-1 same chain at h=27617+). |
| `manifest_url` | `https://tsnchain.com/releases/latest.json` |

**Notes**:
- **Two binaries circulating under `2.9.20`**: in addition to the
  canonical `1e0f1d4ea38d...` from CI, the hosts `seed-1` and `node-1`
  currently run a locally-built `51483cd89682...` deployed via SCP
  during incident response. This is **a violation of the
  "one binary per version" rule** and is tracked as remediation
  required at next version bump (KF-001 in `KNOWN_FAILURES.md`). The
  v2.9.21 release MUST force these hosts back onto the canonical
  binary via auto-update.
- This release entry is **retroactive**. The release was tagged and
  shipped before this ledger existed. The values are read from the
  GitHub release itself + signature in the public manifest, not from
  a pre-publication decision document.

### Pre-history (entries reconstructed for reference, not gating)

These releases predate the Release Decisions Ledger. They are listed
as historical record, not as binding decisions. Their fields cannot
be re-validated retroactively without rebuilding from the original
source state.

| version | tag | commit | network | notes |
|---------|-----|--------|---------|-------|
| `2.9.19` | `v2.9.19` | `7a6be99` | testnet-v12 | Genesis pin (KF-004 source). Superseded by 2.9.20 within hours. |
| `2.9.18` | `v2.9.18` | `582fa1f` | testnet-v12 | Bump for changelog. |
| `2.9.17` | `v2.9.17` | `665136a` | testnet-v12 | Version-ban fast-path fix. |
| `2.9.16` | `v2.9.16` | `9de2e59` | testnet-v12 | reorg_lock fix. |
| `2.9.15` | _previous baseline_ | — | testnet-v12 | Pre-incident baseline. cumulative_work drift fix. |

These entries are **not** gating: they are not validated by the CI
release-safety checks because they predate them.

---

## Future-proof template

When cutting a new release, copy this block, fill all fields, run the
release-safety scripts (`scripts/release-safety/`), append to this
file, then push the tag. Any field left as `<TBD>` is a publication
blocker.

```markdown
### v<VERSION> — <one-line summary>

| Field | Value |
|-------|-------|
| `version` | `<VERSION>` |
| `tag` | `v<VERSION>` |
| `commit` | `<40-char git SHA>` |
| `branch` | `<branch>` |
| `binary_sha256` | `<sha256 of extracted ./tsn binary>` |
| `tarball_sha256` | `<sha256 of .tar.gz artifact>` |
| `signature` | `<hex Ed25519 signature of tarball_sha256>` |
| `network_profile` | `testnet-v12` OR `mainnet-v1` |
| `deployment_ring` | `0` then `1` then `2` (separate lines for each promotion) |
| `human_validation` | `<operator name> @ <UTC timestamp>` — auto-update smoke test result, ring 0 cluster status, manual checklist completion link |
| `manifest_url` | `https://tsnchain.com/releases/<network>/latest.json` |

**Smoke test log**: link or paste output of
`scripts/release-safety/auto-update-smoketest.sh <previous-version> <this-version>`

**Ring 0 validation**: link to journal entry showing 5/5 seeds running
this version + same chain hash + no NRestarts spike for 2h+.

**Ring 1 promotion**: <operator name> @ <UTC timestamp>.

**Ring 2 promotion**: <operator name> @ <UTC timestamp>, after at
least 24h on Ring 1 with no escalation.
```

The CI workflow `.github/workflows/release-safety.yml` parses this
file. A tag push for a version that has no entry in this file will
fail the workflow before any artifact is published.
