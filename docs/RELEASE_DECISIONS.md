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
