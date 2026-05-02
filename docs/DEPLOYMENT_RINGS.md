# Deployment Rings

A TSN release does not reach the public network in one step. It moves
through three rings of progressively wider exposure, with explicit
gates between rings. Skipping a ring is forbidden.

The rings exist because the 2026-05-02 incident demonstrated that a
release with a broken auto-update path or a misconfigured manifest
cannot be silently rolled back from the community — the only recovery
is per-host manual intervention. Rings cap that blast radius.

## Ring 0 — Private cluster

**Hosts:**
- `seed-1` (151.240.19.253)
- `seed-2` (45.145.164.76)
- `seed-3` (146.19.168.71)
- `seed-4` (45.132.96.141)
- `node-1` (45.145.165.223, alias nexus)
- 1 local miner on `epyc1` (192.168.1.170) — currently stopped after
  the 2026-05-02 incident; if/when restarted, it MUST be `--role relay`
  or `-t ≤ 4` to avoid the KF-009 hashpower asymmetry that triggered
  the original solo fork.

**Population:** entirely under our direct operational control. Each
host runs the systemd `tsn-node.service` with the hardening drop-ins
in `scripts/systemd/`. Each host is observable from the operator's
shell.

**Promotion criteria:** see `RELEASE_CHECKLIST.md` "Ring 0 deployment"
section. In particular: 24-hour soak with all 6 hosts on the new
version, same chain hash, no `NRestarts > 2`, no `SOLO FORK
confirmed` in journals.

**Manifest visibility:** the new manifest is **NOT** yet published to
the public URL during Ring 0. The Ring 0 hosts are upgraded by hand
(via signed auto-update from a private staging URL, or via the
`/admin/force-resync` endpoint after `scp` of the canonical binary).
This is the only authorized way SCP touches a Ring 0 host for a
release artifact.

## Ring 1 — Operator-controlled community-facing

**Hosts:** any TSN node operated by us but exposed publicly that is
not in Ring 0. Examples: explorer.tsnchain.com backend, monitoring
nodes, mirrors. Currently: empty (we have no Ring 1 hosts beyond
those already in Ring 0 — Ring 1 is reserved for future operator-run
public-facing nodes that aren't authoritative seeds).

**Promotion criteria:** Ring 0 cleared 24-hour soak. No incident
opened during the soak.

**Manifest visibility:** at Ring 1 promotion the public manifest URL
(`https://tsnchain.com/releases/latest.json`) is updated to the new
release. This makes the release available to every community node's
next auto-update tick — but the announcement to the community is held
until Ring 2.

## Ring 2 — Public community

**Hosts:** every TSN node we do not operate. Discovered via P2P
connections, identified in the explorer by their auto-generated names
(see `docs/network-profiles/testnet-v12.md` for the naming
algorithm). Examples seen during the 2026-05-02 incident:
`Aurora-Kernel`, `Stellar-Kernel`, `Stellar-Shield`, `Nexus-Bastion`.

**Promotion criteria:** Ring 1 cleared 48-hour soak. ≥ 80% of
known community peers seen on the new version via auto-update.

**Manifest visibility:** the manifest has been public since Ring 1.
At Ring 2, the release is **announced** to the community via Discord
+ tsnchain.com. The announcement triggers nodes that disabled
auto-update to upgrade manually.

## Forbidden patterns

These were the patterns that caused or amplified the 2026-05-02
incident. They are now banned:

- **Ring-0 skip.** Pushing a tag and immediately publishing the
  manifest. CI release-safety workflow does not enforce this — it
  is a process rule, but the gate is in `RELEASE_CHECKLIST.md`.
- **Local-build deploy.** Building on a developer machine and
  copying the binary to a Ring 0+ host via SCP. The canonical
  artifact is the GitHub Actions build. Local builds are for dev
  only. (KF-001 enforcement.)
- **Mixed rings.** Hosts in Ring 0 running a different version from
  hosts also in Ring 0. Ring 0 is atomic — all hosts upgrade
  together (or are explicitly held back with documented reason).
- **Silent manifest swap.** Updating the manifest URL without
  opening a `RELEASE_DECISIONS.md` entry. CI rejects tag pushes
  that have no entry.
- **Public announce before Ring 1.** Discord posts about a release
  before Ring 1 has been promoted. The community uses such posts as
  a signal to manually update — pushing an unstable release in the
  community via that channel is equivalent to skipping Ring 1.

## Ring 0 access matrix

| Person / role | Ring 0 SSH | Ring 0 manifest deploy | Ring 0 reset |
|---------------|------------|------------------------|--------------|
| Primary operator (tsnchain.com owner) | yes | yes | yes |
| AI assistant under operator supervision | yes (read), yes (with explicit approval per action) | no (operator pushes) | yes for forensic reset only |
| External operator | no | no | no |

`/admin/force-resync` HTTP endpoint is currently **unauthenticated**
on testnet seeds (KF gap, tracked in
`docs/network-profiles/mainnet-v1.md` launch blockers). On testnet
the endpoint is reachable only on `localhost:9333` because the seeds
do not bind 0.0.0.0 for that route — so practical access requires
SSH access first.

## Pre-mainnet hardening of rings

For mainnet (`docs/network-profiles/mainnet-v1.md`), the rings get
stricter:

- Ring 0 expands to ≥ 5 geographically distributed seeds with
  documented operators.
- Ring 0 → Ring 1 gate becomes 72 hours (not 24).
- Ring 1 → Ring 2 gate becomes 7 days (not 48 hours).
- `/admin/force-resync` requires authentication.
- A mainnet release that fails any release-safety check at any ring
  triggers an automatic rollback drill (binary + data_dir + manifest)
  before the next attempt.
