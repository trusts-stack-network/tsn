#!/usr/bin/env bash
# validate-manifest.sh
#
# Validates a TSN auto-update manifest JSON against the rules in
# docs/network-profiles/<network>.md.
#
# Exit codes:
#   0 — manifest is valid
#   1 — manifest is invalid (specific error printed to stderr)
#   2 — script usage error or environment problem
#
# Usage:
#   validate-manifest.sh <manifest-file-or-url> [<expected-version>]
#
# Examples:
#   validate-manifest.sh ./latest.json
#   validate-manifest.sh https://tsnchain.com/releases/latest.json 2.9.20
#
# What is checked:
#   - JSON parses
#   - 'version' field is non-empty semver-ish, matches <expected-version> if given
#   - 'assets' map has exactly one key
#   - asset key matches "tsn-{version}-linux-x86_64.tar.gz" (no 'v' prefix)
#   - asset URL is non-empty https
#   - asset sha256 is 64 hex chars
#   - signature is non-empty 128 hex chars
#   - tarball at asset URL downloads
#   - downloaded tarball sha256 matches manifest sha256
#   - Ed25519 signature verifies against the embedded RELEASE_SIGNING_PUBKEY
#
# This script is the single source of truth for "is this manifest safe
# to publish". The CI pipeline runs it before pushing the manifest to
# the public URL.

set -euo pipefail
SCRIPT_NAME=$(basename "$0")
log()  { echo "[$SCRIPT_NAME] $*" >&2; }
fail() { echo "[$SCRIPT_NAME] FAIL: $*" >&2; exit 1; }

# RELEASE_SIGNING_PUBKEY from src/network/auto_update.rs (raw 32 bytes hex)
EMBEDDED_PUBKEY_HEX="8abd0a68f768c744a8e26f27f82688ef002f696068f77b1572c8fb15f0fb290a"

[ $# -ge 1 ] || { echo "usage: $SCRIPT_NAME <manifest-file-or-url> [<expected-version>]" >&2; exit 2; }
SRC=$1
EXPECTED_VERSION=${2:-}

# Locate the manifest body, regardless of source
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

case "$SRC" in
  http://*|https://*)
    log "Fetching manifest from $SRC"
    curl -fsSL --max-time 30 "$SRC" -o "$TMPDIR/manifest.json" || fail "manifest URL not reachable"
    ;;
  *)
    [ -f "$SRC" ] || fail "manifest file not found: $SRC"
    cp "$SRC" "$TMPDIR/manifest.json"
    ;;
esac

# Parse + structural checks via python (jq not assumed installed)
python3 - <<'PYEOF' "$TMPDIR/manifest.json" "$EXPECTED_VERSION"
import json, re, sys
path, expected_version = sys.argv[1], sys.argv[2]
try:
    m = json.load(open(path))
except Exception as e:
    sys.exit(f"FAIL: cannot parse manifest JSON: {e}")

def fail(msg):
    sys.exit(f"FAIL: {msg}")

if "version" not in m or not m["version"]:
    fail("manifest 'version' field missing or empty")
v = m["version"]
if not re.match(r"^\d+\.\d+\.\d+$", v):
    fail(f"manifest 'version' is not semver: {v!r}")
if v.startswith("v"):
    fail("manifest 'version' must not have 'v' prefix")
if expected_version and v != expected_version:
    fail(f"manifest version {v!r} != expected {expected_version!r}")

if "assets" not in m or not isinstance(m["assets"], dict):
    fail("manifest 'assets' must be a non-empty object")
if len(m["assets"]) != 1:
    fail(f"manifest must have exactly 1 asset, found {len(m['assets'])}")

expected_key = f"tsn-{v}-linux-x86_64.tar.gz"
asset_keys = list(m["assets"].keys())
if asset_keys[0] != expected_key:
    fail(f"asset key mismatch: expected {expected_key!r}, got {asset_keys[0]!r}")

asset = m["assets"][expected_key]
for f in ("url","sha256"):
    if f not in asset or not asset[f]:
        fail(f"asset '{expected_key}' field {f!r} missing or empty")

if not asset["url"].startswith("https://"):
    fail(f"asset URL must be https://, got {asset['url']!r}")
if not re.match(r"^[0-9a-f]{64}$", asset["sha256"]):
    fail(f"asset sha256 not 64 hex chars: {asset['sha256']!r}")

sig = m.get("signature","")
if not sig:
    fail("manifest 'signature' missing or empty")
if not re.match(r"^[0-9a-f]{128}$", sig):
    fail(f"signature not 128 hex chars: length={len(sig)}")

print(asset["url"])
print(asset["sha256"])
print(sig)
PYEOF

# Re-parse to retrieve the values for the next steps.
python3 - <<'PYEOF' "$TMPDIR/manifest.json" > "$TMPDIR/parsed"
import json, sys
m = json.load(open(sys.argv[1]))
asset = list(m["assets"].values())[0]
print(asset["url"])
print(asset["sha256"])
print(m["signature"])
print(m["version"])
PYEOF

URL=$(sed -n 1p "$TMPDIR/parsed")
EXPECTED_SHA=$(sed -n 2p "$TMPDIR/parsed")
SIG_HEX=$(sed -n 3p "$TMPDIR/parsed")
MV=$(sed -n 4p "$TMPDIR/parsed")
log "manifest version=$MV asset_url=$URL"

# Download tarball + verify SHA256
log "Downloading tarball for SHA256 + signature verification..."
curl -fsSL --max-time 180 "$URL" -o "$TMPDIR/tarball" || fail "tarball download failed"
ACTUAL_SHA=$(sha256sum "$TMPDIR/tarball" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    fail "tarball sha256 mismatch: manifest says $EXPECTED_SHA, actual $ACTUAL_SHA"
fi
log "tarball sha256 OK: $ACTUAL_SHA"

# Verify Ed25519 signature
python3 - <<PYEOF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import sys
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex("$EMBEDDED_PUBKEY_HEX"))
try:
    pub.verify(bytes.fromhex("$SIG_HEX"), bytes.fromhex("$EXPECTED_SHA"))
except Exception as e:
    sys.exit(f"FAIL: Ed25519 signature does not verify against embedded pubkey: {e}")
print("[validate-manifest.sh] Ed25519 signature OK", file=sys.stderr)
PYEOF

log "manifest valid"
exit 0
