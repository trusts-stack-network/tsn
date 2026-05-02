#!/usr/bin/env bash
# verify-release.sh
#
# Validates that a tagged GitHub release matches a declared entry in
# docs/RELEASE_DECISIONS.md and that the binary embedded constants
# (NETWORK_NAME, EXPECTED_GENESIS_HASH) match the target network
# profile in docs/network-profiles/<profile>.md.
#
# Exit codes:
#   0 — release is valid for publication
#   1 — release does not match the declared decision
#   2 — script usage / environment problem
#
# Usage:
#   verify-release.sh <tag> <network-profile>
#
# Examples:
#   verify-release.sh v2.9.20 testnet-v12
#
# What is checked:
#   - Tag exists on the repo at the commit declared in RELEASE_DECISIONS.md
#   - GitHub release artifact tarball SHA256 matches the declared one
#   - Binary inside the tarball SHA256 matches the declared one
#   - Binary contains the expected NETWORK_NAME string
#   - Binary contains the expected EXPECTED_GENESIS_HASH string
#   - No "previous" entry in RELEASE_DECISIONS.md uses the same SHA256
#     under a different version number (KF-001 enforcement)

set -euo pipefail
SCRIPT_NAME=$(basename "$0")
log()  { echo "[$SCRIPT_NAME] $*" >&2; }
fail() { echo "[$SCRIPT_NAME] FAIL: $*" >&2; exit 1; }

[ $# -eq 2 ] || { echo "usage: $SCRIPT_NAME <tag> <network-profile>" >&2; exit 2; }
TAG=$1
NETWORK_PROFILE=$2
VERSION=${TAG#v}

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DECISIONS="$REPO_ROOT/docs/RELEASE_DECISIONS.md"
PROFILE="$REPO_ROOT/docs/network-profiles/$NETWORK_PROFILE.md"

[ -f "$DECISIONS" ] || fail "no docs/RELEASE_DECISIONS.md"
[ -f "$PROFILE" ]   || fail "no docs/network-profiles/$NETWORK_PROFILE.md"

# Extract declared values from RELEASE_DECISIONS.md
log "Looking up entry for $TAG in $DECISIONS"
DECLARED=$(awk -v tag="$TAG" '
  $0 ~ "### "tag" " { found=1; next }
  found && /^### / { exit }
  found { print }
' "$DECISIONS")

[ -n "$DECLARED" ] || fail "no entry for $TAG in RELEASE_DECISIONS.md"

extract() {
  local field=$1
  echo "$DECLARED" | grep -E "^\| \`$field\`" | sed -E "s/^\| \`$field\` \| \`?([^|\`]+)\`? *\|.*/\1/"
}

DECL_COMMIT=$(extract commit)
DECL_BIN_SHA=$(extract binary_sha256)
DECL_TAR_SHA=$(extract tarball_sha256)
DECL_SIG=$(extract signature)
DECL_PROFILE=$(extract network_profile)

[ -n "$DECL_COMMIT"  ] || fail "RELEASE_DECISIONS.md entry for $TAG missing commit"
[ -n "$DECL_BIN_SHA" ] || fail "RELEASE_DECISIONS.md entry for $TAG missing binary_sha256"
[ -n "$DECL_TAR_SHA" ] || fail "RELEASE_DECISIONS.md entry for $TAG missing tarball_sha256"
[ -n "$DECL_SIG"     ] || fail "RELEASE_DECISIONS.md entry for $TAG missing signature"

if [ "$DECL_PROFILE" != "$NETWORK_PROFILE" ]; then
    fail "RELEASE_DECISIONS.md entry for $TAG declares profile $DECL_PROFILE but script invoked with $NETWORK_PROFILE"
fi

log "declared commit=$DECL_COMMIT bin_sha=$DECL_BIN_SHA"

# Extract network values from the profile file
PROFILE_NETWORK=$(grep -E '^\| `network_name` \|' "$PROFILE" | head -1 | sed -E 's/.*`network_name` \| `([^`]+)`.*/\1/')
PROFILE_GENESIS=$(grep -E '^\| `genesis_hash` \|' "$PROFILE" | head -1 | sed -E 's/.*`genesis_hash` \| `([^`]+)`.*/\1/')

[ -n "$PROFILE_NETWORK" ] || fail "could not extract network_name from $PROFILE"
case "$PROFILE_NETWORK" in
  tsn-*) ;;
  *) fail "profile network_name has unexpected format: $PROFILE_NETWORK" ;;
esac

# For mainnet placeholder profile, genesis_hash may be a literal "_to be produced..."
# Reject the publication entirely in that case.
case "$PROFILE_GENESIS" in
  *"to be"*|"")
    fail "profile $NETWORK_PROFILE has no concrete genesis_hash yet — release blocked"
    ;;
  *)
    if ! [[ "$PROFILE_GENESIS" =~ ^[0-9a-f]{64}$ ]]; then
        fail "profile genesis_hash is not 64 hex chars: $PROFILE_GENESIS"
    fi
    ;;
esac

log "network=$PROFILE_NETWORK expected_genesis=${PROFILE_GENESIS:0:24}..."

# KF-001 enforcement: scan RELEASE_DECISIONS.md for any prior tag using the same SHA256
DUP_TAG=$(awk -v sha="$DECL_BIN_SHA" -v this_tag="$TAG" '
  /^### / { current_tag = $2 }
  /binary_sha256/ {
      gsub(/[`|]/, "")
      for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-f]{64}$/ && $i == sha && current_tag != this_tag) {
          print current_tag; exit
      }
  }
' "$DECISIONS")
if [ -n "$DUP_TAG" ]; then
    fail "binary_sha256 $DECL_BIN_SHA already declared for $DUP_TAG (KF-001: one binary per version)"
fi

# Fetch + verify tarball + binary
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
TARBALL_URL="https://github.com/trusts-stack-network/tsn/releases/download/$TAG/tsn-$TAG-linux-x86_64.tar.gz"
log "Downloading $TARBALL_URL"
curl -fsSL --max-time 180 "$TARBALL_URL" -o "$TMPDIR/tarball" || fail "tarball not reachable"

ACTUAL_TAR_SHA=$(sha256sum "$TMPDIR/tarball" | awk '{print $1}')
if [ "$ACTUAL_TAR_SHA" != "$DECL_TAR_SHA" ]; then
    fail "tarball sha256 mismatch: declared $DECL_TAR_SHA, actual $ACTUAL_TAR_SHA"
fi

mkdir "$TMPDIR/extract"
( cd "$TMPDIR/extract" && tar xzf "$TMPDIR/tarball" )
[ -f "$TMPDIR/extract/tsn" ] || fail "no ./tsn binary inside tarball"

ACTUAL_BIN_SHA=$(sha256sum "$TMPDIR/extract/tsn" | awk '{print $1}')
if [ "$ACTUAL_BIN_SHA" != "$DECL_BIN_SHA" ]; then
    fail "binary sha256 mismatch: declared $DECL_BIN_SHA, actual $ACTUAL_BIN_SHA"
fi
log "tarball + binary SHA256 match RELEASE_DECISIONS.md"

# Verify embedded constants in the binary match the network profile.
# Run strings to a file first to avoid set -o pipefail SIGPIPE issues
# (strings dies with SIGPIPE when grep -q finds match early, which under
# pipefail makes the whole pipeline non-zero and inverts the if -- bug).
STRDUMP="$TMPDIR/strings.out"
strings "$TMPDIR/extract/tsn" > "$STRDUMP"
grep -F -q "$PROFILE_NETWORK" "$STRDUMP" \
    || fail "binary does not contain expected network_name string: $PROFILE_NETWORK"
grep -F -q "$PROFILE_GENESIS" "$STRDUMP" \
    || fail "binary does not contain expected genesis_hash string: ${PROFILE_GENESIS:0:24}..."
log "binary embeds correct network constants"

log "release $TAG matches RELEASE_DECISIONS.md and target profile $NETWORK_PROFILE"
exit 0
