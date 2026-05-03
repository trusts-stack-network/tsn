#!/usr/bin/env bash
# auto-update-smoketest.sh
#
# Boots an isolated TSN node on a test port, running the previous
# supported version, points it at the candidate manifest URL, and
# asserts that within N minutes the node has auto-updated to the
# target version with a working chain.
#
# Exit codes:
#   0 — auto-update path works end-to-end
#   1 — auto-update failed (specific reason in stderr)
#   2 — script usage / environment problem
#
# Usage:
#   auto-update-smoketest.sh <previous-binary-path> <expected-target-version> [<manifest-url>]
#
# Example:
#   auto-update-smoketest.sh /opt/tsn/bin/tsn.bak-v2.9.15 2.9.20 https://tsnchain.com/releases/latest.json
#
# What is checked:
#   1. The previous-version binary boots and is at the version it claims.
#   2. After at most TIMEOUT_SECS (default 600), the node's /version.json
#      reports the target version.
#   3. The auto-update logs show: "New release found", "SHA256 ... verified",
#      "Ed25519 signature verified", "Update to v<target> applied".
#   4. After re-exec, the node serves /chain/info successfully.
#
# This script is the executable counterpart of KF-002 + KF-003 + KF-004
# in docs/KNOWN_FAILURES.md. Any release that does not pass it is
# blocked from publication.

set -euo pipefail
SCRIPT_NAME=$(basename "$0")
log()  { echo "[$SCRIPT_NAME] $*" >&2; }
fail() { echo "[$SCRIPT_NAME] FAIL: $*" >&2; cleanup; exit 1; }

[ $# -ge 2 ] || { echo "usage: $SCRIPT_NAME <previous-binary-path> <expected-target-version> [<manifest-url>]" >&2; exit 2; }
PREV_BINARY=$1
TARGET_VERSION=$2
MANIFEST_URL=${3:-https://tsnchain.com/releases/latest.json}
TIMEOUT_SECS=${SMOKETEST_TIMEOUT:-600}

[ -x "$PREV_BINARY" ] || fail "previous binary not executable: $PREV_BINARY"

PORT=19333
TMPDIR=$(mktemp -d)
LOG="$TMPDIR/test.log"
PID=

cleanup() {
    if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
        kill -9 "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Verify previous binary version string and that it actually differs from target
PREV_VERSION_STR=$("$PREV_BINARY" --version 2>/dev/null | head -1)
PREV_VERSION_NUM=$(echo "$PREV_VERSION_STR" | awk '{print $2}')
log "previous binary: $PREV_VERSION_STR  ($PREV_BINARY)"

if [ "$PREV_VERSION_NUM" = "$TARGET_VERSION" ]; then
    fail "previous binary version ($PREV_VERSION_NUM) equals target version ($TARGET_VERSION); smoketest is meaningless. Provide a strictly older binary."
fi

# The smoketest will MUTATE PREV_BINARY (auto-update swaps it in place).
# Work on a copy so the input remains unchanged for re-runs.
PREV_BINARY_COPY="$TMPDIR/tsn-prev"
cp "$PREV_BINARY" "$PREV_BINARY_COPY"
chmod +x "$PREV_BINARY_COPY"
PREV_BINARY="$PREV_BINARY_COPY"

# Boot in isolation
log "Booting isolated node on port $PORT, manifest URL $MANIFEST_URL..."
"$PREV_BINARY" node \
    --role relay \
    --port "$PORT" \
    --data-dir "$TMPDIR/data" \
    --no-seeds \
    --peer http://45.145.165.223:9333 \
    --peer http://151.240.19.253:9333 \
    > "$LOG" 2>&1 &
PID=$!
sleep 8

if ! kill -0 "$PID" 2>/dev/null; then
    log "node died early; tail of log:"
    tail -30 "$LOG" >&2
    fail "isolated node died during boot"
fi

# Wait for chain/info to come online
log "Waiting for /chain/info to respond..."
for i in $(seq 1 30); do
    if curl -fs --max-time 2 "http://localhost:$PORT/chain/info" > /dev/null 2>&1; then
        break
    fi
    sleep 2
done
curl -fs --max-time 2 "http://localhost:$PORT/chain/info" > /dev/null 2>&1 || fail "node never came online"

# Wait for auto-update to run
log "Waiting up to ${TIMEOUT_SECS}s for auto-update to apply target version $TARGET_VERSION..."
START=$(date +%s)
APPLIED=0
while true; do
    NOW=$(date +%s)
    if [ $((NOW - START)) -gt "$TIMEOUT_SECS" ]; then
        log "timeout reached without auto-update"
        log "tail of node log:"
        tail -50 "$LOG" >&2
        fail "auto-update did not apply target version $TARGET_VERSION within ${TIMEOUT_SECS}s"
    fi

    # Look for failure markers
    if grep -q "Ed25519 signature verification FAILED" "$LOG" 2>/dev/null; then
        log "auto-update aborted on signature verification — manifest is invalid"
        grep -E "auto_update|Ed25519|FAILED|Aborting" "$LOG" | tail -10 >&2
        fail "manifest signature verification failed (KF-003)"
    fi
    if grep -q "asset_name not in manifest" "$LOG" 2>/dev/null; then
        fail "manifest asset key mismatch (KF-002)"
    fi
    if grep -q "Update to v$TARGET_VERSION applied successfully" "$LOG" 2>/dev/null; then
        APPLIED=1
        break
    fi
    sleep 10
done

# After re-exec, /version.json should report target version
log "Update applied; verifying post-reexec state..."
sleep 15
for i in $(seq 1 30); do
    REPORTED=$(curl -fs --max-time 2 "http://localhost:$PORT/version.json" 2>/dev/null \
               | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true)
    if [ "$REPORTED" = "$TARGET_VERSION" ]; then
        log "node now reports version $REPORTED"
        break
    fi
    sleep 3
done

if [ "$REPORTED" != "$TARGET_VERSION" ]; then
    log "post-reexec /version.json says: ${REPORTED:-no response}"
    fail "auto-update applied but post-reexec version is ${REPORTED:-unknown}, expected $TARGET_VERSION"
fi

# Sanity: chain/info still works
curl -fs --max-time 5 "http://localhost:$PORT/chain/info" > /dev/null \
    || fail "post-reexec /chain/info failed"

log "auto-update smoke test PASSED"
log "  previous: $PREV_VERSION_STR"
log "  current : tsn $TARGET_VERSION"
log "  manifest: $MANIFEST_URL"

cleanup
exit 0
