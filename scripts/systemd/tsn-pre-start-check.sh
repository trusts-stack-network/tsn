#!/bin/bash
# TSN pre-start check: detect orphan tsn process holding DB lock
# Designed to be called by systemd ExecStartPre= 
# Exits 0 if safe to start, exits 1 with diagnostic if a lock is held

set -u
DATA_DIR="${1:-/opt/tsn/data}"
DB_DIR="${DATA_DIR}/blockchain/db"

# Phase 1: check no orphan tsn process holding the DB
ORPHANS=$(lsof "${DB_DIR}" 2>/dev/null | awk 'NR>1 && $1=="tsn" {print $2}' | sort -u)
if [ -n "$ORPHANS" ]; then
    # Check if these are managed by our systemd unit
    OUR_PID=$(systemctl show tsn-node --property=MainPID --value 2>/dev/null)
    BAD_PIDS=""
    for p in $ORPHANS; do
        if [ "$p" != "$OUR_PID" ] && [ -d "/proc/$p" ]; then
            CMD=$(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')
            BAD_PIDS="$BAD_PIDS $p($CMD)"
        fi
    done
    if [ -n "$BAD_PIDS" ]; then
        echo "ERROR: Orphan tsn process holds DB lock at ${DB_DIR}" >&2
        echo "Offending PIDs:$BAD_PIDS" >&2
        echo "Either kill them manually or wait for them to exit. systemd will not respawn." >&2
        exit 1
    fi
fi

# Phase 2: check Sled lock file isn't stale-held by an unrelated process
LOCK_FILE="${DB_DIR}/db"
if [ -e "${LOCK_FILE}" ]; then
    # Try to acquire fcntl exclusive lock for 1s — if fails, another process holds it
    if ! flock -x -n -E 200 "${LOCK_FILE}" -c true 2>/dev/null; then
        # flock can't tell us which PID holds it, but we already checked above
        echo "WARNING: Sled DB file ${LOCK_FILE} appears locked but no tsn process found" >&2
        # Don't fail here — could be filesystem or other transient
    fi
fi

exit 0
