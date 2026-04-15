#!/usr/bin/env bash
set -euo pipefail

# Tests rapides dans le container
echo "🔍 Verification binaire…"
/usr/local/bin/tsn --version

echo "🔍 Verification genesis…"
test -f /etc/tsn/genesis.json

echo "🔍 Verification user…"
test "$(id -u)" = "10000"

echo "✅ Container OK"