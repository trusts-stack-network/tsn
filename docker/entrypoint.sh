#!/usr/bin/env bash
set -euo pipefail

# Yuki.T – Script d'entry pour container TSN
# ------------------------------------------------
# Variables d'env avec valeurs par default
TSN_DATA_DIR="${TSN_DATA_DIR:-/data}"
TSN_CHAIN="${TSN_CHAIN:-mainnet}"
TSN_BOOTNODES="${TSN_BOOTNODES:-}"

mkdir -p "$TSN_DATA_DIR"

exec /usr/local/bin/tsn \
  --base-path "$TSN_DATA_DIR" \
  --chain "$TSN_CHAIN" \
  --bootnodes "$TSN_BOOTNODES" \
  --rpc-external --ws-external --rpc-cors all \
  --prometheus-external \
  "$@"