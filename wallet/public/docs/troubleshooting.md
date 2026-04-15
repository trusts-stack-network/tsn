# ⚡ Guide Troubleshooting TSN

Solutions aux problems courants encountereds avec Trust Stack Network.

## 🚨 Problems de compilation

### Error : `failed to compile tsn`

**Symptomes :**
```bash
error: failed to compile `tsn v0.4.0`
Caused by: feature `generic_const_exprs` is incompletee
```

**Solutions :**

1. **Verify la version de Rust**
```bash
rustc --version
# Doit be >= 1.75.0

# Si necessary, mettre to jour
rustup update stable
rustup default stable
```

2. **Clean + rebuild complete**
```bash
cargo clean
cargo build --release
```

3. **Dependencies system missings**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential pkg-config libssl-dev

# macOS
brew install openssl
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl
```

### Error de linking : `cannot find -lpq`

**Solution :**
```bash
# Ubuntu/Debian
sudo apt install libpq-dev

# macOS
brew install postgresql
```

---

## 🔌 Problems de network

### Node ne se connecte pas aux peers

**Symptomes :**
```
[WARN] No peers connected after 30 seconds
[ERROR] Failed to sync with network
```

**Diagnostic :**
```bash
# Verify connectivity network
./target/release/tsn node --test-network

# Verify les ports (par default: 8333)
netstat -tuln | grep 8333
```

**Solutions :**

1. **Firewall/NAT**
```bash
# Ouvrir le port TSN (Ubuntu/ufw)
sudo ufw allow 8333

# Test de connectivity
telnet seed1.tsnchain.com 8333
```

2. **Configuration explicite des peers**
```bash
# Forcer les seed nodes
./target/release/tsn node \
  --peers seed1.tsnchain.com:8333,seed2.tsnchain.com:8333
```

3. **Network derriera proxy**
```bash
# Configuration SOCKS5
export ALL_PROXY=socks5://127.0.0.1:9050
./target/release/tsn node
```

### Error : "Invalid commitment root"

**Symptomes :**
```
[ERROR] Block validation failed: Invalid commitment root
[WARN] Rejecting block #1234 from peer
```

**Causes principales :**
- Desynchronization avec le network principal
- Corruption de data locals
- Version obsolete du client

**Solutions :**

1. **Resync completee**
```bash
# Backupr le wallet d'abord !
cp ~/.tsn/wallet.json ~/wallet-backup.json

# Nettoyer les data corrompues
rm -rf ~/.tsn/data/
./target/release/tsn node --resync
```

2. **Verify version client**
```bash
./target/release/tsn --version
# Si < v0.4.0, mettre to jour mandatory
git pull origin main
cargo build --release
```

---

## ⛏️ Problems de mining

### Hashrate very faible

**Symptomes :**
```
[INFO] Mining hashrate: 12.3 H/s (expected: 500+ H/s)
```

**Optimisations :**

1. **Verify SIMD support**
```bash
# Linux : verify les flags CPU
cat /proc/cpuinfo | grep -E "(sse|avx|neon)"

# macOS : verify Apple Silicon
sysctl -n machdep.cpu.brand_string
```

2. **Optimiser les threads**
```bash
# Tester different configurations
./target/release/tsn mine --jobs 1    # Baseline
./target/release/tsn mine --jobs 4    # Standard
./target/release/tsn mine --jobs 8    # High-end

# Surveiller l'utilisation CPU
top -p $(pgrep tsn)
```

3. **Compilation optimized**
```bash
# Build avec optimisations native
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Pour Raspberry Pi (ARMv8)
RUSTFLAGS="-C target-cpu=cortex-a72" cargo build --release
```

### Mining rate = 0

**Diagnostic :**
```bash
# Verify wallet mineur
./target/release/tsn wallet info --file miner-wallet.json

# Tester le hashing
./target/release/tsn benchmark --poseidon --duration 10
```

**Solutions :**

1. **Wallet invalide**
```bash
# Recreate le wallet mineur
./target/release/tsn new-wallet --output new-miner.json
./target/release/tsn mine --wallet new-miner.json
```

2. **Node non synchronized**
```bash
# Attendre sync completee avant mining
./target/release/tsn node --sync-only
# Une fois sync, relancer avec mining
./target/release/tsn node --mine miner-wallet.json
```

---

## 💼 Problems de wallet

### Error : "Insufficient funds"

**Diagnostic :**
```bash
# Verify balance
./target/release/tsn wallet balance --file my-wallet.json

# Verify historique transactions
./target/release/tsn wallet history --file my-wallet.json --limit 10
```

**Solutions :**

1. **Transaction en attente**
```bash
# Lister les transactions pending
./target/release/tsn wallet pending --file my-wallet.json

# Attendre confirmation (2-3 blocs)
./target/release/tsn node info | grep "Current height"
```

2. **Usesr le faucet testnet**
```bash
# Recover l'adresse wallet
ADDR=$(./target/release/tsn wallet address --file my-wallet.json)

# Demander des TSN testnet
curl -X POST https://faucet.tsnchain.com/request \
  -H "Content-Type: application/json" \
  -d "{\"address\": \"$ADDR\"}"
```

### Wallet corrompu

**Symptomes :**
```
[ERROR] Failed to load wallet: Invalid key format
[ERROR] Wallet decryption failed
```

**Solutions :**

1. **Recovery depuis backup**
```bash
# Si backup available
cp ~/wallet-backup.json ~/.tsn/wallet.json

# Verify integrity
./target/release/tsn wallet verify --file ~/.tsn/wallet.json
```

2. **Recovery depuis seed phrase**
```bash
# Restaurer depuis mnemonic
./target/release/tsn wallet recover \
  --mnemonic "word1 word2 ... word24" \
  --output recovered-wallet.json
```

---

## 🔧 Diagnostic system

### Verification completee

```bash
#!/bin/bash
# Script de diagnostic TSN complete

echo "=== TSN System Diagnostic ==="

# 1. Version info
echo "[INFO] TSN Version:"
./target/release/tsn --version

# 2. Network connectivity
echo "[INFO] Network test:"
./target/release/tsn node --test-network --timeout 10

# 3. Crypto benchmarks
echo "[INFO] Performance test:"
./target/release/tsn benchmark --all --duration 5

# 4. Storage check
echo "[INFO] Database status:"
du -sh ~/.tsn/data/
./target/release/tsn node --verify-db --limit 100

# 5. Wallet status
echo "[INFO] Wallet verification:"
./target/release/tsn wallet verify --file ~/.tsn/wallet.json

echo "=== Diagnostic Complete ==="
```

### Logs de debug

```bash
# Activer logs detailed
export RUST_LOG=debug
./target/release/tsn node 2>&1 | tee tsn-debug.log

# Filtrer par composant
export RUST_LOG=tsn::network=debug,tsn::consensus=info
./target/release/tsn node

# Analyze les errors
grep -i error tsn-debug.log | tail -20
```

### Monitoring performance

```bash
# CPU/RAM usage
watch -n 1 'ps aux | grep tsn'

# Network I/O
ss -tuln | grep :8333
netstat -i

# Disk I/O
iotop -p $(pgrep tsn)

# TSN-specific metrics
./target/release/tsn node info --json | jq
```

---

## 📊 Metrics de health

### Indicateurs keys

| Metrique | Normal | Warning | Critical |
|----------|--------|---------|----------|
| **Sync lag** | < 5 blocs | 5-20 blocs | > 20 blocs |
| **Peers** | 8-32 | 3-7 | < 3 |
| **Memory** | < 500 MB | 500 MB - 2 GB | > 2 GB |
| **CPU usage** | < 50% | 50-80% | > 80% |
| **Mining rate** | > 100 H/s | 10-100 H/s | < 10 H/s |

### Monitoring automatested

```bash
#!/bin/bash
# Script monitoring TSN

while true; do
  HEIGHT=$(./target/release/tsn node info | grep height | cut -d: -f2)
  PEERS=$(./target/release/tsn node peers | wc -l)
  MEM=$(ps aux | grep tsn | grep -v grep | awk '{print $6}')

  echo "[$(date)] Height: $HEIGHT | Peers: $PEERS | Memory: ${MEM}KB"

  sleep 30
done
```

---

## 🆘 Support d'urgence

### Contacts fasts

- **GitHub Issues** : [github.com/Trust-Stack-Network/tsn/issues](https://github.com/Trust-Stack-Network/tsn/issues)
- **Discord #support** : [discord.gg/truststack](https://discord.gg/truststack)
- **Email urgent** : support@tsnchain.com

### Informations to fournir

Quand vous reportez un bug, incluez toujours :

1. **Version TSN** : `./target/release/tsn --version`
2. **OS/Architecture** : `uname -a`
3. **Config Rust** : `rustc --version`
4. **Logs d'error** : Les 20 last lignes avec timestamps
5. **Commande exacte** qui generates l'error
6. **Hardware** : CPU, RAM, type de stockage

### Debug advanced

```bash
# Capture completee pour support
{
  echo "=== TSN Debug Report ==="
  date
  ./target/release/tsn --version
  uname -a
  rustc --version
  echo "=== Last errors ==="
  journalctl -u tsn --since "1 hour ago" --no-pager | tail -50
} > tsn-debug-report.txt
```

---

*Guide troubleshooting TSN v0.4.0 • Last mise to jour : Mars 2026*