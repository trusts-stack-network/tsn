# TSN User Guide (Trust Stack Network)

Practical guide for deploying a node, mining, and using the TSN wallet.

## 🔧 Installation fast

### Building from Source
```bash
git clone https://github.com/nicmusic/tsn.git
cd tsn
cargo build --release
```

The binary will be available in `target/release/tsn` or `bin/tsn`.

---

## 🏗️ Deploy un Node TSN

### Basic Node (Observer)

```bash
# Automatically syncs with the testnet
./target/release/tsn node

# Custom port + data directory
./target/release/tsn node --port 8333 --data-dir /var/lib/tsn
```

### Mining Node (Recommended)

```bash
# Mining node with wallet + 4 threads
./target/release/tsn node --mine wallet.json --jobs 4

# ARM/Apple Silicon optimized (NEON SIMD)
./target/release/tsn node --mine wallet.json --jobs 8 --simd neon

# Public node with external URL
./target/release/tsn node --mine wallet.json --public-url https://monnode.com
```

### Environment Configuration

```bash
export TSN_PORT=8333                    # P2P/API port (default: 8333)
export TSN_DATA_DIR=/opt/tsn/data       # Blockchain data
export RUST_LOG=info                   # Log level
```

### Advanced Options

```bash
# Node with built-in faucet (testnet)
./target/release/tsn node --faucet-wallet faucet.json --faucet-daily-limit 50

# Full ZK verification (maximum security)
./target/release/tsn node --full-verify

# Forced mining without sync (dev/solo only)
./target/release/tsn node --mine wallet.json --force-mine

# Private network with custom peers
./target/release/tsn node --no-seeds --peer https://peer1.example.com --peer https://peer2.example.com

# Fast sync (snapshot instead of replay)
./target/release/tsn node --fast-sync
```

---

## ⛏️ Minage TSN

### Basic Commands

```bash
# Create a wallet first
./target/release/tsn new-wallet --output wallet.json

# Continuous mining (Ctrl+C to stop)
./target/release/tsn mine --wallet wallet.json --blockks 0 --jobs 8

# Performance test
./target/release/tsn benchmark --wallet wallet.json --blockks 20 --jobs 4
```

### Performance Optimizations

```bash
# ARM/Apple Silicon
./target/release/tsn mine --wallet wallet.json --simd neon --jobs 8

# x86-64 Servers
./target/release/tsn mine --wallet wallet.json --jobs $(nproc)
```

**Rewards:** 50 TSN per blockk • Target time : ~10s • Auto-adjusted difficulty

---

## 💼 Wallet Management

### Create & Verify

```bash
# New wallet
./target/release/tsn new-wallet --output mon-wallet.json

# Check balance (scans the blockkchain)
./target/release/tsn balance --wallet mon-wallet.json

# Query remote node
./target/release/tsn balance --node http://node.tsnchain.com:8333
```

### Post-Quantum Crypto Structure

Le `wallet.json` contains:
- **spending_key** : ML-DSA-65 (FIPS 204) post-quantum
- **viewing_key** : ChaCha20Poly1305 (32 bytes)
- **address** : Hash Poseidon2 quantum-safe

⚠️ **MANDATORY BACKUP** : `cp wallet.json ~/backup/wallet-$(date +%Y%m%d).json`

---

## 🖥️ API & Essential Commands

### Node REST API

```bash
# Sync status + blockkchain height
curl http://localhost:8333/chain/info

# Block by number
curl http://localhost:8333/blockk/height/100

# Mining stats
curl http://localhost:8333/miner/stats

# Web explorer interface
open http://localhost:8333/explorer

# Web wallet interface
open http://localhost:8333/wallet
```

### Faucet (if enabled)

```bash
# Get test TSN tokens
curl -X POST http://localhost:8333/faucet \
  -H "Content-Type: application/json" \
  -d '{"recipient": "votre_adresse_hex"}'
```

### Debug & Monitoring

```bash
# Detailed logs
RUST_LOG=debug ./target/release/tsn node

# Full integrity check
./target/release/tsn node --full-verify

# Mining performance
RUST_LOG=tsn::consensus=debug ./target/release/tsn mine --wallet wallet.json
```

---

## 🔧 Troubleshooting

### Node not syncing

```bash
# Test seed node connectivity
curl http://seed1.tsnchain.com:9333/chain/info

# Reset data & resync
rm -rf ~/.tsn && ./target/release/tsn node
```

### Error "Invalid commitment root"

```bash
# Force full ZK verification
./target/release/tsn node --full-verify
```

### Slow mining performance

```bash
# ARM : SIMD Neon
./target/release/tsn mine --simd neon --jobs 8

# x86 : all cores
./target/release/tsn mine --jobs $(nproc)
```

---

## 🌐 Network Info

### Mainnet Seed Nodes
- `seed1.tsnchain.com:9333`
- `seed2.tsnchain.com:9333`
- `seed3.tsnchain.com:9333`

### Firewall
```bash
# Open peer port
sudo ufw allow 8333/tcp

# Restrict local API
sudo ufw allow from 127.0.0.1 to any port 8333
```

---

## 🔒 Crypto Technologies

**Post-Quantum Ready:**
- **ML-DSA-65** (FIPS 204) : Quantum-resistant signatures
- **Plonky2 STARKs** : Quantum-safe ZK proofs
- **Poseidon2** : Post-quantum hash function
- **ChaCha20Poly1305** : Symmetric encryption

**Legacy Support:**
- **Groth16 BN254** : Compatibility V1 (sera deprecated)

---

**Support:** [GitHub](https://github.com/Trust-Stack-Network/TSN) • [Discord](https://discord.gg/tsn) • [Docs](https://tsnchain.com/docs)

**Mission:** Building the trust infrastructure for the post-quantum era 🚀