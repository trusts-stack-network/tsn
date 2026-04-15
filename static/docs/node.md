# 🏗️ Guide Deployment Node TSN

Guide complete pour installer, configurer et deploy un node Trust Stack Network.

## 📋 Prerequisites

### Materiel recommended

| Composant | Minimum | Recommande | Optimal |
|-----------|---------|------------|---------|
| **CPU** | 2 cores 2.0 GHz | 4 cores 3.0 GHz | 8+ cores 3.5+ GHz |
| **RAM** | 4 GB | 8 GB | 16+ GB |
| **Stockage** | 20 GB SSD | 100 GB NVMe | 500+ GB NVMe |
| **Network** | 10 Mbps | 100 Mbps | 1 Gbps |

### Logiciels requis

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential curl git

# Installation Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default stable
```

## 🚀 Installation fast

### 1. Cloner et compiler

```bash
# Cloner le repository
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn

# Compiler en mode release (optimized)
cargo build --release

# Verify l'installation
./target/release/tsn --version
```

### 2. Configuration de base

```bash
# Create le directory de data
mkdir -p ~/.tsn/data

# Generate la configuration par default
./target/release/tsn node --help
```

## 🎯 Types de nodes

TSN propose 4 types de nodes selon vos besoins :

### 🔵 Light Node (Usage personnel)

**Pour** : Portefeuilles, applications lemanagess
**Ressources** : Minimales (2 GB RAM, 10 GB disque)

```bash
# Start un light node
./target/release/tsn node --role light --port 8333

# Avec directory de data custom
./target/release/tsn node --role light \
    --data-dir ~/.tsn/light \
    --port 8334
```

**Fonctionnalites** :
- ✅ Synchronisation des headers de blocs seulement
- ✅ Verification des preuves ZK received
- ✅ Envoi/reception de transactions
- ❌ Pas de minage
- ❌ Ne stocke pas la blockchain completee

### ⛏️ Miner Node (Mining + revenue)

**Pour** : Mineurs cherchant des recompenses
**Ressources** : Moyennes (8 GB RAM, 100 GB disque)

```bash
# Create un wallet pour les recompenses
./target/release/tsn new-wallet --output miner-wallet.json

# Start le mining (4 threads)
./target/release/tsn node --role miner \
    --mine miner-wallet.json \
    --jobs 4 \
    --port 8333
```

**Fonctionnalites** :
- ✅ Synchronisation completee de la blockchain
- ✅ Minage de nouveaux blocs
- ✅ Rewards de bloc (50 TSN currently)
- ✅ Validation des transactions
- ✅ Relais des blocs vers autres nodes

### 🌐 Relay Node (Infrastructure network)

**Pour** : Soutenir le network, relais robuste
**Ressources** : Elevees (16 GB RAM, 500 GB disque)

```bash
# Node relay avec URL publique
./target/release/tsn node --role relay \
    --port 8333 \
    --public-url https://relay.mondomaine.com \
    --data-dir /opt/tsn/data
```

**Fonctionnalites** :
- ✅ Stockage complete de la blockchain
- ✅ Pas de minage (focus sur la stability)
- ✅ Relais haute performance
- ✅ Point d'entry pour autres nodes
- ✅ APIs REST completees

### ℹ️ Note v0.6.0

Le role **Prover** a been deleted en v0.6.0. Les preuves ZK sont henceforth generated directement par les **Miners** lors du minage (PoW + ZK integrateds).

## ⚙️ Configuration advanced

### Variables d'environnement

```bash
# Configuration par env vars
export TSN_PORT=8333
export TSN_DATA_DIR=/opt/tsn/data
export TSN_LOG_LEVEL=info
export TSN_PEERS="peer1.example.com:8333,peer2.example.com:8333"

# Start avec config env
./target/release/tsn node
```

### Fichier de configuration

Create `~/.tsn/config.toml` :

```toml
[network]
port = 8333
peers = [
    "seed1.tsnchain.com:8333",
    "seed2.tsnchain.com:8333"
]
max_peers = 50

[mining]
enabled = true
wallet_file = "wallet.json"
threads = 4
simd_mode = "neon"  # Sur ARM64

[storage]
data_dir = "/opt/tsn/data"
cache_size_mb = 1024

[logging]
level = "info"
file = "/var/log/tsn.log"

[faucet]
enabled = false
wallet_file = "faucet-wallet.json"
daily_limit = 50
```

### Optimisations performance

```bash
# Mode SIMD sur ARM64 (Raspberry Pi, M1/M2)
./target/release/tsn node --mine wallet.json --simd neon

# Fast sync (sync fast depuis snapshot)
./target/release/tsn node --fast-sync

# Plus de threads mining
./target/release/tsn node --mine wallet.json --jobs 8

# Disable les seeds (node isolated)
./target/release/tsn node --no-seeds --force-mine
```

## 🔧 Gestion du service

### Systemd (Linux)

Create `/etc/systemd/system/tsn.service` :

```ini
[Unit]
Description=TSN Node
After=network.target

[Service]
Type=simple
User=tsn
WorkingDirectory=/opt/tsn
ExecStart=/opt/tsn/target/release/tsn node --role miner --mine /opt/tsn/wallet.json
Restart=on-failure
RestartSec=10
Environment=TSN_DATA_DIR=/opt/tsn/data
Environment=TSN_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Activer et start
sudo systemctl enable tsn
sudo systemctl start tsn
sudo systemctl status tsn

# Logs
sudo journalctl -u tsn -f
```

### Docker

```dockerfile
# Dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tsn /usr/local/bin/
EXPOSE 8333
CMD ["tsn", "node", "--role", "relay"]
```

```bash
# Build et run
docker build -t tsn:latest .
docker run -d \
    -p 8333:8333 \
    -v tsn-data:/root/.tsn \
    --name tsn-node \
    tsn:latest
```

## 📊 Monitoring

### Health check

```bash
# Verify l'state du node
curl http://localhost:8333/health

# Informations blockchain
curl http://localhost:8333/chain/info

# Statesttiques mining
curl http://localhost:8333/mining/stats
```

### Metrics importantes

```bash
# Hauteur de la blockchain local
curl http://localhost:8333/chain/height

# Nombre de peers connected
curl http://localhost:8333/network/peers

# Hashrate mining
curl http://localhost:8333/mining/hashrate

# Usage memory
curl http://localhost:8333/system/memory
```

## 🚨 Troubleshooting

### Problems courants

**Sync lente** :
```bash
# Usesr fast sync
./target/release/tsn node --fast-sync

# Verify les peers
curl http://localhost:8333/network/peers
```

**Pas de connection peers** :
```bash
# Ajouter peers manuellement
./target/release/tsn node --peer seed1.tsnchain.com:8333

# Debug network
./target/release/tsn node --log-level debug
```

**Mining ne starts pas** :
```bash
# Solo mining pour test
./target/release/tsn node --force-mine --mine wallet.json

# Verify le wallet
./target/release/tsn balance --wallet wallet.json
```

## 🔐 Security

### Pare-feu

```bash
# Ubuntu/Debian ufw
sudo ufw allow 8333/tcp
sudo ufw enable

# CentOS/RHEL firewalld
sudo firewall-cmd --add-port=8333/tcp --permanent
sudo firewall-cmd --reload
```

### Backup du wallet

```bash
# Backup automatique quotidien
echo "0 2 * * * cp /opt/tsn/wallet.json /opt/tsn/backups/wallet-$(date +\%Y\%m\%d).json" | crontab -
```

### SSL/TLS (nginx)

```nginx
server {
    listen 443 ssl;
    server_name node.mondomaine.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8333;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🌐 Deployment production

### VPS Cloud

**Configuration recommended** :
- 4 vCPU, 8 GB RAM, 100 GB SSD
- Ubuntu 22.04 LTS
- Ports 8333 (TSN), 22 (SSH), 80/443 (HTTP/S)

**Providers tested** :
- DigitalOcean (Droplet Premium Intel)
- AWS (t3.large)
- Hetzner Cloud (CX31)

### Haute availability

```bash
# Load balancer avec HAProxy
backend tsn_nodes
    balance roundrobin
    server node1 10.0.1.10:8333 check
    server node2 10.0.1.11:8333 check
    server node3 10.0.1.12:8333 check
```

---

*Guide Node TSN v0.4.0 • Mis to jour Mars 2026*