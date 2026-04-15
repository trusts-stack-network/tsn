# 🔒 Guide Security TSN

Guide complete des bonnes pratiques de security pour Trust Stack Network.

## 🛡️ Security Post-Quantique

### Pourquoi TSN est-il already secure ?

TSN a been designed **from le depart** pour resist aux ordinateurs quantiques — contrairement aux autres blockchains qui devront migrer.

| Composant | Cryptographie classique vulnerable | TSN post-quantique |
|-----------|-----------------------------------|-------------------|
| **Signatures** | ECDSA (Bitcoin), EdDSA (Ethereum) | **ML-DSA-65 (FIPS 204)** |
| **Signatures backup** | RSA | **SLH-DSA (FIPS 205)** |
| **Hash functions** | SHA-256 (secure) | **Poseidon2** (ZK-optimized) |
| **ZK Proofs** | Groth16 (courbes elliptiques) | **Plonky3 STARKs** (hash-based) |
| **Encryption** | AES-GCM | **ChaCha20-Poly1305** |

### Verification de l'integrity crypto

TSN verifies automatically l'integrity des keys de verification ZK :

```bash
# Les checksums sont verified au startup
./target/release/tsn node
# ✓ Using committed verification keys (checksums verified)
```

**Checksums attendus** (circuits/keys/) :
- `spend_vkey.json`: `a1ff15d0968e066b6d8285993580f57065d67fb7ce5625ed7966fd13a8952e27`
- `output_vkey.json`: `c97a5eb20c85009a2abd2f85b1bece88c054e913a24423e1973e0629537ff038`

---

## 🔑 Security des Wallets

### Generation secure

```bash
# Generation d'un wallet avec entropie cryptographic forte
./target/release/tsn new-wallet --output my-secure-wallet.json

# IMPORTANT: Backupz immediately le file JSON !
cp my-secure-wallet.json ~/backup/wallet-$(date +%Y%m%d).json.backup
```

### Protection du file wallet

```bash
# Permissions restrictives (lecture seule pour le owner)
chmod 400 my-wallet.json

# Encryption du wallet (optional)
gpg --symmetric my-wallet.json
rm my-wallet.json  # Supprimer la version non encryptede
```

### Viewing Keys — monitoring sans exposition

TSN support les **viewing keys** pour surveiller un wallet sans exposer les keys de spending :

```bash
# Exporter la viewing key (lecture seule)
./target/release/tsn export-viewing-key --wallet my-wallet.json

# Create un wallet watch-only avec la viewing key
./target/release/tsn import-viewing-key --viewing-key vk1abc... --output watch-only.json
```

**Cas d'usage** :
- Monitoring de solde sur un server non secure
- Comptabilite d'entreprise
- Audit sans access aux fonds

---

## 🏗️ Security des Nodes

### Verification completee des preuves ZK

Par default, TSN uses **assume-valid** pour accelerate la sync. Pour une security maximale :

```bash
# Verify TOUTES les preuves ZK depuis le bloc genesis
./target/release/tsn node --full-verify

# ⚠️  Plus lent mais garantie cryptographic completee
```

### Isolation network

```bash
# Node mineur isolated (pas d'API publique)
./target/release/tsn node --role miner --port 18333 --mine my-wallet.json

# Node relay public avec reverse proxy
./target/release/tsn node --role relay --port 8333 --public-url https://node.example.com
```

### Configuration firewall

```bash
# Ouvrir seulement le port P2P TSN
sudo ufw allow 8333/tcp    # Port principal TSN
sudo ufw allow 9333/tcp    # Port testnet TSN
sudo ufw deny 8333/tcp from any to any port 22  # Bloquer SSH via port TSN
```

### Monitoring et logs

```bash
# Logs de security detailed
RUST_LOG=tsn=debug ./target/release/tsn node

# Metrics en temps real
curl http://localhost:8333/metrics | grep -E "(peers|height|mempool)"
```

---

## 🔍 Verification et Audit

### Verification de l'state de la blockchain

```bash
# Verify l'integrity de la chain local
./target/release/tsn verify-chain

# Comparer avec several peers
curl http://peer1.example.com:8333/chain/info
curl http://peer2.example.com:8333/chain/info
curl http://localhost:8333/chain/info
```

### Audit des nullifiers

Les nullifiers preventsnt le double-spend. Verification manuelle :

```bash
# Verify qu'un nullifier n'a pas been spent
curl -X POST http://localhost:8333/nullifiers/check \
  -H "Content-Type: application/json" \
  -d '{"nullifiers": ["null1abc...", "null2def..."]}'
```

### Validation de transaction avant broadcast

```bash
# Simuler une transaction sans la broadcaster
./target/release/tsn send --wallet my-wallet.json \
  --to tsnaddr1abc... --amount 10.5 --dry-run
```

---

## ⚡ Anti-Attacks Network

### Protection contre les attacks Eclipse

TSN inclut des protections automatic :

| Protection | Description |
|------------|-------------|
| **Seed nodes diversifies** | 4 seed nodes dans different data centers |
| **Kademlia DHT** | Discovery de peers decentralized |
| **Rotation des connections** | Renouvellement automatique des peers |
| **Detection de fork** | Limite de reorganization (100 blocs max) |

### Configuration anti-Sybil

```bash
# Limiter les connections entrantes
./target/release/tsn node --max-inbound-peers 8

# Usesr des peers de trust only
./target/release/tsn node --no-seeds \
  --peer peer1.mycompany.com:8333 \
  --peer peer2.mycompany.com:8333
```

### Rate limiting integrated

TSN limite automatically :
- **Requests API** : 100 req/min par IP
- **Transactions mempool** : 10 tx/min par peer
- **Downloads blocks** : 1 GB/hour par peer

---

## 🚨 Detection d'Intrusions

### Alerts automatic

```bash
# Surveiller les attempts de double-spend
tail -f ~/.tsn/logs/security.log | grep "DOUBLE_SPEND_ATTEMPT"

# Alerts sur les forks suspects
tail -f ~/.tsn/logs/chain.log | grep "REORG_DETECTED"
```

### Metrics de security

```bash
# Verify la health du network
curl http://localhost:8333/network/health

# Exemple de response
{
  "peers_connected": 12,
  "chain_height": 185434,
  "last_block_time": "2026-03-15T14:23:12Z",
  "mempool_size": 7,
  "sync_status": "synced",
  "reorg_alerts": 0
}
```

---

## 🛠️ Recovery d'Urgence

### Backup du wallet

```bash
# Script de backup automatique
#!/bin/bash
WALLET_FILE="my-wallet.json"
BACKUP_DIR="~/crypto-backups/tsn/"
DATE=$(date +%Y%m%d-%H%M)

mkdir -p "$BACKUP_DIR"
cp "$WALLET_FILE" "$BACKUP_DIR/wallet-$DATE.json"
gpg --symmetric "$BACKUP_DIR/wallet-$DATE.json"
rm "$BACKUP_DIR/wallet-$DATE.json"  # Garder seulement la version encryptede

echo "Wallet saved : $BACKUP_DIR/wallet-$DATE.json.gpg"
```

### Recovery depuis un backup

```bash
# Decrypt et restaurer
gpg --decrypt wallet-20260315-1423.json.gpg > my-wallet.json
chmod 400 my-wallet.json

# Verify l'integrity
./target/release/tsn balance --wallet my-wallet.json
```

### Recovery en cas de corruption de node

```bash
# Resync completee depuis des peers
rm -rf ~/.tsn/data/
./target/release/tsn node --fast-sync

# Alternative : resync lente mais plus secure
./target/release/tsn node --full-verify
```

---

## ✅ Checklist Security

### Avant le deployment

- [ ] **Wallet backup** encrypted et tested
- [ ] **Permissions files** restrictives (400)
- [ ] **Firewall** configured (ports 8333/9333 seulement)
- [ ] **Monitoring** logs et metrics actif
- [ ] **Checksums** keys de verification validateds

### Maintenance reguliera

- [ ] **Updates TSN** vers last version stable
- [ ] **Rotation backup** wallets (mensuelle)
- [ ] **Audit peers** connected (verify reputation)
- [ ] **Monitoring reorg** (alerts > 5 blocs)
- [ ] **Test recovery** procedures (trimestriel)

### En cas d'incident

- [ ] **Isoler le node** (couper network)
- [ ] **Backupr l'state** avant investigation
- [ ] **Analyze les logs** pour comprendre l'attack
- [ ] **Resync depuis backup** verified
- [ ] **Signaler** l'incident to l'team TSN

---

## 🔗 Ressources complementaires

- **Audit de code** : Le code TSN sera open-source to la mainnet
- **Bug bounty** : Programme de recompenses expected pour le testnet public
- **Standards crypto** : [FIPS 204](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/post-quantum-cryptography-standards) (ML-DSA), [FIPS 205](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/post-quantum-cryptography-standards) (SLH-DSA)
- **Support security** : security@tsnchain.com

---

*Guide de security TSN v0.4.0 • Last mise to jour : Mars 2026*
*⚠️ La security est une responsabilite shared — suivez toujours les bonnes pratiques*