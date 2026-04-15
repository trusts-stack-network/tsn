# 🔧 API Reference TSN

Documentation completee de l'API REST Trust Stack Network pour developers et integrations.

## 📡 URL de base

```
# Local node
http://localhost:8333

# Public nodes
https://api.tsnchain.com
https://node1.tsnchain.com:8333
```

**Format responses** : JSON
**Authentication** : Aucune (lecture), API key (writing)
**Rate limiting** : 100 req/min par IP

---

## 🌐 Endpoints generaux

### GET /health

Statut de health du node.

```bash
curl http://localhost:8333/health
```

**Response** :
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "version": "0.4.0",
  "network": "testnet",
  "sync_status": "synced"
}
```

### GET /info

Informations generals du node.

```bash
curl http://localhost:8333/info
```

**Response** :
```json
{
  "node_id": "tsn_node_abc123",
  "version": "0.4.0",
  "network": "testnet",
  "role": "miner",
  "startup_time": "2026-03-15T10:00:00Z",
  "peers_connected": 12,
  "mining_active": true
}
```

---

## ⛓️ Blockchain API

### GET /chain/info

Informations de la blockchain.

```bash
curl http://localhost:8333/chain/info
```

**Response** :
```json
{
  "height": 1234,
  "latest_hash": "0x1a2b3c4d5e6f...",
  "difficulty": 18,
  "network": "testnet",
  "total_supply": "1234567.89",
  "circulating_supply": "1000000.0"
}
```

### GET /chain/height

Hauteur actuelle de la blockchain.

```bash
curl http://localhost:8333/chain/height
```

**Response** :
```json
{
  "height": 1234
}
```

### GET /block/:height

Recover un bloc par sa hauteur.

```bash
curl http://localhost:8333/block/1234
```

**Response** :
```json
{
  "height": 1234,
  "hash": "0x1a2b3c4d...",
  "previous_hash": "0x9z8y7x6w...",
  "timestamp": "2026-03-15T12:34:56Z",
  "miner": "tsn1abcd1234...",
  "difficulty": 18,
  "nonce": "0x123abc",
  "reward": 50.0,
  "transactions": [...],
  "size_bytes": 2048,
  "signature": "ml_dsa_signature_proof"
}
```

### GET /block/hash/:hash

Recover un bloc par son hash.

```bash
curl http://localhost:8333/block/hash/0x1a2b3c4d...
```

### GET /blocks

Liste des blocs recent avec pagination.

```bash
# 10 derniers blocs
curl http://localhost:8333/blocks

# Avec pagination
curl http://localhost:8333/blocks?limit=50&offset=100
```

**Parameters** :
- `limit` : Nombre de blocs (default: 10, max: 100)
- `offset` : Offset pour pagination
- `order` : `desc` (default) ou `asc`

---

## 💰 Transaction API

### GET /tx/:hash

Recover une transaction par son hash.

```bash
curl http://localhost:8333/tx/0xabc123def456...
```

**Response** :
```json
{
  "hash": "0xabc123def456...",
  "from": "tsn1sender...",
  "to": "tsn1recipient...",
  "amount": "25.5",
  "fee": "0.1",
  "memo": "Payment invoice #123",
  "timestamp": "2026-03-15T12:34:56Z",
  "block_height": 1234,
  "confirmations": 6,
  "status": "confirmed",
  "signature": "ml_dsa_signature_data"
}
```

### POST /tx/submit

Soumettre une nouvelle transaction.

```bash
curl -X POST http://localhost:8333/tx/submit \
  -H "Content-Type: application/json" \
  -d '{
    "from": "tsn1sender...",
    "to": "tsn1recipient...",
    "amount": "25.5",
    "fee": "0.1",
    "memo": "Test transaction",
    "signature": "ml_dsa_signature_proof"
  }'
```

### GET /address/:address/balance

Solde d'une adresse.

```bash
curl http://localhost:8333/address/tsn1abcd.../balance
```

**Response** :
```json
{
  "address": "tsn1abcd...",
  "balance": "250.5",
  "pending": "10.0",
  "total": "260.5"
}
```

### GET /address/:address/history

Historique des transactions d'une adresse.

```bash
curl http://localhost:8333/address/tsn1abcd.../history?limit=20
```

**Parameters** :
- `limit` : Nombre de transactions (default: 10, max: 100)
- `offset` : Offset pour pagination
- `type` : `sent`, `received`, ou `all` (default)

---

## ⛏️ Mining API

### GET /mining/stats

Statesttiques de mining.

```bash
curl http://localhost:8333/mining/stats
```

**Response** :
```json
{
  "mining_active": true,
  "hashrate": 2800000,
  "blocks_mined": 15,
  "shares_submitted": 156,
  "mining_threads": 4,
  "simd_enabled": true,
  "uptime_seconds": 3600,
  "difficulty": 18,
  "estimated_time_next_block": 8.5
}
```

### GET /mining/hashrate

Hashrate actuel du node.

```bash
curl http://localhost:8333/mining/hashrate
```

**Response** :
```json
{
  "hashrate": 2800000,
  "unit": "hashes_per_second",
  "simd_boost": 2.3
}
```

### POST /mining/start

Start le mining (requires API key).

```bash
curl -X POST http://localhost:8333/mining/start \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"wallet": "tsn1miner...", "threads": 4}'
```

### POST /mining/stop

Shutdowner le mining.

```bash
curl -X POST http://localhost:8333/mining/stop \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

## 🌐 Network API

### GET /network/peers

Liste des peers connected.

```bash
curl http://localhost:8333/network/peers
```

**Response** :
```json
{
  "peers_count": 12,
  "peers": [
    {
      "id": "peer_abc123",
      "address": "192.168.1.10:8333",
      "version": "0.4.0",
      "connected_since": "2026-03-15T10:00:00Z",
      "last_seen": "2026-03-15T12:34:56Z",
      "sync_height": 1234,
      "latency_ms": 45
    }
  ]
}
```

### GET /network/discovery

State de la discovery network.

```bash
curl http://localhost:8333/network/discovery
```

**Response** :
```json
{
  "discovery_active": true,
  "known_peers": 45,
  "bootstrap_nodes": 3,
  "kademlia_routing_table_size": 128
}
```

---

## 📊 Metrics API

### GET /metrics

Metrics Prometheus format.

```bash
curl http://localhost:8333/metrics
```

**Response** (format Prometheus) :
```
# HELP tsn_blocks_height Current blockchain height
# TYPE tsn_blocks_height gauge
tsn_blocks_height 1234

# HELP tsn_mining_hashrate Current hashrate
# TYPE tsn_mining_hashrate gauge
tsn_mining_hashrate 2800000

# HELP tsn_peers_connected Number of connected peers
# TYPE tsn_peers_connected gauge
tsn_peers_connected 12
```

### GET /system/memory

Usage memory du node.

```bash
curl http://localhost:8333/system/memory
```

**Response** :
```json
{
  "total_mb": 8192,
  "used_mb": 2048,
  "available_mb": 6144,
  "blockchain_cache_mb": 1024,
  "mempool_size_mb": 64
}
```

### GET /system/cpu

Usage CPU du node.

```bash
curl http://localhost:8333/system/cpu
```

**Response** :
```json
{
  "cpu_count": 8,
  "cpu_usage_percent": 45.2,
  "mining_threads": 4,
  "consensus_threads": 2,
  "network_threads": 2
}
```

---

## 🔍 Explorer API

### GET /explorer/search

Recherche universelle (bloc, transaction, adresse).

```bash
curl http://localhost:8333/explorer/search?q=tsn1abcd...
curl http://localhost:8333/explorer/search?q=0xabc123...
curl http://localhost:8333/explorer/search?q=1234
```

### GET /explorer/richlist

Liste des adresses les plus riches.

```bash
curl http://localhost:8333/explorer/richlist?limit=100
```

### GET /explorer/network-stats

Statesttiques network pour l'explorer.

```bash
curl http://localhost:8333/explorer/network-stats
```

**Response** :
```json
{
  "total_addresses": 5678,
  "total_transactions": 12345,
  "avg_block_time": 10.2,
  "network_hashrate": 150000000,
  "difficulty": 18,
  "next_difficulty_adjustment": 156
}
```

---

## 🔐 Security API

### GET /crypto/validate-signature

Valider une signature ML-DSA.

```bash
curl -X POST http://localhost:8333/crypto/validate-signature \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello TSN",
    "signature": "ml_dsa_signature_data",
    "public_key": "ml_dsa_public_key"
  }'
```

### GET /crypto/proof-verify

Verify une preuve ZK.

```bash
curl -X POST http://localhost:8333/crypto/proof-verify \
  -H "Content-Type: application/json" \
  -d '{
    "proof": "plonky3_proof_data",
    "public_entrys": [...],
    "circuit_id": "transaction_proof_v1"
  }'
```

---

## 📝 Faucet API (Testnet only)

### POST /faucet/request

Demander des TSN de test.

```bash
curl -X POST http://localhost:8333/faucet/request \
  -H "Content-Type: application/json" \
  -d '{"address": "tsn1recipient..."}'
```

**Limites** :
- 50 TSN par adresse par jour
- 1 request par IP par heure
- Captcha requis sur l'interface web

---

## ⚙️ Admin API (API Key requise)

### POST /admin/shutdown

Shutdowner proprement le node.

```bash
curl -X POST http://localhost:8333/admin/shutdown \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### POST /admin/restart-mining

Restart le mining.

```bash
curl -X POST http://localhost:8333/admin/restart-mining \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

### GET /admin/logs

Recover les logs recent.

```bash
curl http://localhost:8333/admin/logs?lines=100 \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

---

## 📡 WebSocket API

### Connexion

```javascript
const ws = new WebSocket('ws://localhost:8333/ws');
```

### Events available

**Nouveaux blocs** :
```json
{
  "type": "new_block",
  "data": {
    "height": 1235,
    "hash": "0x1a2b3c...",
    "miner": "tsn1abcd...",
    "transactions": 15
  }
}
```

**Nouvelles transactions** :
```json
{
  "type": "new_transaction",
  "data": {
    "hash": "0xabc123...",
    "from": "tsn1sender...",
    "to": "tsn1recipient...",
    "amount": "25.5"
  }
}
```

**Mining stats** :
```json
{
  "type": "mining_update",
  "data": {
    "hashrate": 2800000,
    "blocks_mined": 16,
    "difficulty": 18
  }
}
```

---

## 🔧 Configuration API

### GET /config

Configuration actuelle du node.

```bash
curl http://localhost:8333/config
```

### PUT /config/mining (Admin)

Modifier la configuration mining.

```bash
curl -X PUT http://localhost:8333/config/mining \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"threads": 6, "simd": true}'
```

---

## 📚 Integration developer

### SDK JavaScript/TypeScript

```bash
npm install @tsn/sdk
```

```typescript
import { TSNClient } from '@tsn/sdk'

const client = new TSNClient('http://localhost:8333')

// Balance
const balance = await client.getBalance('tsn1abcd...')

// Transaction
const tx = await client.sendTransaction({
  to: 'tsn1recipient...',
  amount: '25.5',
  fee: '0.1'
})

// Subscribe to events
client.onNewBlock((block) => {
  console.log(`New block #${block.height}`)
})
```

### SDK Rust

```toml
[dependencies]
tsn-client = "0.4.0"
```

```rust
use tsn_client::TSNClient;

#[tokio::main]
async fn main() {
    let client = TSNClient::new("http://localhost:8333");

    // Balance
    let balance = client.get_balance("tsn1abcd...").await?;

    // Block info
    let block = client.get_block(1234).await?;
}
```

---

## 🚨 Codes d'error

| Code | Signification | Description |
|------|---------------|-------------|
| 200 | OK | Success |
| 400 | Bad Request | Parameters invalides |
| 401 | Unauthorized | API key missing/invalide |
| 404 | Not Found | Ressource inexisting |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Error internal du node |
| 503 | Service Unavailable | Node en cours de sync |

**Format error** :
```json
{
  "error": {
    "code": 400,
    "message": "Invalid address format",
    "details": "Address must start with 'tsn1' or 'tst1'"
  }
}
```

---

**🚀 Cette API REST vous donne un access complete to la blockchain TSN. Integrez la revolution post-quantique dans vos applications !**

---

*API Reference TSN v0.4.0 • Mis to jour Mars 2026*