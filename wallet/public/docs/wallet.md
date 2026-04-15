# 💼 Guide Wallet TSN

Guide complete pour manage vos wallets Trust Stack Network, securiser vos TSN et effectuer des transactions.

## 🎯 Types de wallets

### 🔹 CLI Wallet (Recommande)

**Pour** : Utilisateurs techniques, security maximale
**Security** : Keys private locals, signatures post-quantiques

```bash
# Create un nouveau wallet
./target/release/tsn new-wallet --output my-wallet.json

# Wallet avec mot de passe
./target/release/tsn new-wallet --output secure-wallet.json --password
```

### 🌐 Web Wallet (En development)

**Pour** : Startants, usage quotidien
**Interface** : React/TypeScript dans `/wallet/`
**Status** : Alpha (Q2 2026)

---

## 🚀 First utilisation

### 1. Create votre premier wallet

```bash
# Wallet simple (pour tests)
./target/release/tsn new-wallet --output test-wallet.json

# Wallet secure avec mot de passe
./target/release/tsn new-wallet --output main-wallet.json --password

# Verify la creation
cat main-wallet.json
```

**Structure du wallet** :
```json
{
  "address": "tsn1abcd1234...",
  "private_key": "encrypted_with_chacha20poly1305",
  "public_key": "ml_dsa_65_public_key",
  "version": "0.4.0",
  "created": "2026-03-15T10:30:00Z"
}
```

### 2. Obtenir votre first adresse

```bash
# Afficher l'adresse publique
./target/release/tsn address --wallet main-wallet.json

# Avec QR code (si qr-code activated)
./target/release/tsn address --wallet main-wallet.json --qr
```

**Format adresse TSN** :
- Prefix : `tsn1` (mainnet), `tst1` (testnet)
- Longueur : 62 characters
- Encoding : Bech32m (post-quantique compatible)

### 3. Obtenir des TSN de test

```bash
# Faucet testnet (50 TSN gratuits)
./target/release/tsn faucet --wallet main-wallet.json

# Verify reception
./target/release/tsn balance --wallet main-wallet.json
```

---

## 💰 Gestion des fonds

### Verify le solde

```bash
# Solde simple
./target/release/tsn balance --wallet main-wallet.json

# Solde detailed avec historique
./target/release/tsn balance --wallet main-wallet.json --verbose

# Via node specific
./target/release/tsn balance --wallet main-wallet.json --node http://node.tsnchain.com:8333
```

**Output detailed** :
```
Wallet: tsn1abcd1234...
Balance: 250.5 TSN
Pending: 10.0 TSN (2 transactions)
Total: 260.5 TSN

Recent transactions:
  + 50.0 TSN - Block mining reward (block #1234)
  - 5.5 TSN  - Sent to tsn1efgh5678... (fee: 0.1 TSN)
  + 200.0 TSN - Mining rewards (blocks #1200-1233)
```

### Envoyer des TSN

```bash
# Transaction simple
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5

# Avec commentaire
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5 \
  --memo "Paiement facture #123"

# Transaction avec frais custom
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1recipient... \
  --amount 25.5 \
  --fee 0.05
```

**Frais de transaction** :
- Defaut : 0.1 TSN
- Minimum : 0.01 TSN
- Priority : 0.2 TSN (confirmation fast)

### Historique des transactions

```bash
# 10 last transactions
./target/release/tsn history --wallet my-wallet.json

# Historique complete
./target/release/tsn history --wallet my-wallet.json --all

# Export CSV
./target/release/tsn history --wallet my-wallet.json --export history.csv
```

---

## 🔐 Security advanced

### Protection par mot de passe

```bash
# Ajouter un mot de passe to un wallet existing
./target/release/tsn encrypt-wallet --wallet unprotected.json --output protected.json

# Changer le mot de passe
./target/release/tsn change-password --wallet protected.json
```

### Backup et restauration

```bash
# Backup secure (seed phrase)
./target/release/tsn backup --wallet my-wallet.json --output backup-seed.txt

# Restaurer depuis seed
./target/release/tsn restore --seed backup-seed.txt --output restored-wallet.json

# Backup JSON complete
cp my-wallet.json /secure/location/wallet-backup-2026-03-15.json
```

**Seed phrase format** :
```
TSN_SEED_V1
abandon ability able about above absent absorb abstract absurd abuse access
accident accord account accurate achieve acid acoustic acquire across act action
24_words_total_bip39_compatible_but_ml_dsa_derivation
CHECKSUM: sha256_of_above_words
```

### Multi-signature (Roadmap Q3 2026)

```bash
# Create wallet 2-of-3 multestig
./target/release/tsn new-multestig \
  --threshold 2 \
  --participants 3 \
  --output multestig-wallet.json

# Signer une transaction multestig
./target/release/tsn multestig-sign \
  --wallet my-partial-wallet.json \
  --transaction unsigned-tx.json
```

---

## 🌐 Interface Web Wallet

### Installation local

```bash
# Start le server wallet
cd /opt/tsn/wallet
npm install
npm run dev

# Interface accessible sur http://localhost:5173
```

### Fonctionnalites available

**✅ Disponible (v0.4.0)** :
- Affichage du solde en temps real
- Historique des transactions
- QR codes pour recevoir
- Connexion secure via WebSocket

**🚧 En development (Q2 2026)** :
- Envoi de transactions depuis l'interface
- Multi-wallet management
- Integration hardware wallet (Ledger)
- Wallet connect protocole

### Configuration

Fichier `wallet/src/config.ts` :
```typescript
export const WALLET_CONFIG = {
  // Node TSN to usesr
  nodeUrl: 'http://localhost:8333',

  // WebSocket pour updates temps real
  wsUrl: 'ws://localhost:8333/ws',

  // Theme interface
  theme: 'dark', // 'light' | 'dark' | 'auto'

  // Security
  autoLockMinutes: 15,
  biometricAuth: true
}
```

---

## 📱 Integrations mobiles

### Wallet mobile (Roadmap 2026)

**Plateformes** :
- iOS (Swift + TSN native SDK)
- Android (Kotlin + TSN JNI)

**Fonctionnalites expectedes** :
- Scan QR codes TSN
- Notifications push pour transactions
- Backup cloud encrypted (iCloud/Google Drive)
- Support hardware security module (TEE)

### Export vers autres wallets

```bash
# Export vers format standard
./target/release/tsn export --wallet my-wallet.json --format json --output export.json

# Export key publique only
./target/release/tsn export --wallet my-wallet.json --public-only --output pubkey.json
```

---

## 🔗 Integration developer

### API wallet programmatique

```bash
# Start wallet en mode daemon
./target/release/tsn wallet-daemon --wallet my-wallet.json --port 8334
```

**Endpoints available** :
```bash
# Solde
curl http://localhost:8334/balance

# Nouvel adresse
curl -X POST http://localhost:8334/new-address

# Envoyer transaction
curl -X POST http://localhost:8334/send \
  -H "Content-Type: application/json" \
  -d '{"to": "tsn1...", "amount": "25.5", "memo": "test"}'
```

### SDK integration

**Rust** :
```rust
use tsn_wallet::Wallet;

// Charger wallet
let wallet = Wallet::load("my-wallet.json")?;

// Balance
let balance = wallet.balance().await?;

// Envoyer
let tx = wallet.send("tsn1recipient...", 25.5).await?;
```

**TypeScript/JavaScript** :
```typescript
import { TSNWallet } from '@tsn/wallet-sdk'

const wallet = await TSNWallet.load('my-wallet.json')
const balance = await wallet.getBalance()
await wallet.send('tsn1recipient...', 25.5)
```

---

## 🛠️ Outils advanceds

### Wallet analytics

```bash
# Analyse des patterns de transactions
./target/release/tsn analyze --wallet my-wallet.json --days 30

# Export pour Excel/Sheets
./target/release/tsn analyze --wallet my-wallet.json --export analytics.xlsx
```

### Optimisation performances

```bash
# Compacter l'historique (> 1000 tx)
./target/release/tsn compact --wallet my-wallet.json

# Sync fast after longue absence
./target/release/tsn sync --wallet my-wallet.json --fast

# Verification integrity
./target/release/tsn verify --wallet my-wallet.json
```

### Wallet watch-only

```bash
# Create wallet observation (sans key private)
./target/release/tsn watch-only --address tsn1abcd... --output watch.json

# Surveiller sans pouvoir spend
./target/release/tsn balance --wallet watch.json
```

---

## 🚨 Troubleshooting

### Problems courants

**Wallet corrompu** :
```bash
# Tenter repeer
./target/release/tsn repeer --wallet corrupted.json --output repeered.json

# Restaurer depuis backup
./target/release/tsn restore --seed backup-seed.txt --output new-wallet.json
```

**Transactions blockeds** :
```bash
# Verify statut transaction
./target/release/tsn tx-status --hash 0xabc123...

# Remplacer transaction (fee plus high)
./target/release/tsn replace-tx --wallet my-wallet.json --hash 0xabc123... --fee 0.2
```

**Sync lente** :
```bash
# Changer de node
./target/release/tsn balance --wallet my-wallet.json --node http://fast-node.com:8333

# Mode offline (consultation only)
./target/release/tsn balance --wallet my-wallet.json --offline
```

**Mot de passe oublie** :
```bash
# Si seed phrase available
./target/release/tsn restore --seed backup-seed.txt --output recovered.json

# Bruteforce (wallets test seulement)
./target/release/tsn bruteforce --wallet protected.json --wordlist common-passwords.txt
```

---

## 🏆 Bonnes pratiques

### Security quotidienne

- ✅ **Toujours** usesr un mot de passe fort
- ✅ **Backup** de la seed phrase hors ligne
- ✅ **Verify** les adresses de destination avant envoi
- ✅ **Tester** avec petites sommes en premier
- ❌ **Jamais** partager votre key private ou seed
- ❌ **Avoid** les wallets sur machines publiques

### Organisation multi-wallets

```bash
# Wallet principal (stockage long terme)
./target/release/tsn new-wallet --output hodl-wallet.json --password

# Wallet spending (usage quotidien)
./target/release/tsn new-wallet --output spending-wallet.json --password

# Wallet mining (recompenses automatic)
./target/release/tsn new-wallet --output miner-wallet.json
```

### Planification fiscale

```bash
# Export transactions annuel
./target/release/tsn history --wallet my-wallet.json \
  --from 2026-01-01 --to 2026-12-31 \
  --export taxes-2026.csv

# Calcul plus/moins values
./target/release/tsn tax-report --wallet my-wallet.json --year 2026
```

---

**💎 Votre wallet TSN est votre passeport vers l'economie post-quantique. Protegez-le comme vos bijoux de famille !**

---

*Guide Wallet TSN v0.4.0 • Mis to jour Mars 2026*