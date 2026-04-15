# Guide Utilisateur Trust Stack Network

Bienvenue dans la documentation completee de **Trust Stack Network (TSN)**, la first blockchain entirely post-quantique avec confidentiality par default.

## 🚀 Premiers pas

### Qu'est-ce que TSN ?

TSN est une blockchain Layer 1 designed from le depart pour :
- **Resistsr aux ordinateurs quantiques** (cryptographie FIPS 204/205)
- **Proteger votre vie private** (transactions encryptedes par default)
- **Etre fast et efficace** (blocs de 10 secondes, preuves ZK optimized)

### Structure de la documentation

| Section | Description |
|---------|-------------|
| [🏗️ **Deploy un Node**](node.md) | Installation et configuration d'un node TSN |
| [⛏️ **Guide Mining**](mining.md) | Tout sur le minage de TSN — configuration, optimisation, recompenses |
| [💼 **Wallet Guide**](wallet.md) | Gestion des wallets, transactions, security |
| [🔧 **API Reference**](api.md) | Documentation completee de l'API REST |
| [⚡ **Troubleshooting**](troubleshooting.md) | Solutions aux problems courants |
| [🔒 **Security**](security.md) | Guide de security et bonnes pratiques |

---

## ⚡ Installation fast

```bash
# 1. Cloner et compiler TSN
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn
cargo build --release

# 2. Create un wallet
./target/release/tsn new-wallet --output my-wallet.json

# 3. Start un node mineur
./target/release/tsn node --mine my-wallet.json --jobs 4
```

**En 3 commandes, votre node TSN mine des blocs et securise le network post-quantique !**

---

## 🎯 Cas d'usage principaux

### 👤 Utilisateur regulier
- [Installer un wallet](wallet.md#installation) pour recevoir et envoyer des TSN
- [Se connecter au network](node.md#node-light) avec un light client
- [Explorer la blockchain](api.md#explorer) via l'interface web

### ⛏️ Mineur
- [Configurer un node mineur](node.md#node-mineur) optimized pour votre materiel
- [Optimiser les performances](mining.md#optimisation) (SIMD, multi-threading)
- [Surveiller les recompenses](mining.md#monitoring) et statesttical

### 🏢 Entreprise/Developpeur
- [Deploy un node infrastructure](node.md#node-relay) (relay ou prover)
- [Integrer l'API TSN](api.md) dans vos applications
- [Configurer un faucet](node.md#faucet) pour testnet

### 🔬 Chercheur/Auditeur
- [Activer la verification completee](security.md#verification) des preuves ZK
- [Acceder aux metrics](api.md#metrics) de performance crypto
- [Examiner le code](security.md#audit) post-quantique

---

## 📊 State du network

| Metrique | Valeur actuelle |
|----------|-----------------|
| **Version** | v0.4.0 |
| **Network** | Testnet private (5 nodes) |
| **Reward bloc** | 50 TSN |
| **Temps de bloc** | ~10 secondes |
| **Difficulty** | Auto-adjusted tous les 10 blocs |
| **Crypto signatures** | ML-DSA-65 (FIPS 204) |
| **Preuves ZK** | Plonky3 STARKs |

---

## 🔮 Pourquoi post-quantique maintenant ?

Les ordinateurs quantiques ne sont plus de la science-fiction :
- **Google Willow** (decembre 2024) peut execute certain calculs en quelques minutes vs. 10^25 annees pour un superordinateur classique
- **IBM vise 100 000+ qubits** d'ici 2033 — sufficient pour casser RSA et ECDSA
- **La NSA recommande** la migration post-quantique **from maintenant**

**TSN ne migrera pas vers le post-quantique — TSN EST post-quantique depuis le jour 1.**

---

## 🤝 Support et communaute

- **GitHub** : [Trust-Stack-Network/tsn](https://github.com/Trust-Stack-Network/tsn)
- **Discord** : [discord.gg/truststack](https://discord.gg/truststack)
- **Site web** : [tsnchain.com](https://tsnchain.com)
- **Explorer** : [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Email** : support@tsnchain.com

---

*Documentation generated pour TSN v0.4.0 • Last mise to jour : Mars 2026*