# 🚀 Premiers Pas avec TSN — Guide Startant

**Nouveau dans l'univers blockchain ? Discoversz Trust Stack Network en 10 minutes !**

## 💡 TSN en 3 points keys

### 🛡️ Post-Quantique from le depart
Contrairement to Bitcoin ou Ethereum qui devront migrer, **TSN resiste already aux ordinateurs quantiques**. Vos TSN seront secures same quand Google ou IBM casseront les cryptos actuelles.

### 🔒 Confidentiality par default
Toutes vos transactions sont **private automatically**. Pas besoin de coins specialized comme Monero — TSN integre la confidentiality dans son ADN.

### ⚡ Rapide et efficace
**10 secondes par bloc**, frais minimaux (0.1 TSN), mining accessible same sur Raspberry Pi avec optimisations SIMD.

---

## 🎯 3 parcours selon votre profil

### 👤 **"Je veux juste essayer"** → Light Wallet
```bash
# 1. Download et compiler (5 minutes)
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn && cargo build --release

# 2. Create votre wallet (30 secondes)
./target/release/tsn new-wallet --output my-wallet.json

# 3. Obtenir des TSN testnet (30 secondes)
./target/release/tsn faucet --wallet my-wallet.json

# ✅ Vous avez 50 TSN pour experimenter !
./target/release/tsn balance --wallet my-wallet.json
```

### ⛏️ **"Je veux miner et gagner des TSN"** → Node Mineur
```bash
# After les steps ci-dessus :
# 4. Start le mining (4 threads)
./target/release/tsn node --mine my-wallet.json --jobs 4

# ✅ Votre node mine et vous accumulez 50 TSN par bloc found !
# Surveillez vos gains : curl http://localhost:8333/mining/stats
```

### 🏢 **"Je veux une infrastructure robuste"** → Node Relay
```bash
# After compilation :
# 4. Node relay haute performance
./target/release/tsn node --role relay --port 8333 --public-url https://mon-domaine.com

# ✅ Votre node soutient le network TSN et expose des APIs !
```

---

## 🌟 Votre first transaction TSN

Une fois votre wallet created et approvisionne :

```bash
# 1. Obtenir l'adresse d'un ami (format tsn1...)
# 2. Envoyer vos premiers TSN
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1abc123def456... \
  --amount 5.0 \
  --memo "Mon premier TSN !"

# 3. Transaction confirmed en ~10 secondes ⚡
```

**🎉 Felicitations ! Vous venez d'usesr la first blockchain post-quantique au monde !**

---

## 🔗 Prochaines steps

| Si vous voulez... | Consultez le guide... |
|-------------------|----------------------|
| Optimiser votre mining | [⛏️ Guide Mining](mining.md) |
| Securiser vos TSN | [💼 Guide Wallet](wallet.md) + [🔒 Security](security.md) |
| Deploy in production | [🏗️ Guide Node](node.md) |
| Integrer TSN dans une app | [🔧 API Reference](api.md) |
| Resoudre un problem | [⚡ Troubleshooting](troubleshooting.md) |

---

## ❓ Questions frequentes

**Q: TSN va-t-il vraiment resist aux ordinateurs quantiques ?**
R: Oui ! TSN uses ML-DSA-65 (FIPS 204) et SLH-DSA (FIPS 205), les standards post-quantiques officiels de la NSA/NIST. Bitcoin et Ethereum devront migrer — TSN est already ready.

**Q: Combien je peux gagner en minant ?**
R: Actuellement 50 TSN par bloc (~10 secondes). Avec 4 threads sur CPU moderne, comptez 1-5 blocs par jour selon la difficulty network.

**Q: TSN est-il vraiment private ?**
R: Oui, thanks to aux preuves ZK Plonky3. Seuls l'sender et destinataire connaissent les montants. Le network voit seulement qu'une transaction valide a eu lieu.

**Q: Je peux miner sur Raspberry Pi ?**
R: Absolument ! TSN supporte ARMv8 NEON SIMD. Un Raspberry Pi 4 peut miner efficacement thanks to aux optimisations specializeds.

---

## 🚀 Rejoindre la revolution post-quantique

**TSN n'est pas une blockchain de plus — c'est la blockchain qui survivra to l'era quantique.**

Pendant que les autres projets paniquent face to l'arrivee des ordinateurs quantiques, vous etes already protected. Bienvenue dans le futur de la crypto !

---

🌐 **Communaute** : [Discord](https://discord.gg/truststack) • [GitHub](https://github.com/Trust-Stack-Network/tsn)
🔗 **Explorer** : [explorer.tsnchain.com](https://explorer.tsnchain.com)
📧 **Support** : support@tsnchain.com

*Guide Startant TSN v0.4.0 • Mars 2026*