# PLAN - Hybrid Sonnet + Qwen Local: Token Economy

**Created:** 2026-03-09
**Status:** PLANNED
**Last updated:** 2026-03-09

---

## Architecture Hybride

```
SONNET (cerveau/Architect) → planifie, spec, review, diagnostic errors
QWEN3-72B local (workers) → executes, code, iterates with cargo check
```

**Economics de base vs full Sonnet : ~65-70%**

---

## Hardware Recommended

### Option 1 — Rig Ryzen 5600 (Already DISPONIBLE, 0€)
- 1×3090 (24GB) + 4×3060 (48GB) + 1×3060ti (12GB) = 84GB VRAM
- 64GB RAM
- Qwen3-72B Q4 (~42GB) → rbetween en VRAM, ~15-20 tok/s
- **Tester en premier before all achat**

### Option 2 — EPYC + 3×3090 (~1600€ pour 2 × 3090 occasion)
- 3×3090 = 72GB VRAM + 512GB RAM + 256 threads
- Qwen3-72B → all en VRAM, ~20-25 tok/s
- Qwen3-235B-A22B (MoE) → 72GB GPU + 58GB RAM, ~12-18 tok/s
- **Meilleur setup si 72B insufficient sur Rust**

---

## 7 Techniques d'Optimisation

### 1. Qwen first, Sonnet en escalade
- Qwen tente seul la task
- cargo check → passe ? → fini (0 tokens Sonnet)
- cargo check → rate ? → envoie l'error to Sonnet pour diagnostic
- **Economics** : ~30-40% of the tasks simples passent without Sonnet

### 2. Sonnet written the tests, Qwen code
- Sonnet produit only le test unitaire (20 lignes)
- Qwen code up to ce que cargo test passe
- Le test EST la spec — pas besoin de spec detailede
- **Economics** : ~50% de tokens Sonnet output

### 3. Playbooks reusables
- Sonnet written UNE FOIS of the templates pour patterns recurring de TSN :
  - "Pour add un message P2P : 1) enum Message 2) Serialize 3) handler..."
  - "Pour add un endpoint API : 1) route 2) handler 3) types..."
- Stored locally, Qwen les suit without redemander
- **Economics** : 1 appel Sonnet at lieu de N for the same pattern

### 4. Diff-only review
- Quand Qwen finit, Sonnet review UNIQUEMENT le diff git
- Pas le file entier de 800 lignes, juste les +/- (50 lignes)
- **Economics** : ~70% de tokens input sur la review

### 5. Batch planning
- Grouper 3-5 tasks similaires en un seul appel Sonnet
- Sonnet charge le contexte une fois, produit 5 specs of a coup
- Qwen executes sequentially
- **Economics** : 1 appel Sonnet (contexte loaded 1×) at lieu de 5

### 6. Cache de signatures / index local
- Index automatic of the types/traits/fn de TSN (tsn_get_module_api)
- Mis up to date after each commit
- Qwen consulte l'index at lieu de lire les files entiers
- Sonnet has not more besoin de "cartographier" to each task
- **Economics** : ~2-3K tokens input saved par task

### 7. Sonnet "compile" son raisonnement en rules
- After each fix, Sonnet extrait la rule generale :
  - "Dans TSN, all les Hash doivent implement AsRef<[u8; 32]>"
  - "Les messages P2P doivent derive Clone + Debug + Serialize"
- Rules saved locally → Qwen les applique automaticment
- **Economics** : avoids de rediscover les same errors

---

## Estimation Economics Cumulative

| Metric | Full Sonnet | Hybride basique | Hybride + 7 techniques |
|----------|-------------|-----------------|------------------------|
| Tokens Sonnet/task | ~38K | ~12K | **~4-5K** |
| Tasks passant par Sonnet | 100% | 100% | **60-70%** |
| Tokens Sonnet/jour (7 bots, 30-50 tasks) | ~1.5M | ~500K | **~150-200K** |
| **Reduction vs full Sonnet** | — | -65% | **-87-90%** |

---

## Implementation in tsn-team

### Files to modifier
- `bots/base.py` — add logique escalade Qwen→Sonnet
- `config.py` — config dual-model (MODEL_BRAIN + MODEL_WORKER)
- `bots/base.py` — cache playbooks + rules locales
- `scripts/build_signatures_index.py` — to create (index types/traits)

### Flow par task
```
1. Bot receives task
2. Consulte playbooks + rules locales
3. Qwen tente seul (contexte chirurgical + tools)
4. cargo check / cargo test
5. Si pass en <3 iterations → DONE (0 Sonnet)
6. Si fail → envoie error + contexte minimal to Sonnet
7. Sonnet diagnostique, renvoie fix precise
8. Qwen applique → cargo check → boucle
9. Sonnet review le diff final (optionnel)
10. Si new rule discovery → saved en local
```

### Metrics to logger
- `sonnet_tokens_used` — tokens Sonnet consumed par task
- `qwen_tokens_used` — tokens Qwen consumed par task
- `escalation_count` — nombre de fois where Qwen a escalated to Sonnet
- `cargo_check_iterations` — nombre d'iterations before pass
- `task_success_rate` — tto de success par model
- `playbook_hits` — nombre de fois that a playbook a been reused

---

## Priority de test

1. **Install Qwen3-72B sur le Ryzen** (0€, tester si suffisant comme worker Rust)
2. **Implement technique #1** (escalade Qwen→Sonnet) in bots/base.py
3. **Implement technique #2** (Sonnet written tests, Qwen implements)
4. **Mesurer** during 1 semaine with les metrics ci-dessus
5. **Decide** si upgrade EPYC + 3×3090 + Qwen3-235B vaut le coup
