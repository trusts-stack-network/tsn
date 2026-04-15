# TSN Fuzzing Suite - Chasse aux Panics

**Auteur**: Marcus.R (Security & QA Engineer)  
**Objectif**: Detect les vulnerabilities critiques dans les deserializers TSN

## 🎯 Vue d'ensemble

Cette suite de fuzzers ultra-agressifs est designed pour detect les **panics non managed** dans les deserializers de transactions et blocs TSN. Chaque panic detected indique une **vulnerability critique** qui pourrait be exploited par un attacker pour crasher des nodes du network.

### 🚨 Absolute rule
**Aucun deserializer ne doit jamais paniquer**, same avec des data completeely corrompues ou malveillantes. Tout panic = vulnerability to corriger immediately.

## 🔧 Fuzzers implementeds

### 1. `panic_hunter_deserialize.rs`
**Fuzzer principal ultra-agressif**

- **Stack overflow** : Structures nested infiniment
- **Integer overflow** : Valeurs proches de MAX/MIN
- **Memory exhaustion** : Allocations massives
- **Corrupted lengths** : Longueurs inconsistent
- **Malformed signatures** : Signatures crypto corrompues
- **Timing attacks** : Mesure des variations temporelles
- **Hybrid V1/V2** : Mix des versions de protocole
- **Boundary conditions** : Valeurs limites des types
- **Recursion bombs** : References circulaires
- **Null pointer deref** : Conditions de dereference null

### 2. `deserialize_property_fuzzer.rs`
**Property-based testing pour invariants**

- **Idempotence** : `deserialize(serialize(x)) == x`
- **Determinism** : Results reproductibles
- **Robustesse** : Resistance aux data corrompues
- **Business invariants** : Respect des rules business
- **Security properties** : Properties de security

### 3. `network_deserialize_fuzzer.rs`
**Fuzzer specialized network**

- **Malformed messages** : Messages network corrompus
- **Oversized payloads** : Attacks DoS par taille
- **Protocol confusion** : Mix de protocoles
- **Message fragmentation** : Messages partiels
- **Timing attacks** : Fuites temporelles network
- **Memory exhaustion** : Exhaustsment memory via network

## 🚀 Utilisation

### Installation des dependencies
```bash
# Installer cargo-fuzz
cargo install cargo-fuzz

# Installer GNU parallel (optional, for parallelization)
sudo apt-get install parallel  # Ubuntu/Debian
brew install parallel          # macOS
```

### Lancement fast
```bash
# Lancer tous les fuzzers pendant 5 minutes
cd fuzz/
chmod +x run_panic_hunters.sh
./run_panic_hunters.sh
```

### Lancement customized
```bash
# Fuzzing plus long (30 minutes par fuzzer)
FUZZ_TIME=1800 ./run_panic_hunters.sh

# Plus de jobs parallel
PARALLEL_JOBS=8 ./run_panic_hunters.sh

# Fuzzer individuel
cargo fuzz run panic_hunter_deserialize --release -- -max_len=1048576
```

### Analyse des results
```bash
# Voir les logs detailed
ls fuzz_logs/
cat fuzz_logs/panic_hunter_deserialize.log

# Examiner les artefacts de crash
ls fuzz_results/
hexdump -C fuzz_results/panic_hunter_deserialize_artifacts/crash-*
```

## 📊 Interprstateion des results

### ✅ Result normal
```
✅ panic_hunter_deserialize: Completed normally (timeout)
✅ Aucune vulnerability critique detected
```

### 🚨 Vulnerability detected
```
🚨 panic_hunter_deserialize: PANIC DETECTED - VULNERABILITY CRITIQUE!
   Voir les details dans: fuzz_logs/panic_hunter_deserialize.log
   Artefacts saved dans: fuzz_results/panic_hunter_deserialize_artifacts/
```

**Action requise** : Analyze immediately le panic et corriger la vulnerability.

## 🔍 Types de vulnerabilities targeted

### Panics critiques
- `unwrap()` sur `None` ou `Err`
- `expect()` avec condition non respected
- Index out of bounds
- Integer overflow/underflow non managed
- Stack overflow par recursion

### Attacks DoS
- Allocation memory excessive
- Parsing infiniment lent
- Boucles infinies
- Structures recursive

### Vulnerabilities crypto
- Signatures malformed accepted
- Timing attacks sur verification
- Keys publics invalides
- Preuves ZK corrompues

### Attacks network
- Messages oversized
- Fragmentation malveillante
- Confusion de protocole
- Injection de data

## 🛠️ Developing new fuzzers

### Structure d'un fuzzer
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    data: Vec<u8>,
    // ... parameters d'attack
}

fuzz_target!(|entry: FuzzInput| {
    // Protection anti-panic global
    let result = std::panic::catch_unwind(|| {
        // Code de test
    });
    
    if let Err(panic_info) = result {
        panic!("VULNERABILITY DETECTED: {}", extract_panic_message(panic_info));
    }
});
```

### Bonnes pratiques
1. **Toujours** wrapper dans `catch_unwind()`
2. **Mesurer** les temps d'execution (detection DoS)
3. **Limiter** les allocations memory du fuzzer
4. **Documenter** each type d'attack tested
5. **Usesr** `arbitrary::Arbitrary` pour la generation de data

## 📋 Checklist de security

Avant each release, verify que :

- [ ] Tous les fuzzers passent sans panic (5+ minutes chacun)
- [ ] Aucun timeout de parsing > 100ms pour des entrys < 1MB
- [ ] Aucune allocation > 100MB pour des entrys < 10MB
- [ ] Variance temporelle < 50ms entre entrys similaires
- [ ] Tous les invariants business respected
- [ ] Pas de regression sur les vulnerabilities connues

## 🔗 Integration CI/CD

```yaml
# .github/workflows/fuzz.yml
name: Security Fuzzing
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run panic hunters
        run: |
          cd fuzz
          FUZZ_TIME=60 ./run_panic_hunters.sh
```

## 📚 References

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [cargo-fuzz Book](https://rust-fuzz.github.io/book/)
- [Arbitrary Crate](https://docs.rs/arbitrary/)
- [TSN Security Model](../docs/security/SECURITY.md)

---

**⚠️ IMPORTANT** : Ce fuzzing ne remplace pas un audit de security complete. Il s'agit d'un outil de detection automatested des vulnerabilities les plus critiques.