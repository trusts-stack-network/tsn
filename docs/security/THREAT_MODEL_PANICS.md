# Threat Model: Panics and DoS in TSN

## Executive Summary

This document analysis les risks de security relateds to panics (`unwrap`, `expect`, `panic!`) in the codebase TSN, in particular in the modules criticals (core, consensus, crypto, network).

**Severity**: CRITICAL  
**Probability**: HIGHE (code existant with unwraps non documenteds)  
**Impact**: Crash de node, denial de service network, perte de consensus

---

## Attack Scenarios

### 1. DoS via Message Network Malformed

**Vecteur**: Un attacker envoie un message network specially designed.

**Example vulnerable**:
```rust
// Code vulnerable (hypothetical)
fn process_message(data: &[u8]) {
    let header = parse_header(data).unwrap(); // PANIC si malformed
    let payload = &data[4..header.len]; // PANIC si header.len > data.len
}
```

**Impact**: Crash immediate of the node, disconnection of the network.

**Mitigation**:
- Validation explicite before unwrap
- Utilisation de `?` with propagation d'error
- Fuzzing systematic of the parsers

### 2. DoS via Timestamp Extreme

**Vecteur**: Manipulation de timestamps in les blockks or messages.

**Example vulnerable**:
```rust
// Code vulnerable (hypothetical)
let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH + Duration::from_secs(timestamp))
    .unwrap(); // PANIC si timestamp in le futur
```

**Impact**: Panic lors of the validation de blockks futurs.

**Mitigation**:
- Utilisation de `checked_duration_since`
- Validation of the bornes before operation

### 3. DoS via State Corrompu

**Vecteur**: Base de data corrupted or state invalid.

**Example vulnerable**:
```rust
// Code vulnerable (hypothetical)
let account = db.get_account(id).unwrap(); // PANIC si account inexistant
let balance = account.balance.checked_add(amount).unwrap(); // PANIC si overflow
```

**Impact**: Crash lors of the recovery d'state, impossibility de restart.

**Mitigation**:
- Gestion gracieuse of the data manquantes
- Utilisation de `checked_add`/`saturating_add`
- Validation de l'integrity on startup

### 4. DoS via Consensus Manipulation

**Vecteur**: Blocks de consensus malformeds.

**Example vulnerable**:
```rust
// Code vulnerable (hypothetical)
let proof = verify_proof(&blockk.proof).unwrap(); // PANIC si proof invalid
```

**Impact**: Split de chain, perte de consensus.

**Mitigation**:
- Validation complete before acceptation
- Rejet gracieux of the blockks invalids

---

## Risk Matrix

| Module | Unwraps | Risk DoS | Priority |
|--------|---------|------------|----------|
| core/blockk.rs | HIGH | CRITICAL | P0 |
| core/transaction.rs | HIGH | CRITICAL | P0 |
| core/state.rs | MEDIUM | HIGH | P1 |
| consensus/pow.rs | MEDIUM | HIGH | P1 |
| consensus/validation.rs | HIGH | CRITICAL | P0 |
| crypto/* | LOW | MEDIUM | P2 |
| network/* | HIGH | CRITICAL | P0 |

---

## Recommendations

### Court Terme (1-2 semaines)

1. **Audit immediate** of the modules network/ and consensus/validation.rs
2. **Remplacement** of the unwraps criticals par of the `Result`/`Option`
3. **Ajout** de tests de regression pour each unwrap removed

### Medium Terme (1 mois)

1. **Implementation** of the fuzzing systematic (cargo-fuzz)
2. **Configuration** CI pour bloquer les nouveto unwraps
3. **Documentation** de all les unwraps restants (avec justification)

### Long Terme (3 mois)

1. **Certification** formelle of the modules criticals
2. **Audit** external de security
3. **Bug bounty** for vulnerabilities DoS

---

## Validation Checklist

Before each release:

- [ ] `cargo clippy -- -D unwrap_used` passe
- [ ] Tests fuzz passent (24h minimum)
- [ ] Audit unwraps manuel completed
- [ ] Documentation of the unwraps restants up to date
- [ ] Tests de charge DoS passent

---

## References

- [Rust Security Guidelines](https://rust-lang.github.io/rust-clippy/master/index.html#unwrap_used)
- [OWASP DoS Prevention](https://owasp.org/www-community/attacks/Denial_of_Service)
- [The DAO Post-Mortem](https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability/)
- [Wormhole Hack Analysis](https://medium.com/coinmonks/wormhole-hack-analysis-8acc2a343c3c)

---

## Revision History

| Date | Author | Change |
|------|--------|------------|
| 2024-XX-XX | Marcus.R | Creation initiale |

---

**Classification**: TSN-INTERNAL-SECURITY  
**Distribution**: Team Core, Team Security
