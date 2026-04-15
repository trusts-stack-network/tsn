# Halo2 Audit Checklist - TSN

## Preamble

This checklist must be completede before each release impliquant le system Halo2.

## 1. Validation of the Enputs

### 1.1 Size of the Proofs

```rust
// Verify: src/crypto/halo2_validator.rs
// La proof must have une size raisonnable
assert!(proof.len() >= 32, "Proof too small");
assert!(proof.len() <= 10_000_000, "Proof too large"); // 10MB
```

- [ ] Minimum 32 bytes (size of a hash)
- [ ] Maximum 10MB (protection DoS)
- [ ] Test de regression pour proof vide
- [ ] Test de regression pour proof excessive

### 1.2 Enputs Publics

```rust
// Verify: nombre of inputs limited
assert!(public_inputs.len() <= 1000, "Too many inputs");

// Verify: size individuelle limitede
for input in &public_inputs {
    assert!(input.len() <= 1_000_000, "Input too large"); // 1MB
}

// Verify: size totale limitede
let total: usize = public_inputs.iter().map(|v| v.len()).sum();
assert!(total <= 100_000_000, "Total input size too large"); // 100MB
```

- [ ] Nombre max: 1000
- [ ] Size max par input: 1MB
- [ ] Size totale max: 100MB
- [ ] Test with inputs vides
- [ ] Test with inputs maximales

### 1.3 Verifying Key Hash

- [ ] Hash always present (32 bytes)
- [ ] Hash verified contre ledger on-chain
- [ ] Rejet si hash inconnu

## 2. Security Cryptographic

### 2.1 Points de Courbe

```rust
// Les points ne doivent pas be:
// - Tous to zero (point to l'infini mal formed)
// - Tous to 0xFF (valeur invalid)
// - Hors of the courbe
```

- [ ] Rejet of the points all zeros
- [ ] Rejet of the points all 0xFF
- [ ] Validation on-curve
- [ ] Test with points invalids

### 2.2 Non-Malleability

```rust
// Une proof modifiede must be invalid
let mut modified = proof.clone();
modified[50] ^= 0x01;
assert!(verify(&modified, &inputs, &vk).is_err());
```

- [ ] Test de malleability (flip bit)
- [ ] Test de malleability (truncation)
- [ ] Test de malleability (extension)

### 2.3 Binding

```rust
// La proof must be related to inputs publics
let different_inputs = /* ... */;
assert!(verify(&proof, &different_inputs, &vk).is_err());
```

- [ ] Test de binding with inputs differentes
- [ ] Test de binding with vk different

## 3. Protection DoS

### 3.1 Timeouts

```rust
// La verification must have un timeout
let result = timeout(Duration::from_secs(30), || {
    verify_proof(&proof, &inputs, &vk)
}).await?;
```

- [ ] Timeout configured (30s par default)
- [ ] Test with proof lente
- [ ] Ressources freed after timeout

### 3.2 Circuit Breaker

```rust
// Trop d'errors = circuit ouvert
if error_rate > threshold {
    circuit_breaker.open();
}
```

- [ ] Circuit breaker integrated
- [ ] Threshold de triggering configured
- [ ] Recovery automatic

### 3.3 Rate Limiting

- [ ] Limite de proofs par seconde
- [ ] Limite par IP/adresse
- [ ] Backoff exponentiel

## 4. Tests de Regression

### 4.1 Cas Limites Connus

- [ ] Proof vide
- [ ] Proof of a byte
- [ ] Proof de 31 bytes (juste under le minimum)
- [ ] Proof de 10MB+1
- [ ] 1001 inputs publics
- [ ] Input de 1MB+1

### 4.2 Attacks Documentedes

- [ ] CVE-20XX-XXXX (si applicable)
- [ ] Attack par padding
- [ ] Attack par compression
- [ ] Attack par deserialization

## 5. Fuzzing

### 5.1 Couverture

- [ ] Fuzzer cargo-fuzz for proofs
- [ ] Fuzzer for inputs publics
- [ ] Fuzzer for VK
- [ ] Corpus de seeds diversified

### 5.2 Results

- [ ] Pas de crash after 1M+ iterations
- [ ] Pas de panic
- [ ] Pas de fuite memory (valgrind)

## 6. Performance

### 6.1 Benchmarks

```bash
cargo bench -- halo2
```

- [ ] Verification < 100ms (proof standard)
- [ ] Memory < 100MB
- [ ] Pas de degradation > 10% vs baseline

### 6.2 Scalability

- [ ] Test with 1000 proofs/minute
- [ ] Test with charge maximale
- [ ] Pas de fuite memory under charge

## 7. Documentation

- [ ] Commentaires de security up to date
- [ ] Guide d'integration securee
- [ ] Procedure d'incident
- [ ] Contact security team

## Signatures

| Role | Name | Date | Signature |
|------|-----|------|-----------|
| Security Engineer | | | |
| Lead Cryptographer | | | |
| DevOps | | | |

## Notes

- This checklist is basede on standards TSN
- Tout failure must be documented and fixed
- La checklist must be revue to each changement majeur
