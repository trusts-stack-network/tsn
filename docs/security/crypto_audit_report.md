# Security Audit - TSN Crypto Module
Date: 2024-12-19  
Auditeur: Marcus.R  
Version target: commit HEAD (`src/crypto/`)

## 1. Surface d’attack principale
- Private keys ML-DSA-65 (FIPS-204) : generation, storage en memory, zeroisation
- Signatures produites/consumedes via RPC (JSON) → inputs adversariales
- Hashes Poseidon2 : collisions, parameters de domaine
- Commitments/nullifiers : double-spend, recompute attacks
- Merkle proofs : leaf, index, root forgey
- RNG ChaCha20Rng : security and reseed side WASM (wallet)

## 2. Threats identifiedes

| ID  | Threat | Impact | Probability | Severity | Status |
|-----|--------|--------|-------------|---------|--------|
| T1  | Signature malleability ML-DSA | High | Medium | High | Open |
| T2  | Timing leak comparaison public keys | Medium | Low | Medium | Open |
| T3  | Panic sur slice malformed side proof decode | High | High | High | Open |
| T4  | Overflow index Merkle tree | Medium | Medium | Medium | Open |
| T5  | Zeroisation memory private key non garantie | High | Low | High | Open |

## 3. Recommendations immediatees

1. Implement fonction `compare_public_key_ct(a: &MlDsaPublicKey, b: &MlDsaPublicKey) -> bool` en constant-time (crate `subtle`)
2. Faire `cargo-fuzz` targetr all les `TryFrom<Vec<u8>>` de messages network
3. Replace all les `.unwrap()` in les parsers par `Result` propagent l’error
4. Add verification que `index < 2^depth` in `merkle_tree.rs`
5. Utiliser `zeroize` crate + `#[derive(ZeroizeOnDrop)]` sur all structure contenant une private key
6. Documenter vecteurs de test connus pour Poseidon2 (parameters, domaine, round constants)

## 4. Tests de regression required
- Signature malleability: verify qu’une signature modifiede fails
- Overflow: `2^32` feuilles → must failsr proprement
- Chain de 1 million de messages RPC malformeds → pas de panic, pas de DoS
- Constant-time: pas de difference mesurable > 5 ns between comparaisons

## 5. References
- FIPS 204 (Draft) – ML-DSA
- RFC 8439 – ChaCha20-Poly1305
- Poseidon2 paper – ePrint 2023/323
- STRIDE – Microsoft Security Development Lifecycle