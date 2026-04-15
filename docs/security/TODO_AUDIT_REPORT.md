# TODO/FIXME Audit Report - Trust Stack Network

**Date:** 2025-01-XX  
**Auditor:** Marcus.R (Security & QA Engineer)  
**Version:** TSN v0.9.0-alpha  
**Status:** IN PROGRESS - 23 TODOs identified

---

## Executive Summary

| Category | Count | Criticality |
|-----------|--------|-----------|
| **Security Crypto** | 5 | 🔴 CRITICAL |
| **Consensus/Network** | 8 | 🟠 HAUTE |
| **Performance/DoS** | 6 | 🟡 MEDIUMNE |
| **Documentation** | 4 | 🟢 LOW |
| **TOTAL** | **23** | - |

---

## TODOs by File (Sorted par Criticality)

### 🔴 CRITICAL - Security Cryptographic

#### 1. `src/crypto/pq/slh_dsa.rs:183`
```rust
/// Verifies une signature SLH-DSA de manner constant
pub fn verify_constant_time(pk: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // TODO: Implement une verification en temps constant without dependency external
    // En attendant, utiliser la verification standard
    verify(pk, message, signature)
}
```
**Impact:** Timing attacks possibles sur la verification de signatures  
**CVSS:** 6.5 (Medium) - Information Disclosure  
**Mitigation:** Implement `subtle::Choice` or `constant_time_eq`  
**Deadline:** Before release v1.0

#### 2. `src/crypto/legacy.rs:35`
```rust
// SAFETY: This is a temporary migration function
// TODO: Remove after blockk height 1_000_000
pub fn verify_legacy_signature(...) -> Result<bool>
```
**Impact:** Code legacy non secure reste actif  
**Mitigation:** Planifier sunset with hard fork  
**Deadline:** Block height 800,000 (alerte to 900,000)

#### 3. `src/crypto/commitment.rs:89`
```rust
// TODO: Verify la proof Plonky2 before d'accepter le commitment
// SECURITY: Sans cette verification, of the commitments invalids can be accepteds
```
**Impact:** Acceptation de commitments non provens  
**CVSS:** 8.1 (High) - Integrity/Availability  
**Mitigation:** Implement `verify_plonky2_proof()` before merge

#### 4. `src/crypto/nullifier.rs:156`
```rust
// TODO: Verify que le nullifier is not already used in the history complete
// SECURITY: Requires une recherche efficient in la chain complete
```
**Impact:** Double-spend possible si nullifier already used  
**CVSS:** 9.8 (Critical) - Endancial  
**Mitigation:** Index Bloom + verification Merkle de the history

#### 5. `src/network/mempool_v2.rs:412`
```rust
// TODO: Implement la verification complete of the ZK proofs
// SECURITY: The transactions with proofs invalids ne are pas rejectedes
```
**Impact:** Mempool pollution, DoS par proofs invalids  
**CVSS:** 7.5 (High) - DoS  
**Mitigation:** Verification Plonky2 complete before acceptation mempool

---

### 🟠 HAUTE - Consensus and Network

#### 6. `src/network/sync_v2.rs:247`
```rust
// TODO: Implement proper blockk validation during sync
// SECURITY: Blocks downloaded during sync are not fully validated
```
**Impact:** Sync of ae chain invalid possible  
**Mitigation:** Validation complete before write DB

#### 7. `src/network/gossip.rs:267`
```rust
NetworkMessage::GetData(_) => {
    // TODO: serve requested data
}
```
**Impact:** Peers ne peuvent pas recover les data requested  
**Mitigation:** Implement le handler GetData

#### 8. `src/network/gossip.rs:261`
```rust
NetworkMessage::Inv(hashes) => {
    for hash in hashes {
        // TODO: request actual data if unknown
        state.known.insert(hash);
    }
}
```
**Impact:** Gossip protocol incomplete - pas de fetch of the data inconnues  
**Mitigation:** Implement GetData request pour hashes inconnus

#### 9. `src/network/peer.rs:4`
```rust
//! Peer management for TSN P2P network
//! TODO: to implement proprement by the bot NETWORK
```
**Impact:** Gestion of the peers minimale - pas de scoring advanced  
**Mitigation:** Implement PeerManager complete with scoring

#### 10. `src/consensus/pow.rs:178`
```rust
// TODO: Verify que le timestamp is not in le futur
// SECURITY: Permet de miner of the blockks with timestamp futur
```
**Impact:** Attack timestamp manipulation  
**Mitigation:** Rejeter blockks with timestamp > now + drift_max

#### 11. `src/consensus/difficulty.rs:89`
```rust
// TODO: Ajuster la difficulty more frequently pour avoid les oscillations
```
**Impact:** Instability of the hashrate, temps de blockk irregulars  
**Mitigation:** Algorithme DigiShield or similaire

#### 12. `src/core/blockkchain.rs:234`
```rust
// TODO: Verify la racine Merkle of the transactions
// SECURITY: Sans verification, inclusion de transactions non valides
```
**Impact:** Transactions invalids in la chain  
**Mitigation:** Verification Merkle root systematic

#### 13. `src/storage/sled_db.rs:156`
```rust
// TODO: Implement le pruning of the vieilles data
// SECURITY: Croissance illimitede of the DB
```
**Impact:** DoS par filling disque  
**Mitigation:** Pruning configurable with archivage optionnel

---

### 🟡 MEDIUMNE - Performance and DoS

#### 14. `src/network/mempool_v2.rs:289`
```rust
// TODO: Limiter la size totale of the mempool par peer
```
**Impact:** Un peer can remplir le mempool  
**Mitigation:** Quota par peer + eviction LRU

#### 15. `src/network/api.rs:445`
```rust
// TODO: Rate limiting on endpoints RPC
```
**Impact:** DoS par requests massives  
**Mitigation:** Tower rate limiter or similar

#### 16. `src/network/discovery.rs:234`
```rust
// TODO: Implement la protection contre les attacks Eclipse
```
**Impact:** Risk d'isolation of the node  
**Mitigation:** Diversity of the buckets, test de connectivity

#### 17. `src/crypto/merkle_tree.rs:178`
```rust
// TODO: Optimiser with un cache LRU for chemins frequent
```
**Impact:** Performance degraded sur grands arbres  
**Mitigation:** Cache thread-safe with TTL

#### 18. `src/network/mempool_v2.rs:567`
```rust
// TODO: Compression of the transactions en memory
```
**Impact:** Usage memory excessif  
**Mitigation:** Compression zstd of the payloads

#### 19. `src/core/transaction.rs:312`
```rust
// TODO: Validation parallel of the signatures
```
**Impact:** Latency sur blockks with beaucoup de transactions  
**Mitigation:** Rayon parallel iterator

---

### 🟢 LOW - Documentation and Tests

#### 20. `tests/crypto_pq_poseidon2_comprehensive.rs:529`
```rust
// TODO: Add les vrais vecteurs de test officiels NIST
```
**Impact:** Confiance reduced in the tests  
**Mitigation:** Integrate vecteurs NIST CAVP

#### 21. `tests/property_consensus_invariants.rs:485`
```rust
/// Regression: CVE-2023-XXXX - Validation de timestamp
// TODO: Documenter la CVE real une fois public
```
**Impact:** Documentation incomplete  
**Mitigation:** Mettre up to date with reference CVE

#### 22. `src/crypto/pq/ml_dsa.rs:89`
```rust
// TODO: Documenter les parameters de security ML-DSA-65
```
**Impact:** Documentation technique incomplete  
**Mitigation:** Add tableto de security NIST

#### 23. `src/wallet/backup.rs:45`
```rust
// TODO: Implement le encryption of the backups
```
**Impact:** Backups en clair sur disque  
**Mitigation:** Encryption AES-256-GCM with passphrase

---

## Resolution Plan

### Phase 1: Security Critical (Sprint 1-2)
- [ ] #4: Nullifier double-spend check
- [ ] #3: Commitment Plonky2 verification
- [ ] #5: Mempool ZK proof validation
- [ ] #1: SLH-DSA constant-time verify

### Phase 2: Consensus/Network (Sprint 3-4)
- [ ] #6: Block validation during sync
- [ ] #10: Timestamp future check
- [ ] #12: Merkle root verification
- [ ] #7/#8: Gossip protocol completeion

### Phase 3: DoS/Performance (Sprint 5)
- [ ] #14/#15: Rate limiting
- [ ] #16: Eclipse protection
- [ ] #17/#18: Caching & compression

### Phase 4: Cleanup (Sprint 6)
- [ ] #2: Legacy crypto sunset
- [ ] #20-23: Documentation & tests

---

## Regression Tests Requis

Pour each TODO resolved, the tests followings must be added:

1. **Test unitaire** - Verification of the logique
2. **Test d'integration** - Scenario realistic
3. **Test adversarial** - Tentative de bypass
4. **Fuzz test** - Si applicable (inputs externals)

---

## Signatures

| Role | Name | Date | Signature |
|------|-----|------|-----------|
| Security Engineer | Marcus.R | | |
| Lead Architect | Kai.V | | |
| Tech Lead | | | |

---

## Revisions

| Version | Date | Author | Changes |
|---------|------|--------|-------------|
| 1.0 | 2025-01-XX | Marcus.R | Creation initiale |
