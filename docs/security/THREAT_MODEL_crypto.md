# Threat Model - TSN Crypto Module
Last Review: 2024-06-xx

## Actifs protecteds
- Private keys utilisateur and validateur (seed 32 bytes)
- Signature post-quantum (FIPS-204 ML-DSA-65)
- ZK Proofs (Plonky2 STARK, Groth16 BN254 legacy)
- Commitments and nullifiers (Poseidon2)
- Data sensibles en memory (secret keys, randomness)

## Model d’adversary
- Capability network : can observer all traffic P2P / RPC
- Capability CPU : can execute of the code sur la same machine (cache-timing)
- Objective : extraction de key, forgey de signature, violation d’anonymat
- Pas d’access physique (cold-storage) mais access to APIs publics

## Surfaces d’attack
1. Derivation de key from seed (brut-force + timing)
2. Signature / verification ML-DSA-65 (side-channel sur secret vector « s »)
3. Comparaison de hash/commitment non constant-time
4. Merkle proof verification (path length forgey)
5. Deserialization de keys from network (panic via unwrap)
6. RNG : faute d’initialization => keys predictables
7. Nullifier collision : deux notes differentes produisent same nullifier

## STRIDE
- Spoofing : keys spoofed si RNG low
- Tampering : blockk invalid accepted si check de root non constant-time
- Repudiation : pas de non-repudiation si signature non audited
- Information disclosure : timing sur comparaison de root
- DoS : panic sur slice[index] in merkle_proof.verify()
- Elevation : double-spend possible si nullifier pas verified before confirmation

## Mitigations implementedes
- ChaCha20Poly1305 for the storage at repos (AEAD)
- Constant-time comparison pour all les primitives > 32 bytes
- Zeroize automatic sur Drop of the keys
- Fuzzing corpus pour each parser external
- Proptest : verification of the invariants de transition de state