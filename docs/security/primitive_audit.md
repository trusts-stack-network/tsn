# Cryptographic Primitives Audit

## Assessment of the Algorithmes

### AEAD: AES-256-GCM & ChaCha20-Poly1305
**Status**: ACCEPTABLE with reserves  
**Risks**:
- AES-GCM: Fragile en cas de nonce reuse (catastrophique)
- Limite ~64GB par key/nonce pour AES-GCM (2^32 blockks)
- ChaCha20: Plus robust at nonce reuse (seulement contenu revealed, pas key)

**Recommendations**:
1. Prefer ChaCha20-Poly1305 pour nouveto developments
2. Implement counter thread-safe pour nonces
3. Refuser encryption si nonce already used (stateful)

### KDF: Argon2id / HKDF-SHA256
**Status**: ACCEPTABLE  
**Parameters**:
- Argon2id: m=65536, t=3, p=4 (OWASP recommendation actuelle)
- HKDF: Salt mandatory, info string unique par contexte

**Vulnerabilities potentialles**:
- Parameters trop lows pour passwords (DoS vs Security tradeoff)
- Salt predictable reduces la security

### Hashing: SHA-3-256 / BLAKE3
**Status**: ACCEPTABLE  
**Notes**:
- SHA-3 resistant to length extension (pas besoin de HMAC)
- BLAKE3 more fast mais less audited que BLAKE2b

### RNG: ChaCha20Rng (seeded from getrandom)
**Status**: ACCEPTABLE  
**Requirements**:
- Reseeding periodic mandatory
- Pas de fork-safety issue (verify `rand::rngs::OsRng`)

## Anti-patterns Detected to Proscrire

1. **ECB Mode**: Never used, same pour testing
2. **CBC without HMAC**: Vulnerable to padding oracles
3. **MD5/SHA1**: Collision found, rejected explicitement
4. **Static IV**: Same pour testing, utiliser IV randoms
5. **Key derivation via simpthe hash**: Always utiliser PBKDF2/Argon2