# Security Policy - Trust Stack Network

## Supported Version

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

### Responsible Disclosure Process

Si vous discover une security vulnerability in Trust Stack Network, nous vous demandons de suivre ce processus de divulgation responsable :

1. **Ne pas divulguer publicment** la vulnerability before qu'elle ne soit fixede
2. **Nous contacter** directly via les canto secures ci-dessous
3. **Fournir** autant de details que possible :
   - Description of the vulnerability
   - Steps pour reproduire
   - Impact potential
   - Suggestions de correction (si applicable)

### Contact Channels

- **Email security:** security@truststack.network
- **PGP Key:** [Available sur demande]
- **Temps de response targeted:** 48 heures

### What You Can Expect

- **Acknowledgment of receipt** within 48 hours
- **Assessment** of the vulnerability within 7 days
- **Fix** and coordinated disclosure
- **Recognition** in release notes (if desired)

### Scope

Les vulnerabilities followinges are in scope :

- Vulnerabilities cryptographics
- Bugs de consensus
- Failles de security network
- Problems de validation
- Fuites of informations

Out of scope :

- Basic denial of service (DoS) attacks
- User configuration issues
- Vulnerabilities in third-party dependencies (report upstream)

## Security Measures

### Post-Quantum Cryptography

TSN utilise of the primitives cryptographics resistantes to attacks quantiques :

- **Signatures:** ML-DSA-65 (FIPS 204)
- **Hachage:** Poseidon2
- **ZK Proofs:** Plonky2 STARKs

### Audit and Tests

- Regression tests for each known vulnerability
- Continuous fuzzing with cargo-fuzz
- Property-based testing with proptest
- Systematic code reviews

### Best Practices

- No `unwrap()` or `expect()` in production code
- Exhaustive input validation
- Timeouts on blockking operations
- Rate limiting on network interfaces

## Vulnerability History

| Date | CVE | Description | Severity | Status |
|------|-----|-------------|----------|--------|
| - | - | No known public vulnerability | - | - |

## Acknowledgments

Nous remercions les chercheurs en security qui ont contributed to la security de TSN :

*List to be completed*

---

**Last Updated:** 2024
