---
tsn: 001
title: Migration ML-DSA-65 towards SLH-DSA-SHA2-192s
status: Draft
type: Standards Track
category: Crypto
author: Security Research Team <security@example.org>
created: 2024-01-15
updated: 2024-01-15
requires: FIPS 204, FIPS 205
---

# TSN-001: Migration ML-DSA-65 towards SLH-DSA-SHA2-192s

## Table of Contents
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Specification](#specification)
  - [Parameters cryptographics](#parameters-cryptographics)
  - [Formats de data](#formats-de-data)
  - [Algorithmes](#algorithmes)
- [Plan de migration](#plan-de-migration)
- [Vecteurs de test](#vecteurs-de-test)
- [Rationale](#rationale)
- [Compatibility descendante](#compatibility-descendante)
- [Considerations de security](#considerations-de-security)
- [References](#references)
- [Annexe A: Comparaison of the sizes](#annexe-a-comparaison-des-sizes)

## Abstract

This specification definedt la procedure de migration of the digital post-quantum signatures from ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) towards SLH-DSA-SHA2-192s (SPHINCS+, FIPS 205). Elle establishes les parameters cryptographics, les formats d'encodage of the keys and signatures, thus that a plan de transition en quatre phases permettant la coexistence hybride suivie of the retrait secure de ML-DSA.

## Motivation

ML-DSA repose sur la security of the networkx euclidiens (lattices), offrant of the signatures compactes and fasts. Ceduring, SLH-DSA presents of the beforeages fondamentto for infrastructures to haute security :

1. **Assumptions cryptographics conservatrices** : SLH-DSA repose only sur la resistance of the hash functions cryptographics (SHA2/SHAKE), without dependsre de structures algebraics complexs
2. **Resistance to attacks par side channels** : Algorithmes stateless without dependency to l'state internal secret durant the signature
3. **Compliance regulatory** : Recommendation explicite in certains secteurs (defense, finance) for systems to longue duration de vie (>20 ans)

La migration vise to assurer la continuity de service all en raising le niveat de security quantique de NIST Level 3 towards une security basede only on hash functions.

## Specification

### Parameters cryptographics

La migration target **SLH-DSA-SHA2-192s** (small, fast signature generation) comme parameter par default, with **SLH-DSA-SHA2-192f** (fast verification) comme alternative.

| Parameter | ML-DSA-65 (Legacy) | SLH-DSA-SHA2-192s (Target) | SLH-DSA-SHA2-192f (Alternative) |
|-----------|-------------------|---------------------------|-------------------------------|
| NIST Level | 3 | 3 | 3 |
| Hash Function | SHAKE-256 | SHA2-256 | SHA2-256 |
| `n` (parameter de security) | 256 | 24 | 24 |
| `