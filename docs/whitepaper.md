# TSN Whitepaper v0.1
## Threshold Secure Network - Architecture Technique Post-Quantum

**Version:** 0.1.0-alpha  
**Date:** 2024-01-15  
**Status:** Brouillon Technique  
**Classification:** Public / Open Specification  

---

## Table of Contents

1. [Executive Summary](#1-summary-executive)
2. [Introduction and Objectives](#2-introduction-et-objectives)
3. [Architecture Globale](#3-architecture-globale)
4. [Layer Cryptographic](#4-layer-cryptographic)
   - 4.1 [SLH-DSA (FIPS 205)](#41-slh-dsa-fips-205)
   - 4.2 [Poseidon2 Hash Function](#42-poseidon2-hash-function)
5. [Layer Proof to Connaissance Nulle](#5-layer-proof-zero-knowledge)
   - 5.1 [Halo2 Recursive Proof System](#51-halo2-recursive-proof-system)
6. [System d'Identity MIK](#6-system-didentity-mik)
7. [Mechanism de Consensus](#7-mechanism-de-consensus)
8. [Layer Network P2P](#8-layer-network-p2p)
9. [Security and Analysis of the Threats](#9-security-et-analysis-des-threats)
10. [Parameters de Deployment](#10-parameters-de-deployment)
11. [References](#11-references)

---

##