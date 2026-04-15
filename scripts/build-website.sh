#!/bin/bash
# ===== TSN WEBSITE BUILD SCRIPT =====
# Trust Stack Network - Build automatested du site web + PDF whitepaper
# Auteur: Yuki.T (Release & DevOps Engineer)

set -euo pipefail

# ===== CONFIGURATION =====
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly BUILD_DIR="${PROJECT_ROOT}/build"
readonly WEBSITE_DIR="${PROJECT_ROOT}/website"
readonly DOCS_DIR="${PROJECT_ROOT}/docs"
readonly OUTPUT_WEBSITE="${BUILD_DIR}/website"
readonly OUTPUT_DOCS="${BUILD_DIR}/docs"

# Couleurs pour les logs
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ===== FONCTIONS UTILITAIRES =====

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Verification des dependencies..."
    
    local missing_deps=()
    
    # Verify pandoc pour le PDF
    if ! command -v pandoc &> /dev/null; then
        missing_deps+=("pandoc")
    fi
    
    # Verify wkhtmltopdf pour le PDF
    if ! command -v wkhtmltopdf &> /dev/null; then
        missing_deps+=("wkhtmltopdf")
    fi
    
    # Verify python3 pour les scripts
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Dependencies missings: ${missing_deps[*]}"
        log_info "Installez avec: sudo apt-get install pandoc wkhtmltopdf python3 python3-pip"
        log_info "Ou utilisez: make website-deps"
        exit 1
    fi
    
    log_success "Toutes les dependencies sont present"
}

create_build_dirs() {
    log_info "Creation des directories de build..."
    mkdir -p "${OUTPUT_WEBSITE}"
    mkdir -p "${OUTPUT_DOCS}"
    log_success "Directories createds"
}

build_website() {
    log_info "Build du site web TSN..."
    
    # Copier les fichiers statiques
    cp -r "${WEBSITE_DIR}"/* "${OUTPUT_WEBSITE}/"
    
    # Injecter la version et la date de build
    local version
    version=$(grep '^version = ' "${PROJECT_ROOT}/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')
    local build_date
    build_date=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    # Remplacer les placeholders dans index.html
    sed -i "s/{{VERSION}}/${version}/g" "${OUTPUT_WEBSITE}/index.html"
    sed -i "s/{{BUILD_DATE}}/${build_date}/g" "${OUTPUT_WEBSITE}/index.html"
    
    # Ajouter le lien vers le whitepaper PDF si il existe
    if [ -f "${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf" ]; then
        log_info "Ajout du lien vers le whitepaper PDF..."
        # Injecter le lien PDF dans la section documentation
        local pdf_link='<a href="docs/whitepaper_tsn_v0.1.pdf" class="btn btn-primary" target="_blank">📄 Download le Whitepaper (PDF)</a>'
        sed -i "s|<!-- PDF_WHITEPAPER_LINK -->|${pdf_link}|g" "${OUTPUT_WEBSITE}/index.html"
    fi
    
    log_success "Site web built dans ${OUTPUT_WEBSITE}"
}

generate_whitepaper_pdf() {
    log_info "Generation du whitepaper PDF..."
    
    local whitepaper_md="${DOCS_DIR}/whitepaper.md"
    local whitepaper_pdf="${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf"
    
    if [ ! -f "${whitepaper_md}" ]; then
        log_warning "Fichier whitepaper.md non found, creation d'un template..."
        create_whitepaper_template
    fi
    
    # Generate le PDF avec pandoc
    pandoc "${whitepaper_md}" \
        -o "${whitepaper_pdf}" \
        --pdf-engine=xelatex \
        --variable geometry:margin=2cm \
        --variable fontsize=11pt \
        --variable documentclass=article \
        --variable colorlinks=true \
        --variable linkcolor=blue \
        --variable urlcolor=blue \
        --toc \
        --toc-depth=3 \
        --number-sections \
        --highlight-style=github \
        2>/dev/null || {
            log_warning "Failure de pandoc, attempt avec wkhtmltopdf..."
            
            # Fallback: convertir MD en HTML puis PDF
            local temp_html="${BUILD_DIR}/temp_whitepaper.html"
            pandoc "${whitepaper_md}" -o "${temp_html}" --standalone --css="${WEBSITE_DIR}/style.css"
            wkhtmltopdf "${temp_html}" "${whitepaper_pdf}"
            rm -f "${temp_html}"
        }
    
    if [ -f "${whitepaper_pdf}" ]; then
        local pdf_size
        pdf_size=$(du -h "${whitepaper_pdf}" | cut -f1)
        log_success "Whitepaper PDF generated: ${whitepaper_pdf} (${pdf_size})"
    else
        log_error "Failure de la generation du PDF"
        return 1
    fi
}

create_whitepaper_template() {
    local whitepaper_md="${DOCS_DIR}/whitepaper.md"
    mkdir -p "${DOCS_DIR}"
    
    cat > "${whitepaper_md}" << 'EOF'
---
title: "Trust Stack Network (TSN) - Whitepaper"
subtitle: "Blockchain Post-Quantique avec Preuves to Divulgation Nulle"
author: "Team Trust Stack Network"
date: "Version 0.1 - December 2024"
---

# Trust Stack Network (TSN)
## Blockchain Post-Quantique avec Preuves to Divulgation Nulle

### Summary Executive

Trust Stack Network (TSN) est une blockchain de nouvelle generation designed pour resist aux attacks des ordinateurs quantiques tout en preserving la confidentiality des transactions thanks to zero-knowledge proofs (Zero-Knowledge Proofs).

### 1. Introduction

L'advent de l'informatique quantique represents une menace existentielle pour les cryptosystems actuels. TSN anticipe cette revolution en implementing from aujourd'hui des algorithmes cryptographic post-quantiques.

#### 1.1 Issue

- **Menace quantique** : Les algorithmes RSA et ECDSA seront broken par les ordinateurs quantiques
- **Confidentiality** : Les blockchains actuelles exposent toutes les transactions publiquement
- **Scalability** : Les solutions actuelles don't scale

#### 1.2 Solution TSN

TSN resolves ces problems en combinant :
- **Cryptographie post-quantique** : FIPS204 ML-DSA-65 pour les signatures
- **Preuves ZK quantum-safe** : Plonky2 STARKs pour la confidentiality
- **Architecture optimized** : Consensus PoW avec ajustement de difficulty

### 2. Architecture Technique

#### 2.1 Couche Cryptographique

**Signatures Post-Quantiques :**
- FIPS204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)
- Resistant aux attacks quantiques (algorithme de Shor)
- Taille de signature : ~3KB (vs ~64B pour ECDSA)

**Zero-Knowledge Proofs :**
- Plonky2 STARKs pour la confidentiality quantum-safe
- Groth16 BN254 pour la compatibility legacy
- Fonction de hachage Poseidon2 optimized

**Chiffrement :**
- ChaCha20Poly1305 pour le encryption symmetric
- Exchange de keys post-quantique en development

#### 2.2 Couche Consensus

**Proof of Work (PoW) :**
- Algorithme de hachage : SHA-256 (compatible Bitcoin)
- Ajustement de difficulty : toutes les 2016 blocs
- Temps de bloc cible : 10 minutes

**Validation des Transactions :**
- Verification des signatures ML-DSA-65
- Validation des preuves ZK
- Control des double-spends

#### 2.3 Couche Network

**Protocole P2P :**
- Discovery automatique des nodes
- Synchronisation des blocs
- Propagation des transactions

**API REST :**
- Interface HTTP pour les wallets
- Endpoints pour l'explorateur de blocs
- Metrics de performance

### 3. Implementation

#### 3.1 Technologies Used

- **Langage** : Rust (security memory, performance)
- **Runtime** : Tokio (programmation asynchrone)
- **Stockage** : Sled (base de data embedded)
- **Network** : Axum (server HTTP haute performance)

#### 3.2 Structure du Code

```
src/
├── core/           # Blockchain, blocs, transactions
├── crypto/         # Cryptographie post-quantique
├── network/        # P2P, API, synchronisation
├── consensus/      # Proof of Work, difficulty
├── storage/        # Persistance des data
├── explorer/       # Explorateur de blocs
└── wallet/         # Wallet de base
```

#### 3.3 Metrics de Performance

- **Throughput** : ~7 transactions/seconde (Bitcoin-like)
- **Latence** : 10 minutes par bloc
- **Taille des blocs** : 1MB maximum
- **Taille des signatures** : ~3KB (ML-DSA-65)

### 4. Security

#### 4.1 Model de Menace

TSN est designed pour resist :
- Attaques quantiques (algorithme de Shor, Grover)
- Attacks classiques (51%, double-spend)
- Attacks sur la confidentiality (analyse de trafic)

#### 4.2 Audit de Security

- Audit automatested avec `cargo audit`
- Verification des dependencies avec `cargo deny`
- Tests de fuzzing en development

### 5. Roadmap

#### Phase 1 (Q1 2025) - MVP
- [x] Blockchain de base avec PoW
- [x] Signatures post-quantiques ML-DSA-65
- [x] API REST et explorateur
- [ ] Wallet complet
- [ ] Tests de charge

#### Phase 2 (Q2 2025) - Confidentiality
- [ ] Preuves ZK Plonky2 integrated
- [ ] Transactions confidentielles
- [ ] Audit de security external

#### Phase 3 (Q3 2025) - Scalability
- [ ] Optimisations de performance
- [ ] Sharding experimental
- [ ] Mainnet beta

#### Phase 4 (Q4 2025) - Production
- [ ] Mainnet production
- [ ] Ecosystem DApps
- [ ] Partenariats institutionnels

### 6. Economy du Token

#### 6.1 Tokenomics

- **Nom** : TSN Token
- **Supply total** : 21 millions (comme Bitcoin)
- **Reward de bloc** : 50 TSN (divided par 2 tous les 210,000 blocs)
- **Frais de transaction** : Variables selon la congestion

#### 6.2 Distribution

- **Mining** : 80% (16.8M TSN)
- **Team** : 10% (2.1M TSN, vesting 4 ans)
- **Reserve** : 10% (2.1M TSN, development)

### 7. Conclusion

Trust Stack Network represents l'evolution naturelle de la blockchain vers l'era post-quantique. En combinant security quantique, confidentiality et performance, TSN pose les bases d'un ecosystem financier decentralized resistant aux futures menaces technologiques.

L'implementation en Rust garantit la security memory et les performances necessary pour une blockchain de production. L'architecture modulaire allows une evolution continue vers de nouveaux algorithmes cryptographic as de leur standardisation.

---

**Contact :**
- Site web : https://truststacknetwork.com
- GitHub : https://github.com/trust-stack-network/tsn
- Email : contact@truststacknetwork.com

**Disclaimer :** Ce document est en version preliminary et peut evolve. TSN est un projet experimental en development actif.
EOF

    log_info "Template whitepaper created dans ${whitepaper_md}"
}

serve_website() {
    log_info "Startup du server local..."
    
    cd "${OUTPUT_WEBSITE}"
    
    # Essayer python3 d'abord, puis python
    if command -v python3 &> /dev/null; then
        log_info "Serveur started sur http://localhost:8000"
        log_info "Appuyez sur Ctrl+C pour stop"
        python3 -m http.server 8000
    elif command -v python &> /dev/null; then
        log_info "Serveur started sur http://localhost:8000"
        log_info "Appuyez sur Ctrl+C pour stop"
        python -m http.server 8000
    else
        log_error "Python non found, impossible de start le server"
        log_info "Fichiers disponibles dans: ${OUTPUT_WEBSITE}"
        return 1
    fi
}

clean_build() {
    log_info "Nettoyage des fichiers de build..."
    rm -rf "${BUILD_DIR}"
    log_success "Build cleaned"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build automatested du site web Trust Stack Network + PDF whitepaper

OPTIONS:
    --website-only    Builder uniquement le site web (sans PDF)
    --pdf-only        Generate only le PDF whitepaper
    --serve           Builder et servir localement sur http://localhost:8000
    --clean           Nettoyer avant de builder
    --help, -h        Afficher cette aide

EXEMPLES:
    $0                      # Build complet (site + PDF)
    $0 --serve              # Build + serveur local
    $0 --clean --serve      # Nettoyage + build + serveur
    $0 --website-only       # Site web seulement
    $0 --pdf-only           # PDF seulement

DEPENDENCIES:
    pandoc, wkhtmltopdf, python3
    Installation: sudo apt-get install pandoc wkhtmltopdf python3
    Ou: make website-deps

EOF
}

# ===== MAIN =====

main() {
    local build_website=true
    local build_pdf=true
    local serve=false
    local clean=false
    
    # Parser les arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --website-only)
                build_pdf=false
                shift
                ;;
            --pdf-only)
                build_website=false
                shift
                ;;
            --serve)
                serve=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Option inconnue: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "=== TSN Website Build Script ==="
    log_info "Build website: ${build_website}"
    log_info "Build PDF: ${build_pdf}"
    log_info "Serve: ${serve}"
    log_info "Clean: ${clean}"
    echo
    
    # Cleanup si requested
    if [ "$clean" = true ]; then
        clean_build
    fi
    
    # Verify les dependencies
    check_dependencies
    
    # Create les directories
    create_build_dirs
    
    # Build du site web
    if [ "$build_website" = true ]; then
        build_website
    fi
    
    # Generation du PDF
    if [ "$build_pdf" = true ]; then
        generate_whitepaper_pdf
    fi
    
    # Servir localment si requested
    if [ "$serve" = true ]; then
        if [ "$build_website" = true ]; then
            serve_website
        else
            log_error "Impossible de servir : site web non built"
            exit 1
        fi
    fi
    
    log_success "=== Build completeed avec success ==="
    
    if [ "$build_website" = true ]; then
        log_info "Site web: ${OUTPUT_WEBSITE}/index.html"
    fi
    
    if [ "$build_pdf" = true ] && [ -f "${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf" ]; then
        log_info "Whitepaper PDF: ${OUTPUT_DOCS}/whitepaper_tsn_v0.1.pdf"
    fi
}

# Execute le script
main "$@"