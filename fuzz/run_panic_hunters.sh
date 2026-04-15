#!/bin/bash

# Script de lancement des fuzzers de chasse aux panics TSN
# Auteur: Marcus.R <marcus@truststack.network>
# 
# Ce script lance les fuzzers ultra-agressifs designed pour detect
# les panics dans les deserializers TSN. Chaque panic detected
# indique une vulnerability critique to corriger.

set -euo pipefail

# Configuration
FUZZ_TIME=${FUZZ_TIME:-300}  # 5 minutes par default
PARALLEL_JOBS=${PARALLEL_JOBS:-4}
OUTPUT_DIR="./fuzz_results"
LOG_DIR="./fuzz_logs"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 TSN PANIC HUNTER FUZZING SUITE${NC}"
echo -e "${BLUE}===================================${NC}"
echo "Temps de fuzzing par target: ${FUZZ_TIME}s"
echo "Jobs parallel: ${PARALLEL_JOBS}"
echo ""

# Create les directories de sortie
mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

# Liste des fuzzers de chasse aux panics
PANIC_HUNTERS=(
    "panic_hunter_deserialize"
    "deserialize_property_fuzzer"
    "network_deserialize_fuzzer"
)

# Fonction pour lancer un fuzzer
run_fuzzer() {
    local fuzzer_name="$1"
    local log_file="$LOG_DIR/${fuzzer_name}.log"
    local artifacts_dir="$OUTPUT_DIR/${fuzzer_name}_artifacts"
    
    echo -e "${YELLOW}🚀 Lancement du fuzzer: ${fuzzer_name}${NC}"
    
    # Create le directory d'artefacts
    mkdir -p "$artifacts_dir"
    
    # Lancer le fuzzer avec timeout
    timeout "${FUZZ_TIME}s" cargo fuzz run "$fuzzer_name" \
        --release \
        -- \
        -artifact_prefix="$artifacts_dir/" \
        -print_final_stats=1 \
        -max_len=1048576 \
        -rss_limit_mb=2048 \
        > "$log_file" 2>&1 || {
        
        local exit_code=$?
        
        if [ $exit_code -eq 124 ]; then
            echo -e "${GREEN}✅ ${fuzzer_name}: Completed normally (timeout)${NC}"
        elif [ $exit_code -eq 77 ]; then
            echo -e "${RED}🚨 ${fuzzer_name}: PANIC DETECTED - VULNERABILITY CRITIQUE!${NC}"
            echo -e "${RED}   Voir les details dans: ${log_file}${NC}"
            echo -e "${RED}   Artefacts saved dans: ${artifacts_dir}${NC}"
        else
            echo -e "${RED}❌ ${fuzzer_name}: Erreur inattendue (code: $exit_code)${NC}"
            echo -e "${YELLOW}   Voir les logs: ${log_file}${NC}"
        fi
    }
}

# Fonction pour analyze les results
analyze_results() {
    echo ""
    echo -e "${BLUE}📊 ANALYSE DES RESULTS${NC}"
    echo -e "${BLUE}========================${NC}"
    
    local total_panics=0
    local total_crashes=0
    
    for fuzzer in "${PANIC_HUNTERS[@]}"; do
        local log_file="$LOG_DIR/${fuzzer}.log"
        local artifacts_dir="$OUTPUT_DIR/${fuzzer}_artifacts"
        
        if [ -f "$log_file" ]; then
            # Compter les panics detecteds
            local panic_count=$(grep -c "PANIC DETECTED\|VULNERABILITY\|CRITICAL" "$log_file" 2>/dev/null || echo "0")
            local crash_count=$(find "$artifacts_dir" -name "crash-*" 2>/dev/null | wc -l)
            
            total_panics=$((total_panics + panic_count))
            total_crashes=$((total_crashes + crash_count))
            
            echo -e "${fuzzer}:"
            echo -e "  Panics detecteds: ${panic_count}"
            echo -e "  Crashes founds: ${crash_count}"
            
            # Afficher les last lignes du log pour un overview
            if [ -s "$log_file" ]; then
                echo -e "  Last lignes du log:"
                tail -3 "$log_file" | sed 's/^/    /'
            fi
            echo ""
        fi
    done
    
    echo -e "${BLUE}SUMMARY GLOBAL:${NC}"
    echo -e "  Total panics detecteds: ${total_panics}"
    echo -e "  Total crashes founds: ${total_crashes}"
    
    if [ $total_panics -gt 0 ] || [ $total_crashes -gt 0 ]; then
        echo -e "${RED}🚨 VULNERABILITIES CRITIQUES DETECTED!${NC}"
        echo -e "${RED}   Action requise: Analyze et corriger les panics founds${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Aucune vulnerability critique detected${NC}"
        return 0
    fi
}

# Fonction pour nettoyer les anciens results
cleanup_old_results() {
    if [ -d "$OUTPUT_DIR" ]; then
        echo -e "${YELLOW}🧹 Cleanup des anciens results...${NC}"
        rm -rf "$OUTPUT_DIR"/*
    fi
    
    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"/*
    fi
}

# Fonction principale
main() {
    # Verify que cargo-fuzz est installed
    if ! command -v cargo-fuzz &> /dev/null; then
        echo -e "${RED}❌ cargo-fuzz n'est pas installed${NC}"
        echo "Installation: cargo install cargo-fuzz"
        exit 1
    fi
    
    # Nettoyer les anciens results
    cleanup_old_results
    
    # Lancer les fuzzers en parallel
    echo -e "${YELLOW}🔄 Lancement des fuzzers en parallel...${NC}"
    
    # Usesr GNU parallel si available, sinon lancer sequentialment
    if command -v parallel &> /dev/null; then
        printf '%s\n' "${PANIC_HUNTERS[@]}" | parallel -j "$PARALLEL_JOBS" run_fuzzer
    else
        echo -e "${YELLOW}⚠️  GNU parallel non available, execution sequential${NC}"
        for fuzzer in "${PANIC_HUNTERS[@]}"; do
            run_fuzzer "$fuzzer"
        done
    fi
    
    # Analyze les results
    analyze_results
}

# Gestion des signaux pour nettoyage
trap 'echo -e "\n${YELLOW}🛑 Shutdown requested, cleanup...${NC}"; pkill -f "cargo fuzz" 2>/dev/null || true; exit 130' INT TERM

# Lancer le script principal
main "$@"