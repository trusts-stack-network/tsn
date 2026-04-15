#!/bin/bash
set -euo pipefail

# =============================================================================
# Script de monitoring du consensus TSN
# =============================================================================
# Ce script surveille les metrics de performance du consensus et alerte
# en cas de problems detecteds, notamment le bug "Invalid commitment root".
#
# Usage:
#   ./scripts/monitor-consensus.sh [OPTIONS]
#
# Options:
#   --metrics-url URL    URL du server de metrics (default: http://localhost:9090)
#   --interval SECONDS   Intervalle de verification (default: 30)
#   --alert-webhook URL  Webhook pour les alertes (optionnel)
#   --log-file FILE      Fichier de log (default: /tmp/tsn-monitor.log)
#   --daemon             Lancer en mode daemon
#   --help               Afficher cette aide
#
# Auteur: Yuki.T (Release & DevOps Engineer)
# =============================================================================

# Configuration par default
METRICS_URL="${TSN_METRICS_URL:-http://localhost:9090}"
CHECK_INTERVAL="${TSN_MONITOR_INTERVAL:-30}"
ALERT_WEBHOOK="${TSN_ALERT_WEBHOOK:-}"
LOG_FILE="${TSN_MONITOR_LOG:-/tmp/tsn-monitor.log}"
DAEMON_MODE=false

# Seuils d'alerte
BLOCK_VALIDATION_FAILURE_THRESHOLD=5
COMMITMENT_ROOT_ERROR_THRESHOLD=3
CHAIN_REORG_DEPTH_THRESHOLD=6
MEMPOOL_SIZE_THRESHOLD=1000
BLOCK_INTERVAL_THRESHOLD=300  # 5 minutes

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'aide
show_help() {
    cat << EOF
Script de monitoring du consensus TSN

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --metrics-url URL      URL du server de metrics (default: $METRICS_URL)
    --interval SECONDS     Intervalle de verification (default: $CHECK_INTERVAL)
    --alert-webhook URL    Webhook pour les alertes
    --log-file FILE        Fichier de log (default: $LOG_FILE)
    --daemon               Lancer en mode daemon
    --help                 Afficher cette aide

EXEMPLES:
    # Verification unique
    $0

    # Monitoring continu avec alertes
    $0 --daemon --alert-webhook https://hooks.slack.com/...

    # Monitoring avec intervalle customized
    $0 --interval 60 --daemon

METRICS MONITORED:
    - Erreurs de validation de blocs
    - Erreurs "Invalid commitment root"
    - Reorganizations de chain profondes
    - Taille excessive du mempool
    - Intervalles entre blocs anormaux
    - Performance general du consensus

EOF
}

# Parsing des arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --metrics-url)
            METRICS_URL="$2"
            shift 2
            ;;
        --interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        --alert-webhook)
            ALERT_WEBHOOK="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --daemon)
            DAEMON_MODE=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Option inconnue: $1"
            show_help
            exit 1
            ;;
    esac
done

# Fonction de logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# Fonction pour envoyer une alerte
send_alert() {
    local severity=$1
    local title=$2
    local message=$3
    
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local payload=$(cat << EOF
{
    "text": "🚨 TSN Consensus Alert",
    "attachments": [
        {
            "color": "$([[ $severity == "critical" ]] && echo "danger" || echo "warning")",
            "title": "$title",
            "text": "$message",
            "footer": "TSN Monitoring",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        if curl -s -X POST -H "Content-Type: application/json" \
           -d "$payload" "$ALERT_WEBHOOK" > /dev/null; then
            log_info "Alerte sent: $title"
        else
            log_error "Failure envoi alerte: $title"
        fi
    fi
}

# Fonction pour retrieve une metric
get_metric() {
    local metric_name=$1
    local value=$(curl -s "$METRICS_URL/metrics?format=json" | \
                  jq -r ".metrics.${metric_name} // 0" 2>/dev/null)
    
    if [[ "$value" == "null" || -z "$value" ]]; then
        echo "0"
    else
        echo "$value"
    fi
}

# Fonction pour verify la connectivity
check_metrics_server() {
    if ! curl -s --max-time 5 "$METRICS_URL/health" > /dev/null; then
        log_error "Impossible de contacter le server de metrics: $METRICS_URL"
        return 1
    fi
    return 0
}

# Fonction principale de verification
check_consensus_health() {
    log_info "Start verification health consensus..."
    
    # Verify la connectivity
    if ! check_metrics_server; then
        send_alert "critical" "Serveur de metrics inaccessible" \
                   "Le server de metrics TSN to $METRICS_URL est inaccessible"
        return 1
    fi
    
    local alerts_count=0
    
    # 1. Verify les errors de validation de blocs
    local blocks_rejected=$(get_metric "blocks_rejected_total")
    local blocks_validated=$(get_metric "blocks_validated_total")
    
    if [[ $blocks_validated -gt 0 ]]; then
        local rejection_rate=$((blocks_rejected * 100 / (blocks_validated + blocks_rejected)))
        if [[ $rejection_rate -gt $BLOCK_VALIDATION_FAILURE_THRESHOLD ]]; then
            log_warn "Taux de rejet de blocs high: ${rejection_rate}%"
            send_alert "warning" "Taux de rejet de blocs high" \
                       "Taux de rejet: ${rejection_rate}% (seuil: ${BLOCK_VALIDATION_FAILURE_THRESHOLD}%)"
            ((alerts_count++))
        fi
    fi
    
    # 2. Verify les errors "Invalid commitment root"
    local commitment_errors=$(get_metric "invalid_commitment_root_errors")
    if [[ $commitment_errors -gt $COMMITMENT_ROOT_ERROR_THRESHOLD ]]; then
        log_error "Errors 'Invalid commitment root' detecteds: $commitment_errors"
        send_alert "critical" "Bug Invalid Commitment Root" \
                   "Nombre d'erreurs: $commitment_errors (seuil: $COMMITMENT_ROOT_ERROR_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 3. Verify les reorganizations de chain
    local last_reorg_depth=$(get_metric "last_reorg_depth")
    if [[ $last_reorg_depth -gt $CHAIN_REORG_DEPTH_THRESHOLD ]]; then
        log_warn "Reorganization de chain profonde detected: $last_reorg_depth blocs"
        send_alert "warning" "Reorganization de chain profonde" \
                   "Profondeur: $last_reorg_depth blocs (seuil: $CHAIN_REORG_DEPTH_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 4. Verify la taille du mempool
    local mempool_size=$(get_metric "mempool_size")
    if [[ $mempool_size -gt $MEMPOOL_SIZE_THRESHOLD ]]; then
        log_warn "Mempool surloaded: $mempool_size transactions"
        send_alert "warning" "Mempool surloaded" \
                   "Taille: $mempool_size transactions (seuil: $MEMPOOL_SIZE_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 5. Afficher un summary des metrics importantes
    local chain_height=$(get_metric "chain_height")
    local forks_detected=$(get_metric "forks_detected_total")
    local orphan_blocks=$(get_metric "orphan_blocks_count")
    local zk_proofs_validated=$(get_metric "zk_proofs_validated_total")
    
    log_info "=== Summary des metrics ==="
    log_info "Hauteur de chain: $chain_height"
    log_info "Blocs validateds: $blocks_validated"
    log_info "Blocs rejected: $blocks_rejected"
    log_info "Erreurs commitment root: $commitment_errors"
    log_info "Forks detecteds: $forks_detected"
    log_info "Blocs orphelins: $orphan_blocks"
    log_info "Preuves ZK validateds: $zk_proofs_validated"
    log_info "Taille mempool: $mempool_size"
    log_info "============================"
    
    if [[ $alerts_count -eq 0 ]]; then
        log_success "Consensus en bonne health - aucune alerte"
    else
        log_warn "Consensus: $alerts_count alerte(s) detected(s)"
    fi
    
    return $alerts_count
}

# Fonction pour le mode daemon
run_daemon() {
    log_info "Startup du monitoring en mode daemon (intervalle: ${CHECK_INTERVAL}s)"
    
    # Create un file PID
    local pid_file="/tmp/tsn-monitor.pid"
    echo $$ > "$pid_file"
    
    # Gestionnaire de signal pour shutdown propre
    trap 'log_info "Shutdown du monitoring daemon"; rm -f "$pid_file"; exit 0' SIGTERM SIGINT
    
    while true; do
        check_consensus_health
        sleep "$CHECK_INTERVAL"
    done
}

# Point d'entry principal
main() {
    log_info "Startup du monitoring TSN Consensus"
    log_info "URL metrics: $METRICS_URL"
    log_info "Fichier log: $LOG_FILE"
    
    # Create le directory de log si necessary
    mkdir -p "$(dirname "$LOG_FILE")"
    
    if [[ "$DAEMON_MODE" == "true" ]]; then
        run_daemon
    else
        check_consensus_health
        exit $?
    fi
}

# Verifications prerequisites
if ! command -v curl &> /dev/null; then
    log_error "curl n'est pas installed"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    log_error "jq n'est pas installed"
    exit 1
fi

# Lancer le script principal
main "$@"