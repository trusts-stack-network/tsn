#!/bin/bash
# Script de mise to jour automatique avec rollback des nodes TSN
# Trust Stack Network DevOps Automation
# Author: Yuki.T Release & DevOps Engineer

set -euo pipefail

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration des nodes
declare -A NODES=(
    ["node1"]="user@node1.tsn.network"
    ["node2"]="user@node2.tsn.network"
    ["node3"]="user@node3.tsn.network"
    ["node4"]="user@node4.tsn.network"
    ["node5"]="user@node5.tsn.network"
)

# Configuration de mise to jour
UPDATE_STRATEGY="${UPDATE_STRATEGY:-rolling}"  # rolling, blue-green, canary
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"
BACKUP_BEFORE_UPDATE="${BACKUP_BEFORE_UPDATE:-true}"
UPDATE_PARALLEL_JOBS="${UPDATE_PARALLEL_JOBS:-1}"  # Pour rolling update

# Configuration Docker
DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io/tsn-network}"
IMAGE_NAME="${DOCKER_REGISTRY}/tsn"
SERVICE_NAME="tsn-node"

# Directories
UPDATE_STATE_DIR="${PROJECT_ROOT}/logs/updates"
ROLLBACK_DATA_DIR="${UPDATE_STATE_DIR}/rollback"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ===== FONCTIONS UTILITAIRES =====
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

info() {
    log "INFO: $*"
    echo -e "${BLUE}ℹ${NC} $*"
}

success() {
    log "SUCCESS: $*"
    echo -e "${GREEN}✓${NC} $*"
}

warn() {
    log "WARN: $*"
    echo -e "${YELLOW}⚠${NC} $*"
}

error() {
    log "ERROR: $*"
    echo -e "${RED}✗${NC} $*"
    exit 1
}

# ===== INITIALISATION =====
init_update() {
    info "Initialization de la mise to jour..."
    
    # Creation des directories
    mkdir -p "$UPDATE_STATE_DIR" "$ROLLBACK_DATA_DIR"
    
    # Verification des prerequisites
    for cmd in ssh docker jq curl; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd n'est pas installed"
        fi
    done
    
    success "Initialization completeed"
}

# ===== VERIFICATION DE VERSION =====
get_current_version() {
    local node_name="$1"
    local ssh_target="${NODES[$node_name]}"
    
    # Recovery de la version depuis l'API du node
    local version
    if version=$(ssh "$ssh_target" "curl -s --max-time 10 http://localhost:8080/api/v1/version | jq -r '.version // \"unknown\"'" 2>/dev/null); then
        echo "$version"
    else
        # Fallback: version depuis l'image Docker
        ssh "$ssh_target" "docker inspect $SERVICE_NAME --format '{{index .Config.Labels \"tsn.version\"}}' 2>/dev/null || echo 'unknown'"
    fi
}

get_image_version() {
    local image_tag="$1"
    
    # Recovery des metadata de l'image
    if docker manifest inspect "$IMAGE_NAME:$image_tag" &>/dev/null; then
        docker inspect "$IMAGE_NAME:$image_tag" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || echo "$image_tag"
    else
        echo "$image_tag"
    fi
}

# ===== VERIFICATIONS HEALTH =====
check_node_health() {
    local node_name="$1"
    local ssh_target="${NODES[$node_name]}"
    local timeout="${2:-30}"
    
    info "Verification de health de $node_name..."
    
    local retries=0
    local max_retries=$((timeout / 5))
    
    while [[ $retries -lt $max_retries ]]; do
        # Test API HTTP
        if ssh "$ssh_target" "curl -f --max-time 5 http://localhost:8080/health" &>/dev/null; then
            # Test connectivity P2P
            if ssh "$ssh_target" "nc -z localhost 9000" &>/dev/null; then
                success "$node_name est en bonne health"
                return 0
            fi
        fi
        
        retries=$((retries + 1))
        sleep 5
    done
    
    error "$node_name n'est pas en bonne health after ${timeout}s"
    return 1
}

# ===== SAUVEGARDE PRE-SET To JOUR =====
backup_node_state() {
    local node_name="$1"
    local ssh_target="${NODES[$node_name]}"
    local backup_id
    backup_id="$(date +%Y%m%d_%H%M%S)"
    local backup_file="${ROLLBACK_DATA_DIR}/${node_name}_${backup_id}.json"
    
    info "Backup de l'state de $node_name..."
    
    # Collecte des informations de rollback
    local rollback_data
    rollback_data=$(ssh "$ssh_target" "
        # Version actuelle
        current_version=\$(docker inspect $SERVICE_NAME --format '{{index .Config.Labels \"tsn.version\"}}' 2>/dev/null || echo 'unknown')
        current_image=\$(docker inspect $SERVICE_NAME --format '{{.Config.Image}}' 2>/dev/null || echo 'unknown')
        
        # Configuration du conteneur
        container_config=\$(docker inspect $SERVICE_NAME 2>/dev/null || echo '[]')
        
        # State du service systemd
        systemd_status=\$(systemctl is-active $SERVICE_NAME 2>/dev/null || echo 'unknown')
        
        # Generation JSON
        jq -n \
            --arg node '$node_name' \
            --arg version \"\$current_version\" \
            --arg image \"\$current_image\" \
            --arg systemd \"\$systemd_status\" \
            --arg timestamp '$(date -u +%Y-%m-%dT%H:%M:%SZ)' \
            --argjson config \"\$container_config\" \
            '{
                node_name: \$node,
                backup_timestamp: \$timestamp,
                current_version: \$version,
                current_image: \$image,
                systemd_status: \$systemd,
                container_config: \$config
            }'
    ")
    
    echo "$rollback_data" > "$backup_file"
    
    success "State saved: $(basename "$backup_file")"
    echo "$backup_file"
}

# ===== MISE To JOUR D'UN NODE =====
update_node() {
    local node_name="$1"
    local target_version="$2"
    local ssh_target="${NODES[$node_name]}"
    local backup_file=""
    
    info "Mise to jour de $node_name vers $target_version..."
    
    # Verification de la version actuelle
    local current_version
    current_version=$(get_current_version "$node_name")
    
    if [[ "$current_version" == "$target_version" ]]; then
        success "$node_name est already en version $target_version"
        return 0
    fi
    
    info "$node_name: $current_version → $target_version"
    
    # Backup pre-set to jour
    if [[ "$BACKUP_BEFORE_UPDATE" == "true" ]]; then
        backup_file=$(backup_node_state "$node_name")
    fi
    
    # Verification que l'image existe
    local target_image="$IMAGE_NAME:$target_version"
    if ! ssh "$ssh_target" "docker pull '$target_image'" &>/dev/null; then
        error "Impossible de retrieve l'image $target_image"
    fi
    
    # Shutdown du service actuel
    info "Shutdown du service sur $node_name..."
    ssh "$ssh_target" "
        sudo systemctl stop $SERVICE_NAME 2>/dev/null || true
        docker stop $SERVICE_NAME 2>/dev/null || true
        docker rm $SERVICE_NAME 2>/dev/null || true
    "
    
    # Startup avec la nouvelle version
    info "Startup de la nouvelle version sur $node_name..."
    ssh "$ssh_target" "
        # Mise to jour de la variable d'environnement systemd
        sudo sed -i 's/TSN_IMAGE_TAG=.*/TSN_IMAGE_TAG=$target_version/' /etc/systemd/system/$SERVICE_NAME.service
        sudo systemctl daemon-reload
        
        # Startup du service
        sudo systemctl start $SERVICE_NAME
    "
    
    # Verification de health
    if check_node_health "$node_name" "$HEALTH_CHECK_TIMEOUT"; then
        success "Mise to jour de $node_name succeedede"
        
        # Nettoyage de l'ancienne image
        ssh "$ssh_target" "docker image prune -f" &>/dev/null || true
        
        return 0
    else
        error "Failure de la mise to jour de $node_name"
        
        # Rollback automatique si activated
        if [[ "$ROLLBACK_ON_FAILURE" == "true" && -n "$backup_file" ]]; then
            warn "Rollback automatique de $node_name..."
            rollback_node "$node_name" "$backup_file"
        fi
        
        return 1
    fi
}

# ===== ROLLBACK D'UN NODE =====
rollback_node() {
    local node_name="$1"
    local backup_file="$2"
    local ssh_target="${NODES[$node_name]}"
    
    info "Rollback de $node_name..."
    
    if [[ ! -f "$backup_file" ]]; then
        error "Fichier de sauvegarde introuvable: $backup_file"
    fi
    
    # Lecture des data de rollback
    local rollback_data
    rollback_data=$(cat "$backup_file")
    local previous_image
    previous_image=$(echo "$rollback_data" | jq -r '.current_image')
    local previous_version
    previous_version=$(echo "$rollback_data" | jq -r '.current_version')
    
    info "Rollback vers $previous_image (version $previous_version)"
    
    # Shutdown du service actuel
    ssh "$ssh_target" "
        sudo systemctl stop $SERVICE_NAME 2>/dev/null || true
        docker stop $SERVICE_NAME 2>/dev/null || true
        docker rm $SERVICE_NAME 2>/dev/null || true
    "
    
    # Restauration de la configuration systemd
    ssh "$ssh_target" "
        sudo sed -i 's/TSN_IMAGE_TAG=.*/TSN_IMAGE_TAG=$previous_version/' /etc/systemd/system/$SERVICE_NAME.service
        sudo systemctl daemon-reload
        sudo systemctl start $SERVICE_NAME
    "
    
    # Verification de health
    if check_node_health "$node_name" "$HEALTH_CHECK_TIMEOUT"; then
        success "Rollback de $node_name succeeded"
        return 0
    else
        error "Failure du rollback de $node_name"
        return 1
    fi
}

# ===== STRATEGIES DE MISE To JOUR =====
rolling_update() {
    local target_version="$1"
    local failed_nodes=()
    
    info "Mise to jour progressive (rolling) vers $target_version..."
    
    for node_name in "${!NODES[@]}"; do
        info "=== Mise to jour de $node_name ==="
        
        if update_node "$node_name" "$target_version"; then
            success "$node_name mis to jour avec success"
            
            # Attente avant le node following
            if [[ "$node_name" != "${!NODES[-1]}" ]]; then
                info "Attente de stabilisation (30s)..."
                sleep 30
            fi
        else
            error "Failure de la mise to jour de $node_name"
            failed_nodes+=("$node_name")
            
            # Shutdown en cas d'failure critique
            if [[ ${#failed_nodes[@]} -gt 1 ]]; then
                error "Trop d'failures, shutdown de la mise to jour"
                break
            fi
        fi
    done
    
    # Rapport final
    if [[ ${#failed_nodes[@]} -eq 0 ]]; then
        success "Mise to jour progressive completeed avec success"
        return 0
    else
        error "Mise to jour progressive failede pour: ${failed_nodes[*]}"
        return 1
    fi
}

canary_update() {
    local target_version="$1"
    local canary_node="node1"  # Premier node comme canary
    
    info "Mise to jour canary vers $target_version..."
    
    # Mise to jour du node canary
    info "=== Mise to jour canary de $canary_node ==="
    if ! update_node "$canary_node" "$target_version"; then
        error "Failure de la mise to jour canary"
        return 1
    fi
    
    # Period d'observation
    info "Period d'observation canary (5 minutes)..."
    sleep 300
    
    # Verification de health extended
    if ! check_node_health "$canary_node" 60; then
        error "Node canary instable, rollback..."
        local backup_file
        backup_file=$(find "$ROLLBACK_DATA_DIR" -name "${canary_node}_*.json" | sort | tail -1)
        rollback_node "$canary_node" "$backup_file"
        return 1
    fi
    
    success "Canary stable, mise to jour des autres nodes..."
    
    # Mise to jour des autres nodes
    local failed_nodes=()
    for node_name in "${!NODES[@]}"; do
        if [[ "$node_name" != "$canary_node" ]]; then
            if ! update_node "$node_name" "$target_version"; then
                failed_nodes+=("$node_name")
            fi
        fi
    done
    
    if [[ ${#failed_nodes[@]} -eq 0 ]]; then
        success "Mise to jour canary completeed avec success"
        return 0
    else
        error "Failure de mise to jour pour: ${failed_nodes[*]}"
        return 1
    fi
}

blue_green_update() {
    local target_version="$1"
    
    info "Mise to jour blue-green vers $target_version..."
    
    # Pour blue-green, on met to jour tous les nodes en parallel
    # puis on bascule le trafic
    
    info "Preparation des nodes green..."
    local pids=()
    local failed_nodes=()
    
    for node_name in "${!NODES[@]}"; do
        update_node "$node_name" "$target_version" &
        pids+=($!)
    done
    
    # Attente de tous les jobs
    local i=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed_nodes+=("${!NODES[$i]}")
        fi
        i=$((i + 1))
    done
    
    if [[ ${#failed_nodes[@]} -eq 0 ]]; then
        success "Mise to jour blue-green completeed avec success"
        return 0
    else
        error "Failure de mise to jour blue-green pour: ${failed_nodes[*]}"
        return 1
    fi
}

# ===== VERIFICATION POST-MISE To JOUR =====
verify_cluster_health() {
    local target_version="$1"
    
    info "Verification de health du cluster..."
    
    local healthy_nodes=0
    local total_nodes=${#NODES[@]}
    
    for node_name in "${!NODES[@]}"; do
        if check_node_health "$node_name" 30; then
            local current_version
            current_version=$(get_current_version "$node_name")
            if [[ "$current_version" == "$target_version" ]]; then
                healthy_nodes=$((healthy_nodes + 1))
                success "$node_name: OK (version $current_version)"
            else
                warn "$node_name: Version incorrecte ($current_version != $target_version)"
            fi
        else
            error "$node_name: Failing"
        fi
    done
    
    local health_percentage
    health_percentage=$(echo "scale=0; $healthy_nodes * 100 / $total_nodes" | bc)
    
    info "Health du cluster: $healthy_nodes/$total_nodes nodes ($health_percentage%)"
    
    if [[ $healthy_nodes -eq $total_nodes ]]; then
        success "Cluster entirely operationnel"
        return 0
    elif [[ $health_percentage -ge 80 ]]; then
        warn "Cluster partiellement operationnel"
        return 1
    else
        error "Cluster en state critique"
        return 2
    fi
}

# ===== RAPPORT DE MISE To JOUR =====
generate_update_report() {
    local target_version="$1"
    local start_time="$2"
    local end_time
    end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local report_file="${UPDATE_STATE_DIR}/update_report_$(date +%Y%m%d_%H%M%S).json"
    
    info "Generation du rapport de mise to jour..."
    
    # Collecte des versions actuelles
    local nodes_status="[]"
    for node_name in "${!NODES[@]}"; do
        local current_version
        current_version=$(get_current_version "$node_name")
        local is_healthy=false
        if check_node_health "$node_name" 10 &>/dev/null; then
            is_healthy=true
        fi
        
        nodes_status=$(echo "$nodes_status" | jq \
            --arg node "$node_name" \
            --arg version "$current_version" \
            --arg healthy "$is_healthy" \
            '. += [{
                node: $node,
                version: $version,
                is_healthy: ($healthy == "true"),
                target_reached: ($version == "'$target_version'")
            }]')
    done
    
    # Generation du rapport
    jq -n \
        --arg start "$start_time" \
        --arg end "$end_time" \
        --arg target "$target_version" \
        --arg strategy "$UPDATE_STRATEGY" \
        --argjson nodes "$nodes_status" \
        '{
            update_timestamp: $start,
            completion_timestamp: $end,
            target_version: $target,
            update_strategy: $strategy,
            duration_seconds: (($end | fromdateiso8601) - ($start | fromdateiso8601)),
            nodes: $nodes,
            summary: {
                total_nodes: ($nodes | length),
                successful_updates: ($nodes | map(select(.target_reached)) | length),
                healthy_nodes: ($nodes | map(select(.is_healthy)) | length),
                success_rate: (($nodes | map(select(.target_reached)) | length) / ($nodes | length) * 100)
            }
        }' > "$report_file"
    
    success "Rapport generated: $report_file"
    
    # Affichage du summary
    local successful_updates
    successful_updates=$(echo "$nodes_status" | jq '[.[] | select(.target_reached)] | length')
    local healthy_nodes
    healthy_nodes=$(echo "$nodes_status" | jq '[.[] | select(.is_healthy)] | length')
    
    echo ""
    echo "=== SUMMARY MISE To JOUR ==="
    echo "Version cible: $target_version"
    echo "Strategy: $UPDATE_STRATEGY"
    echo "Mises to jour succeededes: $successful_updates/${#NODES[@]}"
    echo "Nodes sains: $healthy_nodes/${#NODES[@]}"
    echo "Duration: $(( $(date +%s) - $(date -d "$start_time" +%s) ))s"
    echo ""
}

# ===== AIDE =====
show_help() {
    cat << EOF
Script de update automatique des nodes TSN

USAGE:
    $0 [COMMAND] [OPTIONS] VERSION

COMMANDS:
    update VERSION      Update vers la version specified
    rollback NODE       Rollback d'un node vers sa version previous
    status              Affichage du status des versions
    list-backups        Liste des sauvegardes disponibles
    help                Afficher cette aide

OPTIONS:
    --strategy STRATEGY     Strategy de update (rolling|canary|blue-green)
    --no-backup            Pas de backup avant update
    --no-rollback          Pas de rollback automatique en cas d'failure
    --timeout SECONDS      Timeout pour les verifications de health
    --parallel JOBS        Jobs parallel (pour rolling update)

VARIABLES D'ENVIRONNEMENT:
    UPDATE_STRATEGY         Strategy par default (rolling)
    HEALTH_CHECK_TIMEOUT    Timeout health (300s)
    ROLLBACK_ON_FAILURE     Rollback auto (true)
    BACKUP_BEFORE_UPDATE    Backup avant MAJ (true)
    DOCKER_REGISTRY         Registry Docker

STRATEGIES:
    rolling     Update sequential node par node (default)
    canary      Update d'un node test puis des autres
    blue-green  Update simultaneous de tous les nodes

EXEMPLES:
    $0 update v1.2.0                    # Update rolling
    $0 update v1.2.0 --strategy canary  # Update canary
    $0 rollback node1                   # Rollback du node 1
    $0 status                           # Status des versions
    $0 list-backups                     # Liste des sauvegardes

SECURITY:
    - Backup automatique avant each update
    - Verifications de health at each step
    - Rollback automatique en cas d'failure
    - Logs detailed de toutes les operations
EOF
}

# ===== FONCTION PRINCIPALE =====
main() {
    local command=""
    local target_version=""
    local node_name=""
    
    # Parsing des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            update|rollback|status|list-backups|help)
                command="$1"
                shift
                ;;
            --strategy)
                UPDATE_STRATEGY="$2"
                shift 2
                ;;
            --no-backup)
                BACKUP_BEFORE_UPDATE="false"
                shift
                ;;
            --no-rollback)
                ROLLBACK_ON_FAILURE="false"
                shift
                ;;
            --timeout)
                HEALTH_CHECK_TIMEOUT="$2"
                shift 2
                ;;
            --parallel)
                UPDATE_PARALLEL_JOBS="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                if [[ "$command" == "update" && -z "$target_version" ]]; then
                    target_version="$1"
                elif [[ "$command" == "rollback" && -z "$node_name" ]]; then
                    node_name="$1"
                else
                    error "Argument inattendu: $1"
                fi
                shift
                ;;
        esac
    done
    
    # Verification de la commande
    if [[ -z "$command" ]]; then
        error "Commande requise. Utilisez --help pour l'aide."
    fi
    
    # Initialisation
    init_update
    
    # Execution de la commande
    local start_time
    start_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    case "$command" in
        "update")
            if [[ -z "$target_version" ]]; then
                error "Version cible requise pour la mise to jour"
            fi
            
            info "Startup de la mise to jour vers $target_version (strategy: $UPDATE_STRATEGY)"
            
            case "$UPDATE_STRATEGY" in
                "rolling")
                    rolling_update "$target_version"
                    ;;
                "canary")
                    canary_update "$target_version"
                    ;;
                "blue-green")
                    blue_green_update "$target_version"
                    ;;
                *)
                    error "Strategy inconnue: $UPDATE_STRATEGY"
                    ;;
            esac
            
            verify_cluster_health "$target_version"
            generate_update_report "$target_version" "$start_time"
            ;;
        "rollback")
            if [[ -z "$node_name" ]]; then
                error "Nom du node requis pour le rollback"
            fi
            
            local backup_file
            backup_file=$(find "$ROLLBACK_DATA_DIR" -name "${node_name}_*.json" | sort | tail -1)
            
            if [[ -z "$backup_file" ]]; then
                error "Aucune backup found pour $node_name"
            fi
            
            rollback_node "$node_name" "$backup_file"
            ;;
        "status")
            echo "=== STATUS DES VERSIONS TSN ==="
            for node_name in "${!NODES[@]}"; do
                local current_version
                current_version=$(get_current_version "$node_name")
                local health_status="❌"
                if check_node_health "$node_name" 10 &>/dev/null; then
                    health_status="✅"
                fi
                echo "$node_name: $current_version $health_status"
            done
            ;;
        "list-backups")
            echo "=== SAUVEGARDES DISPONIBLES ==="
            if [[ -d "$ROLLBACK_DATA_DIR" ]]; then
                find "$ROLLBACK_DATA_DIR" -name "*.json" -printf "%TY-%Tm-%Td %TH:%TM  %f\n" | sort -r
            else
                echo "Aucune backup found"
            fi
            ;;
        "help")
            show_help
            ;;
        *)
            error "Commande inconnue: $command"
            ;;
    esac
    
    success "Operation '$command' completeed"
}

# Point d'entry
main "$@"