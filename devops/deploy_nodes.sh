#!/bin/bash
# Script de deployment automatique TSN sur 5 nodes
# Trust Stack Network DevOps Automation
# Author: Yuki.T Release & DevOps Engineer

set -euo pipefail

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${TSN_VERSION:-$(git describe --tags --always --dirty)}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse HEAD)}"

# Configuration des nodes (to adapt to infrastructure)
declare -A NODES=(
    ["node1"]="user@node1.tsn.network"
    ["node2"]="user@node2.tsn.network" 
    ["node3"]="user@node3.tsn.network"
    ["node4"]="user@node4.tsn.network"
    ["node5"]="user@node5.tsn.network"
)

# Configuration Docker
DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io/tsn-network}"
IMAGE_NAME="${DOCKER_REGISTRY}/tsn"
IMAGE_TAG="${VERSION}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

# Configuration des services
SERVICE_NAME="tsn-node"
SERVICE_USER="tsn"
DATA_DIR="/opt/tsn/data"
CONFIG_DIR="/opt/tsn/config"
LOGS_DIR="/opt/tsn/logs"

# Timeouts et retry
DEPLOY_TIMEOUT=300
HEALTH_TIMEOUT=120
MAX_RETRIES=3
PARALLEL_JOBS=3

# ===== FONCTIONS UTILITAIRES =====
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

error() {
    log "ERROR: $*"
    exit 1
}

warn() {
    log "WARN: $*"
}

info() {
    log "INFO: $*"
}

# Verification des prerequisites
check_prerequisites() {
    info "Verification des prerequisites..."
    
    # Verify Docker
    if ! command -v docker &> /dev/null; then
        error "Docker n'est pas installed"
    fi
    
    # Verify Git
    if ! command -v git &> /dev/null; then
        error "Git n'est pas installed"
    fi
    
    # Verify SSH
    if ! command -v ssh &> /dev/null; then
        error "SSH n'est pas installed"
    fi
    
    # Verify connection aux nodes
    info "Test de connectivity SSH..."
    for node_name in "${!NODES[@]}"; do
        ssh_target="${NODES[$node_name]}"
        if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${ssh_target}" "echo 'SSH OK'" &>/dev/null; then
            warn "Connexion SSH vers ${node_name} (${ssh_target}) failede"
        else
            info "✓ ${node_name} accessible"
        fi
    done
}

# Construction de l'image Docker
build_image() {
    info "Construction de l'image Docker ${FULL_IMAGE}..."
    
    cd "${PROJECT_ROOT}"
    
    # Build de l'image avec build args
    docker build \
        -f devops/Dockerfile \
        -t "${FULL_IMAGE}" \
        -t "${IMAGE_NAME}:latest" \
        --build-arg TSN_VERSION="${VERSION}" \
        --build-arg GIT_COMMIT="${GIT_COMMIT}" \
        --build-arg BUILD_DATE="${BUILD_DATE}" \
        --target runtime \
        .
    
    info "✓ Image Docker construite: ${FULL_IMAGE}"
}

# Test de l'image Docker localement
test_image() {
    info "Test de l'image Docker..."
    
    # Test de base: verify que le binaire fonctionne
    docker run --rm "${FULL_IMAGE}" --version || error "Test de l'image failed"
    
    info "✓ Image Docker tested"
}

# Push de l'image vers le registry
push_image() {
    if [[ "${SKIP_PUSH:-false}" == "true" ]]; then
        info "Push vers registry ignored (SKIP_PUSH=true)"
        return 0
    fi
    
    info "Push de l'image vers ${DOCKER_REGISTRY}..."
    
    # Login au registry si credentials disponibles
    if [[ -n "${DOCKER_USERNAME:-}" && -n "${DOCKER_PASSWORD:-}" ]]; then
        echo "${DOCKER_PASSWORD}" | docker login "${DOCKER_REGISTRY}" -u "${DOCKER_USERNAME}" --password-stdin
    fi
    
    docker push "${FULL_IMAGE}"
    docker push "${IMAGE_NAME}:latest"
    
    info "✓ Image pushed vers registry"
}

# Deployment sur un node
deploy_to_node() {
    local node_name="$1"
    local ssh_target="${NODES[$node_name]}"
    
    info "Deployment sur ${node_name} (${ssh_target})..."
    
    # Script de deployment distant
    ssh "${ssh_target}" "bash -s" << EOF
set -euo pipefail

# Fonction de log distant
log() {
    echo "[${node_name}] \$*"
}

log "Start du deployment..."

# Creation utilisateur tsn si inexisting
if ! id "${SERVICE_USER}" &>/dev/null; then
    log "Creation utilisateur ${SERVICE_USER}..."
    sudo useradd -r -s /bin/false -d /opt/tsn "${SERVICE_USER}" || true
fi

# Creation des directories
log "Creation des directories..."
sudo mkdir -p "${DATA_DIR}" "${CONFIG_DIR}" "${LOGS_DIR}"
sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}" "${CONFIG_DIR}" "${LOGS_DIR}"

# Installation/mise to jour Docker si necessary
if ! command -v docker &>/dev/null; then
    log "Installation Docker..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker \$USER
fi

# Pull de l'image
log "Pull de l'image Docker..."
sudo docker pull "${FULL_IMAGE}"

# Shutdown du service existing
log "Shutdown du service existing..."
sudo systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
sudo docker rm -f "${SERVICE_NAME}" 2>/dev/null || true

# Startup du nouveau conteneur
log "Startup du nouveau conteneur..."
sudo docker run -d \\
    --name "${SERVICE_NAME}" \\
    --restart unless-stopped \\
    --user "${SERVICE_USER}" \\
    -v "${DATA_DIR}:/data/tsn" \\
    -v "${LOGS_DIR}:/data/tsn/logs" \\
    -p 8080:8080 \\
    -p 9000:9000 \\
    -p 9001:9001 \\
    -p 9090:9090 \\
    --log-driver json-file \\
    --log-opt max-size=100m \\
    --log-opt max-file=3 \\
    "${FULL_IMAGE}"

# Attendre que le service starts
log "Attente du startup du service..."
for i in {1..30}; do
    if sudo docker exec "${SERVICE_NAME}" curl -f http://localhost:8080/health &>/dev/null; then
        log "✓ Service started avec success"
        break
    fi
    if [[ \$i -eq 30 ]]; then
        log "ERREUR: Service n'a pas started dans les temps"
        exit 1
    fi
    sleep 2
done

log "Deployment completeed avec success"
EOF
    
    if [[ $? -eq 0 ]]; then
        info "✓ ${node_name} deployed avec success"
    else
        error "✗ Failure du deployment sur ${node_name}"
    fi
}

# Verification de health des nodes
health_check() {
    info "Verification de health des nodes..."
    
    local failed_nodes=()
    
    for node_name in "${!NODES[@]}"; do
        ssh_target="${NODES[$node_name]}"
        
        info "Test health ${node_name}..."
        if ssh "${ssh_target}" "curl -f http://localhost:8080/health" &>/dev/null; then
            info "✓ ${node_name} en bonne health"
        else
            warn "✗ ${node_name} ne responds pas"
            failed_nodes+=("${node_name}")
        fi
    done
    
    if [[ ${#failed_nodes[@]} -gt 0 ]]; then
        warn "Nodes failing: ${failed_nodes[*]}"
        return 1
    fi
    
    info "✓ Tous les nodes sont en bonne health"
    return 0
}

# Installation des configurations systemd
install_systemd_configs() {
    info "Installation des configurations systemd..."
    
    for node_name in "${!NODES[@]}"; do
        ssh_target="${NODES[$node_name]}"
        
        # Copie du fichier systemd
        scp "${SCRIPT_DIR}/systemd/tsn-node.service" "${ssh_target}:/tmp/"
        
        ssh "${ssh_target}" "
            sudo mv /tmp/tsn-node.service /etc/systemd/system/
            sudo systemctl daemon-reload
            sudo systemctl enable ${SERVICE_NAME}
        "
    done
}

# Affichage du statut final
show_status() {
    info "=== STATUT FINAL ==="
    
    for node_name in "${!NODES[@]}"; do
        ssh_target="${NODES[$node_name]}"
        
        echo "=== ${node_name} ==="
        ssh "${ssh_target}" "
            echo 'Service Status:'
            sudo systemctl status ${SERVICE_NAME} --no-pager -l || true
            echo
            echo 'Container Status:'
            sudo docker ps --filter name=${SERVICE_NAME} || true
            echo
        " || warn "Impossible de retrieve le statut de ${node_name}"
    done
}

# ===== FONCTION PRINCIPALE =====
main() {
    local action="${1:-deploy}"
    
    case "${action}" in
        "build")
            check_prerequisites
            build_image
            test_image
            ;;
        "deploy")
            check_prerequisites
            build_image
            test_image
            push_image
            install_systemd_configs
            
            info "Deployment sur ${#NODES[@]} nodes..."
            for node_name in "${!NODES[@]}"; do
                deploy_to_node "${node_name}" &
                
                # Limitation du parallelism
                if (( $(jobs -r | wc -l) >= PARALLEL_JOBS )); then
                    wait -n
                fi
            done
            wait
            
            sleep 5
            health_check
            show_status
            ;;
        "health")
            health_check
            ;;
        "status")
            show_status
            ;;
        "stop")
            info "Shutdown des services sur tous les nodes..."
            for node_name in "${!NODES[@]}"; do
                ssh "${NODES[$node_name]}" "
                    sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true
                    sudo docker stop ${SERVICE_NAME} 2>/dev/null || true
                " &
            done
            wait
            ;;
        *)
            echo "Usage: $0 {build|deploy|health|status|stop}"
            echo ""
            echo "Actions:"
            echo "  build  - Construire l'image Docker uniquement"
            echo "  deploy - Deployment complete sur tous les nodes"
            echo "  health - Verification de health only"
            echo "  status - Affichage du statut des nodes"
            echo "  stop   - Shutdown des services sur tous les nodes"
            echo ""
            echo "Variables d'environnement:"
            echo "  TSN_VERSION      - Version to deploy (default: git describe)"
            echo "  DOCKER_REGISTRY  - Registry Docker (default: ghcr.io/tsn-network)"
            echo "  SKIP_PUSH        - Ignorer le push (default: false)"
            exit 1
            ;;
    esac
    
    info "Action '${action}' completeed avec success"
}

# Trap pour cleanup
trap 'echo "Script interrompu"; jobs -p | xargs -r kill; exit 130' INT TERM

# Point d'entry
main "$@"