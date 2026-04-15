#!/bin/bash
# Script de backup automatique des nodes TSN
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

# Configuration backup
BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/opt/tsn-backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
BACKUP_COMPRESSION="${BACKUP_COMPRESSION:-true}"
BACKUP_ENCRYPTION="${BACKUP_ENCRYPTION:-true}"
BACKUP_PARALLEL_JOBS="${BACKUP_PARALLEL_JOBS:-3}"

# Directories to save sur each node
BACKUP_PATHS=(
    "/opt/tsn/data"
    "/opt/tsn/config"
    "/opt/tsn/logs"
    "/etc/systemd/system/tsn-node.service"
)

# Configuration S3 (optionnel)
S3_BUCKET="${S3_BUCKET:-}"
S3_PREFIX="${S3_PREFIX:-tsn-backups}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Configuration encryption
GPG_RECIPIENT="${GPG_RECIPIENT:-}"
BACKUP_PASSWORD="${BACKUP_PASSWORD:-}"

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

# ===== VERIFICATIONS PREREQUISITES =====
check_prerequisites() {
    info "Verification des prerequisites..."
    
    # Commandes requises
    local required_commands=("ssh" "rsync" "tar" "gzip")
    
    if [[ "$BACKUP_ENCRYPTION" == "true" ]]; then
        if [[ -n "$GPG_RECIPIENT" ]]; then
            required_commands+=("gpg")
        elif [[ -n "$BACKUP_PASSWORD" ]]; then
            required_commands+=("openssl")
        fi
    fi
    
    if [[ -n "$S3_BUCKET" ]]; then
        required_commands+=("aws")
    fi
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd n'est pas installed"
        fi
    done
    
    # Verification de l'espace disque
    local available_space
    available_space=$(df "$BACKUP_BASE_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $available_space -lt 10485760 ]]; then  # 10GB en KB
        warn "Espace disque faible: $(( available_space / 1024 / 1024 ))GB disponible"
    fi
    
    # Creation du directory de backup
    mkdir -p "$BACKUP_BASE_DIR"
    
    success "Prerequisites verifieds"
}

# ===== BACKUP D'UN NODE =====
backup_node() {
    local node_name="$1"
    local ssh_target="${NODES[$node_name]}"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    local backup_dir="${BACKUP_BASE_DIR}/${node_name}/${timestamp}"
    
    info "Backup du node $node_name..."
    
    # Creation du directory de backup
    mkdir -p "$backup_dir"
    
    # Verification de la connectivity SSH
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" "echo 'SSH OK'" &>/dev/null; then
        error "Impossible de se connecter to $node_name ($ssh_target)"
    fi
    
    # Shutdown temporaire du service pour coherence (optional)
    local service_stopped=false
    if [[ "${STOP_SERVICE_FOR_BACKUP:-false}" == "true" ]]; then
        info "Shutdown temporaire du service TSN sur $node_name..."
        ssh "$ssh_target" "sudo systemctl stop tsn-node" || warn "Impossible d'stop le service"
        service_stopped=true
        sleep 5
    fi
    
    # Backup de each directory
    local backup_success=true
    for path in "${BACKUP_PATHS[@]}"; do
        local path_name
        path_name="$(basename "$path")"
        local local_backup_path="${backup_dir}/${path_name}"
        
        info "Backup de $path depuis $node_name..."
        
        # Verification que le directory existe
        if ! ssh "$ssh_target" "test -e '$path'"; then
            warn "Directory $path n'existe pas sur $node_name"
            continue
        fi
        
        # Rsync avec compression et preservation des attributs
        if rsync -avz --compress-level=6 \
                 --exclude='*.tmp' \
                 --exclude='*.lock' \
                 --exclude='logs/*.log.*' \
                 -e "ssh -o ConnectTimeout=30" \
                 "$ssh_target:$path/" \
                 "$local_backup_path/"; then
            success "Backup de $path completeed"
        else
            error "Failure du backup de $path"
            backup_success=false
        fi
    done
    
    # Restartup du service si stopped
    if [[ "$service_stopped" == "true" ]]; then
        info "Restartup du service TSN sur $node_name..."
        ssh "$ssh_target" "sudo systemctl start tsn-node" || warn "Impossible de restart le service"
        
        # Attente que le service restarts
        local retries=0
        while [[ $retries -lt 30 ]]; do
            if ssh "$ssh_target" "curl -f http://localhost:8080/health" &>/dev/null; then
                success "Service TSN restarted sur $node_name"
                break
            fi
            sleep 2
            retries=$((retries + 1))
        done
        
        if [[ $retries -eq 30 ]]; then
            warn "Service TSN n'a pas restarted correctly sur $node_name"
        fi
    fi
    
    if [[ "$backup_success" == "false" ]]; then
        error "Failure du backup de $node_name"
    fi
    
    # Collecte des metadata
    local metadata_file="${backup_dir}/metadata.json"
    cat > "$metadata_file" << EOF
{
    "node_name": "$node_name",
    "ssh_target": "$ssh_target",
    "backup_timestamp": "$timestamp",
    "backup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_paths": $(printf '%s\n' "${BACKUP_PATHS[@]}" | jq -R . | jq -s .),
    "service_stopped": $service_stopped,
    "backup_size_bytes": $(du -sb "$backup_dir" | cut -f1),
    "backup_version": "1.0"
}
EOF
    
    # Compression du backup
    if [[ "$BACKUP_COMPRESSION" == "true" ]]; then
        info "Compression du backup de $node_name..."
        local archive_file="${BACKUP_BASE_DIR}/${node_name}/${node_name}_${timestamp}.tar.gz"
        
        if tar -czf "$archive_file" -C "$backup_dir" .; then
            # Deletion du directory non compressed
            rm -rf "$backup_dir"
            backup_dir="$archive_file"
            success "Backup compressed: $(basename "$archive_file")"
        else
            error "Failure de la compression"
        fi
    fi
    
    # Chiffrement du backup
    if [[ "$BACKUP_ENCRYPTION" == "true" ]]; then
        info "Chiffrement du backup de $node_name..."
        local encrypted_file="${backup_dir}.enc"
        
        if [[ -n "$GPG_RECIPIENT" ]]; then
            # Chiffrement GPG
            if gpg --trust-model always --encrypt -r "$GPG_RECIPIENT" --output "$encrypted_file" "$backup_dir"; then
                rm -f "$backup_dir"
                backup_dir="$encrypted_file"
                success "Backup encrypted avec GPG"
            else
                error "Failure du encryption GPG"
            fi
        elif [[ -n "$BACKUP_PASSWORD" ]]; then
            # Chiffrement OpenSSL
            if openssl enc -aes-256-cbc -salt -pbkdf2 -in "$backup_dir" -out "$encrypted_file" -pass pass:"$BACKUP_PASSWORD"; then
                rm -f "$backup_dir"
                backup_dir="$encrypted_file"
                success "Backup encrypted avec OpenSSL"
            else
                error "Failure du encryption OpenSSL"
            fi
        fi
    fi
    
    # Upload vers S3 (optionnel)
    if [[ -n "$S3_BUCKET" ]]; then
        info "Upload du backup de $node_name vers S3..."
        local s3_key="${S3_PREFIX}/${node_name}/$(basename "$backup_dir")"
        
        if aws s3 cp "$backup_dir" "s3://${S3_BUCKET}/${s3_key}" --region "$AWS_REGION"; then
            success "Backup uploaded vers S3: s3://${S3_BUCKET}/${s3_key}"
            
            # Deletion local after upload succeeded (optional)
            if [[ "${DELETE_LOCAL_AFTER_S3:-false}" == "true" ]]; then
                rm -f "$backup_dir"
                info "Backup local deleted after upload S3"
            fi
        else
            warn "Failure de l'upload S3"
        fi
    fi
    
    success "Backup de $node_name completeed: $(basename "$backup_dir")"
}

# ===== NETTOYAGE DES ANCIENS BACKUPS =====
cleanup_old_backups() {
    info "Nettoyage des anciens backups (> $BACKUP_RETENTION_DAYS jours)..."
    
    local deleted_count=0
    
    for node_name in "${!NODES[@]}"; do
        local node_backup_dir="${BACKUP_BASE_DIR}/${node_name}"
        
        if [[ ! -d "$node_backup_dir" ]]; then
            continue
        fi
        
        # Suppression des fichiers anciens
        while IFS= read -r -d '' file; do
            rm -f "$file"
            deleted_count=$((deleted_count + 1))
            info "Deleted: $(basename "$file")"
        done < <(find "$node_backup_dir" -type f -mtime +$BACKUP_RETENTION_DAYS -print0 2>/dev/null || true)
        
        # Deletion des directories vides
        find "$node_backup_dir" -type d -empty -delete 2>/dev/null || true
    done
    
    if [[ $deleted_count -gt 0 ]]; then
        success "$deleted_count anciens backups deleted"
    else
        info "Aucun ancien backup to supprimer"
    fi
    
    # Nettoyage S3 (optionnel)
    if [[ -n "$S3_BUCKET" ]]; then
        info "Nettoyage des anciens backups S3..."
        local cutoff_date
        cutoff_date=$(date -d "$BACKUP_RETENTION_DAYS days ago" +%Y-%m-%d)
        
        # Liste et suppression des objets anciens
        aws s3api list-objects-v2 \
            --bucket "$S3_BUCKET" \
            --prefix "$S3_PREFIX/" \
            --query "Contents[?LastModified<'$cutoff_date'].Key" \
            --output text | \
        while read -r key; do
            if [[ -n "$key" && "$key" != "None" ]]; then
                aws s3 rm "s3://${S3_BUCKET}/${key}"
                info "Deleted S3: $key"
            fi
        done
    fi
}

# ===== VERIFICATION DES BACKUPS =====
verify_backup() {
    local backup_file="$1"
    
    info "Verification du backup: $(basename "$backup_file")"
    
    # Verification de l'integrity selon le type de file
    if [[ "$backup_file" == *.tar.gz ]]; then
        if tar -tzf "$backup_file" > /dev/null; then
            success "Archive tar.gz valide"
            return 0
        else
            error "Archive tar.gz corrompue"
            return 1
        fi
    elif [[ "$backup_file" == *.enc ]]; then
        # Pour les files encrypted, on ne peut que verify la taille
        if [[ -s "$backup_file" ]]; then
            success "Fichier encrypted present"
            return 0
        else
            error "Fichier encrypted vide ou missing"
            return 1
        fi
    else
        # Directory non compressed
        if [[ -d "$backup_file" ]]; then
            success "Directory de backup valide"
            return 0
        else
            error "Directory de backup missing"
            return 1
        fi
    fi
}

# ===== RAPPORT DE BACKUP =====
generate_backup_report() {
    local report_file="${BACKUP_BASE_DIR}/backup_report_$(date +%Y%m%d_%H%M%S).json"
    
    info "Generation du rapport de backup..."
    
    # Collecte des informations sur tous les backups
    local backup_info="[]"
    
    for node_name in "${!NODES[@]}"; do
        local node_backup_dir="${BACKUP_BASE_DIR}/${node_name}"
        
        if [[ ! -d "$node_backup_dir" ]]; then
            continue
        fi
        
        # Liste des backups pour ce node
        while IFS= read -r -d '' backup_path; do
            local backup_name
            backup_name="$(basename "$backup_path")"
            local backup_size
            backup_size="$(du -sb "$backup_path" 2>/dev/null | cut -f1 || echo "0")"
            local backup_date
            backup_date="$(stat -c %Y "$backup_path" 2>/dev/null || echo "0")"
            
            # Verification du backup
            local is_valid=false
            if verify_backup "$backup_path" &>/dev/null; then
                is_valid=true
            fi
            
            # Ajout to la liste
            backup_info=$(echo "$backup_info" | jq \
                --arg node "$node_name" \
                --arg name "$backup_name" \
                --arg path "$backup_path" \
                --arg size "$backup_size" \
                --arg date "$backup_date" \
                --arg valid "$is_valid" \
                '. += [{
                    node: $node,
                    name: $name,
                    path: $path,
                    size_bytes: ($size | tonumber),
                    date_timestamp: ($date | tonumber),
                    date_iso: ($date | tonumber | strftime("%Y-%m-%dT%H:%M:%SZ")),
                    is_valid: ($valid == "true")
                }]')
        done < <(find "$node_backup_dir" -maxdepth 1 -type f -print0 2>/dev/null || true)
    done
    
    # Statistiques globales
    local total_backups
    total_backups=$(echo "$backup_info" | jq 'length')
    local total_size
    total_size=$(echo "$backup_info" | jq '[.[].size_bytes] | add // 0')
    local valid_backups
    valid_backups=$(echo "$backup_info" | jq '[.[] | select(.is_valid)] | length')
    
    # Generation du rapport final
    jq -n \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg total "$total_backups" \
        --arg valid "$valid_backups" \
        --arg size "$total_size" \
        --argjson backups "$backup_info" \
        '{
            timestamp: $timestamp,
            summary: {
                total_backups: ($total | tonumber),
                valid_backups: ($valid | tonumber),
                total_size_bytes: ($size | tonumber),
                total_size_gb: (($size | tonumber) / 1024 / 1024 / 1024 | round * 100 / 100),
                success_rate: (($valid | tonumber) / ($total | tonumber) * 100 | round)
            },
            backups: $backups
        }' > "$report_file"
    
    success "Rapport generated: $report_file"
    
    # Affichage du summary
    echo ""
    echo "=== SUMMARY BACKUP TSN ==="
    echo "Total backups: $total_backups"
    echo "Backups valides: $valid_backups"
    echo "Taille totale: $(echo "scale=2; $total_size / 1024 / 1024 / 1024" | bc)GB"
    echo "Taux de success: $(echo "scale=0; $valid_backups * 100 / $total_backups" | bc)%"
    echo ""
}

# ===== RESTAURATION =====
restore_backup() {
    local node_name="$1"
    local backup_file="$2"
    local target_dir="${3:-/tmp/tsn-restore}"
    
    info "Restauration du backup $backup_file pour $node_name..."
    
    mkdir -p "$target_dir"
    
    # Decryption si necessary
    local working_file="$backup_file"
    if [[ "$backup_file" == *.enc ]]; then
        info "Decryption du backup..."
        local decrypted_file="${target_dir}/$(basename "$backup_file" .enc)"
        
        if [[ -n "$GPG_RECIPIENT" ]]; then
            gpg --decrypt --output "$decrypted_file" "$backup_file"
        elif [[ -n "$BACKUP_PASSWORD" ]]; then
            openssl enc -aes-256-cbc -d -pbkdf2 -in "$backup_file" -out "$decrypted_file" -pass pass:"$BACKUP_PASSWORD"
        else
            error "Aucune method de decryption configured"
        fi
        
        working_file="$decrypted_file"
    fi
    
    # Decompression si necessary
    if [[ "$working_file" == *.tar.gz ]]; then
        info "Decompression du backup..."
        tar -xzf "$working_file" -C "$target_dir"
    else
        info "Copie du backup..."
        cp -r "$working_file"/* "$target_dir/"
    fi
    
    success "Backup restored dans: $target_dir"
    
    # Affichage du contenu
    echo "Contenu restored:"
    ls -la "$target_dir"
}

# ===== AIDE =====
show_help() {
    cat << EOF
Script de backup automatique des nodes TSN

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    backup [NODE]       Backup d'un node specific ou tous
    cleanup             Nettoyage des anciens backups
    verify [FILE]       Verification d'un backup
    restore NODE FILE   Restauration d'un backup
    report              Generation d'un rapport
    list                Liste des backups disponibles
    help                Afficher cette aide

OPTIONS:
    --retention DAYS    Retention en jours (default: 30)
    --compress          Activer la compression (default: true)
    --encrypt           Activer le encryption (default: true)
    --stop-service      Shutdowner le service pendant backup
    --parallel JOBS     Jobs parallel (default: 3)

VARIABLES D'ENVIRONNEMENT:
    BACKUP_BASE_DIR         Directory de backup (default: /opt/tsn-backups)
    BACKUP_RETENTION_DAYS   Retention en jours (default: 30)
    BACKUP_PASSWORD         Mot de passe pour chiffrement
    GPG_RECIPIENT          Destinataire GPG pour chiffrement
    S3_BUCKET              Bucket S3 pour stockage distant
    S3_PREFIX              Prefix S3 (default: tsn-backups)

EXEMPLES:
    $0 backup                    # Backup de tous les nodes
    $0 backup node1              # Backup du node 1 only
    $0 cleanup                   # Nettoyage des anciens backups
    $0 verify backup.tar.gz      # Verification d'un backup
    $0 restore node1 backup.tar.gz  # Restauration
    $0 report                    # Rapport des backups

CONFIGURATION:
    Edit les variables NODES, BACKUP_PATHS et autres en head de script
    pour adapter to your infrastructure.
EOF
}

# ===== FONCTION PRINCIPALE =====
main() {
    local command="backup"
    local target_node=""
    local backup_file=""
    
    # Parsing des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            backup|cleanup|verify|restore|report|list|help)
                command="$1"
                shift
                ;;
            --retention)
                BACKUP_RETENTION_DAYS="$2"
                shift 2
                ;;
            --compress)
                BACKUP_COMPRESSION="true"
                shift
                ;;
            --no-compress)
                BACKUP_COMPRESSION="false"
                shift
                ;;
            --encrypt)
                BACKUP_ENCRYPTION="true"
                shift
                ;;
            --no-encrypt)
                BACKUP_ENCRYPTION="false"
                shift
                ;;
            --stop-service)
                STOP_SERVICE_FOR_BACKUP="true"
                shift
                ;;
            --parallel)
                BACKUP_PARALLEL_JOBS="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                if [[ "$command" == "backup" && -z "$target_node" ]]; then
                    target_node="$1"
                elif [[ "$command" == "verify" && -z "$backup_file" ]]; then
                    backup_file="$1"
                elif [[ "$command" == "restore" ]]; then
                    if [[ -z "$target_node" ]]; then
                        target_node="$1"
                    elif [[ -z "$backup_file" ]]; then
                        backup_file="$1"
                    fi
                else
                    error "Argument inattendu: $1"
                fi
                shift
                ;;
        esac
    done
    
    # Verifications
    check_prerequisites
    
    # Execution de la commande
    case "$command" in
        "backup")
            if [[ -n "$target_node" ]]; then
                if [[ -z "${NODES[$target_node]:-}" ]]; then
                    error "Node inconnu: $target_node"
                fi
                backup_node "$target_node"
            else
                # Backup de tous les nodes
                local pids=()
                for node_name in "${!NODES[@]}"; do
                    backup_node "$node_name" &
                    pids+=($!)
                    
                    # Limitation du parallelism
                    if [[ ${#pids[@]} -ge $BACKUP_PARALLEL_JOBS ]]; then
                        wait "${pids[0]}"
                        pids=("${pids[@]:1}")
                    fi
                done
                
                # Attendre les derniers jobs
                for pid in "${pids[@]}"; do
                    wait "$pid"
                done
            fi
            cleanup_old_backups
            generate_backup_report
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "verify")
            if [[ -z "$backup_file" ]]; then
                error "Fichier de backup requis pour la verification"
            fi
            verify_backup "$backup_file"
            ;;
        "restore")
            if [[ -z "$target_node" || -z "$backup_file" ]]; then
                error "Node et file de backup requis pour la restauration"
            fi
            restore_backup "$target_node" "$backup_file"
            ;;
        "report")
            generate_backup_report
            ;;
        "list")
            echo "=== BACKUPS DISPONIBLES ==="
            for node_name in "${!NODES[@]}"; do
                local node_backup_dir="${BACKUP_BASE_DIR}/${node_name}"
                if [[ -d "$node_backup_dir" ]]; then
                    echo "Node: $node_name"
                    find "$node_backup_dir" -type f -printf "  %TY-%Tm-%Td %TH:%TM  %s bytes  %f\n" | sort -r
                    echo ""
                fi
            done
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