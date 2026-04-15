#!/bin/bash
set -euo pipefail

# Script de startup Prometheus pour TSN
# Manages la generation de config, validation et startup

SCRIPT_DIR="$(dirname "$0")"
CONFIG_FILE="$SCRIPT_DIR/prometheus-consensus.yml"
ALERTS_FILE="$SCRIPT_DIR/consensus_alerts.yml"
DATA_DIR="$SCRIPT_DIR/../data/prometheus"
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
PROMETHEUS_VERSION=${PROMETHEUS_VERSION:-"2.47.2"}

echo "🚀 Startup de Prometheus pour TSN"
echo "   Config: $CONFIG_FILE"
echo "   Alerts: $ALERTS_FILE"
echo "   Data: $DATA_DIR"
echo "   Port: $PROMETHEUS_PORT"

# Verify si Prometheus est installed
if ! command -v prometheus &> /dev/null; then
    echo "❌ Prometheus non found. Installation automatique..."
    
    # Detect l'architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) PROM_ARCH="amd64" ;;
        aarch64|arm64) PROM_ARCH="arm64" ;;
        *) echo "❌ Architecture non supported: $ARCH"; exit 1 ;;
    esac
    
    # Download et installer Prometheus
    PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-${PROM_ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    echo "📥 Download de Prometheus $PROMETHEUS_VERSION pour $PROM_ARCH..."
    curl -L "$PROM_URL" | tar -xz -C "$TEMP_DIR" --strip-components=1
    
    # Installer dans /usr/local/bin
    sudo mv "$TEMP_DIR/prometheus" /usr/local/bin/
    sudo mv "$TEMP_DIR/promtool" /usr/local/bin/
    sudo chmod +x /usr/local/bin/prometheus /usr/local/bin/promtool
    
    rm -rf "$TEMP_DIR"
    echo "✅ Prometheus installed avec success"
fi

# Generate la configuration si elle n'existe pas ou si forced
if [[ ! -f "$CONFIG_FILE" ]] || [[ "${FORCE_REGEN:-false}" == "true" ]]; then
    echo "🔧 Generation de la configuration Prometheus..."
    "$SCRIPT_DIR/generate-prometheus-config.sh" "$CONFIG_FILE"
fi

# Verify que les files de configuration existent
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Fichier de configuration manquant: $CONFIG_FILE"
    exit 1
fi

if [[ ! -f "$ALERTS_FILE" ]]; then
    echo "❌ Fichier d'alertes manquant: $ALERTS_FILE"
    exit 1
fi

# Valider la configuration avec promtool
echo "🔍 Validation de la configuration..."
if ! promtool check config "$CONFIG_FILE"; then
    echo "❌ Configuration Prometheus invalide"
    exit 1
fi

if ! promtool check rules "$ALERTS_FILE"; then
    echo "❌ Rules d'alerte invalides"
    exit 1
fi

echo "✅ Configuration validated"

# Create le directory de data
mkdir -p "$DATA_DIR"

# Verify si Prometheus est already en cours d'execution
if pgrep -f "prometheus.*$PROMETHEUS_PORT" > /dev/null; then
    echo "⚠️  Prometheus semble already en cours d'execution sur le port $PROMETHEUS_PORT"
    echo "   Shutdown de l'instance existing..."
    pkill -f "prometheus.*$PROMETHEUS_PORT" || true
    sleep 2
fi

# Start Prometheus
echo "🎯 Startup de Prometheus..."
prometheus \
    --config.file="$CONFIG_FILE" \
    --storage.tsdb.path="$DATA_DIR" \
    --web.listen-address="0.0.0.0:$PROMETHEUS_PORT" \
    --web.console.libraries=/usr/local/share/prometheus/console_libraries \
    --web.console.templates=/usr/local/share/prometheus/consoles \
    --storage.tsdb.retention.time=30d \
    --storage.tsdb.retention.size=10GB \
    --web.enable-lifecycle \
    --web.enable-admin-api \
    --log.level=info \
    --log.format=logfmt &

PROMETHEUS_PID=$!
echo "✅ Prometheus started (PID: $PROMETHEUS_PID)"
echo ""
echo "📊 Interface web disponible sur:"
echo "   http://localhost:$PROMETHEUS_PORT"
echo ""
echo "🎯 Targets configured:"
echo "   http://localhost:$PROMETHEUS_PORT/targets"
echo ""
echo "📈 Metrics de consensus TSN:"
echo "   http://localhost:$PROMETHEUS_PORT/graph?g0.expr=tsn_consensus_blocks_processed_total"
echo ""
echo "🔍 Pour surveiller les logs:"
echo "   tail -f $DATA_DIR/prometheus.log"
echo ""
echo "⏹️  Pour stop Prometheus:"
echo "   kill $PROMETHEUS_PID"

# Attendre quelques secondes et verify que Prometheus starts correctly
sleep 3
if ! kill -0 $PROMETHEUS_PID 2>/dev/null; then
    echo "❌ Prometheus n'a pas pu start correctly"
    exit 1
fi

echo "🎉 Prometheus operationnel !"

# Garder le script en vie si launched en mode interactif
if [[ "${PROMETHEUS_DAEMON:-false}" == "false" ]]; then
    echo ""
    echo "Appuyez sur Ctrl+C pour stop Prometheus..."
    trap "echo '🛑 Shutdown de Prometheus...'; kill $PROMETHEUS_PID; exit 0" INT
    wait $PROMETHEUS_PID
fi