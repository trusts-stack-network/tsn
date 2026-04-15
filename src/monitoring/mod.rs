//! Dashboard de monitoring in temps real for Trust Stack Network (TSN)
//!
//! This module provides :
//! - Surveillance of metrics blockchain in temps real
//! - Transaction throughput, block validation, peer state
//! - Health cryptographique post-quantique
//! - Interface REST for integration externe
//! - WebSocket for mises up to date temps real

pub mod api;
pub mod crypto_health;
pub mod dashboard_server;
pub mod realtime;
pub mod websocket;

pub use api::MonitoringApi;
pub use crypto_health::CryptoHealthMonitor;
pub use dashboard_server::DashboardServer;
pub use realtime::RealtimeMetricsCollector;
pub use websocket::WebSocketManager;

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Version of the dashboard de monitoring
pub const DASHBOARD_VERSION: &str = "1.0.0";

/// Port by default for the dashboard
pub const DEFAULT_DASHBOARD_PORT: u16 = 8080;

/// Port by default for the metrics Prometheus
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Intervalle de refresh by default (secondes)
pub const DEFAULT_REFRESH_INTERVAL: u64 = 5;

/// Configuration of the dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Port d'listening of the dashboard
    pub port: u16,
    /// Bind address
    pub bind_address: String,
    /// Intervalle de refresh of metrics (secondes)
    pub refresh_interval: u64,
    /// Enable WebSocket updates
    pub enable_websocket: bool,
    /// Activer l'API REST
    pub enable_rest_api: bool,
    /// Activer the metrics Prometheus
    pub enable_prometheus: bool,
    /// Port for the metrics Prometheus
    pub prometheus_port: u16,
    /// Duration de retention of data historiques (heures)
    pub data_retention_hours: u64,
    /// Maximum number of data points per series
    pub max_data_points: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_DASHBOARD_PORT,
            bind_address: "0.0.0.0".to_string(),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            enable_websocket: true,
            enable_rest_api: true,
            enable_prometheus: true,
            prometheus_port: DEFAULT_METRICS_PORT,
            data_retention_hours: 24,
            max_data_points: 10000,
        }
    }
}

/// Statut global of the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Version of the node
    pub node_version: String,
    /// Version of the dashboard
    pub dashboard_version: String,
    /// Uptime in secondes
    pub uptime_seconds: u64,
    /// Timestamp of the dernier update
    pub last_update: u64,
    /// Statut general (healthy, degraded, critical)
    pub overall_status: HealthStatus,
    /// Sous-systems
    pub subsystems: SubsystemStatus,
}

/// Statut de health
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
    Unknown,
}

/// Statut of sous-systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemStatus {
    /// Blockchain
    pub blockchain: HealthStatus,
    /// Network P2P
    pub network: HealthStatus,
    /// Consensus
    pub consensus: HealthStatus,
    /// Cryptographie
    pub crypto: HealthStatus,
    /// Mempool
    pub mempool: HealthStatus,
    /// Stockage
    pub storage: HealthStatus,
}

impl Default for SubsystemStatus {
    fn default() -> Self {
        Self {
            blockchain: HealthStatus::Unknown,
            network: HealthStatus::Unknown,
            consensus: HealthStatus::Unknown,
            crypto: HealthStatus::Unknown,
            mempool: HealthStatus::Unknown,
            storage: HealthStatus::Unknown,
        }
    }
}

/// Performance metrics critique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalMetrics {
    /// Throughput de transactions (TPS)
    pub transactions_per_second: f64,
    /// Average block validation time (ms)
    pub avg_block_validation_time_ms: f64,
    /// Network latency moyenne (ms)
    pub avg_network_latency_ms: f64,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Mempool size
    pub mempool_size: usize,
    /// Height de the blockchain
    pub block_height: u64,
    /// Hashrate of the network (estimation)
    pub network_hashrate: f64,
    /// Taux d'orphan blocks (%)
    pub orphan_rate_percent: f64,
}

/// Point of data temporel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub value: f64,
}

/// Helper for obtenir the timestamp actuel
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Helper for formater a duration
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Helper for formater of bytes
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_idx])
}

/// Helper for formater a hashrate
pub fn format_hashrate(hps: f64) -> String {
    const UNITS: &[&str] = &["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
    let mut rate = hps;
    let mut unit_idx = 0;
    
    while rate >= 1000.0 && unit_idx < UNITS.len() - 1 {
        rate /= 1000.0;
        unit_idx += 1;
    }
    
    format!("{:.2} {}", rate, UNITS[unit_idx])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3665), "1h 1m 5s");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512.00 B");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }
    
    #[test]
    fn test_format_hashrate() {
        assert_eq!(format_hashrate(500.0), "500.00 H/s");
        assert_eq!(format_hashrate(1500.0), "1.50 KH/s");
        assert_eq!(format_hashrate(2000000.0), "2.00 MH/s");
    }
}