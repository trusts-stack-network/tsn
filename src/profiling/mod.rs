//! Module de profiling integrated pour diagnostics TSN
//!
//! Ce module fournit des metrics detailed sur les performances des
//! operations critiques : signature/verification crypto, serialization,
//! requests DB. Les metrics sont exported via Prometheus.
//!
//! ## Utilisation
//!
//! ```rust
//! use tsn::profiling::{profile_crypto_op, profile_db_op, profile_serde_op};
//!
//! // Profiler une operation crypto
//! let result = profile_crypto_op("sign", || {
//!     sign_message(message, keypair)
//! });
//!
//! // Profiler une request DB
//! let block = profile_db_op("load_block", || {
//!     db.load_block(&hash)
//! });
//! ```

pub mod macros;
pub mod metrics;
pub mod instrumentation;

pub use metrics::{
    ProfilingMetrics, CRYPTO_METRICS, DB_METRICS, SERDE_METRICS,
    ProfilingGuard, profile_duration, record_histogram,
};
pub use instrumentation::{
    profile_crypto_op, profile_db_op, profile_serde_op,
    profile_crypto_verify, profile_crypto_sign,
    profile_db_read, profile_db_write, profile_db_scan,
    profile_serde_serialize, profile_serde_deserialize,
};

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

/// Version du module de profiling
pub const PROFILING_VERSION: &str = "1.0.0";

/// Enable or disable profiling globally
static PROFILING_ENABLED: AtomicU64 = AtomicU64::new(1);

/// Seuil minimum pour logger un avertissement (en millisecondes)
static SLOW_OP_THRESHOLD_MS: AtomicU64 = AtomicU64::new(100);

/// Verifies si le profiling est enabled
pub fn is_profiling_enabled() -> bool {
    PROFILING_ENABLED.load(Ordering::Relaxed) != 0
}

/// Active le profiling
pub fn enable_profiling() {
    PROFILING_ENABLED.store(1, Ordering::Relaxed);
}

/// Disables le profiling
pub fn disable_profiling() {
    PROFILING_ENABLED.store(0, Ordering::Relaxed);
}

/// Defines le seuil d'avertissement pour les operations lentes (en ms)
pub fn set_slow_threshold_ms(threshold: u64) {
    SLOW_OP_THRESHOLD_MS.store(threshold, Ordering::Relaxed);
}

/// Retrieves le seuil d'avertissement actuel
pub fn get_slow_threshold_ms() -> u64 {
    SLOW_OP_THRESHOLD_MS.load(Ordering::Relaxed)
}

/// Structure pour mesurer la duration d'une operation
pub struct OperationTimer {
    start: Instant,
    name: String,
    category: OperationCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationCategory {
    Crypto,
    Database,
    Serialization,
    Consensus,
    Network,
}

impl OperationTimer {
    /// Creates un nouveau timer
    pub fn new(name: impl Into<String>, category: OperationCategory) -> Self {
        Self {
            start: Instant::now(),
            name: name.into(),
            category,
        }
    }
    
    /// Stoppinge le timer et enregistre la metric
    pub fn stop(self) -> Duration {
        let duration = self.start.elapsed();
        
        if is_profiling_enabled() {
            record_duration(self.category, &self.name, duration);
            
            // Verify si l'operation est lente
            let threshold = Duration::from_millis(get_slow_threshold_ms());
            if duration > threshold {
                tracing::warn!(
                    operation = %self.name,
                    category = ?self.category,
                    duration_ms = %duration.as_millis(),
                    threshold_ms = %threshold.as_millis(),
                    "Operation lente detectede"
                );
            }
        }
        
        duration
    }
    
    /// Stoppinge le timer sans register (pour les errors)
    pub fn cancel(self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        // Rien to faire ici, utiliser explicitement stop() ou cancel()
    }
}

/// Enregistre une duration dans les metrics appropriate
fn record_duration(category: OperationCategory, name: &str, duration: Duration) {
    let duration_secs = duration.as_secs_f64();
    
    match category {
        OperationCategory::Crypto => {
            metrics::CRYPTO_METRICS.record_operation(name, duration_secs);
        }
        OperationCategory::Database => {
            metrics::DB_METRICS.record_operation(name, duration_secs);
        }
        OperationCategory::Serialization => {
            metrics::SERDE_METRICS.record_operation(name, duration_secs);
        }
        OperationCategory::Consensus => {
            // Integrated avec les metrics consensus existantes
        }
        OperationCategory::Network => {
            // Integrated avec les metrics network existantes
        }
    }
}

/// Wrapper pour profiler une fonction
pub fn profile_fn<T, F>(name: &str, category: OperationCategory, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(name, category);
    let result = f();
    timer.stop();
    result
}

/// Wrapper async pour profiler une fonction async
pub async fn profile_async<T, F>(name: &str, category: OperationCategory, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(name, category);
    let result = f.await;
    timer.stop();
    result
}

/// Collecte toutes les metrics de profiling
pub fn collect_profiling_metrics() -> ProfilingSnapshot {
    ProfilingSnapshot {
        crypto: CRYPTO_METRICS.snapshot(),
        database: DB_METRICS.snapshot(),
        serialization: SERDE_METRICS.snapshot(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

/// Snapshot des metrics de profiling
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfilingSnapshot {
    pub crypto: metrics::CategorySnapshot,
    pub database: metrics::CategorySnapshot,
    pub serialization: metrics::CategorySnapshot,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_operation_timer() {
        let timer = OperationTimer::new("test_op", OperationCategory::Crypto);
        std::thread::sleep(Duration::from_millis(10));
        let duration = timer.stop();
        assert!(duration >= Duration::from_millis(10));
    }
    
    #[test]
    fn test_profile_fn() {
        let result = profile_fn("test", OperationCategory::Crypto, || {
            std::thread::sleep(Duration::from_millis(5));
            42
        });
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_profiling_toggle() {
        assert!(is_profiling_enabled());
        disable_profiling();
        assert!(!is_profiling_enabled());
        enable_profiling();
        assert!(is_profiling_enabled());
    }
}