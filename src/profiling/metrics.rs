//! Prometheus metrics for profiling critical operations
//!
//! This module defines histograms and counters for:
//! - Cryptographic operations (sign, verify, hash)
//! - Database operations (read, write, scan)
//! - Serialization/deserialization (serialize, deserialize)

use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec,
    register_histogram, register_histogram_vec, 
    register_int_counter, register_int_counter_vec,
    opts, histogram_opts,
};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Duration;

/// Metrics for cryptographic operations
pub struct CryptoMetrics {
    /// Duration histogram by operation
    pub duration: HistogramVec,
    /// Total operation counter
    pub total_count: IntCounterVec,
    /// Error counter
    pub error_count: IntCounterVec,
    /// Slow operation counter (> 100ms)
    pub slow_count: IntCounterVec,
}

impl CryptoMetrics {
    /// Creates a new crypto metrics instance
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_crypto_duration_seconds",
                    "Duration of cryptographic operations in seconds",
                    vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
                ),
                &["operation"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_operations_total",
                    "Total number of cryptographic operations"
                ),
                &["operation"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_errors_total",
                    "Number of errors during cryptographic operations"
                ),
                &["operation"]
            )?,
            
            slow_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_slow_operations_total",
                    "Number of slow cryptographic operations (> 100ms)"
                ),
                &["operation"]
            )?,
        })
    }
    
    /// Records a successful operation
    pub fn record_operation(&self, operation: &str, duration_secs: f64) {
        self.duration.with_label_values(&[operation]).observe(duration_secs);
        self.total_count.with_label_values(&[operation]).inc();
        
        if duration_secs > 0.1 {
            self.slow_count.with_label_values(&[operation]).inc();
        }
    }
    
    /// Records an error
    pub fn record_error(&self, operation: &str) {
        self.error_count.with_label_values(&[operation]).inc();
    }
    
    /// Creates a snapshot of current metrics
    pub fn snapshot(&self) -> CategorySnapshot {
        // Les valeurs are collected via Prometheus
        CategorySnapshot {
            category: "crypto",
            operations: vec![
                "sign", "verify", "hash", "batch_verify",
                "zk_proof_verify", "zk_proof_generate",
            ],
        }
    }
}

/// Metrics for database operations
pub struct DatabaseMetrics {
    /// Duration histogram by operation
    pub duration: HistogramVec,
    /// Total operation counter
    pub total_count: IntCounterVec,
    /// Error counter
    pub error_count: IntCounterVec,
    /// Slow operation counter
    pub slow_count: IntCounterVec,
    /// Size of read/written data
    pub bytes_transferred: HistogramVec,
}

impl DatabaseMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_db_duration_seconds",
                    "Duration of database operations in seconds",
                    vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
                ),
                &["operation", "table"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_operations_total",
                    "Total number of database operations"
                ),
                &["operation", "table"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_errors_total",
                    "Number of errors during database operations"
                ),
                &["operation", "table"]
            )?,
            
            slow_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_slow_operations_total",
                    "Number of slow database operations (> 50ms)"
                ),
                &["operation", "table"]
            )?,
            
            bytes_transferred: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_db_bytes_transferred",
                    "Number of bytes transferred during DB operations",
                    vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0]
                ),
                &["operation", "table"]
            )?,
        })
    }
    
    /// Records a successful operation
    pub fn record_operation(&self, operation: &str, table: &str, duration_secs: f64) {
        self.duration
            .with_label_values(&[operation, table])
            .observe(duration_secs);
        self.total_count
            .with_label_values(&[operation, table])
            .inc();
        
        if duration_secs > 0.05 {
            self.slow_count
                .with_label_values(&[operation, table])
                .inc();
        }
    }
    
    /// Records an operation with data size
    pub fn record_operation_with_size(
        &self, 
        operation: &str, 
        table: &str, 
        duration_secs: f64,
        bytes: usize
    ) {
        self.record_operation(operation, table, duration_secs);
        self.bytes_transferred
            .with_label_values(&[operation, table])
            .observe(bytes as f64);
    }
    
    /// Records an error
    pub fn record_error(&self, operation: &str, table: &str) {
        self.error_count.with_label_values(&[operation, table]).inc();
    }
    
    /// Creates a snapshot of metrics
    pub fn snapshot(&self) -> CategorySnapshot {
        CategorySnapshot {
            category: "database",
            operations: vec![
                "read", "write", "scan", "delete", "batch_write",
            ],
        }
    }
}

/// Metrics for serialization/deserialization
pub struct SerdeMetrics {
    /// Duration histogram
    pub duration: HistogramVec,
    /// Total operation counter
    pub total_count: IntCounterVec,
    /// Size of serialized/deserialized data
    pub bytes_processed: HistogramVec,
    /// Error counter
    pub error_count: IntCounterVec,
}

impl SerdeMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_serde_duration_seconds",
                    "Duration of serialization operations in seconds",
                    vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
                ),
                &["operation", "type"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_serde_operations_total",
                    "Total number of serialization operations"
                ),
                &["operation", "type"]
            )?,
            
            bytes_processed: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_serde_bytes_processed",
                    "Number of bytes processed during serialization",
                    vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0]
                ),
                &["operation", "type"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_serde_errors_total",
                    "Number of errors during serialization operations"
                ),
                &["operation", "type"]
            )?,
        })
    }
    
    /// Records a serialization operation
    pub fn record_operation(
        &self, 
        operation: &str, 
        type_name: &str, 
        duration_secs: f64,
        bytes: usize
    ) {
        self.duration
            .with_label_values(&[operation, type_name])
            .observe(duration_secs);
        self.total_count
            .with_label_values(&[operation, type_name])
            .inc();
        self.bytes_processed
            .with_label_values(&[operation, type_name])
            .observe(bytes as f64);
    }
    
    /// Records an error
    pub fn record_error(&self, operation: &str, type_name: &str) {
        self.error_count.with_label_values(&[operation, type_name]).inc();
    }
    
    /// Creates a snapshot of metrics
    pub fn snapshot(&self) -> CategorySnapshot {
        CategorySnapshot {
            category: "serialization",
            operations: vec![
                "serialize", "deserialize",
            ],
        }
    }
}

/// Snapshot of a metrics category
#[derive(Debug, Clone, serde::Serialize)]
pub struct CategorySnapshot {
    pub category: &'static str,
    pub operations: Vec<&'static str>,
}

// === Global instances ===

pub static CRYPTO_METRICS: Lazy<CryptoMetrics> = Lazy::new(|| {
    CryptoMetrics::new().expect("INIT: failure metrics crypto Prometheus — noms duplicated?")
});

pub static DB_METRICS: Lazy<DatabaseMetrics> = Lazy::new(|| {
    DatabaseMetrics::new().expect("INIT: failure metrics DB Prometheus — noms duplicated?")
});

pub static SERDE_METRICS: Lazy<SerdeMetrics> = Lazy::new(|| {
    SerdeMetrics::new().expect("INIT: failure metrics serde Prometheus — noms duplicated?")
});

/// Guard for automatically measuring duration
pub struct ProfilingGuard {
    histogram: Option<Histogram>,
    start: std::time::Instant,
}

impl ProfilingGuard {
    /// Creates a new guard for a histogram
    pub fn new(histogram: Histogram) -> Self {
        Self {
            histogram: Some(histogram),
            start: std::time::Instant::now(),
        }
    }
    
    /// Creates an empty guard (no-op)
    pub fn noop() -> Self {
        Self {
            histogram: None,
            start: std::time::Instant::now(),
        }
    }
}

impl Drop for ProfilingGuard {
    fn drop(&mut self) {
        if let Some(h) = self.histogram.take() {
            h.observe(self.start.elapsed().as_secs_f64());
        }
    }
}

/// Records a value in a histogram
pub fn record_histogram(histogram: &Histogram, duration: Duration) {
    histogram.observe(duration.as_secs_f64());
}

/// Creates a profiling guard and starts the timer
pub fn profile_duration(histogram: &Histogram) -> ProfilingGuard {
    ProfilingGuard::new(histogram.clone())
}

/// Macro for measuring the duration of an expression
#[macro_export]
macro_rules! profile {
    ($metrics:expr, $operation:expr, $body:expr) => {{
        let _timer = $metrics.duration.with_label_values(&[$operation]).start_timer();
        let result = $body;
        result
    }};
}

/// Macro for measuring with error handling
#[macro_export]
macro_rules! profile_result {
    ($metrics:expr, $operation:expr, $body:expr) => {{
        let timer = $metrics.duration.with_label_values(&[$operation]).start_timer();
        let result = $body;
        timer.observe_duration();
        
        if result.is_err() {
            $metrics.error_count.with_label_values(&[$operation]).inc();
        }
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_metrics() {
        CRYPTO_METRICS.record_operation("test", 0.001);
        CRYPTO_METRICS.record_error("test");
        
        let snapshot = CRYPTO_METRICS.snapshot();
        assert_eq!(snapshot.category, "crypto");
    }
    
    #[test]
    fn test_db_metrics() {
        DB_METRICS.record_operation("read", "blocks", 0.001);
        DB_METRICS.record_operation_with_size("write", "accounts", 0.002, 1024);
        
        let snapshot = DB_METRICS.snapshot();
        assert_eq!(snapshot.category, "database");
    }
    
    #[test]
    fn test_serde_metrics() {
        SERDE_METRICS.record_operation("serialize", "Block", 0.0001, 512);
        
        let snapshot = SERDE_METRICS.snapshot();
        assert_eq!(snapshot.category, "serialization");
    }
}