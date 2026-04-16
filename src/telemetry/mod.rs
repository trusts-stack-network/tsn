//! Structured telemetry module for TSN
//!
//! This module provides logging and tracing utilities for the entire
//! the TSN application. It centralizes the subscriber configuration and provides
//! predefined spans for critical operations.
//!
//! # Usage
//!
//! ```rust
//! use tsn::telemetry::{init_tracing, crypto_span, network_span};
//! use tracing::{info, instrument};
//!
//! // Initialize tracing at startup
//! init_tracing("info");
//!
//! // Use a predefined span
//! let _span = crypto_span("signature_validation");
//! info!(target: "tsn::crypto", "Validation startede");
//! ```

use std::time::Duration;
use tracing::{span, Level, Span};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Initializes the tracing system with TSN configuration.
///
/// # Arguments
/// * `default_level` - Default log level (e.g., "info", "debug")
///
/// # Exemple
/// ```rust
/// init_tracing("tsn=info,network=debug");
/// ```
pub fn init_tracing(default_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_span_events(FmtSpan::CLOSE)
                .with_timer(fmt::time::UtcTime::rfc_3339()),
        )
        .with(filter)
        .init();
}

/// Creates a span for critical cryptographic operations.
///
/// # Arguments
/// * `operation` - Operation name (e.g., "signature_validation", "proof_generation")
pub fn crypto_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "crypto_operation",
        operation = operation,
        category = "cryptography",
        sensitivity = "high"
    )
}

/// Creates a span for network operations.
///
/// # Arguments
/// * `operation` - Operation name (e.g., "sync", "mempool_relay")
pub fn network_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "network_operation",
        operation = operation,
        category = "network",
        sensitivity = "medium"
    )
}

/// Creates a span for consensus operations.
///
/// # Arguments
/// * `operation` - Operation name (e.g., "block_validation", "fork_choice")
pub fn consensus_span(operation: &str) -> Span {
    span!(
        Level::INFO,
        "consensus_operation",
        operation = operation,
        category = "consensus",
        sensitivity = "high"
    )
}

/// Creates a span for storage operations.
///
/// # Arguments
/// * `operation` - Operation name (e.g., "block_write", "state_read")
pub fn storage_span(operation: &str) -> Span {
    span!(
        Level::TRACE,
        "storage_operation",
        operation = operation,
        category = "storage",
        sensitivity = "low"
    )
}

/// Creates a span for wallet operations.
///
/// # Arguments
/// * `operation` - Operation name (e.g., "transaction_create", "note_scan")
pub fn wallet_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "wallet_operation",
        operation = operation,
        category = "wallet",
        sensitivity = "high"
    )
}

/// Instruments a function for tracing with standard attributes.
///
/// This macro automatically adds attributes like module, line,
/// and execution time.
#[macro_export]
macro_rules! trace_fn {
    ($level:expr, $name:expr) => {
        let _span = tracing::span!($level, $name, module = module_path!(), line = line!());
        let _enter = _span.enter();
    };
}

/// Log a performance metric with context.
///
/// # Arguments
/// * `name` - Metric name
/// * `value` - Value (in milliseconds generally)
/// * `context` - Contexte additionnel
pub fn log_metric(name: &str, value: u64, context: &str) {
    tracing::info!(
        target: "tsn::metrics",
        metric = name,
        value_ms = value,
        context = context,
        "Performance metric"
    );
}

/// Log a security event with criticality level.
///
/// # Arguments
/// * `level` - Criticality level (warn, error)
/// * `event_type` - Type d'event
/// * `description` - Description detailed
/// * `source` - Source de l'event
pub fn log_security_event(level: Level, event_type: &str, description: &str, source: &str) {
    match level {
        Level::ERROR => {
            tracing::error!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
        Level::WARN => {
            tracing::warn!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
        _ => {
            tracing::info!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
    }
}

/// Structure for measuring the execution time of an operation.
///
/// Uses the RAII pattern to automatically measure duration.
pub struct Timer {
    name: String,
    start: std::time::Instant,
    context: String,
}

impl Timer {
    /// Creates a new timer.
    ///
    /// # Arguments
    /// * `name` - Name of the measured operation
    /// * `context` - Contexte additionnel
    pub fn new(name: &str, context: &str) -> Self {
        Self {
            name: name.to_string(),
            start: std::time::Instant::now(),
            context: context.to_string(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        log_metric(&self.name, elapsed.as_millis() as u64, &self.context);
    }
}

/// Extension trait for instrumenting results with logging.
pub trait InstrumentResult<T, E> {
    /// Log the result with the appropriate level.
    fn instrument(self, operation: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> InstrumentResult<T, E> for Result<T, E> {
    fn instrument(self, operation: &str) -> Result<T, E> {
        match &self {
            Ok(_) => {
                tracing::debug!(target: "tsn::operations", operation = operation, "Success");
            }
            Err(e) => {
                tracing::error!(
                    target: "tsn::operations",
                    operation = operation,
                    error = %e,
                    "Operation failed"
                );
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let span = crypto_span("test_operation");
        assert_eq!(span.metadata().unwrap().name(), "crypto_operation");
    }

    #[test]
    fn test_timer_creation() {
        let timer = Timer::new("test_op", "test_context");
        // Timer will be dropped at end of test
        drop(timer);
    }
}
