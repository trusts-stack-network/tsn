//! Structured logging system with rotation for TSN
//!
//! This module provides a unified logging system with:
//! - JSON support for easy ingestion by log aggregation tools
//! - Automatic file rotation by size or date
//! - Configurable log levels per module
//! - Integration with tracing for distributed spans and traces
//!
//! # Usage
//!
//! ```rust
//! use tsn::logging::{init_logging, LogConfig, LogRotation, LoggingHandle};
//!
//! let config = LogConfig::builder()
//!     .json_output(true)
//!     .rotation(LogRotation::Daily)
//!     .max_files(7)
//!     .build();
//!
//! let handle = init_logging(config).expect("Failed to initialize logging");
//! // For graceful shutdown:
//! // handle.shutdown();
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

mod appender;
mod config;
mod json_layer;
mod rotation;

pub use appender::{RotatingFileAppender, RotationPolicy};
pub use config::{LogConfig, LogConfigBuilder, LogOutput, LogRotation};
pub use json_layer::JsonLayer;
pub use rotation::{LogStats, RotationManager};

/// Logging system errors
#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("Failed to initialize file appender: {0}")]
    FileAppenderError(String),
    
    #[error("Failed to create log directory: {0}")]
    DirectoryCreationError(#[from] std::io::Error),
    
    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),
    
    #[error("Failed to initialize subscriber: {0}")]
    SubscriberInitError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Logging already initialized")]
    AlreadyInitialized,
    
    #[error("Invalid module log directive '{module}={level}': {source}")]
    InvalidModuleDirective {
        module: String,
        level: String,
        source: String,
    },
}

/// Result type for logging operations
pub type Result<T> = std::result::Result<T, LoggingError>;

/// Handle for controlling the logging system
/// 
/// This structure encapsulates the resources necessary for handling
/// the logging system lifecycle, including graceful shutdown
/// of the rotation manager.
#[derive(Debug, Clone)]
pub struct LoggingHandle {
    /// Cancellation token for the rotation manager
    rotation_cancel_token: Option<Arc<CancellationToken>>,
}

impl LoggingHandle {
    /// Creates a new handle without rotation manager
    fn new() -> Self {
        Self {
            rotation_cancel_token: None,
        }
    }

    /// Creates a new handle with a cancellation token for rotation
    fn with_rotation_token(token: CancellationToken) -> Self {
        Self {
            rotation_cancel_token: Some(Arc::new(token)),
        }
    }

    /// Gracefully stops the rotation manager
    /// 
    /// This method signals the rotation manager to
    /// shut down. It has no effect if rotation is not enabled.
    /// 
    /// # Exemple
    /// 
    /// ```rust
    /// use tsn::logging::{init_logging, LogConfig};
    /// 
    /// async fn example() {
    ///     let config = LogConfig::builder().build();
    ///     let handle = init_logging(config).unwrap();
    ///     
    ///     // ... using logging ...
    ///     
    ///     handle.shutdown();
    /// }
    /// ```
    pub fn shutdown(&self) {
        if let Some(token) = &self.rotation_cancel_token {
            token.cancel();
            tracing::info!(target: "tsn::logging", "Rotation manager shutdown requested");
        }
    }

    /// Checks if the rotation manager is active
    pub fn has_rotation(&self) -> bool {
        self.rotation_cancel_token.is_some()
    }
}

/// Initializes the logging system with the provided configuration.
///
/// This function configures the tracing subscriber with:
/// - A console layer (optional)
/// - A file layer with rotation (optional)
/// - A JSON layer for production (optional)
/// - An environment filter for controlling levels
///
/// # Arguments
/// * `config` - Configuration of the logging
///
/// # Returns
/// A `LoggingHandle` for controlling the logging lifecycle.
///
/// # Exemple
///
/// ```rust
/// use tsn::logging::{init_logging, LogConfig, LogRotation};
///
/// let config = LogConfig::builder()
///     .log_dir("./logs")
///     .file_name("tsn")
///     .rotation(LogRotation::Daily)
///     .max_files(7)
///     .console_output(true)
///     .json_output(true)
///     .build();
///
/// let handle = init_logging(config).unwrap();
/// ```
pub fn init_logging(config: LogConfig) -> Result<LoggingHandle> {
    // Create the log directory if necessary
    if !config.log_dir.exists() {
        std::fs::create_dir_all(&config.log_dir)?;
    }

    // Construire the filtre d'environnement
    let filter = build_env_filter(&config)?;

    // Initialize the subscriber with configured layers
    let subscriber = tracing_subscriber::registry().with(filter);

    // Add console layer if enabled
    let subscriber = if config.console_output {
        let console_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(config.show_thread_ids)
            .with_thread_names(config.show_thread_names)
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(fmt::time::UtcTime::rfc_3339())
            .with_ansi(config.use_ansi_colors);
        
        subscriber.with(console_layer)
    } else {
        subscriber.with(None)
    };

    // Add the file layer with rotation
    let subscriber = if config.file_output {
        let file_appender = RotatingFileAppender::new(
            config.log_dir.clone(),
            config.file_name.clone(),
            config.rotation.clone(),
            config.max_file_size,
        )?;
        
        let file_layer = if config.json_output {
            // JSON layer for production
            JsonLayer::new(file_appender).boxed()
        } else {
            // Formatted text layer for development
            fmt::layer()
                .with_writer(Arc::new(file_appender))
                .with_target(true)
                .with_thread_ids(config.show_thread_ids)
                .with_thread_names(config.show_thread_names)
                .with_span_events(FmtSpan::CLOSE)
                .with_timer(fmt::time::UtcTime::rfc_3339())
                .with_ansi(false)
                .boxed()
        };
        
        subscriber.with(file_layer)
    } else {
        subscriber.with(None)
    };

    // Initialize the subscriber
    subscriber.init();

    let mut handle = LoggingHandle::new();

    // Configure the rotation manager if necessary
    if config.file_output && config.rotation != LogRotation::Never {
        let rotation_manager = RotationManager::new(config.clone())?;
        
        // Create a cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();
        handle = LoggingHandle::with_rotation_token(cancel_token.clone());
        
        // Start the task de rotation in background
        let _handle = tokio::spawn(async move {
            rotation_manager.run(cancel_token).await;
        });
    }

    tracing::info!(
        target: "tsn::logging",
        log_dir = %config.log_dir.display(),
        rotation = ?config.rotation,
        json_output = config.json_output,
        "Logging system initialized"
    );

    Ok(handle)
}

/// Gracefully stops the rotation manager
/// 
/// # Deprecated
/// This function is deprecated. Use `LoggingHandle::shutdown()` instead.
/// It is temporarily kept for backward compatibility.
#[deprecated(since = "0.2.0", note = "Utilisez LoggingHandle::shutdown() to la place")]
pub fn shutdown_rotation() {
    // This function no longer does anything as the token is no longer global
    // Users should migrate to LoggingHandle::shutdown()
    tracing::warn!(
        target: "tsn::logging",
        "shutdown_rotation() est deprecated. Utilisez LoggingHandle::shutdown()"
    );
}

/// Builds the environment filter from the configuration.
/// 
/// # Errors
/// Returns an error if a module directive is invalid.
fn build_env_filter(config: &LogConfig) -> Result<EnvFilter> {
    // First try the RUST_LOG environment variable
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|e| {
            // If RUST_LOG is not defined or invalid, log the error and use default_level
            tracing::warn!(
                target: "tsn::logging",
                error = %e,
                "RUST_LOG invalid or not defined, using default level"
            );
            EnvFilter::try_new(&config.default_level)
                .unwrap_or_else(|e| {
                    tracing::error!(
                        target: "tsn::logging",
                        error = %e,
                        default_level = %config.default_level,
                        "Default log level invalid, falling back to 'info'"
                    );
                    EnvFilter::new("info")
                })
        });

    // Add module-specific level directives
    let mut filter = filter;
    for (module, level) in &config.module_levels {
        let directive_str = format!("{}={}", module, level);
        match directive_str.parse::<tracing_subscriber::filter::Directive>() {
            Ok(directive) => {
                filter = filter.add_directive(directive);
            }
            Err(e) => {
                // Propagate the error with context instead of silencing
                return Err(LoggingError::InvalidModuleDirective {
                    module: module.clone(),
                    level: level.clone(),
                    source: e.to_string(),
                });
            }
        }
    }

    Ok(filter)
}

/// Retrieves the default log directory
pub fn default_log_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tsn")
        .join("logs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_config_builder() {
        let config = LogConfig::builder()
            .log_dir("/tmp/test")
            .file_name("test")
            .console_output(true)
            .build();
        
        assert_eq!(config.log_dir, PathBuf::from("/tmp/test"));
        assert_eq!(config.file_name, "test");
        assert!(config.console_output);
    }

    #[test]
    fn test_default_log_dir() {
        let dir = default_log_dir();
        assert!(dir.to_string_lossy().contains("tsn"));
        assert!(dir.to_string_lossy().contains("logs"));
    }

    #[test]
    fn test_logging_handle_new() {
        let handle = LoggingHandle::new();
        assert!(!handle.has_rotation());
    }

    #[test]
    fn test_logging_handle_with_rotation() {
        let token = CancellationToken::new();
        let handle = LoggingHandle::with_rotation_token(token);
        assert!(handle.has_rotation());
    }

    #[test]
    fn test_invalid_module_directive_error() {
        use std::collections::HashMap;
        
        let mut module_levels = HashMap::new();
        // Invalid level: "invalid_level" is not a valid log level
        module_levels.insert("tsn::crypto".to_string(), "invalid_level".to_string());
        
        let config = LogConfig {
            log_dir: PathBuf::from("/tmp/test"),
            file_name: "test".to_string(),
            rotation: LogRotation::Never,
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            console_output: false,
            file_output: false,
            json_output: false,
            default_level: "info".to_string(),
            module_levels,
            show_thread_ids: false,
            show_thread_names: false,
            use_ansi_colors: true,
        };
        
        let result = build_env_filter(&config);
        assert!(result.is_err());
        
        match result {
            Err(LoggingError::InvalidModuleDirective { module, level, .. }) => {
                assert_eq!(module, "tsn::crypto");
                assert_eq!(level, "invalid_level");
            }
            _ => panic!("Expected InvalidModuleDirective error"),
        }
    }

    #[test]
    fn test_valid_module_directives() {
        use std::collections::HashMap;
        
        let mut module_levels = HashMap::new();
        module_levels.insert("tsn::crypto".to_string(), "debug".to_string());
        module_levels.insert("tsn::network".to_string(), "warn".to_string());
        
        let config = LogConfig {
            log_dir: PathBuf::from("/tmp/test"),
            file_name: "test".to_string(),
            rotation: LogRotation::Never,
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            console_output: false,
            file_output: false,
            json_output: false,
            default_level: "info".to_string(),
            module_levels,
            show_thread_ids: false,
            show_thread_names: false,
            use_ansi_colors: true,
        };
        
        let result = build_env_filter(&config);
        assert!(result.is_ok(), "Valid directives should not fail: {:?}", result.err());
    }
}
