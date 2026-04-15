//! Structured logging system with rotation for TSN
//!
//! This module provides a unified logging system with:
//! - Support JSON pour une ingestion facile par les outils de log aggregation
//! - Automatic file rotation by size or date
//! - Niveaux de log configurables par module
//! - Integration avec tracing pour les spans et traces distribuees
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
//! // Pour arreter proprement:
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

/// Erreurs du system de logging
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

/// Handle to control the logging system
/// 
/// Cette structure encapsule les ressources necessarys pour gerer
/// the logging system lifecycle, including graceful shutdown
/// du manager de rotation.
#[derive(Debug, Clone)]
pub struct LoggingHandle {
    /// Token d'annulation pour le manager de rotation
    rotation_cancel_token: Option<Arc<CancellationToken>>,
}

impl LoggingHandle {
    /// Creates a nouveau handle sans manager de rotation
    fn new() -> Self {
        Self {
            rotation_cancel_token: None,
        }
    }

    /// Creates a nouveau handle avec un token d'annulation pour la rotation
    fn with_rotation_token(token: CancellationToken) -> Self {
        Self {
            rotation_cancel_token: Some(Arc::new(token)),
        }
    }

    /// Arrete proprement le manager de rotation
    /// 
    /// Cette methode signale au manager de rotation qu'il doit
    /// s'arreter. Elle est sans effet si la rotation n'est pas activee.
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
    ///     // ... utilisation du logging ...
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
/// Cette fonction configure le subscriber tracing avec:
/// - Un layer console (optionnel)
/// - A file layer with rotation (optionnel)
/// - Un layer JSON pour la production (optionnel)
/// - Un filtre d'environnement pour controler les niveaux
///
/// # Arguments
/// * `config` - Configuration du logging
///
/// # Retourne
/// Un `LoggingHandle` allowstant de controler le cycle de vie du logging.
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
    // Create the directory de logs if needed
    if !config.log_dir.exists() {
        std::fs::create_dir_all(&config.log_dir)?;
    }

    // Construire le filtre d'environnement
    let filter = build_env_filter(&config)?;

    // Initialize le subscriber avec les layers configures
    let subscriber = tracing_subscriber::registry().with(filter);

    // Ajouter le layer console si active
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

    // Ajouter le layer file avec rotation
    let subscriber = if config.file_output {
        let file_appender = RotatingFileAppender::new(
            config.log_dir.clone(),
            config.file_name.clone(),
            config.rotation.clone(),
            config.max_file_size,
        )?;
        
        let file_layer = if config.json_output {
            // Layer JSON pour la production
            JsonLayer::new(file_appender).boxed()
        } else {
            // Layer texte formate pour le developpement
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

    // Initialize le subscriber
    subscriber.init();

    let mut handle = LoggingHandle::new();

    // Configurer le manager de rotation if needed
    if config.file_output && config.rotation != LogRotation::Never {
        let rotation_manager = RotationManager::new(config.clone())?;
        
        // Create a token d'annulation pour pouvoir arreter proprement
        let cancel_token = CancellationToken::new();
        handle = LoggingHandle::with_rotation_token(cancel_token.clone());
        
        // Start the task de rotation en arriere-plan
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

/// Arrete proprement le manager de rotation
/// 
/// # Deprecie
/// Cette fonction est depreciee. Utilisez `LoggingHandle::shutdown()` a la place.
/// Elle est conservee temporairement pour la compatibility ascendante.
#[deprecated(since = "0.2.0", note = "Use LoggingHandle::shutdown() instead")]
pub fn shutdown_rotation() {
    // Cette fonction ne fait plus rien car le token n'est plus global
    // Les utilisateurs doivent migrer vers LoggingHandle::shutdown()
    tracing::warn!(
        target: "tsn::logging",
        "shutdown_rotation() is deprecated. Use LoggingHandle::shutdown()"
    );
}

/// Construit le filtre d'environnement a partir de la configuration.
/// 
/// # Errors
/// Retourne une error si une directive de module est invalid.
fn build_env_filter(config: &LogConfig) -> Result<EnvFilter> {
    // Essayer d'abord la variable d'environnement RUST_LOG
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|e| {
            // Si RUST_LOG n'est pas definie ou invalid, logger l'error et usesr default_level
            tracing::warn!(
                target: "tsn::logging",
                error = %e,
                "RUST_LOG invalid or undefined, using default level"
            );
            EnvFilter::try_new(&config.default_level)
                .unwrap_or_else(|e| {
                    tracing::error!(
                        target: "tsn::logging",
                        error = %e,
                        default_level = %config.default_level,
                        "Invalid default log level, falling back to 'info'"
                    );
                    EnvFilter::new("info")
                })
        });

    // Ajouter les directives de niveau specifiques aux modules
    let mut filter = filter;
    for (module, level) in &config.module_levels {
        let directive_str = format!("{}={}", module, level);
        match directive_str.parse::<tracing_subscriber::filter::Directive>() {
            Ok(directive) => {
                filter = filter.add_directive(directive);
            }
            Err(e) => {
                // Propager l'error avec contexte au lieu de silencer
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

/// Recupere le directory de logs by default
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
        // Niveau invalid: "invalid_level" n'est pas un niveau de log valide
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
