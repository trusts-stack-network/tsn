//! Logging system configuration
//!
//! This module defines configuration structures for logging,
//! including rotation options, log levels, and output formats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::Level;

/// Log file rotation policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogRotation {
    /// No rotation
    Never,
    /// Daily rotation
    Daily,
    /// Weekly rotation
    Weekly,
    /// Monthly rotation
    Monthly,
    /// Rotation by size (in bytes)
    Size(u64),
}

impl Default for LogRotation {
    fn default() -> Self {
        LogRotation::Daily
    }
}

impl std::fmt::Display for LogRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogRotation::Never => write!(f, "never"),
            LogRotation::Daily => write!(f, "daily"),
            LogRotation::Weekly => write!(f, "weekly"),
            LogRotation::Monthly => write!(f, "monthly"),
            LogRotation::Size(bytes) => write!(f, "size:{}bytes", bytes),
        }
    }
}

/// Log output destination
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogOutput {
    /// Console output only
    Console,
    /// File only
    File,
    /// Console and file
    Both,
}

impl Default for LogOutput {
    fn default() -> Self {
        LogOutput::Both
    }
}

/// Complete logging system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log file directory
    pub log_dir: PathBuf,
    /// Base name for log files
    pub file_name: String,
    /// Rotation policy
    pub rotation: LogRotation,
    /// Maximum log file size (in bytes) before rotation
    pub max_file_size: u64,
    /// Maximum number of log files to retain
    pub max_files: usize,
    /// Display logs on the console
    pub console_output: bool,
    /// Write logs to a file
    pub file_output: bool,
    /// Use JSON format for files
    pub json_output: bool,
    /// Use ANSI colors in the console
    pub use_ansi_colors: bool,
    /// Display thread IDs
    pub show_thread_ids: bool,
    /// Display thread names
    pub show_thread_names: bool,
    /// Log level by default
    pub default_level: String,
    /// Module-specific log levels
    pub module_levels: HashMap<String, String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("./logs"),
            file_name: String::from("tsn"),
            rotation: LogRotation::Daily,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_files: 7,
            console_output: true,
            file_output: true,
            json_output: false,
            use_ansi_colors: true,
            show_thread_ids: false,
            show_thread_names: true,
            default_level: String::from("info"),
            module_levels: HashMap::new(),
        }
    }
}

impl LogConfig {
    /// Creates a new builder for constructing a configuration
    pub fn builder() -> LogConfigBuilder {
        LogConfigBuilder::default()
    }

    /// Checks if the configuration is valid
    pub fn validate(&self) -> Result<(), String> {
        if self.file_output && self.log_dir.as_os_str().is_empty() {
            return Err(String::from("log_dir cannot be empty when file_output is enabled"));
        }

        if self.file_output && self.file_name.is_empty() {
            return Err(String::from("file_name cannot be empty when file_output is enabled"));
        }

        // Verify that the default log level is valid
        match self.default_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(format!("invalid default_level: {}", self.default_level)),
        }

        Ok(())
    }

    /// Gets the current log file path
    pub fn current_log_path(&self) -> PathBuf {
        let timestamp = chrono::Local::now().format("%Y-%m-%d");
        self.log_dir.join(format!("{}_{}.log", self.file_name, timestamp))
    }

    /// Gets the file name pattern for rotation
    pub fn file_pattern(&self) -> String {
        format!("{}_*.log", self.file_name)
    }
}

/// Builder for constructing a logging configuration
#[derive(Debug, Default)]
pub struct LogConfigBuilder {
    log_dir: Option<PathBuf>,
    file_name: Option<String>,
    rotation: Option<LogRotation>,
    max_file_size: Option<u64>,
    max_files: Option<usize>,
    console_output: Option<bool>,
    file_output: Option<bool>,
    json_output: Option<bool>,
    use_ansi_colors: Option<bool>,
    show_thread_ids: Option<bool>,
    show_thread_names: Option<bool>,
    default_level: Option<String>,
    module_levels: HashMap<String, String>,
}

impl LogConfigBuilder {
    /// Sets the log file directory
    pub fn log_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.log_dir = Some(path.into());
        self
    }

    /// Sets the base name for log files
    pub fn file_name<S: Into<String>>(mut self, name: S) -> Self {
        self.file_name = Some(name.into());
        self
    }

    /// Defines the rotation policy
    pub fn rotation(mut self, rotation: LogRotation) -> Self {
        self.rotation = Some(rotation);
        self
    }

    /// Sets the maximum file size before rotation (in bytes)
    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = Some(size);
        self
    }

    /// Sets the maximum number of files to retain
    pub fn max_files(mut self, count: usize) -> Self {
        self.max_files = Some(count);
        self
    }

    /// Enables/disables console output
    pub fn console_output(mut self, enabled: bool) -> Self {
        self.console_output = Some(enabled);
        self
    }

    /// Enables/disables file output
    pub fn file_output(mut self, enabled: bool) -> Self {
        self.file_output = Some(enabled);
        self
    }

    /// Enables/disables JSON format
    pub fn json_output(mut self, enabled: bool) -> Self {
        self.json_output = Some(enabled);
        self
    }

    /// Enables/disables ANSI colors
    pub fn use_ansi_colors(mut self, enabled: bool) -> Self {
        self.use_ansi_colors = Some(enabled);
        self
    }

    /// Enables/disables thread ID display
    pub fn show_thread_ids(mut self, enabled: bool) -> Self {
        self.show_thread_ids = Some(enabled);
        self
    }

    /// Enables/disables thread name display
    pub fn show_thread_names(mut self, enabled: bool) -> Self {
        self.show_thread_names = Some(enabled);
        self
    }

    /// Defines the default log level
    pub fn default_level<S: Into<String>>(mut self, level: S) -> Self {
        self.default_level = Some(level.into());
        self
    }

    /// Adds a module-specific log level
    pub fn module_level<S: Into<String>>(mut self, module: S, level: S) -> Self {
        self.module_levels.insert(module.into(), level.into());
        self
    }

    /// Builds the final configuration
    pub fn build(self) -> LogConfig {
        let default = LogConfig::default();
        
        LogConfig {
            log_dir: self.log_dir.unwrap_or(default.log_dir),
            file_name: self.file_name.unwrap_or(default.file_name),
            rotation: self.rotation.unwrap_or(default.rotation),
            max_file_size: self.max_file_size.unwrap_or(default.max_file_size),
            max_files: self.max_files.unwrap_or(default.max_files),
            console_output: self.console_output.unwrap_or(default.console_output),
            file_output: self.file_output.unwrap_or(default.file_output),
            json_output: self.json_output.unwrap_or(default.json_output),
            use_ansi_colors: self.use_ansi_colors.unwrap_or(default.use_ansi_colors),
            show_thread_ids: self.show_thread_ids.unwrap_or(default.show_thread_ids),
            show_thread_names: self.show_thread_names.unwrap_or(default.show_thread_names),
            default_level: self.default_level.unwrap_or(default.default_level),
            module_levels: self.module_levels,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_rotation_display() {
        assert_eq!(LogRotation::Never.to_string(), "never");
        assert_eq!(LogRotation::Daily.to_string(), "daily");
        assert_eq!(LogRotation::Size(1024).to_string(), "size:1024bytes");
    }

    #[test]
    fn test_config_builder() {
        let config = LogConfig::builder()
            .log_dir("/var/log/tsn")
            .file_name("node")
            .rotation(LogRotation::Weekly)
            .max_files(10)
            .console_output(false)
            .json_output(true)
            .default_level("debug")
            .module_level("tsn::network", "trace")
            .build();

        assert_eq!(config.log_dir, PathBuf::from("/var/log/tsn"));
        assert_eq!(config.file_name, "node");
        assert_eq!(config.rotation, LogRotation::Weekly);
        assert_eq!(config.max_files, 10);
        assert!(!config.console_output);
        assert!(config.json_output);
        assert_eq!(config.default_level, "debug");
        assert_eq!(config.module_levels.get("tsn::network"), Some(&"trace".to_string()));
    }

    #[test]
    fn test_config_validation() {
        let valid_config = LogConfig::builder()
            .log_dir("/tmp/logs")
            .file_name("test")
            .build();
        assert!(valid_config.validate().is_ok());

        let invalid_config = LogConfig::builder()
            .log_dir("")
            .file_output(true)
            .build();
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_default_config() {
        let config = LogConfig::default();
        assert_eq!(config.file_name, "tsn");
        assert_eq!(config.rotation, LogRotation::Daily);
        assert_eq!(config.max_files, 7);
        assert!(config.console_output);
        assert!(config.file_output);
    }
}
