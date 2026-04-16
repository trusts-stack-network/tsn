//! Log file rotation manager
//!
//! This module provides an asynchronous manager that monitors
//! and cleans up old log files according to the configured policy.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::{LogConfig, LoggingError, Result};

/// Log file rotation manager
pub struct RotationManager {
    /// Configuration of the logging
    config: LogConfig,
    /// Check interval
    check_interval: Duration,
    /// File pattern to watch
    file_pattern: String,
}

impl RotationManager {
    /// Creates a new rotation manager
    pub fn new(config: LogConfig) -> Result<Self> {
        let file_pattern = config.file_pattern();
        
        Ok(RotationManager {
            config,
            check_interval: Duration::from_secs(300), // 5 minutes by default
            file_pattern,
        })
    }

    /// Sets the verification interval
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Starts the rotation manager with cancellation support
    /// 
    /// This method must be called in a tokio context.
/// It shuts down cleanly when the cancellation token is triggered.
    pub async fn run(self, cancel_token: tokio_util::sync::CancellationToken) {
        info!(
            "Starting rotation manager: interval={:?}, max_files={}",
            self.check_interval,
            self.config.max_files
        );

        let mut ticker = interval(self.check_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.cleanup_old_logs().await {
                        error!("Error cleaning old log files: {}", e);
                    }
                }
                _ = cancel_token.cancelled() => {
                    info!("Stopping rotation manager");
                    break;
                }
            }
        }
    }

    /// Cleans up old log files
    async fn cleanup_old_logs(&self) -> Result<()> {
        if self.config.max_files == 0 {
            return Ok(());
        }

        let log_dir = &self.config.log_dir;
        
        if !log_dir.exists() {
            return Ok(());
        }

        // List all log files with explicit error handling
        let mut log_files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        
        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            // Check if it's a log file
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                // Verify the pattern
                if file_name_str.starts_with(&self.config.file_name)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                // Explicit handling of modified() - if error, use UNIX_EPOCH
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                log_files.push((modified_time, path));
                            }
                        }
                        Err(e) => {
                            warn!("Unable to read metadata of {:?}: {}", path, e);
                            // Continue with other files
                        }
                    }
                }
            }
        }

        // Sort by modification date (newest to oldest)
        log_files.sort_by(|a, b| b.0.cmp(&a.0));

        // Delete excess files
        if log_files.len() > self.config.max_files {
            let files_to_remove = &log_files[self.config.max_files..];
            
            for (_, file_path) in files_to_remove {
                debug!("Removing old log file: {:?}", file_path);
                
                match tokio::fs::remove_file(file_path).await {
                    Ok(_) => {
                        info!("Log file removed: {:?}", file_path);
                    }
                    Err(e) => {
                        warn!("Failed to remove log file {:?}: {}", file_path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Gets the list of current log files
    pub fn list_log_files(&self) -> Result<Vec<PathBuf>> {
        let log_dir = &self.config.log_dir;
        
        if !log_dir.exists() {
            return Ok(Vec::new());
        }

        let mut log_files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        
        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                if file_name_str.starts_with(&self.config.file_name)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                log_files.push((modified_time, path));
                            }
                        }
                        Err(e) => {
                            warn!("Unable to read metadata of {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Sort by modification date (newest to oldest)
        log_files.sort_by(|a, b| b.0.cmp(&a.0));
        
        Ok(log_files.into_iter().map(|(_, path)| path).collect())
    }

    /// Calculates disk space used by logs
    pub fn calculate_log_size(&self) -> Result<u64> {
        let files = self.list_log_files()?;
        let mut total_size: u64 = 0;

        for file in files {
            if let Ok(metadata) = std::fs::metadata(&file) {
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }

    /// Forces immediate rotation
    pub async fn force_rotation(&self) -> Result<()> {
        info!("Forced log file rotation");
        self.cleanup_old_logs().await
    }
}

/// Log file statistics
#[derive(Debug, Clone)]
pub struct LogStats {
    /// Number of files
    pub file_count: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Average size per file
    pub average_size: u64,
    /// Most recent file
    pub newest_file: Option<PathBuf>,
    /// Oldest file
    pub oldest_file: Option<PathBuf>,
}

impl LogStats {
    /// Calculates statistics for a log directory
    pub fn calculate(log_dir: &Path, file_prefix: &str) -> Result<Self> {
        let mut files: Vec<(std::time::SystemTime, PathBuf, u64)> = Vec::new();
        
        if !log_dir.exists() {
            return Ok(LogStats {
                file_count: 0,
                total_size: 0,
                average_size: 0,
                newest_file: None,
                oldest_file: None,
            });
        }

        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                if file_name_str.starts_with(file_prefix)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                let size = metadata.len();
                                files.push((modified_time, path, size));
                            }
                        }
                        Err(e) => {
                            warn!("Unable to read metadata of {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        let file_count = files.len();
        let total_size: u64 = files.iter().map(|(_, _, size)| size).sum();
        let average_size = if file_count > 0 {
            total_size / file_count as u64
        } else {
            0
        };

        // Sort by date (newest to oldest)
        files.sort_by(|a, b| b.0.cmp(&a.0));

        let newest_file = files.first().map(|(_, p, _)| p.clone());
        let oldest_file = files.last().map(|(_, p, _)| p.clone());

        Ok(LogStats {
            file_count,
            total_size,
            average_size,
            newest_file,
            oldest_file,
        })
    }

    /// Formats total size in human-readable units
    pub fn format_total_size(&self) -> String {
        format_bytes(self.total_size)
    }

    /// Formats average size in human-readable units
    pub fn format_average_size(&self) -> String {
        format_bytes(self.average_size)
    }
}

/// Formats a size in bytes to human-readable units
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[tokio::test]
    async fn test_rotation_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config = LogConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_name: "test".to_string(),
            max_files: 2,
            ..Default::default()
        };

        let manager = RotationManager::new(config.clone()).unwrap();

        // Create some log files
        for i in 0..5 {
            let file_path = temp_dir.path().join(format!("test_{}.log", i));
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "Log content {}").unwrap();
            // Small pause to differentiate timestamps
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Verify we have 5 files
        let files = manager.list_log_files().unwrap();
        assert_eq!(files.len(), 5);

        // Cleanup
        manager.cleanup_old_logs().await.unwrap();

        // Verify only 2 files remain
        let files = manager.list_log_files().unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_log_stats() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some files
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("test_{}.log", i));
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "Content").unwrap();
        }

        let stats = LogStats::calculate(temp_dir.path(), "test").unwrap();
        assert_eq!(stats.file_count, 3);
        assert!(stats.total_size > 0);
        assert!(stats.average_size > 0);
        assert!(stats.newest_file.is_some());
        assert!(stats.oldest_file.is_some());
    }
}
