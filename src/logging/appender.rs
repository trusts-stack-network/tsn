//! File appender with rotation
//!
//! This module provides a file appender that supports rotation
//! automatique basee sur la taille ou la date.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{LogRotation, LoggingError, Result};

/// Politique de rotation pour l'appender
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    /// Pas de rotation
    Never,
    /// Rotation basee sur la taille (in bytes)
    Size(u64),
    /// Rotation quotidienne
    Daily,
    /// Rotation hebdomadaire
    Weekly,
}

impl From<LogRotation> for RotationPolicy {
    fn from(rotation: LogRotation) -> Self {
        match rotation {
            LogRotation::Never => RotationPolicy::Never,
            LogRotation::Daily => RotationPolicy::Daily,
            LogRotation::Weekly => RotationPolicy::Weekly,
            LogRotation::Monthly => RotationPolicy::Weekly, // Simplifie
            LogRotation::Size(bytes) => RotationPolicy::Size(bytes),
        }
    }
}

/// Appender de file avec support de rotation
pub struct RotatingFileAppender {
    /// Directory des logs
    log_dir: PathBuf,
    /// Base file name
    file_name: String,
    /// Politique de rotation
    rotation: RotationPolicy,
    /// Maximum file size
    max_size: u64,
    /// State interne protege par mutex
    state: Mutex<AppenderState>,
}

struct AppenderState {
    /// Currently open file
    current_file: Option<std::fs::File>,
    /// Current file path
    current_path: PathBuf,
    /// Current file size
    current_size: u64,
    /// Date of last file change (for time-based rotation)
    last_rotation: chrono::DateTime<chrono::Utc>,
}

impl RotatingFileAppender {
    /// Creates a nouvel appender avec rotation
    pub fn new(
        log_dir: PathBuf,
        file_name: String,
        rotation: LogRotation,
        max_size: u64,
    ) -> Result<Self> {
        // Create directory if needed
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).map_err(|e| {
                LoggingError::DirectoryCreationError(e)
            })?;
        }

        let rotation_policy = rotation.into();
        let current_path = Self::generate_file_path(&log_dir, &file_name, rotation_policy);
        
        // Open or create the file
        let (file, current_size) = Self::open_or_create_file(&current_path)?;

        let state = AppenderState {
            current_file: Some(file),
            current_path,
            current_size,
            last_rotation: chrono::Utc::now(),
        };

        Ok(RotatingFileAppender {
            log_dir,
            file_name,
            rotation: rotation_policy,
            max_size,
            state: Mutex::new(state),
        })
    }

    /// Generates the log file path based on the policy
    fn generate_file_path(
        log_dir: &Path,
        file_name: &str,
        rotation: RotationPolicy,
    ) -> PathBuf {
        let timestamp = match rotation {
            RotationPolicy::Never => String::new(),
            RotationPolicy::Size(_) => {
                // Pour la rotation par taille, on uses un timestamp precis
                chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string()
            }
            RotationPolicy::Daily => {
                chrono::Utc::now().format("%Y-%m-%d").to_string()
            }
            RotationPolicy::Weekly => {
                let now = chrono::Utc::now();
                let iso_week = now.iso_week();
                format!("{}-W{:02}", now.year(), iso_week.week())
            }
        };

        if timestamp.is_empty() {
            log_dir.join(format!("{}.log", file_name))
        } else {
            log_dir.join(format!("{}_{}.log", file_name, timestamp))
        }
    }

    /// Opens an existing file or creates a new one
    fn open_or_create_file(path: &Path) -> Result<(std::fs::File, u64)> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LoggingError::FileAppenderError(e.to_string()))?;

        let metadata = file.metadata().map_err(|e| {
            LoggingError::FileAppenderError(e.to_string())
        })?;
        
        Ok((file, metadata.len()))
    }

    /// Checks if rotation is needed
    fn should_rotate(&self,
        state: &AppenderState,
    ) -> bool {
        match self.rotation {
            RotationPolicy::Never => false,
            RotationPolicy::Size(max_size) => {
                state.current_size >= max_size
            }
            RotationPolicy::Daily => {
                let now = chrono::Utc::now();
                now.date_naive() != state.last_rotation.date_naive()
            }
            RotationPolicy::Weekly => {
                let now = chrono::Utc::now();
                now.iso_week() != state.last_rotation.iso_week()
            }
        }
    }

    /// Performs file rotation
    fn rotate(&self, state: &mut AppenderState) -> Result<()> {
        // Close the current file
        if let Some(file) = state.current_file.take() {
            drop(file);
        }

        // Generate le nouveau path
        let new_path = Self::generate_file_path(&self.log_dir,
            &self.file_name,
            self.rotation,
        );

        // Open the new file
        let (file, size) = Self::open_or_create_file(&new_path)?;

        state.current_file = Some(file);
        state.current_path = new_path;
        state.current_size = size;
        state.last_rotation = chrono::Utc::now();

        Ok(())
    }

    /// Gets the current file path
    pub fn current_path(&self) -> PathBuf {
        let state = self.state.lock().unwrap();
        state.current_path.clone()
    }

    /// Gets the current file size
    pub fn current_size(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.current_size
    }
}

impl Write for RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        // Check if rotation is needed
        if self.should_rotate(&state) {
            self.rotate(&mut state).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;
        }

        // Write to the file
        if let Some(ref mut file) = state.current_file {
            let written = file.write(buf)?;
            state.current_size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for writing",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        if let Some(ref mut file) = state.current_file {
            file.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for flushing",
            ))
        }
    }
}

impl Write for &RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        // Check if rotation is needed
        if self.should_rotate(&state) {
            self.rotate(&mut state).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;
        }

        // Write to the file
        if let Some(ref mut file) = state.current_file {
            let written = file.write(buf)?;
            state.current_size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for writing",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        if let Some(ref mut file) = state.current_file {
            file.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for flushing",
            ))
        }
    }
}

impl std::fmt::Debug for RotatingFileAppender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingFileAppender")
            .field("log_dir", &self.log_dir)
            .field("file_name", &self.file_name)
            .field("rotation", &self.rotation)
            .field("max_size", &self.max_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_appender_creation() {
        let temp_dir = TempDir::new().unwrap();
        let appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Never,
            1024,
        ).unwrap();

        assert!(appender.current_path().exists());
    }

    #[test]
    fn test_appender_write() {
        let temp_dir = TempDir::new().unwrap();
        let mut appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Never,
            1024,
        ).unwrap();

        let data = b"Hello, World!\n";
        let written = appender.write(data).unwrap();
        assert_eq!(written, data.len());

        appender.flush().unwrap();
        
        // Check that the file contains the data
        let content = std::fs::read_to_string(appender.current_path()).unwrap();
        assert_eq!(content, "Hello, World!\n");
    }

    #[test]
    fn test_rotation_by_size() {
        let temp_dir = TempDir::new().unwrap();
        let mut appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Size(10), // Rotation after 10 octets
            10,
        ).unwrap();

        let initial_path = appender.current_path();
        
        // Write assez of data pour declencher la rotation
        appender.write(b"0123456789").unwrap(); // 10 octets
        appender.write(b"trigger").unwrap(); // Declenche rotation

        // The file should have changed
        assert_ne!(appender.current_path(), initial_path);
    }

    #[test]
    fn test_generate_file_path() {
        let temp_dir = PathBuf::from("/tmp/logs");
        
        let path = RotatingFileAppender::generate_file_path(
            &temp_dir,
            "app",
            RotationPolicy::Never,
        );
        assert_eq!(path, PathBuf::from("/tmp/logs/app.log"));

        let path = RotatingFileAppender::generate_file_path(
            &temp_dir,
            "app",
            RotationPolicy::Daily,
        );
        assert!(path.to_string_lossy().contains("app_"));
        assert!(path.to_string_lossy().ends_with(".log"));
    }
}
