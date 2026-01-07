//! Configuration persistence for vault and application settings

#![allow(dead_code)] // Config APIs for future use

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

// Re-export BackendType from mount-common for convenience
pub use oxcrypt_mount::BackendType;

/// User preference for application theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    /// Follow system preference (default)
    #[default]
    System,
    /// Always use light theme
    Light,
    /// Always use dark theme
    Dark,
}

impl ThemePreference {
    /// Get all available theme preferences
    pub fn all() -> &'static [ThemePreference] {
        &[
            ThemePreference::System,
            ThemePreference::Light,
            ThemePreference::Dark,
        ]
    }

    /// Get a user-friendly display name
    pub fn display_name(self) -> &'static str {
        match self {
            ThemePreference::System => "System",
            ThemePreference::Light => "Light",
            ThemePreference::Dark => "Dark",
        }
    }

    /// Get description for the UI
    pub fn description(self) -> &'static str {
        match self {
            ThemePreference::System => "Match your system settings",
            ThemePreference::Light => "Always use light mode",
            ThemePreference::Dark => "Always use dark mode",
        }
    }

    /// Get the CSS class to apply to the root element
    /// Returns None for System (let the browser handle it)
    pub fn css_class(self) -> Option<&'static str> {
        match self {
            ThemePreference::System => None,
            ThemePreference::Light => Some("theme-light"),
            ThemePreference::Dark => Some("theme-dark"),
        }
    }
}

/// Errors that can occur during configuration operations
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Failed to find config directory")]
    NoConfigDir,
}

/// Status of config load operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLoadStatus {
    /// Config loaded successfully from disk
    Loaded,
    /// No config file existed, using fresh defaults
    Fresh,
    /// Config file was corrupted, using defaults (backup created)
    Corrupted {
        /// Path to the backup of the corrupted config
        backup_path: PathBuf,
        /// Error message describing the corruption
        error: String,
    },
    /// Config file couldn't be read, using defaults
    ReadError {
        /// Error message
        error: String,
    },
}

impl ConfigLoadStatus {
    /// Returns true if the config was loaded successfully
    pub fn is_ok(&self) -> bool {
        matches!(self, ConfigLoadStatus::Loaded | ConfigLoadStatus::Fresh)
    }

    /// Returns true if there was an error that the user should be warned about
    pub fn needs_warning(&self) -> bool {
        matches!(
            self,
            ConfigLoadStatus::Corrupted { .. } | ConfigLoadStatus::ReadError { .. }
        )
    }

    /// Get a user-friendly warning message, if applicable
    pub fn warning_message(&self) -> Option<String> {
        match self {
            ConfigLoadStatus::Corrupted { backup_path, error } => Some(format!(
                "Your configuration file was corrupted and could not be loaded. \
                 A backup has been saved to:\n{}\n\nError: {}\n\n\
                 Your vault list has been reset. You may need to re-add your vaults.",
                backup_path.display(),
                error
            )),
            ConfigLoadStatus::ReadError { error } => Some(format!(
                "Could not read your configuration file: {error}\n\n\
                 Your vault list has been reset. You may need to re-add your vaults."
            )),
            _ => None,
        }
    }
}

/// Configuration for a single vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Unique identifier for this vault configuration
    pub id: String,
    /// User-friendly display name
    pub name: String,
    /// Path to the vault directory
    pub path: PathBuf,
    /// Preferred filesystem backend for mounting
    #[serde(default)]
    pub preferred_backend: BackendType,
    /// Custom mount point (if None, auto-generated)
    pub default_mountpoint: Option<PathBuf>,
    /// Use local mode with shorter cache TTLs (1s instead of 60s).
    /// Enable this when the vault is on a local/fast filesystem.
    /// Default (false) is optimized for network filesystems (Google Drive, etc.)
    #[serde(default)]
    pub local_mode: bool,
}

impl VaultConfig {
    /// Create a new vault configuration with auto-generated ID
    pub fn new(name: impl Into<String>, path: PathBuf) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            path,
            preferred_backend: BackendType::default(),
            default_mountpoint: None,
            local_mode: false,
        }
    }

    /// Create a new vault configuration with a specific backend preference
    pub fn with_backend(name: impl Into<String>, path: PathBuf, backend: BackendType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            path,
            preferred_backend: backend,
            default_mountpoint: None,
            local_mode: false,
        }
    }

    /// Validate that this vault configuration points to a valid vault
    pub fn validate(&self) -> Result<(), String> {
        if !self.path.exists() {
            return Err(format!("Vault path does not exist: {}", self.path.display()));
        }

        let vault_file = self.path.join("vault.cryptomator");
        if !vault_file.exists() {
            return Err(format!(
                "Not a valid Cryptomator vault: missing vault.cryptomator at {}",
                self.path.display()
            ));
        }

        Ok(())
    }
}

/// Application-wide configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// List of configured vaults
    pub vaults: Vec<VaultConfig>,
    /// Default mount location prefix
    pub default_mount_prefix: Option<PathBuf>,
    /// Default backend preference for new vaults
    #[serde(default)]
    pub default_backend: BackendType,
    /// Start application minimized to tray
    #[serde(default)]
    pub start_minimized: bool,
    /// Theme preference (system, light, or dark)
    #[serde(default)]
    pub theme: ThemePreference,
}

impl AppConfig {
    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let dirs =
            directories::ProjectDirs::from("com", "oxcrypt", "vault").ok_or(ConfigError::NoConfigDir)?;
        let config_dir = dirs.config_dir();
        Ok(config_dir.join("config.json"))
    }

    /// Load configuration from disk, or return default if not found
    ///
    /// This is a convenience wrapper around `load_with_status()` that discards
    /// the status. Use `load_with_status()` if you need to warn the user about
    /// config corruption.
    pub fn load() -> Self {
        Self::load_with_status().0
    }

    /// Load configuration from disk with status information.
    ///
    /// Returns a tuple of (config, status) where status indicates whether the
    /// config was loaded successfully, or if there was an error that the user
    /// should be warned about.
    ///
    /// If the config file is corrupted, a backup is created before returning
    /// defaults.
    pub fn load_with_status() -> (Self, ConfigLoadStatus) {
        let config_path = match Self::config_path() {
            Ok(path) => path,
            Err(e) => {
                tracing::warn!("Could not determine config path: {}", e);
                return (
                    Self::default(),
                    ConfigLoadStatus::ReadError {
                        error: e.to_string(),
                    },
                );
            }
        };

        if !config_path.exists() {
            tracing::info!("No config file found, using defaults");
            return (Self::default(), ConfigLoadStatus::Fresh);
        }

        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded config from {}", config_path.display());
                    (config, ConfigLoadStatus::Loaded)
                }
                Err(e) => {
                    tracing::error!("Failed to parse config: {}", e);

                    // Create a backup of the corrupted config
                    let backup_path = Self::backup_corrupted_config(&config_path, &contents);

                    (
                        Self::default(),
                        ConfigLoadStatus::Corrupted {
                            backup_path,
                            error: e.to_string(),
                        },
                    )
                }
            },
            Err(e) => {
                tracing::error!("Failed to read config: {}", e);
                (
                    Self::default(),
                    ConfigLoadStatus::ReadError {
                        error: e.to_string(),
                    },
                )
            }
        }
    }

    /// Create a backup of a corrupted config file.
    ///
    /// Returns the path to the backup file.
    fn backup_corrupted_config(config_path: &Path, contents: &str) -> PathBuf {
        // Generate backup filename with timestamp
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let backup_name = format!("config.corrupted.{timestamp}.json");
        let backup_path = config_path.with_file_name(backup_name);

        // Write backup
        if let Err(e) = std::fs::write(&backup_path, contents) {
            tracing::error!(
                "Failed to create backup of corrupted config at {}: {}",
                backup_path.display(),
                e
            );
            // Return the intended path even if write failed, so the user knows
            // where we tried to save it
        } else {
            tracing::info!(
                "Created backup of corrupted config at {}",
                backup_path.display()
            );
        }

        backup_path
    }

    /// Save configuration to disk
    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&config_path, contents)?;
        tracing::info!("Saved config to {}", config_path.display());

        Ok(())
    }

    /// Find a vault by ID
    pub fn find_vault(&self, id: &str) -> Option<&VaultConfig> {
        self.vaults.iter().find(|v| v.id == id)
    }

    /// Find a vault by ID (mutable)
    pub fn find_vault_mut(&mut self, id: &str) -> Option<&mut VaultConfig> {
        self.vaults.iter_mut().find(|v| v.id == id)
    }

    /// Add a new vault configuration
    pub fn add_vault(&mut self, config: VaultConfig) {
        // Check for duplicates by path
        if !self.vaults.iter().any(|v| v.path == config.path) {
            self.vaults.push(config);
        }
    }

    /// Remove a vault configuration by ID
    pub fn remove_vault(&mut self, id: &str) -> bool {
        let initial_len = self.vaults.len();
        self.vaults.retain(|v| v.id != id);
        self.vaults.len() != initial_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_config_new() {
        let config = VaultConfig::new("Test Vault", PathBuf::from("/tmp/vault"));
        assert_eq!(config.name, "Test Vault");
        assert_eq!(config.path, PathBuf::from("/tmp/vault"));
        assert_eq!(config.preferred_backend, BackendType::Fuse);
        assert!(!config.id.is_empty());
    }

    #[test]
    fn test_app_config_serialization() {
        let mut config = AppConfig::default();
        config.add_vault(VaultConfig::new("Test", PathBuf::from("/tmp/test")));

        let json = serde_json::to_string(&config).unwrap();
        let loaded: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.vaults.len(), 1);
        assert_eq!(loaded.vaults[0].name, "Test");
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(BackendType::Fuse.display_name(), "FUSE");
    }
}
