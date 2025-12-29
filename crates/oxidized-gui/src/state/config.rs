//! Configuration persistence for vault and application settings

#![allow(dead_code)] // Config APIs for future use

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

// Re-export BackendType from cryptolib for convenience
pub use oxidized_cryptolib::BackendType;

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
    pub fn display_name(&self) -> &'static str {
        match self {
            ThemePreference::System => "System",
            ThemePreference::Light => "Light",
            ThemePreference::Dark => "Dark",
        }
    }

    /// Get description for the UI
    pub fn description(&self) -> &'static str {
        match self {
            ThemePreference::System => "Match your system settings",
            ThemePreference::Light => "Always use light mode",
            ThemePreference::Dark => "Always use dark mode",
        }
    }

    /// Get the CSS class to apply to the root element
    /// Returns None for System (let the browser handle it)
    pub fn css_class(&self) -> Option<&'static str> {
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
    /// User dismissed the FSKit setup wizard (don't show again)
    #[serde(default)]
    pub fskit_setup_dismissed: bool,
    /// Enable debug logging (verbose output)
    #[serde(default)]
    pub debug_logging: bool,
    /// Theme preference (system, light, or dark)
    #[serde(default)]
    pub theme: ThemePreference,
}

impl AppConfig {
    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let dirs =
            directories::ProjectDirs::from("com", "oxidized", "vault").ok_or(ConfigError::NoConfigDir)?;
        let config_dir = dirs.config_dir();
        Ok(config_dir.join("config.json"))
    }

    /// Load configuration from disk, or return default if not found
    pub fn load() -> Self {
        let config_path = match Self::config_path() {
            Ok(path) => path,
            Err(e) => {
                tracing::warn!("Could not determine config path: {}", e);
                return Self::default();
            }
        };

        if !config_path.exists() {
            tracing::info!("No config file found, using defaults");
            return Self::default();
        }

        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded config from {}", config_path.display());
                    config
                }
                Err(e) => {
                    tracing::error!("Failed to parse config: {}", e);
                    Self::default()
                }
            },
            Err(e) => {
                tracing::error!("Failed to read config: {}", e);
                Self::default()
            }
        }
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
    use tempfile::tempdir;

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
        assert_eq!(BackendType::FSKit.display_name(), "FSKit");
    }
}
