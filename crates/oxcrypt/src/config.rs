//! Configuration file support for oxcrypt CLI.
//!
//! Configuration is stored at `~/.config/oxcrypt/config.toml` (XDG standard)
//! or `~/Library/Application Support/com.oxidized.oxcrypt/config.toml` on macOS.
//!
//! # Example configuration
//!
//! ```toml
//! [defaults]
//! backend = "fuse"
//! color = "auto"
//!
//! [vaults.work]
//! path = "/home/user/work-vault"
//! mountpoint = "/mnt/work"
//!
//! [vaults.photos]
//! path = "/home/user/photos-vault"
//! backend = "webdav"
//! ```
//!
//! # Usage
//!
//! ```bash
//! # Use vault alias
//! oxcrypt @work ls /
//! oxcrypt mount @photos
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Main configuration structure
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Default settings applied to all commands
    #[serde(default)]
    pub defaults: Defaults,

    /// Named vault configurations (aliases)
    #[serde(default)]
    pub vaults: HashMap<String, VaultConfig>,
}

/// Default settings
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Defaults {
    /// Default mount backend (fuse, fskit, webdav, nfs)
    pub backend: Option<String>,

    /// Default color mode (auto, always, never)
    pub color: Option<String>,

    /// Default verbosity level (0-3)
    pub verbosity: Option<u8>,
}

/// Configuration for a named vault
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    /// Path to the vault directory
    pub path: PathBuf,

    /// Optional default mountpoint for this vault
    pub mountpoint: Option<PathBuf>,

    /// Optional backend override for this vault
    pub backend: Option<String>,

    /// Optional keyfile path (for future keyfile support)
    pub keyfile: Option<PathBuf>,

    /// Mount read-only by default
    #[serde(default)]
    pub read_only: bool,
}

impl Config {
    /// Load configuration from the default path, or return empty config if not found.
    pub fn load() -> Result<Self> {
        let path = config_path()?;

        if !path.exists() {
            return Ok(Config::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Get a vault configuration by alias name.
    pub fn get_vault(&self, alias: &str) -> Option<&VaultConfig> {
        self.vaults.get(alias)
    }

    /// List all configured vault aliases.
    pub fn list_vault_aliases(&self) -> Vec<&String> {
        self.vaults.keys().collect()
    }
}

/// Get the path to the configuration file.
///
/// Uses XDG config directory on Linux, Application Support on macOS.
pub fn config_path() -> Result<PathBuf> {
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    #[cfg(target_os = "macos")]
    {
        // macOS: ~/Library/Application Support/com.oxidized.oxcrypt/config.toml
        let config_dir = base_dirs
            .home_dir()
            .join("Library/Application Support/com.oxidized.oxcrypt");
        Ok(config_dir.join("config.toml"))
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux/other: ~/.config/oxcrypt/config.toml
        let config_dir = base_dirs.config_dir().join("oxcrypt");
        Ok(config_dir.join("config.toml"))
    }
}

/// Get the configuration directory (for creating it if needed).
pub fn config_dir() -> Result<PathBuf> {
    config_path().map(|p| p.parent().unwrap().to_path_buf())
}

/// Resolve a vault path, handling @alias syntax.
///
/// If the path starts with '@', look it up in the config file.
/// Otherwise, validate that the path exists and is a directory.
pub fn resolve_vault_alias(path_or_alias: &str) -> Result<PathBuf> {
    if let Some(alias) = path_or_alias.strip_prefix('@') {
        let config = Config::load()?;

        let vault_config = config.get_vault(alias).ok_or_else(|| {
            let available = config.list_vault_aliases();
            if available.is_empty() {
                anyhow::anyhow!(
                    "Unknown vault alias '@{}'.\n\
                     No vault aliases are configured.\n\n\
                     Create a config file at {} with:\n\n\
                     [vaults.{}]\n\
                     path = \"/path/to/your/vault\"",
                    alias,
                    config_path().map(|p| p.display().to_string()).unwrap_or_else(|_| "~/.config/oxcrypt/config.toml".to_string()),
                    alias
                )
            } else {
                anyhow::anyhow!(
                    "Unknown vault alias '@{}'.\n\n\
                     Available aliases: {}\n\n\
                     Add to {} with:\n\n\
                     [vaults.{}]\n\
                     path = \"/path/to/your/vault\"",
                    alias,
                    available.iter().map(|a| format!("@{}", a)).collect::<Vec<_>>().join(", "),
                    config_path().map(|p| p.display().to_string()).unwrap_or_else(|_| "~/.config/oxcrypt/config.toml".to_string()),
                    alias
                )
            }
        })?;

        // Validate the configured path exists
        let path = &vault_config.path;
        if !path.exists() {
            anyhow::bail!(
                "Vault path for '@{}' does not exist: {}\n\
                 Update the path in your config file.",
                alias,
                path.display()
            );
        }
        if !path.is_dir() {
            anyhow::bail!(
                "Vault path for '@{}' is not a directory: {}",
                alias,
                path.display()
            );
        }

        Ok(path.clone())
    } else {
        // Regular path - just convert to PathBuf
        Ok(PathBuf::from(path_or_alias))
    }
}

/// Get vault-specific configuration (backend, mountpoint, etc.)
pub fn get_vault_config(path_or_alias: &str) -> Result<Option<VaultConfig>> {
    if let Some(alias) = path_or_alias.strip_prefix('@') {
        let config = Config::load()?;
        Ok(config.get_vault(alias).cloned())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.vaults.is_empty());
        assert!(config.defaults.backend.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
            [defaults]
            backend = "fuse"
            color = "auto"

            [vaults.work]
            path = "/home/user/work-vault"
            mountpoint = "/mnt/work"

            [vaults.photos]
            path = "/home/user/photos-vault"
            backend = "webdav"
            read_only = true
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.defaults.backend.as_deref(), Some("fuse"));
        assert_eq!(config.defaults.color.as_deref(), Some("auto"));

        let work = config.get_vault("work").unwrap();
        assert_eq!(work.path, PathBuf::from("/home/user/work-vault"));
        assert_eq!(work.mountpoint, Some(PathBuf::from("/mnt/work")));
        assert!(!work.read_only);

        let photos = config.get_vault("photos").unwrap();
        assert_eq!(photos.path, PathBuf::from("/home/user/photos-vault"));
        assert_eq!(photos.backend.as_deref(), Some("webdav"));
        assert!(photos.read_only);
    }

    #[test]
    fn test_resolve_alias_without_at() {
        let result = resolve_vault_alias("/some/path");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/some/path"));
    }
}
