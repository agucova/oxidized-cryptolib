//! Runtime vault state management
//!
//! Tracks the state of each vault (locked, unlocked, mounted) and manages
//! transitions between states.

#![allow(dead_code)] // Vault state APIs for future use

use std::path::PathBuf;

use super::config::{AppConfig, BackendType, VaultConfig};

/// The runtime state of a vault
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum VaultState {
    /// Vault is locked (password not entered)
    #[default]
    Locked,
    /// Vault is mounted at the specified path
    Mounted { mountpoint: PathBuf },
}


impl VaultState {
    /// Returns true if the vault is currently locked
    pub fn is_locked(&self) -> bool {
        matches!(self, VaultState::Locked)
    }

    /// Returns true if the vault is currently mounted
    pub fn is_mounted(&self) -> bool {
        matches!(self, VaultState::Mounted { .. })
    }

    /// Returns the mount point if mounted
    pub fn mountpoint(&self) -> Option<&PathBuf> {
        match self {
            VaultState::Mounted { mountpoint } => Some(mountpoint),
            _ => None,
        }
    }

    /// Returns a human-readable status string
    pub fn status_text(&self) -> &'static str {
        match self {
            VaultState::Locked => "Locked",
            VaultState::Mounted { .. } => "Mounted",
        }
    }
}

/// A vault with its configuration and runtime state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVault {
    /// Persistent configuration
    pub config: VaultConfig,
    /// Current runtime state
    pub state: VaultState,
}

impl ManagedVault {
    /// Create a new managed vault from a configuration
    pub fn new(config: VaultConfig) -> Self {
        Self {
            config,
            state: VaultState::Locked,
        }
    }

    /// Check if this vault's directory still exists
    pub fn is_valid(&self) -> bool {
        self.config.path.exists()
    }
}

/// Application state holding all managed vaults
#[derive(Debug, Clone)]
pub struct AppState {
    /// Persistent configuration
    pub config: AppConfig,
    /// Runtime state for each vault (keyed by vault ID)
    vault_states: std::collections::HashMap<String, VaultState>,
}

impl AppState {
    /// Load application state from disk
    pub fn load() -> Self {
        let config = AppConfig::load();
        let vault_states = config
            .vaults
            .iter()
            .map(|v| (v.id.clone(), VaultState::Locked))
            .collect();

        Self { config, vault_states }
    }

    /// Get all vaults as managed vaults
    pub fn vaults(&self) -> Vec<ManagedVault> {
        self.config
            .vaults
            .iter()
            .map(|config| ManagedVault {
                config: config.clone(),
                state: self.vault_states.get(&config.id).cloned().unwrap_or_default(),
            })
            .collect()
    }

    /// Get a specific vault by ID
    pub fn get_vault(&self, id: &str) -> Option<ManagedVault> {
        self.config.find_vault(id).map(|config| ManagedVault {
            config: config.clone(),
            state: self.vault_states.get(id).cloned().unwrap_or_default(),
        })
    }

    /// Update the state of a vault
    pub fn set_vault_state(&mut self, id: &str, state: VaultState) {
        self.vault_states.insert(id.to_string(), state);
    }

    /// Update the preferred backend for a vault
    pub fn set_vault_backend(&mut self, id: &str, backend: BackendType) {
        if let Some(vault_config) = self.config.find_vault_mut(id) {
            vault_config.preferred_backend = backend;
        }
    }

    /// Add a new vault
    pub fn add_vault(&mut self, config: VaultConfig) {
        let id = config.id.clone();
        self.config.add_vault(config);
        self.vault_states.insert(id, VaultState::Locked);
    }

    /// Remove a vault (does not delete files, only removes from config)
    pub fn remove_vault(&mut self, id: &str) {
        self.config.remove_vault(id);
        self.vault_states.remove(id);
    }

    /// Save the current configuration to disk
    pub fn save(&self) -> Result<(), super::config::ConfigError> {
        self.config.save()
    }

    /// Get the number of vaults
    pub fn vault_count(&self) -> usize {
        self.config.vaults.len()
    }

    /// Get the number of mounted vaults
    pub fn mounted_count(&self) -> usize {
        self.vault_states
            .values()
            .filter(|s| s.is_mounted())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_vault_state_transitions() {
        let state = VaultState::Locked;
        assert!(state.is_locked());
        assert!(!state.is_mounted());

        let state = VaultState::Mounted {
            mountpoint: PathBuf::from("/mnt/vault"),
        };
        assert!(!state.is_locked());
        assert!(state.is_mounted());
        assert_eq!(state.mountpoint(), Some(&PathBuf::from("/mnt/vault")));
    }

    #[test]
    fn test_managed_vault() {
        let config = VaultConfig::new("Test", PathBuf::from("/tmp/test"));
        let vault = ManagedVault::new(config.clone());

        assert_eq!(vault.config.name, "Test");
        assert!(vault.state.is_locked());
    }
}
