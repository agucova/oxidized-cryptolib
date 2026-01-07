//! Runtime vault state management
//!
//! Tracks the state of each vault (locked, unlocked, mounted) and manages
//! transitions between states.

#![allow(dead_code)] // Vault state APIs for future use

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::config::{AppConfig, BackendType, ConfigLoadStatus, VaultConfig};
use crate::backend::{mount_manager, DesktopMountState};

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
            VaultState::Locked => None,
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
    /// Status of the config load operation (for showing warnings)
    config_load_status: ConfigLoadStatus,
    /// Warnings about unavailable backends
    backend_warnings: Vec<String>,
}

impl AppState {
    /// Load application state from disk
    ///
    /// This also attempts to clean up orphaned mounts from the shared mount state file.
    /// If a vault has an orphaned mount (from a previous session that crashed),
    /// we attempt to unmount it with a timeout and leave the vault as Locked
    /// so the user can re-authenticate.
    pub fn load() -> Self {
        let (config, config_load_status) = AppConfig::load_with_status();

        // Log warning if config was corrupted or couldn't be read
        if let Some(warning) = config_load_status.warning_message() {
            tracing::warn!("Config load issue: {}", warning);
        }

        // Initialize all vaults as locked
        let vault_states: std::collections::HashMap<String, VaultState> = config
            .vaults
            .iter()
            .map(|v| (v.id.clone(), VaultState::Locked))
            .collect();

        // Clean up orphaned mounts from previous sessions
        // This runs synchronously at startup - orphaned mounts should be rare
        cleanup_orphaned_mounts(&config);

        // Validate backend preferences and collect warnings
        let backend_warnings = Self::validate_backend_preferences(&config);
        for warning in &backend_warnings {
            tracing::warn!("Backend warning: {}", warning);
        }

        Self {
            config,
            vault_states,
            config_load_status,
            backend_warnings,
        }
    }

    /// Validate that preferred backends are available on this system.
    ///
    /// Returns a list of warning messages for backends that are configured
    /// but not available.
    fn validate_backend_preferences(config: &AppConfig) -> Vec<String> {
        let mut warnings = Vec::new();
        let manager = mount_manager();

        // Check default backend
        if manager.get_backend(config.default_backend).is_err() {
            warnings.push(format!(
                "Default backend '{}' is not available on this system. \
                 You may need to install it or choose a different backend in Settings.",
                config.default_backend.display_name()
            ));
        }

        // Check each vault's preferred backend
        for vault in &config.vaults {
            if manager.get_backend(vault.preferred_backend).is_err() {
                warnings.push(format!(
                    "Vault '{}' uses '{}' backend which is not available. \
                     Click the backend badge to change it.",
                    vault.name,
                    vault.preferred_backend.display_name()
                ));
            }
        }

        warnings
    }

    /// Get the config load status
    ///
    /// Returns information about how the config was loaded, including any
    /// errors that occurred.
    pub fn config_load_status(&self) -> &ConfigLoadStatus {
        &self.config_load_status
    }

    /// Check if there's a config warning that should be shown to the user.
    ///
    /// Returns the warning message if there is one. This includes both config
    /// load issues and backend availability warnings.
    pub fn config_warning(&self) -> Option<String> {
        let mut messages = Vec::new();

        // Config load warnings (corruption, read errors)
        if let Some(msg) = self.config_load_status.warning_message() {
            messages.push(msg);
        }

        // Backend availability warnings
        if !self.backend_warnings.is_empty() {
            messages.push(format!(
                "Some backend preferences are unavailable:\n\n{}",
                self.backend_warnings.join("\n\n")
            ));
        }

        if messages.is_empty() {
            None
        } else {
            Some(messages.join("\n\n---\n\n"))
        }
    }

    /// Clear the config warning (after user acknowledges it).
    ///
    /// This clears both config load status and backend warnings.
    pub fn clear_config_warning(&mut self) {
        self.config_load_status = ConfigLoadStatus::Loaded;
        self.backend_warnings.clear();
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

    /// Update mount settings (backend and local_mode) for a vault
    pub fn set_vault_mount_settings(&mut self, id: &str, backend: BackendType, local_mode: bool) {
        if let Some(vault_config) = self.config.find_vault_mut(id) {
            vault_config.preferred_backend = backend;
            vault_config.local_mode = local_mode;
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

/// Clean up orphaned mounts from previous sessions.
///
/// This is called at startup to detect and clean up mounts from crashed sessions.
/// For each orphaned mount (where the process is dead):
/// 1. Attempt force unmount with a timeout
/// 2. If timeout expires, give up on unmount (the mount may be in a bad state)
/// 3. Remove from state file regardless
///
/// Vaults are left as Locked so the user can re-authenticate.
fn cleanup_orphaned_mounts(config: &AppConfig) {
    const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

    // Get the state manager
    let state_manager = match DesktopMountState::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("Could not initialize mount state manager: {}", e);
            return;
        }
    };

    // Get vault paths we know about
    let known_paths: Vec<PathBuf> = config.vaults.iter().map(|v| v.path.clone()).collect();

    // Find orphaned mounts
    let orphans = match state_manager.find_orphaned_mounts(&known_paths) {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("Could not check for orphaned mounts: {}", e);
            return;
        }
    };

    if orphans.is_empty() {
        return;
    }

    tracing::info!(
        "Found {} orphaned mount(s) from previous session, attempting cleanup...",
        orphans.len()
    );

    for orphan in orphans {
        let mountpoint = orphan.mountpoint.clone();
        tracing::info!(
            "Cleaning up orphaned mount: {} (vault: {}, backend: {})",
            mountpoint.display(),
            orphan.vault_path.display(),
            orphan.backend
        );

        // Attempt force unmount with timeout
        let mp_clone = mountpoint.clone();
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let result = force_unmount_path(&mp_clone);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(UNMOUNT_TIMEOUT) {
            Ok(Ok(())) => {
                tracing::info!("Successfully unmounted orphan at {}", mountpoint.display());
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to unmount orphan at {}: {}",
                    mountpoint.display(),
                    e
                );
            }
            Err(_) => {
                tracing::warn!(
                    "Unmount of orphan at {} timed out after {:?}, giving up",
                    mountpoint.display(),
                    UNMOUNT_TIMEOUT
                );
            }
        }

        // Always remove from state file, regardless of unmount success
        if let Err(e) = state_manager.remove_mount(&mountpoint) {
            tracing::warn!(
                "Failed to remove orphan from state file: {}",
                e
            );
        }
    }
}

/// Force unmount a path using platform-specific tools.
fn force_unmount_path(mountpoint: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Try diskutil first (handles FUSE mounts better)
        let output = std::process::Command::new("diskutil")
            .args(["unmount", "force", &mountpoint.to_string_lossy()])
            .output()
            .map_err(|e| format!("Failed to run diskutil: {e}"))?;

        if output.status.success() {
            return Ok(());
        }

        // Fall back to umount
        let output = std::process::Command::new("umount")
            .args(["-f", &mountpoint.to_string_lossy()])
            .output()
            .map_err(|e| format!("Failed to run umount: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "umount failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("umount")
            .args(["-f", "-l", &mountpoint.to_string_lossy()])
            .output()
            .map_err(|e| format!("Failed to run umount: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "umount failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows doesn't have force unmount in the same way
        // For WebDAV, we could try net use /delete
        let output = std::process::Command::new("net")
            .args(["use", &mountpoint.to_string_lossy(), "/delete", "/y"])
            .output()
            .map_err(|e| format!("Failed to run net use: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "net use /delete failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Force unmount not implemented for this platform".to_string())
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
