//! Filesystem backend implementations and mount management
//!
//! This module provides concrete implementations of the [`MountBackend`] trait
//! from `oxidized-cryptolib`, as well as a [`MountManager`] for coordinating
//! active mounts.

mod fuse;
mod fskit;

pub use fuse::FuseBackend;
pub use fskit::FSKitBackend;

// Re-export traits and types from cryptolib
pub use oxidized_cryptolib::{BackendType, MountBackend, MountError, MountHandle};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

/// Manager for active filesystem mounts
///
/// Coordinates mounting/unmounting of vaults using the configured backend.
/// Tracks active mounts and provides lifecycle management.
pub struct MountManager {
    /// Active mounts keyed by vault ID
    mounts: Mutex<HashMap<String, Box<dyn MountHandle>>>,
    /// Available backends
    backends: Vec<Box<dyn MountBackend>>,
}

impl Default for MountManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MountManager {
    /// Create a new mount manager with default backends
    pub fn new() -> Self {
        Self {
            mounts: Mutex::new(HashMap::new()),
            backends: vec![
                Box::new(FuseBackend::new()),
                Box::new(FSKitBackend::default()),
            ],
        }
    }

    /// Get all registered backends
    pub fn backends(&self) -> &[Box<dyn MountBackend>] {
        &self.backends
    }

    /// Get available backends (those that can be used on this system)
    pub fn available_backends(&self) -> Vec<&dyn MountBackend> {
        self.backends
            .iter()
            .filter(|b| b.is_available())
            .map(|b| b.as_ref())
            .collect()
    }

    /// Get a backend by type
    pub fn get_backend(&self, backend_type: BackendType) -> Option<&dyn MountBackend> {
        match backend_type {
            BackendType::Fuse => self.backends.iter().find(|b| b.id() == "fuse"),
            BackendType::FSKit => self.backends.iter().find(|b| b.id() == "fskit"),
            BackendType::Auto => self.select_best_backend(),
        }
        .map(|b| b.as_ref())
    }

    /// Select the best available backend automatically
    ///
    /// Priority: FSKit (if available) > FUSE
    fn select_best_backend(&self) -> Option<&Box<dyn MountBackend>> {
        // Prefer FSKit on macOS 15.4+ (better integration)
        if let Some(fskit) = self.backends.iter().find(|b| b.id() == "fskit") {
            if fskit.is_available() {
                return Some(fskit);
            }
        }
        // Fall back to FUSE
        self.backends.iter().find(|b| b.id() == "fuse" && b.is_available())
    }

    /// Mount a vault using the specified backend type
    ///
    /// If `backend_type` is `Auto`, selects the best available backend.
    pub fn mount_with_backend(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
        backend_type: BackendType,
    ) -> Result<PathBuf, MountError> {
        let backend = self.get_backend(backend_type).ok_or_else(|| {
            MountError::BackendUnavailable(format!(
                "No {} backend available",
                backend_type.display_name()
            ))
        })?;

        if !backend.is_available() {
            return Err(MountError::BackendUnavailable(
                backend.unavailable_reason().unwrap_or_else(|| "Unknown reason".to_string()),
            ));
        }

        // Create mount point directory if it doesn't exist
        if !mountpoint.exists() {
            std::fs::create_dir_all(mountpoint)?;
        }

        // Mount using the selected backend
        let handle = backend.mount(vault_id, vault_path, password, mountpoint)?;
        let mp = handle.mountpoint().to_path_buf();

        // Store the handle
        let mut mounts = self.mounts.lock().unwrap();
        mounts.insert(vault_id.to_string(), handle);

        tracing::info!(
            "Mounted vault {} at {} using {}",
            vault_id,
            mp.display(),
            backend.name()
        );

        Ok(mp)
    }

    /// Mount a vault using the default FUSE backend
    ///
    /// This is the simplified 4-parameter API for callers that don't need
    /// backend selection. Uses FUSE backend by default.
    pub fn mount(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
    ) -> Result<PathBuf, MountError> {
        self.mount_with_backend(vault_id, vault_path, password, mountpoint, BackendType::Fuse)
    }

    /// Unmount a vault
    pub fn unmount(&self, vault_id: &str) -> Result<(), MountError> {
        let mut mounts = self.mounts.lock().unwrap();

        if let Some(handle) = mounts.remove(vault_id) {
            let mountpoint = handle.mountpoint().to_path_buf();
            handle.unmount()?;
            tracing::info!("Unmounted vault {} from {}", vault_id, mountpoint.display());
            Ok(())
        } else {
            Err(MountError::NotMounted)
        }
    }

    /// Check if a vault is currently mounted
    pub fn is_mounted(&self, vault_id: &str) -> bool {
        let mounts = self.mounts.lock().unwrap();
        mounts.contains_key(vault_id)
    }

    /// Get the mount point for a vault
    pub fn get_mountpoint(&self, vault_id: &str) -> Option<PathBuf> {
        let mounts = self.mounts.lock().unwrap();
        mounts.get(vault_id).map(|h| h.mountpoint().to_path_buf())
    }

    /// Unmount all vaults (called on shutdown)
    pub fn unmount_all(&self) {
        let mut mounts = self.mounts.lock().unwrap();
        for (vault_id, handle) in mounts.drain() {
            let mountpoint = handle.mountpoint().to_path_buf();
            tracing::info!("Unmounting vault {} from {}", vault_id, mountpoint.display());
            if let Err(e) = handle.unmount() {
                tracing::error!("Failed to unmount {}: {}", vault_id, e);
            }
        }
    }
}

/// Global mount manager instance
static MOUNT_MANAGER: OnceLock<Arc<MountManager>> = OnceLock::new();

/// Get the global mount manager
pub fn mount_manager() -> Arc<MountManager> {
    MOUNT_MANAGER
        .get_or_init(|| Arc::new(MountManager::new()))
        .clone()
}

/// Generate a platform-appropriate mount point path for a vault
pub fn generate_mountpoint(vault_name: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Volumes").join(vault_name)
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join("mnt").join(vault_name)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from("/tmp").join("oxidized").join(vault_name)
    }
}
