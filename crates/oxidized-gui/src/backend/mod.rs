//! Filesystem backend implementations and mount management
//!
//! This module provides concrete implementations of the [`MountBackend`] trait
//! from `oxidized-cryptolib`, as well as a [`MountManager`] for coordinating
//! active mounts.
//!
//! # Backend Availability
//!
//! Backends are compiled as stubs when their features are disabled, allowing
//! the GUI to compile on all platforms while showing appropriate availability
//! status at runtime.
//!
//! - `fuse`: FUSE backend (Linux, macOS) - requires macFUSE or libfuse
//! - `fskit`: FSKit backend (macOS 15.4+) - native Apple framework
//! - `webdav`: WebDAV backend (all platforms) - no kernel extensions needed

#![allow(dead_code)] // MountManager APIs for future use

mod fuse;
mod fskit;
mod webdav;

pub use fuse::FuseBackend;
pub use fskit::FSKitBackend;
pub use webdav::WebDavBackend;

// Re-export traits and types from cryptolib
pub use oxidized_cryptolib::{
    BackendInfo, BackendType, MountBackend, MountError, MountHandle,
    first_available_backend, list_backend_info, select_backend,
};

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
    ///
    /// Backends are ordered by preference: FSKit first (better macOS integration),
    /// then FUSE, then WebDAV as fallback. This order is used by `first_available_backend()`.
    ///
    /// On platforms where a backend isn't available (e.g., FUSE on Windows),
    /// a stub is included that reports itself as unavailable.
    pub fn new() -> Self {
        Self {
            mounts: Mutex::new(HashMap::new()),
            backends: vec![
                // FSKit preferred on macOS 15.4+ (better integration, no kernel extension)
                Box::new(FSKitBackend::new()),
                // FUSE as second choice (cross-platform Unix)
                Box::new(FuseBackend::new()),
                // WebDAV as fallback (works everywhere, no kernel extensions)
                Box::new(WebDavBackend::new()),
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

    /// Get information about all registered backends
    pub fn backend_info(&self) -> Vec<BackendInfo> {
        list_backend_info(&self.backends)
    }

    /// Select a backend by type using shared selection logic
    ///
    /// Returns an error if the requested backend is not available.
    pub fn get_backend(&self, backend_type: BackendType) -> Result<&dyn MountBackend, MountError> {
        select_backend(&self.backends, backend_type)
    }

    /// Mount a vault using the specified backend type
    pub fn mount_with_backend(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
        backend_type: BackendType,
    ) -> Result<PathBuf, MountError> {
        // Use shared selection logic
        let backend = self.get_backend(backend_type)?;

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

    /// Mount a vault using the first available backend
    ///
    /// This is the simplified 4-parameter API for callers that don't need
    /// explicit backend selection. Uses the first available backend based on
    /// the order defined in `new()` (FSKit preferred, then FUSE, then WebDAV).
    pub fn mount(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
    ) -> Result<PathBuf, MountError> {
        let backend = first_available_backend(&self.backends)?;

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

/// Unmount all vaults and exit the application
///
/// This is the standard shutdown routine used by signal handlers and quit actions.
/// Ensures all mounted vaults are cleanly unmounted before terminating.
pub fn cleanup_and_exit() -> ! {
    tracing::info!("App exiting, unmounting all vaults...");
    mount_manager().unmount_all();
    std::process::exit(0)
}

/// Generate a platform-appropriate mount point path for a vault
pub fn generate_mountpoint(vault_name: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // Use ~/Vaults/ instead of /Volumes/ since /Volumes requires root
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let mount_dir = PathBuf::from(home).join("Vaults");
        // Create the directory if it doesn't exist
        let _ = std::fs::create_dir_all(&mount_dir);
        mount_dir.join(vault_name)
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join("mnt").join(vault_name)
    }
    #[cfg(target_os = "windows")]
    {
        // On Windows, WebDAV mounts are typically mapped to drive letters
        // Return a placeholder; actual drive letter is chosen at mount time
        PathBuf::from(format!("{}:", vault_name.chars().next().unwrap_or('Z').to_ascii_uppercase()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp").join("oxidized").join(vault_name)
    }
}
