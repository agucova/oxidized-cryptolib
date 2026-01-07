//! Filesystem backend implementations and mount management
//!
//! This module provides concrete implementations of the [`MountBackend`] trait
//! from `oxcrypt-core`, as well as a [`MountManager`] for coordinating
//! active mounts.
//!
//! # Backend Availability
//!
//! Backends are compiled as stubs when their features are disabled, allowing
//! the GUI to compile on all platforms while showing appropriate availability
//! status at runtime.
//!
//! - `fuse`: FUSE backend (Linux, macOS) - requires macFUSE or libfuse
//! - `nfs`: NFS backend (Linux, macOS) - no kernel extensions needed
//! - `webdav`: WebDAV backend (all platforms) - no kernel extensions needed

#![allow(dead_code)] // MountManager APIs for future use

mod fileprovider;
pub mod fileprovider_recovery;
mod fuse;
pub mod mount_state;
mod nfs;
mod webdav;

pub use fileprovider::FileProviderBackend;
pub use fileprovider_recovery::{init_recovery_service, recovery_service};
pub use fuse::FuseBackend;
pub use mount_state::{DesktopMountState, MountEntry};
pub use nfs::NfsBackend;
pub use webdav::WebDavBackend;

// Re-export traits and types from mount-common
pub use oxcrypt_mount::{
    ActivityStatus, BackendInfo, BackendType, MountBackend, MountError, MountHandle, MountOptions,
    VaultStats, first_available_backend, list_backend_info, select_backend,
};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;

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
    /// Backends are ordered by preference: File Provider first (macOS 13+ cloud storage
    /// integration), then FUSE (cross-platform), then NFS and WebDAV as fallbacks.
    /// This order is used by `first_available_backend()`.
    ///
    /// On platforms where a backend isn't available (e.g., FUSE on Windows),
    /// a stub is included that reports itself as unavailable.
    pub fn new() -> Self {
        Self {
            mounts: Mutex::new(HashMap::new()),
            backends: vec![
                // File Provider on macOS 13+ (cloud storage integration, no kernel extension)
                Box::new(FileProviderBackend::new()),
                // FUSE as second choice (cross-platform Unix)
                Box::new(FuseBackend::new()),
                // NFS as third choice (no kernel extensions, Unix only)
                Box::new(NfsBackend::new()),
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
            .map(std::convert::AsRef::as_ref)
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

        // Mount using the selected backend
        // The backend handles directory creation and stale mount detection
        // with timeout protection internally
        let handle = backend.mount(vault_id, vault_path, password, mountpoint)?;
        let mp = handle.mountpoint().to_path_buf();

        // Persist mount state for crash recovery
        if let Ok(state_manager) = DesktopMountState::new() {
            let entry = MountEntry::new_gui_mount(
                vault_path.to_path_buf(),
                mp.clone(),
                backend.id(),
            );
            if let Err(e) = state_manager.add_mount(entry) {
                tracing::warn!("Failed to persist mount state: {}", e);
            }
        }

        // Store the handle
        let mut mounts = self.mounts.lock();
        mounts.insert(vault_id.to_string(), handle);

        tracing::info!(
            "Mounted vault {} at {} using {}",
            vault_id,
            mp.display(),
            backend.name()
        );

        Ok(mp)
    }

    /// Mount a vault using the specified backend type with mount options
    ///
    /// This allows passing additional configuration like local mode (shorter cache TTLs)
    /// for vaults on local/fast filesystems.
    pub fn mount_with_backend_and_options(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
        backend_type: BackendType,
        options: &MountOptions,
    ) -> Result<PathBuf, MountError> {
        // Use shared selection logic
        let backend = self.get_backend(backend_type)?;

        // Mount using the selected backend with options
        let handle = backend.mount_with_options(vault_id, vault_path, password, mountpoint, options)?;
        let mp = handle.mountpoint().to_path_buf();

        // Persist mount state for crash recovery
        if let Ok(state_manager) = DesktopMountState::new() {
            let entry = MountEntry::new_gui_mount(
                vault_path.to_path_buf(),
                mp.clone(),
                backend.id(),
            );
            if let Err(e) = state_manager.add_mount(entry) {
                tracing::warn!("Failed to persist mount state: {}", e);
            }
        }

        // Store the handle
        let mut mounts = self.mounts.lock();
        mounts.insert(vault_id.to_string(), handle);

        tracing::info!(
            "Mounted vault {} at {} using {} (local_mode={})",
            vault_id,
            mp.display(),
            backend.name(),
            options.local_mode
        );

        Ok(mp)
    }

    /// Mount a vault using the first available backend
    ///
    /// This is the simplified 4-parameter API for callers that don't need
    /// explicit backend selection. Uses the first available backend based on
    /// the order defined in `new()` (File Provider preferred, then FUSE, then NFS/WebDAV).
    pub fn mount(
        &self,
        vault_id: &str,
        vault_path: &std::path::Path,
        password: &str,
        mountpoint: &std::path::Path,
    ) -> Result<PathBuf, MountError> {
        let backend = first_available_backend(&self.backends)?;

        // Mount using the selected backend
        // The backend handles directory creation and stale mount detection
        // with timeout protection internally
        let handle = backend.mount(vault_id, vault_path, password, mountpoint)?;
        let mp = handle.mountpoint().to_path_buf();

        // Persist mount state for crash recovery
        if let Ok(state_manager) = DesktopMountState::new() {
            let entry = MountEntry::new_gui_mount(
                vault_path.to_path_buf(),
                mp.clone(),
                backend.id(),
            );
            if let Err(e) = state_manager.add_mount(entry) {
                tracing::warn!("Failed to persist mount state: {}", e);
            }
        }

        // Store the handle
        let mut mounts = self.mounts.lock();
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
        let mut mounts = self.mounts.lock();

        if let Some(handle) = mounts.remove(vault_id) {
            let mountpoint = handle.mountpoint().to_path_buf();
            handle.unmount()?;

            // Remove from persisted state
            if let Ok(state_manager) = DesktopMountState::new()
                && let Err(e) = state_manager.remove_mount(&mountpoint) {
                    tracing::warn!("Failed to update mount state: {}", e);
                }

            tracing::info!("Unmounted vault {} from {}", vault_id, mountpoint.display());
            Ok(())
        } else {
            Err(MountError::NotMounted)
        }
    }

    /// Force unmount a vault, even if files are open
    ///
    /// This uses OS-level force unmount mechanisms which may cause data loss
    /// in applications with unsaved changes.
    pub fn force_unmount(&self, vault_id: &str) -> Result<(), MountError> {
        let mut mounts = self.mounts.lock();

        if let Some(handle) = mounts.remove(vault_id) {
            let mountpoint = handle.mountpoint().to_path_buf();
            handle.force_unmount()?;

            // Remove from persisted state
            if let Ok(state_manager) = DesktopMountState::new()
                && let Err(e) = state_manager.remove_mount(&mountpoint) {
                    tracing::warn!("Failed to update mount state: {}", e);
                }

            tracing::info!("Force unmounted vault {} from {}", vault_id, mountpoint.display());
            Ok(())
        } else {
            Err(MountError::NotMounted)
        }
    }

    /// Check if a vault is currently mounted
    pub fn is_mounted(&self, vault_id: &str) -> bool {
        let mounts = self.mounts.lock();
        mounts.contains_key(vault_id)
    }

    /// Get the mount point for a vault
    pub fn get_mountpoint(&self, vault_id: &str) -> Option<PathBuf> {
        let mounts = self.mounts.lock();
        mounts.get(vault_id).map(|h| h.mountpoint().to_path_buf())
    }

    /// Get the display location for a mounted vault, if the backend provides one.
    pub fn get_display_location(&self, vault_id: &str) -> Option<String> {
        let mounts = self.mounts.lock();
        mounts.get(vault_id).and_then(|h| h.display_location())
    }

    /// Get statistics for a mounted vault
    ///
    /// Returns None if the vault is not mounted or the backend doesn't support stats.
    pub fn get_stats(&self, vault_id: &str) -> Option<Arc<VaultStats>> {
        let mounts = self.mounts.lock();
        mounts.get(vault_id).and_then(|h| h.stats())
    }

    /// Register a FileProvider domain with the recovery service (if available).
    ///
    /// Call this after successfully mounting a vault via FileProvider to enable
    /// automatic health monitoring and recovery. This is a no-op if the FileProvider
    /// feature is not enabled or if the recovery service hasn't been initialized.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault directory
    /// * `backend_type` - The backend that was used for mounting
    #[cfg(feature = "fileprovider")]
    pub fn register_fileprovider_domain(
        &self,
        vault_path: &std::path::Path,
        mountpoint: &std::path::Path,
        backend_type: BackendType,
    ) {
        use oxcrypt_mount::BackendType;

        // Only register if this was a FileProvider mount
        if !matches!(backend_type, BackendType::FileProvider) {
            return;
        }

        // Check if recovery service is available
        let Some(service) = recovery_service() else {
            tracing::debug!("FileProvider recovery service not available");
            return;
        };

        let display_name = mountpoint
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Vault (OxCrypt)")
            .to_string();

        // Encode vault path as domain ID (matches FileProvider backend logic)
        let domain_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            vault_path.to_string_lossy().as_bytes()
        );

        let vault_path = vault_path.to_path_buf();

        // Register asynchronously
        tokio::spawn(async move {
            service.register_domain(domain_id, display_name, vault_path).await;
        });
    }

    /// Stub for register_fileprovider_domain when fileprovider feature is disabled
    #[cfg(not(feature = "fileprovider"))]
    pub fn register_fileprovider_domain(
        &self,
        _vault_path: &std::path::Path,
        _mountpoint: &std::path::Path,
        _backend_type: BackendType,
    ) {
        // No-op when FileProvider is not enabled
    }

    /// Unregister a FileProvider domain from the recovery service.
    ///
    /// Call this when unmounting a vault that was mounted via FileProvider.
    /// This is a no-op if the FileProvider feature is not enabled or if the
    /// recovery service hasn't been initialized.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault directory
    #[cfg(feature = "fileprovider")]
    pub fn unregister_fileprovider_domain(&self, vault_path: &std::path::Path) {
        // Check if recovery service is available
        let Some(service) = recovery_service() else {
            return;
        };

        // Encode vault path as domain ID (matches FileProvider backend logic)
        let domain_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            vault_path.to_string_lossy().as_bytes()
        );

        // Unregister asynchronously
        tokio::spawn(async move {
            service.unregister_domain(&domain_id).await;
        });
    }

    /// Stub for unregister_fileprovider_domain when fileprovider feature is disabled
    #[cfg(not(feature = "fileprovider"))]
    pub fn unregister_fileprovider_domain(&self, _vault_path: &std::path::Path) {
        // No-op when FileProvider is not enabled
    }

    /// Unmount all vaults (called on shutdown)
    ///
    /// Each unmount operation has a 10-second timeout to prevent hanging on shutdown.
    /// If an unmount times out, we attempt force unmount as a fallback.
    pub fn unmount_all(&self) {
        const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

        // Get state manager once for all cleanup operations
        let state_manager = DesktopMountState::new().ok();

        let mut mounts = self.mounts.lock();
        for (vault_id, handle) in mounts.drain() {
            let mountpoint = handle.mountpoint().to_path_buf();
            tracing::info!("Unmounting vault {} from {}", vault_id, mountpoint.display());

            // Spawn unmount in a thread so we can timeout
            let (tx, rx) = std::sync::mpsc::channel();
            let vault_id_clone = vault_id.clone();
            std::thread::spawn(move || {
                let result = handle.unmount();
                let _ = tx.send(result);
            });

            match rx.recv_timeout(UNMOUNT_TIMEOUT) {
                Ok(Ok(())) => {
                    tracing::info!("Successfully unmounted {}", vault_id);
                    // Remove from persisted state
                    if let Some(ref manager) = state_manager
                        && let Err(e) = manager.remove_mount(&mountpoint) {
                            tracing::warn!("Failed to update mount state: {}", e);
                        }
                }
                Ok(Err(e)) => {
                    tracing::error!("Failed to unmount {}: {}", vault_id, e);
                    // Still remove from state - mount may have been force-unmounted
                    if let Some(ref manager) = state_manager {
                        let _ = manager.remove_mount(&mountpoint);
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        "Unmount of {} timed out after {:?}, mount may be orphaned",
                        vault_id_clone,
                        UNMOUNT_TIMEOUT
                    );
                    // Note: The spawned thread still owns the handle and will eventually
                    // complete or be cleaned up when the process exits. We can't force
                    // unmount here because we no longer own the handle.
                    // Don't remove from state - proactive_cleanup will handle orphaned mounts
                }
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
///
/// The short delay before exit allows the non-blocking tracing logger to flush
/// any pending log events to the file.
pub fn cleanup_and_exit() -> ! {
    tracing::info!("App exiting, unmounting all vaults...");
    mount_manager().unmount_all();
    tracing::info!("Cleanup complete, exiting");

    // Give the non-blocking log writer time to flush pending events
    // before process::exit() terminates without running destructors
    std::thread::sleep(Duration::from_millis(100));

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
        // On Windows, prefer an available drive letter so the UI doesn't show
        // an invalid or already-used path.
        let mut selected = None;
        for letter in ('D'..='Z').rev() {
            let candidate = format!("{}:\\", letter);
            if !std::path::Path::new(&candidate).exists() {
                selected = Some(letter);
                break;
            }
        }

        let letter = selected.unwrap_or('Z');
        PathBuf::from(format!("{}:", letter))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp").join("oxcrypt").join(vault_name)
    }
}
