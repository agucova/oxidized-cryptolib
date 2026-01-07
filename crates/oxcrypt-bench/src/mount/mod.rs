//! Mount management for benchmark targets.
//!
//! This module handles mounting and unmounting the various filesystem
//! implementations that we benchmark, using the unified `MountBackend` trait.

mod external;

pub use external::ExternalMount;

// Re-export MountBackend types from mount-common
pub use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};

// Import timeout-protected filesystem operations
use oxcrypt_mount::TimeoutFs;

// Re-export backend implementations
#[cfg(not(test))]
pub use oxcrypt_fuse::{FuseBackend, FuseMountHandle};
#[cfg(test)]
mod fuse_stub {
    use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::{Path, PathBuf};

    #[derive(Debug, Clone, Default)]
    pub struct FuseBackend;

    impl FuseBackend {
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for FuseBackend {
        fn name(&self) -> &'static str {
            "FUSE"
        }

        fn id(&self) -> &'static str {
            "fuse"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some("FUSE backend is disabled in tests.".to_string())
        }

        fn backend_type(&self) -> BackendType {
            BackendType::Fuse
        }

        fn description(&self) -> &'static str {
            "FUSE backend disabled in tests"
        }

        fn mount(
            &self,
            _vault_id: &str,
            _vault_path: &Path,
            _password: &str,
            _mountpoint: &Path,
        ) -> Result<Box<dyn MountHandle>, MountError> {
            Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ))
        }
    }

    #[derive(Debug, Default)]
    pub struct FuseMountHandle {
        mountpoint: PathBuf,
    }

    impl MountHandle for FuseMountHandle {
        fn mountpoint(&self) -> &Path {
            self.mountpoint.as_path()
        }

        fn unmount(self: Box<Self>) -> Result<(), MountError> {
            Ok(())
        }

        fn force_unmount(self: Box<Self>) -> Result<(), MountError> {
            Ok(())
        }
    }
}
#[cfg(test)]
pub use fuse_stub::{FuseBackend, FuseMountHandle};
pub use oxcrypt_webdav::WebDavBackend;
pub use oxcrypt_nfs::NfsBackend;

// FileProvider backend (macOS 13+ only)
#[cfg(all(target_os = "macos", feature = "fileprovider"))]
pub use oxcrypt_fileprovider::FileProviderBackend;

// FSKit backend stub (macOS 15.4+)
// The oxcrypt-fskit crate is an FFI layer for Swift and doesn't implement MountBackend.
// Once the full FSKit backend is implemented, this stub should be replaced.
#[cfg(target_os = "macos")]
mod fskit_stub {
    use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle};
    use std::path::Path;

    /// FSKit-based mounting backend (stub for oxbench)
    ///
    /// This is a placeholder until the full FSKit backend is implemented.
    /// FSKit requires macOS 15.4+ and the system extension to be enabled.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FSKitBackend;

    impl FSKitBackend {
        /// Create a new FSKitBackend stub
        pub fn new() -> Self {
            Self
        }
    }

    impl MountBackend for FSKitBackend {
        fn name(&self) -> &'static str {
            "FSKit"
        }

        fn id(&self) -> &'static str {
            "fskit"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some(
                "FSKit backend is not yet implemented in oxbench. \
                 Use the GUI (oxvault) for FSKit support."
                    .to_string(),
            )
        }

        fn backend_type(&self) -> BackendType {
            BackendType::FSKit
        }

        fn description(&self) -> &'static str {
            "Uses Apple's native FSKit framework (macOS 15.4+)"
        }

        fn mount(
            &self,
            _vault_id: &str,
            _vault_path: &Path,
            _password: &str,
            _mountpoint: &Path,
        ) -> Result<Box<dyn MountHandle>, MountError> {
            Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub use fskit_stub::FSKitBackend;

use crate::config::Implementation;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

/// Global FUSE backend instance
static FUSE_BACKEND: OnceLock<FuseBackend> = OnceLock::new();

/// Global FSKit backend instance (macOS only)
#[cfg(target_os = "macos")]
static FSKIT_BACKEND: OnceLock<FSKitBackend> = OnceLock::new();

/// Global NFS backend instance
static NFS_BACKEND: OnceLock<NfsBackend> = OnceLock::new();

/// Global FileProvider backend instance (macOS only)
#[cfg(all(target_os = "macos", feature = "fileprovider"))]
static FILEPROVIDER_BACKEND: OnceLock<FileProviderBackend> = OnceLock::new();

/// Get the FUSE backend
pub fn fuse_backend() -> &'static FuseBackend {
    FUSE_BACKEND.get_or_init(FuseBackend::new)
}

/// Get the FSKit backend (macOS only)
#[cfg(target_os = "macos")]
pub fn fskit_backend() -> &'static FSKitBackend {
    FSKIT_BACKEND.get_or_init(FSKitBackend::new)
}

/// Get the NFS backend
pub fn nfs_backend() -> &'static NfsBackend {
    NFS_BACKEND.get_or_init(NfsBackend::new)
}

/// Get the FileProvider backend (macOS only)
#[cfg(all(target_os = "macos", feature = "fileprovider"))]
pub fn fileprovider_backend() -> &'static FileProviderBackend {
    FILEPROVIDER_BACKEND.get_or_init(FileProviderBackend::new)
}

/// Check if a backend is available for the given implementation.
pub fn is_backend_available(implementation: Implementation) -> bool {
    match implementation {
        Implementation::OxidizedFuse => fuse_backend().is_available(),
        #[cfg(target_os = "macos")]
        Implementation::OxidizedFsKit => fskit_backend().is_available(),
        #[cfg(not(target_os = "macos"))]
        Implementation::OxidizedFsKit => false,
        Implementation::OxidizedWebDav => WebDavBackend::new().is_available(),
        Implementation::OxidizedNfs => nfs_backend().is_available(),
        #[cfg(all(target_os = "macos", feature = "fileprovider"))]
        Implementation::OxidizedFileProvider => fileprovider_backend().is_available(),
        #[cfg(not(all(target_os = "macos", feature = "fileprovider")))]
        Implementation::OxidizedFileProvider => false,
        Implementation::OfficialCryptomator => true, // External, always "available" (user manages it)
    }
}

/// Get the reason a backend is unavailable.
pub fn backend_unavailable_reason(implementation: Implementation) -> Option<String> {
    match implementation {
        Implementation::OxidizedFuse => fuse_backend().unavailable_reason(),
        #[cfg(target_os = "macos")]
        Implementation::OxidizedFsKit => fskit_backend().unavailable_reason(),
        #[cfg(not(target_os = "macos"))]
        Implementation::OxidizedFsKit => Some("FSKit is only available on macOS 15.4+".to_string()),
        Implementation::OxidizedWebDav => WebDavBackend::new().unavailable_reason(),
        Implementation::OxidizedNfs => nfs_backend().unavailable_reason(),
        #[cfg(all(target_os = "macos", feature = "fileprovider"))]
        Implementation::OxidizedFileProvider => fileprovider_backend().unavailable_reason(),
        #[cfg(not(all(target_os = "macos", feature = "fileprovider")))]
        Implementation::OxidizedFileProvider => Some("FileProvider is only available on macOS 13+ (enable 'fileprovider' feature)".to_string()),
        Implementation::OfficialCryptomator => None,
    }
}

/// Wrapper around MountHandle that also stores the implementation type.
pub struct BenchMount {
    handle: Option<Box<dyn MountHandle>>,
    /// For external mounts without a handle, store the mount point directly
    external_mount_point: Option<PathBuf>,
    implementation: Implementation,
}

impl BenchMount {
    /// Get the mount point path.
    pub fn mount_point(&self) -> &Path {
        if let Some(ref handle) = self.handle {
            handle.mountpoint()
        } else if let Some(ref mp) = self.external_mount_point {
            mp
        } else {
            Path::new("")
        }
    }

    /// Get the implementation type.
    pub fn implementation(&self) -> Implementation {
        self.implementation
    }

    /// Get vault statistics if available.
    ///
    /// Returns `None` for external mounts (Official Cryptomator) since we
    /// don't have access to their internal statistics.
    pub fn stats(&self) -> Option<std::sync::Arc<oxcrypt_mount::VaultStats>> {
        self.handle.as_ref().and_then(|h| h.stats())
    }

    /// Get lock contention metrics if available.
    ///
    /// Returns `None` for backends that don't support lock metrics or for external mounts.
    pub fn lock_metrics(&self) -> Option<std::sync::Arc<oxcrypt_core::vault::lock_metrics::LockMetrics>> {
        self.handle.as_ref().and_then(|h| h.lock_metrics())
    }
}

impl Drop for BenchMount {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            tracing::debug!(
                "Unmounting {} at {}",
                self.implementation,
                handle.mountpoint().display()
            );
            if let Err(e) = handle.unmount() {
                tracing::warn!("Failed to unmount {}: {}", self.implementation, e);
            }
        }
    }
}

/// Mount a filesystem implementation using the MountBackend trait.
pub fn mount_implementation(
    implementation: Implementation,
    vault_path: &Path,
    password: &str,
    mount_point: &Path,
) -> Result<BenchMount> {
    match implementation {
        Implementation::OxidizedFuse => {
            let backend = fuse_backend();
            let handle = backend
                .mount("bench", vault_path, password, mount_point)
                .with_context(|| format!("Failed to mount FUSE at {}", mount_point.display()))?;
            Ok(BenchMount {
                handle: Some(handle),
                external_mount_point: None,
                implementation,
            })
        }
        #[cfg(target_os = "macos")]
        Implementation::OxidizedFsKit => {
            let backend = fskit_backend();
            let handle = backend
                .mount("bench", vault_path, password, mount_point)
                .with_context(|| format!("Failed to mount FSKit at {}", mount_point.display()))?;
            Ok(BenchMount {
                handle: Some(handle),
                external_mount_point: None,
                implementation,
            })
        }
        #[cfg(not(target_os = "macos"))]
        Implementation::OxidizedFsKit => {
            anyhow::bail!("FSKit is only available on macOS 15.4+");
        }
        Implementation::OxidizedWebDav => {
            let backend = WebDavBackend::new();
            tracing::debug!(
                "Starting WebDAV mount at {}",
                mount_point.display(),
            );
            let handle = backend
                .mount("bench", vault_path, password, mount_point)
                .with_context(|| format!("Failed to mount WebDAV at {}", mount_point.display()))?;

            // Verify the mount actually worked (WebDAV auto-mount can fail silently)
            // Wait a moment for the mount to stabilize
            tracing::debug!("WebDAV mount returned, waiting for stabilization...");
            std::thread::sleep(Duration::from_millis(500));

            let is_mp = is_mount_point(mount_point).unwrap_or(false);
            tracing::debug!("is_mount_point({}) = {}", mount_point.display(), is_mp);

            if !is_mp {
                // Try reading the directory to see if it's accessible
                match std::fs::read_dir(mount_point) {
                    Ok(_) => {
                        // Directory is readable but not a mount point - auto-mount failed
                        tracing::error!("WebDAV auto-mount failed - directory readable but not a mount point");
                        anyhow::bail!(
                            "WebDAV auto-mount failed at {}. The WebDAV server is running but macOS mount_webdav failed. \
                            You may need to mount manually via Finder (Cmd+K). Check system logs for details.",
                            mount_point.display()
                        );
                    }
                    Err(e) => {
                        tracing::error!("WebDAV mount not accessible: {}", e);
                        anyhow::bail!(
                            "WebDAV mount at {} is not accessible: {}",
                            mount_point.display(),
                            e
                        );
                    }
                }
            }

            tracing::info!("WebDAV mount verified at {}", mount_point.display());
            Ok(BenchMount {
                handle: Some(handle),
                external_mount_point: None,
                implementation,
            })
        }
        Implementation::OxidizedNfs => {
            let backend = nfs_backend();
            let handle = backend
                .mount("bench", vault_path, password, mount_point)
                .with_context(|| format!("Failed to mount NFS at {}", mount_point.display()))?;
            Ok(BenchMount {
                handle: Some(handle),
                external_mount_point: None,
                implementation,
            })
        }
        #[cfg(all(target_os = "macos", feature = "fileprovider"))]
        Implementation::OxidizedFileProvider => {
            let backend = fileprovider_backend();
            // Note: FileProvider ignores mount_point and uses ~/Library/CloudStorage/
            // The actual path is returned via handle.mountpoint()
            let handle = backend
                .mount("bench", vault_path, password, mount_point)
                .with_context(|| "Failed to mount FileProvider")?;
            tracing::info!(
                "FileProvider mounted at {}",
                handle.mountpoint().display()
            );
            Ok(BenchMount {
                handle: Some(handle),
                external_mount_point: None,
                implementation,
            })
        }
        #[cfg(not(all(target_os = "macos", feature = "fileprovider")))]
        Implementation::OxidizedFileProvider => {
            anyhow::bail!("FileProvider is only available on macOS 13+ (enable 'fileprovider' feature)");
        }
        Implementation::OfficialCryptomator => {
            // External mount - just validate it exists
            ExternalMount::validate(mount_point)?;
            // Store the mount point for later use (we don't manage the lifecycle)
            Ok(BenchMount {
                handle: None,
                external_mount_point: Some(mount_point.to_path_buf()),
                implementation,
            })
        }
    }
}

/// Ensure a mount point directory exists using a unique timestamp-based path.
///
/// This function always generates a unique path using a millisecond timestamp suffix.
/// This avoids any sequential probing or mount table queries that could hang on
/// ghost mounts.
///
/// # Example
///
/// Input: `/tmp/oxbench/fuse`
/// Output: `/tmp/oxbench/fuse-1704278400123` (with current timestamp)
pub fn ensure_mount_point(path: &Path) -> Result<PathBuf> {
    use oxcrypt_mount::normalize_mount_path;

    // Always use a unique suffix to avoid any collision with ghost mounts
    // This eliminates all mount table queries and sequential probing
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    // Normalize path BEFORE adding timestamp to handle /tmp -> /private/tmp on macOS
    let normalized = normalize_mount_path(path);
    let candidate = PathBuf::from(format!("{}-{}", normalized.display(), timestamp));

    // Single attempt to create the directory
    let fs = TimeoutFs::default();
    fs.create_dir_all(&candidate)
        .map_err(|e| anyhow::anyhow!("Failed to create mount point: {e}"))?;

    tracing::debug!("Using mount point: {}", candidate.display());
    Ok(candidate)
}

/// Check if a path is a mount point (different device from parent).
/// Uses timeout-protected filesystem operations to avoid blocking on ghost mounts.
#[cfg(unix)]
pub fn is_mount_point(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let fs = TimeoutFs::default();
    let path_meta = fs
        .metadata(path)
        .map_err(|e| anyhow::anyhow!("Failed to get metadata for {}: {}", path.display(), e))?;
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent_meta = fs
        .metadata(parent)
        .map_err(|e| anyhow::anyhow!("Failed to get metadata for {}: {}", parent.display(), e))?;

    Ok(path_meta.dev() != parent_meta.dev())
}

#[cfg(not(unix))]
pub fn is_mount_point(path: &Path) -> Result<bool> {
    let fs = TimeoutFs::default();
    Ok(fs.is_dir(path))
}
