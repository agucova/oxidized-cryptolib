//! Mount management for benchmark targets.
//!
//! This module handles mounting and unmounting the various filesystem
//! implementations that we benchmark, using the unified `MountBackend` trait.

mod external;

pub use external::ExternalMount;

// Re-export MountBackend types from mount-common
pub use oxidized_mount_common::{BackendType, MountBackend, MountError, MountHandle};

// Re-export backend implementations
pub use oxidized_fuse::{FuseBackend, FuseMountHandle};
#[cfg(target_os = "macos")]
pub use oxidized_fskit::{FSKitBackend, FSKitMountHandle};
pub use oxidized_webdav::WebDavBackend;
pub use oxidized_nfs::NfsBackend;

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

/// Global WebDAV backend instance
static WEBDAV_BACKEND: OnceLock<WebDavBackend> = OnceLock::new();

/// Global NFS backend instance
static NFS_BACKEND: OnceLock<NfsBackend> = OnceLock::new();

/// Get the FUSE backend
pub fn fuse_backend() -> &'static FuseBackend {
    FUSE_BACKEND.get_or_init(FuseBackend::new)
}

/// Get the FSKit backend (macOS only)
#[cfg(target_os = "macos")]
pub fn fskit_backend() -> &'static FSKitBackend {
    FSKIT_BACKEND.get_or_init(FSKitBackend::new)
}

/// Get the WebDAV backend
pub fn webdav_backend() -> &'static WebDavBackend {
    WEBDAV_BACKEND.get_or_init(WebDavBackend::new)
}

/// Get the NFS backend
pub fn nfs_backend() -> &'static NfsBackend {
    NFS_BACKEND.get_or_init(NfsBackend::new)
}

/// Check if a backend is available for the given implementation.
pub fn is_backend_available(implementation: Implementation) -> bool {
    match implementation {
        Implementation::OxidizedFuse => fuse_backend().is_available(),
        #[cfg(target_os = "macos")]
        Implementation::OxidizedFsKit => fskit_backend().is_available(),
        #[cfg(not(target_os = "macos"))]
        Implementation::OxidizedFsKit => false,
        Implementation::OxidizedWebDav => webdav_backend().is_available(),
        Implementation::OxidizedNfs => nfs_backend().is_available(),
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
        Implementation::OxidizedWebDav => webdav_backend().unavailable_reason(),
        Implementation::OxidizedNfs => nfs_backend().unavailable_reason(),
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
            let backend = webdav_backend();
            tracing::debug!("Starting WebDAV mount at {}", mount_point.display());
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

/// Ensure a mount point directory exists, cleaning up any stale mounts first.
pub fn ensure_mount_point(path: &Path) -> Result<()> {
    // If the path exists and is a mount point from a previous interrupted run, unmount it
    if path.exists() && is_mount_point(path).unwrap_or(false) {
        tracing::warn!(
            "Detected stale mount at {}, attempting cleanup...",
            path.display()
        );
        cleanup_stale_mount(path)?;
    }

    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Attempt to unmount a stale mount point from a previous interrupted run.
#[cfg(target_os = "macos")]
fn cleanup_stale_mount(path: &Path) -> Result<()> {
    use std::process::Command;

    // Try diskutil unmount force first (most reliable on macOS)
    let output = Command::new("diskutil")
        .args(["unmount", "force"])
        .arg(path)
        .output()
        .context("Failed to run diskutil")?;

    if output.status.success() {
        tracing::info!("Successfully unmounted stale mount at {}", path.display());
        // Give the system a moment to release the mount
        std::thread::sleep(Duration::from_millis(200));
        return Ok(());
    }

    // Fallback to umount -f
    let output = Command::new("umount")
        .arg("-f")
        .arg(path)
        .output()
        .context("Failed to run umount")?;

    if output.status.success() {
        tracing::info!("Successfully unmounted stale mount at {}", path.display());
        std::thread::sleep(Duration::from_millis(200));
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "Failed to unmount stale mount at {}: {}",
        path.display(),
        stderr
    );
}

#[cfg(target_os = "linux")]
fn cleanup_stale_mount(path: &Path) -> Result<()> {
    use std::process::Command;

    // Try fusermount first (for FUSE mounts)
    let output = Command::new("fusermount")
        .args(["-uz"])
        .arg(path)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            tracing::info!("Successfully unmounted stale FUSE mount at {}", path.display());
            std::thread::sleep(Duration::from_millis(200));
            return Ok(());
        }
    }

    // Fallback to lazy umount
    let output = Command::new("umount")
        .arg("-l")
        .arg(path)
        .output()
        .context("Failed to run umount")?;

    if output.status.success() {
        tracing::info!("Successfully unmounted stale mount at {}", path.display());
        std::thread::sleep(Duration::from_millis(200));
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "Failed to unmount stale mount at {}: {}",
        path.display(),
        stderr
    );
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cleanup_stale_mount(path: &Path) -> Result<()> {
    anyhow::bail!(
        "Cannot cleanup stale mount at {} on this platform",
        path.display()
    );
}

/// Check if a path is a mount point (different device from parent).
#[cfg(unix)]
pub fn is_mount_point(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let path_meta = std::fs::metadata(path)?;
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent_meta = std::fs::metadata(parent)?;

    Ok(path_meta.dev() != parent_meta.dev())
}

#[cfg(not(unix))]
pub fn is_mount_point(path: &Path) -> Result<bool> {
    Ok(path.is_dir())
}
