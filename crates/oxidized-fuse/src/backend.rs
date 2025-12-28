//! FUSE backend implementation of MountBackend trait.
//!
//! Provides a unified mounting interface for FUSE-based filesystem mounts.

use crate::CryptomatorFS;
use fuser::{BackgroundSession, MountOption};
use oxidized_cryptolib::{MountBackend, MountError, MountHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Handle to a FUSE-mounted filesystem.
///
/// Wraps the fuser `BackgroundSession`. Dropping this handle triggers unmount.
pub struct FuseMountHandle {
    session: Option<BackgroundSession>,
    mountpoint: PathBuf,
}

impl MountHandle for FuseMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        if let Some(session) = self.session.take() {
            // Join the session to ensure clean unmount
            session.join();
        }
        Ok(())
    }
}

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        // Ensure session is dropped even if unmount() wasn't called
        if let Some(session) = self.session.take() {
            tracing::debug!("Unmounting FUSE filesystem at {}", self.mountpoint.display());
            session.join();
        }
    }
}

/// FUSE-based mounting backend.
///
/// Uses the `oxidized-fuse` crate to create a FUSE filesystem and mount it
/// using macFUSE (macOS) or libfuse (Linux).
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseBackend {
    /// Timeout for waiting for mount readiness
    pub mount_timeout: Duration,
    /// Polling interval when waiting for mount
    pub poll_interval: Duration,
}

impl FuseBackend {
    /// Create a new FUSE backend with default settings.
    pub fn new() -> Self {
        Self {
            mount_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
        }
    }

    /// Create a new FUSE backend with custom timeouts.
    pub fn with_timeouts(mount_timeout: Duration, poll_interval: Duration) -> Self {
        Self {
            mount_timeout,
            poll_interval,
        }
    }

    /// Wait for the mount to become ready by polling for actual content.
    fn wait_for_mount(&self, mount_point: &Path) -> Result<(), MountError> {
        let deadline = Instant::now() + self.mount_timeout;

        while Instant::now() < deadline {
            if let Ok(entries) = std::fs::read_dir(mount_point) {
                // Check if we can actually read entries
                let has_content = entries.filter_map(|e| e.ok()).next().is_some();
                if has_content {
                    return Ok(());
                }
            }
            std::thread::sleep(self.poll_interval);
        }

        Err(MountError::Mount(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "FUSE mount did not become ready within {:?}",
                self.mount_timeout
            ),
        )))
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
        #[cfg(target_os = "macos")]
        {
            // Check for macFUSE installation
            Path::new("/Library/Filesystems/macfuse.fs").exists()
        }
        #[cfg(target_os = "linux")]
        {
            // Check for FUSE kernel module
            Path::new("/dev/fuse").exists()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            return None;
        }

        #[cfg(target_os = "macos")]
        {
            Some("macFUSE is not installed. Download it from https://osxfuse.github.io/".to_string())
        }
        #[cfg(target_os = "linux")]
        {
            Some("FUSE is not available. Ensure the fuse kernel module is loaded.".to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Some("FUSE is not supported on this platform.".to_string())
        }
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Create the CryptomatorFS filesystem
        let fs = CryptomatorFS::new(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Configure mount options
        let options = vec![
            MountOption::FSName(format!("cryptomator:{}", vault_id)),
            MountOption::Subtype("oxidized".to_string()),
            MountOption::AutoUnmount,
        ];

        // Mount the filesystem in a background thread
        let session = fuser::spawn_mount2(fs, mountpoint, &options)?;

        // Wait for mount to become ready
        self.wait_for_mount(mountpoint)?;

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            mountpoint: mountpoint.to_path_buf(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_backend_id() {
        let backend = FuseBackend::new();
        assert_eq!(backend.id(), "fuse");
        assert_eq!(backend.name(), "FUSE");
    }

    #[test]
    fn fuse_backend_availability_check() {
        let backend = FuseBackend::new();
        // Just verify the method doesn't panic
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }

    #[test]
    fn fuse_backend_custom_timeouts() {
        let backend = FuseBackend::with_timeouts(Duration::from_secs(5), Duration::from_millis(100));
        assert_eq!(backend.mount_timeout, Duration::from_secs(5));
        assert_eq!(backend.poll_interval, Duration::from_millis(100));
    }
}
