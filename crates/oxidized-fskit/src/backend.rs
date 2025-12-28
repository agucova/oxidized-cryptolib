//! FSKit backend implementation of MountBackend trait (macOS 15.4+).
//!
//! Provides a unified mounting interface for FSKit-based filesystem mounts.

use crate::CryptomatorFSKit;
use fskit_rs::MountOptions;
use oxidized_cryptolib::{MountBackend, MountError, MountHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

/// Handle to an FSKit-mounted filesystem.
///
/// Contains the async runtime and session. Dropping this handle triggers unmount.
pub struct FSKitMountHandle {
    /// The mount session (boxed to hide the private fskit_rs::Session type)
    _session: Box<dyn std::any::Any + Send + Sync>,
    mountpoint: PathBuf,
    /// Keep runtime alive to prevent session from being dropped
    #[allow(dead_code)]
    runtime: Runtime,
}

// SAFETY: The session is managed by the runtime and doesn't need to be Sync
// The runtime itself is Send + Sync
unsafe impl Sync for FSKitMountHandle {}

impl MountHandle for FSKitMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(self: Box<Self>) -> Result<(), MountError> {
        // Session is dropped automatically when _session is dropped
        tracing::debug!(
            "Unmounting FSKit filesystem at {}",
            self.mountpoint.display()
        );
        Ok(())
    }
}

impl Drop for FSKitMountHandle {
    fn drop(&mut self) {
        tracing::debug!(
            "Dropping FSKit mount handle for {}",
            self.mountpoint.display()
        );
        // Session will be dropped automatically
    }
}

/// FSKit-based mounting backend (macOS 15.4+).
///
/// Uses Apple's native FSKit framework for mounting. Benefits over FUSE:
/// - No kernel extension required
/// - Better system integration
/// - Survives sleep/wake more reliably
/// - Native Finder integration
#[derive(Debug, Clone, Copy)]
pub struct FSKitBackend {
    /// Timeout for waiting for mount readiness
    pub mount_timeout: Duration,
    /// Polling interval when waiting for mount
    pub poll_interval: Duration,
}

impl Default for FSKitBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FSKitBackend {
    /// Create a new FSKit backend with default settings.
    pub fn new() -> Self {
        Self {
            mount_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
        }
    }

    /// Create a new FSKit backend with custom timeouts.
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
                "FSKit mount did not become ready within {:?}",
                self.mount_timeout
            ),
        )))
    }

    /// Check if FSKit is available on this macOS version.
    #[cfg(target_os = "macos")]
    fn check_macos_version() -> bool {
        use std::process::Command;

        // Run sw_vers -productVersion to get macOS version
        if let Ok(output) = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            if let Ok(version) = String::from_utf8(output.stdout) {
                let parts: Vec<&str> = version.trim().split('.').collect();
                if parts.len() >= 2 {
                    if let (Ok(major), Ok(minor)) = (
                        parts[0].parse::<u32>(),
                        parts[1].parse::<u32>(),
                    ) {
                        // FSKit requires macOS 15.4+
                        return major > 15 || (major == 15 && minor >= 4);
                    }
                }
            }
        }
        false
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
        #[cfg(target_os = "macos")]
        {
            Self::check_macos_version()
        }
        #[cfg(not(target_os = "macos"))]
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
            Some("FSKit requires macOS 15.4 or later.".to_string())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some("FSKit is only available on macOS 15.4 and later.".to_string())
        }
    }

    fn mount(
        &self,
        _vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Create async runtime for FSKit
        let runtime = Runtime::new().map_err(|e| {
            MountError::Mount(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create tokio runtime: {}", e),
            ))
        })?;

        // Ensure mount point exists
        if !mountpoint.exists() {
            std::fs::create_dir_all(mountpoint)?;
        }

        // Create filesystem
        let fs = CryptomatorFSKit::new(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Configure mount options
        let opts = MountOptions {
            mount_point: mountpoint.to_path_buf(),
            force: true,
            ..Default::default()
        };

        // Mount within the runtime
        let session = runtime
            .block_on(async { fskit_rs::mount(fs, opts).await })
            .map_err(|e| {
                MountError::Mount(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("FSKit mount failed: {}", e),
                ))
            })?;

        // Wait for mount to become ready
        self.wait_for_mount(mountpoint)?;

        Ok(Box::new(FSKitMountHandle {
            _session: Box::new(session),
            mountpoint: mountpoint.to_path_buf(),
            runtime,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fskit_backend_id() {
        let backend = FSKitBackend::new();
        assert_eq!(backend.id(), "fskit");
        assert_eq!(backend.name(), "FSKit");
    }

    #[test]
    fn fskit_backend_availability_check() {
        let backend = FSKitBackend::new();
        // Just verify the method doesn't panic
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }

    #[test]
    fn fskit_backend_custom_timeouts() {
        let backend =
            FSKitBackend::with_timeouts(Duration::from_secs(5), Duration::from_millis(100));
        assert_eq!(backend.mount_timeout, Duration::from_secs(5));
        assert_eq!(backend.poll_interval, Duration::from_millis(100));
    }
}
