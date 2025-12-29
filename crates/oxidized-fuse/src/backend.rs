//! FUSE backend implementation of MountBackend trait.
//!
//! Provides a unified mounting interface for FUSE-based filesystem mounts.

use crate::CryptomatorFS;
use fuser::{BackgroundSession, MountOption};
use oxidized_mount_common::{
    find_available_mountpoint, is_directory_readable, BackendType, MountBackend, MountError,
    MountHandle, MountPointError, VaultStats, DEFAULT_ACCESS_TIMEOUT,
};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Handle to a FUSE-mounted filesystem.
///
/// Wraps the fuser `BackgroundSession`. Dropping this handle triggers unmount.
pub struct FuseMountHandle {
    session: Option<BackgroundSession>,
    mountpoint: PathBuf,
    /// Statistics for monitoring vault activity
    stats: Arc<VaultStats>,
}

impl FuseMountHandle {
    /// Force unmount the filesystem using system tools.
    /// This is a fallback when the normal unmount is blocked.
    fn force_unmount_impl(&self) {
        #[cfg(target_os = "macos")]
        {
            // Try diskutil unmount force first (more reliable on macOS)
            let result = std::process::Command::new("diskutil")
                .args(["unmount", "force"])
                .arg(&self.mountpoint)
                .output();

            match result {
                Ok(output) if output.status.success() => {
                    tracing::debug!("Force unmount via diskutil succeeded");
                    return;
                }
                _ => {
                    tracing::debug!("diskutil unmount failed, trying umount");
                }
            }

            // Fallback to umount
            let _ = std::process::Command::new("umount")
                .arg("-f")
                .arg(&self.mountpoint)
                .output();
        }

        #[cfg(target_os = "linux")]
        {
            // Try lazy unmount on Linux
            let _ = std::process::Command::new("fusermount")
                .args(["-uz"])
                .arg(&self.mountpoint)
                .output();
        }
    }
}

impl MountHandle for FuseMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn stats(&self) -> Option<Arc<VaultStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        if let Some(session) = self.session.take() {
            // Join the session for clean unmount
            // This may block if files are open
            session.join();
        }
        Ok(())
    }

    fn force_unmount(mut self: Box<Self>) -> Result<(), MountError> {
        if let Some(session) = self.session.take() {
            // First, force unmount using OS tools to release any busy handles
            self.force_unmount_impl();

            // Brief pause to let the force unmount take effect
            std::thread::sleep(Duration::from_millis(100));

            // Now join the session (should complete quickly after force unmount)
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

            // Force unmount first to avoid blocking on drop
            self.force_unmount_impl();
            std::thread::sleep(Duration::from_millis(100));

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

    /// Wait for the mount to become ready by polling until we can read the directory.
    ///
    /// Uses timeout-wrapped filesystem operations to avoid blocking indefinitely
    /// on stale mounts.
    fn wait_for_mount(&self, mount_point: &Path) -> Result<(), MountError> {
        let deadline = Instant::now() + self.mount_timeout;
        // Timeout for each individual read_dir attempt (prevents blocking on stale mounts)
        let single_check_timeout = Duration::from_millis(500);

        while Instant::now() < deadline {
            // Use timeout-wrapped directory read to avoid blocking on stale mounts
            if is_directory_readable(mount_point, single_check_timeout) {
                return Ok(());
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

    /// Try to mount with spawn_mount2, with a timeout to handle cases where
    /// the mount syscall itself blocks (e.g., stale mount at mountpoint).
    fn spawn_mount_with_timeout(
        &self,
        fs: CryptomatorFS,
        mountpoint: &Path,
        options: &[MountOption],
    ) -> Result<BackgroundSession, MountError> {
        let mountpoint = mountpoint.to_path_buf();
        let options: Vec<MountOption> = options.to_vec();
        let (tx, rx) = mpsc::channel();

        // Spawn the mount in a separate thread so we can timeout
        std::thread::spawn(move || {
            let result = fuser::spawn_mount2(fs, &mountpoint, &options);
            let _ = tx.send(result);
        });

        // Wait for mount with timeout
        match rx.recv_timeout(self.mount_timeout) {
            Ok(Ok(session)) => Ok(session),
            Ok(Err(e)) => Err(MountError::Mount(e)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(MountError::Mount(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Mount operation timed out - the mountpoint may be on a stale FUSE mount",
            ))),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(MountError::Mount(
                std::io::Error::other("Mount thread terminated unexpectedly"),
            ))
        }
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

    fn backend_type(&self) -> BackendType {
        BackendType::Fuse
    }

    fn description(&self) -> &'static str {
        "Uses macFUSE (macOS) or libfuse (Linux) for filesystem mounting"
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

        // Find an available mount point, detecting stale mounts and trying alternatives
        let actual_mountpoint = find_available_mountpoint(mountpoint, DEFAULT_ACCESS_TIMEOUT)
            .map_err(|e| match e {
                MountPointError::ParentOnStaleFuseMount { parent, fuse_mount } => {
                    MountError::Mount(std::io::Error::other(format!(
                        "Cannot mount: {} is on a stale FUSE mount ({}). \
                         Please unmount the stale mount first using: \
                         diskutil unmount force {}",
                        parent.display(),
                        fuse_mount.display(),
                        fuse_mount.display()
                    )))
                }
                MountPointError::ParentInaccessible(path) => {
                    MountError::Mount(std::io::Error::other(format!(
                        "Parent directory {} is inaccessible. \
                         It may be on a stale mount. Try: diskutil unmount force {}",
                        path.display(),
                        path.display()
                    )))
                }
                other => MountError::Mount(std::io::Error::other(other.to_string())),
            })?;

        // Log if we're using an alternative mountpoint
        if actual_mountpoint != mountpoint {
            tracing::info!(
                "Using alternative mount point {} (original {} was unavailable)",
                actual_mountpoint.display(),
                mountpoint.display()
            );
        }

        // Create mount point directory if it doesn't exist
        if !actual_mountpoint.exists() {
            std::fs::create_dir_all(&actual_mountpoint)?;
        }

        // Create the CryptomatorFS filesystem
        let fs = CryptomatorFS::new(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Capture stats before spawning (spawn_mount2 takes ownership of fs)
        let stats = fs.stats();

        // Configure mount options
        let mut options = vec![
            MountOption::FSName(format!("cryptomator:{}", vault_id)),
            MountOption::Subtype("oxidized".to_string()),
            MountOption::AutoUnmount,
        ];

        // On macOS, set the volume name shown in Finder
        #[cfg(target_os = "macos")]
        {
            options.push(MountOption::CUSTOM(format!("volname={}", vault_id)));
        }

        // Mount the filesystem with timeout protection
        let session = self.spawn_mount_with_timeout(fs, &actual_mountpoint, &options)?;

        // Wait for mount to become ready (also with timeout protection)
        self.wait_for_mount(&actual_mountpoint)?;

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            mountpoint: actual_mountpoint,
            stats,
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
