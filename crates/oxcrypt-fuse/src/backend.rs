//! FUSE backend implementation of MountBackend trait.
//!
//! Provides a unified mounting interface for FUSE-based filesystem mounts.

use crate::scheduler::SchedulerStatsCollector;
use crate::{CryptomatorFS, MountConfig};
use fuser::{BackgroundSession, MountOption};
use oxcrypt_mount::{
    find_available_mountpoint, BackendType, MountBackend, MountError, MountHandle, MountOptions,
    SchedulerStatsSnapshot, VaultStats,
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
    /// Lock contention metrics for profiling
    lock_metrics: Arc<oxcrypt_core::vault::lock_metrics::LockMetrics>,
    /// Scheduler stats collector for detailed scheduler metrics
    scheduler_collector: Option<SchedulerStatsCollector>,
}

impl FuseMountHandle {
    /// Get lock contention metrics for profiling fast path performance.
    ///
    /// Returns metrics about sync fast path hit rate and async lock acquisitions.
    pub fn lock_metrics(&self) -> &Arc<oxcrypt_core::vault::lock_metrics::LockMetrics> {
        &self.lock_metrics
    }

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

    fn lock_metrics(&self) -> Option<Arc<oxcrypt_core::vault::lock_metrics::LockMetrics>> {
        Some(Arc::clone(&self.lock_metrics))
    }

    fn scheduler_stats(&self) -> Option<SchedulerStatsSnapshot> {
        self.scheduler_collector.as_ref().map(|c| c.to_mount_snapshot())
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        tracing::info!(mountpoint = %self.mountpoint.display(), "Unmounting FUSE filesystem");
        if let Some(session) = self.session.take() {
            // Join the session for clean unmount
            // This may block if files are open
            session.join();
        }
        tracing::info!(mountpoint = %self.mountpoint.display(), "FUSE unmount successful");
        Ok(())
    }

    fn force_unmount(mut self: Box<Self>) -> Result<(), MountError> {
        tracing::info!(mountpoint = %self.mountpoint.display(), "Force unmounting FUSE filesystem");
        if let Some(session) = self.session.take() {
            // First, force unmount using OS tools to release any busy handles
            self.force_unmount_impl();

            // Brief pause to let the force unmount take effect
            std::thread::sleep(Duration::from_millis(100));

            // Now join the session (should complete quickly after force unmount)
            session.join();
        }
        tracing::info!(mountpoint = %self.mountpoint.display(), "FUSE force unmount successful");
        Ok(())
    }
}

/// Timeout for graceful session.join() before forcing unmount.
/// Thread may leak on timeout, but this is acceptable vs blocking forever.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        // Ensure session is dropped even if unmount() wasn't called
        if let Some(session) = self.session.take() {
            tracing::debug!("Unmounting FUSE filesystem at {}", self.mountpoint.display());

            // Spawn thread for potentially blocking join() so we can timeout
            let (tx, rx) = mpsc::channel();
            let mountpoint_for_log = self.mountpoint.clone();
            std::thread::spawn(move || {
                session.join();
                let _ = tx.send(());
            });

            // Wait for graceful unmount with timeout
            match rx.recv_timeout(JOIN_TIMEOUT) {
                Ok(()) => {
                    tracing::debug!(
                        "Graceful unmount completed for {}",
                        self.mountpoint.display()
                    );
                }
                Err(_) => {
                    // Timeout - force unmount to unblock the join thread
                    tracing::warn!(
                        "session.join() timed out after {:?} for {}, forcing unmount",
                        JOIN_TIMEOUT,
                        mountpoint_for_log.display()
                    );
                    self.force_unmount_impl();
                    // Note: join thread will eventually complete or leak,
                    // which is acceptable vs blocking the entire program
                }
            }
        }
    }
}

/// FUSE-based mounting backend.
///
/// Uses the `oxcrypt-fuse` crate to create a FUSE filesystem and mount it
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

    /// Wait for the mount to become ready by polling until the mount is active.
    ///
    /// Uses device ID comparison (stat-based) rather than mount table parsing,
    /// since the mount command can block on ghost mounts. A mount is detected
    /// when the path's device ID differs from its parent's.
    fn wait_for_mount(&self, mount_point: &Path) -> Result<(), MountError> {
        use oxcrypt_mount::TimeoutFs;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let deadline = Instant::now() + self.mount_timeout;
        let fs = TimeoutFs::new(Duration::from_millis(500));

        // Get parent path for device comparison
        let parent = mount_point.parent().unwrap_or(Path::new("/"));

        while Instant::now() < deadline {
            // Check if mount point has different device ID than parent (indicates active mount)
            #[cfg(unix)]
            {
                if let (Ok(path_meta), Ok(parent_meta)) =
                    (fs.metadata(mount_point), fs.metadata(parent))
                    && path_meta.dev() != parent_meta.dev() {
                        tracing::debug!(
                            "FUSE mount confirmed active at {} (dev {} != parent dev {})",
                            mount_point.display(),
                            path_meta.dev(),
                            parent_meta.dev()
                        );
                        return Ok(());
                    }
            }

            // Non-unix fallback: just check if directory exists
            #[cfg(not(unix))]
            {
                if fs.is_dir(mount_point) {
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
        tracing::info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            "Starting FUSE mount"
        );

        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Find an available mount point (one that's not already a mount point)
        let actual_mountpoint = find_available_mountpoint(mountpoint)
            .map_err(|e| MountError::Mount(std::io::Error::other(e.to_string())))?;

        // Log if we're using an alternative mountpoint
        if actual_mountpoint != mountpoint {
            tracing::info!(
                "Using alternative mount point {} (original {} already mounted)",
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

        // Capture stats, lock metrics, and scheduler collector before spawning
        // (spawn_mount2 takes ownership of fs)
        let stats = fs.stats();
        let lock_metrics = Arc::clone(fs.lock_metrics());
        let scheduler_collector = fs.scheduler_stats_collector();
        // Get pointer to notifier cell that we can use after fs is moved
        let notifier_cell_ptr: *const std::sync::OnceLock<fuser::Notifier> = fs.notifier_cell();

        // Configure mount options
        let mut options = vec![
            MountOption::FSName(format!("cryptomator:{vault_id}")),
            MountOption::Subtype("oxcrypt".to_string()),
            MountOption::AutoUnmount,
            // Let kernel handle permission checks - avoids access() calls for every operation
            MountOption::DefaultPermissions,
        ];

        // On macOS, set the volume name shown in Finder
        #[cfg(target_os = "macos")]
        {
            options.push(MountOption::CUSTOM(format!("volname={vault_id}")));
            // Auto-eject after 30s if daemon stops responding (prevents ghost mounts)
            options.push(MountOption::CUSTOM("daemon_timeout=30".to_string()));
        }

        // Mount the filesystem with timeout protection
        let session = self.spawn_mount_with_timeout(fs, &actual_mountpoint, &options)?;

        // Inject notifier for kernel cache invalidation
        // SAFETY: The pointer is valid because CryptomatorFS is kept alive by the session,
        // and the OnceLock is at a stable address within the struct.
        {
            let notifier = session.notifier();
            let notifier_cell = unsafe { &*notifier_cell_ptr };
            tracing::debug!("Injecting kernel notifier for cache invalidation");
            if notifier_cell.set(notifier).is_err() {
                tracing::warn!("Failed to set notifier - already initialized");
            } else {
                tracing::info!("Successfully injected kernel notifier for cache invalidation");
            }
        }

        // Wait for mount to become ready (also with timeout protection)
        self.wait_for_mount(&actual_mountpoint)?;

        tracing::info!(
            mountpoint = %actual_mountpoint.display(),
            vault_id = %vault_id,
            "FUSE mount successful"
        );

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            mountpoint: actual_mountpoint,
            stats,
            lock_metrics,
            scheduler_collector,
        }))
    }

    fn mount_with_options(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
        options: &MountOptions,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        tracing::info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            local_mode = options.local_mode,
            "Starting FUSE mount with options"
        );

        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Find an available mount point (one that's not already a mount point)
        let actual_mountpoint = find_available_mountpoint(mountpoint)
            .map_err(|e| MountError::Mount(std::io::Error::other(e.to_string())))?;

        // Log if we're using an alternative mountpoint
        if actual_mountpoint != mountpoint {
            tracing::info!(
                "Using alternative mount point {} (original {} already mounted)",
                actual_mountpoint.display(),
                mountpoint.display()
            );
        }

        // Create mount point directory if it doesn't exist
        if !actual_mountpoint.exists() {
            std::fs::create_dir_all(&actual_mountpoint)?;
        }

        // Convert MountOptions to MountConfig
        let mut config = if options.local_mode {
            MountConfig::local()
        } else {
            MountConfig::default()
        };

        // Apply custom TTL if specified
        if let Some(ttl) = options.attr_ttl {
            config = config.attr_ttl(ttl);
        }

        tracing::info!(
            "Mounting vault {} with {} mode (cache TTL: {:?})",
            vault_id,
            if options.local_mode { "local" } else { "network" },
            config.attr_ttl
        );

        // Create the CryptomatorFS filesystem with config
        let fs = CryptomatorFS::with_config(vault_path, password, config)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Capture stats, lock metrics, and scheduler collector before spawning
        // (spawn_mount2 takes ownership of fs)
        let stats = fs.stats();
        let lock_metrics = Arc::clone(fs.lock_metrics());
        let scheduler_collector = fs.scheduler_stats_collector();
        // Get pointer to notifier cell that we can use after fs is moved
        let notifier_cell_ptr: *const std::sync::OnceLock<fuser::Notifier> = fs.notifier_cell();

        // Configure mount options
        let mut mount_options = vec![
            MountOption::FSName(format!("cryptomator:{vault_id}")),
            MountOption::Subtype("oxcrypt".to_string()),
            MountOption::AutoUnmount,
        ];

        // On macOS, set the volume name shown in Finder
        #[cfg(target_os = "macos")]
        {
            mount_options.push(MountOption::CUSTOM(format!("volname={vault_id}")));
            // Auto-eject after 30s if daemon stops responding (prevents ghost mounts)
            mount_options.push(MountOption::CUSTOM("daemon_timeout=30".to_string()));
        }

        // Mount the filesystem with timeout protection
        let session = self.spawn_mount_with_timeout(fs, &actual_mountpoint, &mount_options)?;

        // Inject notifier for kernel cache invalidation
        // SAFETY: The pointer is valid because CryptomatorFS is kept alive by the session,
        // and the OnceLock is at a stable address within the struct.
        {
            let notifier = session.notifier();
            let notifier_cell = unsafe { &*notifier_cell_ptr };
            tracing::debug!("Injecting kernel notifier for cache invalidation");
            if notifier_cell.set(notifier).is_err() {
                tracing::warn!("Failed to set notifier - already initialized");
            } else {
                tracing::info!("Successfully injected kernel notifier for cache invalidation");
            }
        }

        // Wait for mount to become ready (also with timeout protection)
        self.wait_for_mount(&actual_mountpoint)?;

        tracing::info!(
            mountpoint = %actual_mountpoint.display(),
            vault_id = %vault_id,
            local_mode = options.local_mode,
            "FUSE mount successful"
        );

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            mountpoint: actual_mountpoint,
            stats,
            lock_metrics,
            scheduler_collector,
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
