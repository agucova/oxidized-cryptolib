//! NFS mount backend implementation.
//!
//! This module implements the `MountBackend` trait for NFS-based mounting
//! of Cryptomator vaults.

use crate::filesystem::CryptomatorNFS;
use nfsserve::tcp::NFSTcp;
use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle, VaultStats};
use oxcrypt_core::vault::operations_async::VaultOperationsAsync;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// Default timeout for mount readiness check.
const DEFAULT_MOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle to a mounted NFS filesystem.
///
/// When dropped, this handle will automatically unmount the filesystem
/// and stop the NFS server.
pub struct NfsMountHandle {
    /// Tokio task running the NFS server.
    server_handle: Option<JoinHandle<()>>,
    /// Runtime for async operations (kept alive for the server task).
    #[allow(dead_code)]
    runtime: Arc<Runtime>,
    /// Path where the filesystem is mounted.
    mountpoint: PathBuf,
    /// Port the NFS server is listening on.
    port: u16,
    /// Flag to track if we've already unmounted.
    unmounted: AtomicBool,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl NfsMountHandle {
    /// Gets the port the NFS server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl MountHandle for NfsMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn stats(&self) -> Option<Arc<VaultStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        self.do_unmount()
    }

    fn force_unmount(mut self: Box<Self>) -> Result<(), MountError> {
        // NFS already uses force unmount commands in do_unmount
        self.do_unmount()
    }
}

impl NfsMountHandle {
    fn do_unmount(&mut self) -> Result<(), MountError> {
        if self.unmounted.swap(true, Ordering::SeqCst) {
            // Already unmounted
            return Ok(());
        }

        info!(mountpoint = ?self.mountpoint, port = self.port, "Unmounting NFS filesystem");

        // TODO: Flush dirty buffers before unmount
        // (requires refactoring to share filesystem reference)

        // STEP 1: Unmount the filesystem
        let unmount_result = self.run_unmount_command();

        // STEP 2: Abort the server task
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }

        unmount_result
    }

    #[cfg(target_os = "macos")]
    fn run_unmount_command(&self) -> Result<(), MountError> {
        // Use shared force_unmount utility (has built-in timeouts)
        oxcrypt_mount::force_unmount(&self.mountpoint)
            .map_err(|e| MountError::UnmountFailed(e.to_string()))
    }

    #[cfg(target_os = "linux")]
    fn run_unmount_command(&self) -> Result<(), MountError> {
        // Use shared lazy_unmount utility (has built-in timeouts and fallbacks)
        oxcrypt_mount::lazy_unmount(&self.mountpoint)
            .map_err(|e| MountError::UnmountFailed(e.to_string()))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn run_unmount_command(&self) -> Result<(), MountError> {
        Err(MountError::UnmountFailed(
            "Unmount not implemented for this platform".to_string(),
        ))
    }
}

impl Drop for NfsMountHandle {
    fn drop(&mut self) {
        if let Err(e) = self.do_unmount() {
            error!(error = %e, "Failed to unmount NFS filesystem on drop");
        }
    }
}

/// NFS mount backend for Cryptomator vaults.
///
/// This backend starts a local NFS server and mounts it using the system's
/// NFS client. It doesn't require any kernel extensions.
#[derive(Debug, Clone)]
pub struct NfsBackend {
    /// Specific port to use (None = auto-select).
    pub port: Option<u16>,
    /// Timeout for mount readiness check.
    pub mount_timeout: Duration,
}

impl Default for NfsBackend {
    fn default() -> Self {
        Self {
            port: None,
            mount_timeout: DEFAULT_MOUNT_TIMEOUT,
        }
    }
}

impl NfsBackend {
    /// Creates a new NFS backend with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new NFS backend with a specific port.
    pub fn with_port(port: u16) -> Self {
        Self {
            port: Some(port),
            ..Default::default()
        }
    }

    /// Finds an available port for the NFS server.
    fn find_available_port(&self) -> Result<u16, MountError> {
        if let Some(port) = self.port {
            return Ok(port);
        }

        // Bind to port 0 to let the OS assign an available port
        let listener = TcpListener::bind("127.0.0.1:0").map_err(MountError::Mount)?;
        let port = listener.local_addr().map_err(MountError::Mount)?.port();
        drop(listener);
        Ok(port)
    }

    /// Waits for the mount to become ready.
    fn wait_for_mount(&self, mountpoint: &Path) -> Result<(), MountError> {
        let start = std::time::Instant::now();
        while start.elapsed() < self.mount_timeout {
            // Check if mountpoint is now a mount
            if self.is_mounted(mountpoint) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(MountError::Mount(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Mount did not become ready in time",
        )))
    }

    /// Checks if a path is a mount point.
    #[cfg(target_os = "macos")]
    #[allow(clippy::unused_self)]
    fn is_mounted(&self, path: &Path) -> bool {
        // Use df instead of mount to avoid hanging on ghost mounts
        let output = Command::new("df").arg(path).output();
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // df output shows the mountpoint in the last column
                // If it's mounted, we should see localhost:/ in the output
                stdout.contains("localhost:/")
            }
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn is_mounted(path: &Path) -> bool {
        let output = Command::new("mountpoint")
            .args(["-q"])
            .arg(path)
            .status();
        matches!(output, Ok(status) if status.success())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn is_mounted(_path: &Path) -> bool {
        false
    }

    /// Runs the mount command for macOS.
    #[cfg(target_os = "macos")]
    fn run_mount_command(port: u16, mountpoint: &Path) -> Result<(), MountError> {
        // mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port={PORT},mountport={PORT} localhost:/ {MOUNTPOINT}
        let port_str = port.to_string();
        let options = format!(
            "nolocks,vers=3,tcp,rsize=131072,actimeo=120,port={port_str},mountport={port_str}"
        );

        debug!(
            port,
            mountpoint = ?mountpoint,
            options = options.as_str(),
            "Running mount_nfs"
        );

        let output = Command::new("mount_nfs")
            .args(["-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()
            .map_err(MountError::Mount)?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let error_msg = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                format!("exit code: {}", output.status)
            };
            Err(MountError::Mount(std::io::Error::other(format!(
                "mount_nfs failed: {error_msg}"
            ))))
        }
    }

    /// Runs the mount command for Linux.
    #[cfg(target_os = "linux")]
    fn run_mount_command(port: u16, mountpoint: &Path) -> Result<(), MountError> {
        // mount.nfs -o user,noacl,nolock,vers=3,tcp,wsize=1048576,rsize=131072,actimeo=120,port={PORT},mountport={PORT} localhost:/ {MOUNTPOINT}
        let port_str = port.to_string();
        let options = format!(
            "user,noacl,nolock,vers=3,tcp,wsize=1048576,rsize=131072,actimeo=120,port={},mountport={}",
            port_str, port_str
        );

        debug!(
            port,
            mountpoint = ?mountpoint,
            options = options.as_str(),
            "Running mount.nfs"
        );

        let output = Command::new("mount.nfs")
            .args(["-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()
            .map_err(MountError::Mount)?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let error_msg = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                format!("exit code: {}", output.status)
            };
            Err(MountError::Mount(std::io::Error::other(format!(
                "mount.nfs failed: {}",
                error_msg
            ))))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn run_mount_command(_port: u16, _mountpoint: &Path) -> Result<(), MountError> {
        Err(MountError::BackendUnavailable(
            "NFS mount not implemented for this platform".to_string(),
        ))
    }
}

impl MountBackend for NfsBackend {
    fn name(&self) -> &'static str {
        "NFS"
    }

    fn id(&self) -> &'static str {
        "nfs"
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            // mount_nfs is built-in on macOS
            true
        }
        #[cfg(target_os = "linux")]
        {
            // Check if mount.nfs exists
            Path::new("/sbin/mount.nfs").exists()
                || Path::new("/usr/sbin/mount.nfs").exists()
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

        #[cfg(target_os = "linux")]
        {
            Some("mount.nfs not found. Install nfs-common package.".to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Some("NFS backend is only available on macOS and Linux".to_string())
        }
        #[cfg(target_os = "macos")]
        {
            None // Should never reach here since macOS is always available
        }
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Nfs
    }

    fn description(&self) -> &'static str {
        "Uses local NFSv3 server with system NFS client (no kernel extensions required)"
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        info!(
            vault_id,
            vault_path = ?vault_path,
            mountpoint = ?mountpoint,
            "Starting NFS mount"
        );

        // Verify mountpoint exists
        if !mountpoint.exists() {
            return Err(MountError::MountPointNotFound(mountpoint.to_path_buf()));
        }

        // Create async operations wrapper
        let runtime = Arc::new(
            Runtime::new().map_err(|e| {
                MountError::FilesystemCreation(format!("Failed to create runtime: {e}"))
            })?,
        );

        // Open the vault
        let ops = Arc::new(VaultOperationsAsync::open(vault_path, password).map_err(|e| {
            MountError::FilesystemCreation(format!("Failed to open vault: {e}"))
        })?);

        // Create NFS filesystem
        let fs = CryptomatorNFS::new(ops);

        // Capture stats before filesystem is moved
        let stats = fs.stats();

        // Find available port
        let port = self.find_available_port()?;

        info!(port, "Starting NFS server");

        // Channel to signal when server is ready
        let (tx, rx) = std::sync::mpsc::channel();

        // Start NFS server in background task
        let server_handle = {
            let _guard = runtime.enter();
            let bind_addr = format!("127.0.0.1:{port}");

            runtime.spawn(async move {
                match nfsserve::tcp::NFSTcpListener::bind(&bind_addr, fs).await {
                    Ok(listener) => {
                        info!("NFS server listening on {}", bind_addr);
                        // Signal that server is ready
                        let _ = tx.send(Ok(()));
                        if let Err(e) = listener.handle_forever().await {
                            error!("NFS server error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to bind NFS server: {}", e);
                        // Signal the error
                        let _ = tx.send(Err(e.to_string()));
                    }
                }
            })
        };

        // Wait for server to start or fail (with timeout)
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                debug!("NFS server successfully started on port {}", port);
            }
            Ok(Err(e)) => {
                return Err(MountError::Mount(std::io::Error::other(format!(
                    "NFS server failed to bind: {e}"
                ))));
            }
            Err(_) => {
                return Err(MountError::Mount(std::io::Error::other(
                    "NFS server failed to start within timeout",
                )));
            }
        }

        // Run mount command
        Self::run_mount_command(port, mountpoint)?;

        // Wait for mount to become ready
        self.wait_for_mount(mountpoint)?;

        info!(
            mountpoint = ?mountpoint,
            port,
            "NFS mount successful"
        );

        Ok(Box::new(NfsMountHandle {
            server_handle: Some(server_handle),
            runtime,
            mountpoint: mountpoint.to_path_buf(),
            port,
            unmounted: AtomicBool::new(false),
            stats,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_info() {
        let backend = NfsBackend::new();
        assert_eq!(backend.name(), "NFS");
        assert_eq!(backend.id(), "nfs");
    }

    #[test]
    fn test_backend_with_port() {
        let backend = NfsBackend::with_port(12345);
        assert_eq!(backend.port, Some(12345));
    }

    #[test]
    fn test_find_available_port() {
        let backend = NfsBackend::new();
        match backend.find_available_port() {
            Ok(port) => assert!(port > 0),
            Err(MountError::Mount(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                // Some environments restrict binding sockets; treat as a skip.
            }
            Err(err) => panic!("Failed to find available port: {err}"),
        }
    }

    #[test]
    fn test_find_specific_port() {
        let backend = NfsBackend::with_port(54321);
        let port = backend.find_available_port().unwrap();
        assert_eq!(port, 54321);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn test_is_available() {
        let backend = NfsBackend::new();
        // On macOS, should always be available
        // On Linux, depends on mount.nfs being installed
        #[cfg(target_os = "macos")]
        assert!(backend.is_available());
    }
}
