//! Test harness for NFS integration tests.
//!
//! Provides a `TestMount` that manages the lifecycle of an NFS-mounted vault,
//! along with filesystem operation convenience methods.
//!
//! Note: Mounting via NFS requires appropriate permissions:
//! - macOS: May need `sudo` for `mount_nfs`
//! - Linux: May need root or appropriate fstab/autofs configuration

use nfsserve::tcp::NFSTcp;
use oxcrypt_core::vault::VaultCreator;
use oxcrypt_mount::{cleanup_test_mounts, force_unmount};
use oxcrypt_nfs::CryptomatorNFS;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::io::IsTerminal;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};
use std::time::Duration;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// Ensure stale test mounts are cleaned up before running tests.
/// This runs at most once per test process.
static CLEANUP_ONCE: Once = Once::new();

/// Clean up any stale test mounts from previous test runs.
///
/// This function is called automatically before creating new mounts,
/// and runs at most once per test process. It cleans up mounts with
/// `cryptomator-test` or `cryptomator:test` in their fsname.
fn cleanup_stale_test_mounts() {
    CLEANUP_ONCE.call_once(|| {
        match cleanup_test_mounts() {
            Ok(results) => {
                for result in results {
                    if result.success
                        && let oxcrypt_mount::CleanupAction::Unmounted = result.action {
                            eprintln!(
                                "[nfs-test-harness] Cleaned stale test mount: {}",
                                result.mountpoint.display()
                            );
                        }
                }
            }
            Err(e) => {
                eprintln!(
                    "[nfs-test-harness] Warning: Failed to clean stale mounts: {e}"
                );
            }
        }
    });
}

/// Test password for temporary vaults.
pub const TEST_PASSWORD: &str = "test-password-12345";

/// How long to wait for mount to become ready.
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Test mount with automatic cleanup.
pub struct TestMount {
    /// Tokio runtime for async operations.
    runtime: Arc<Runtime>,
    /// Server task handle.
    server_handle: Option<JoinHandle<()>>,
    /// Port the NFS server is running on.
    port: u16,
    /// Mount point directory.
    mount_point: PathBuf,
    /// Whether we successfully mounted (for cleanup).
    mounted: bool,
    /// Temporary vault directory (cleaned up on drop).
    _temp_vault: Option<TempDir>,
    /// Temporary mount point directory (cleaned up on drop).
    _temp_mount: Option<TempDir>,
}

impl TestMount {
    /// Start a mount with a fresh temporary vault.
    ///
    /// Creates a new empty vault that gets cleaned up when the mount is dropped.
    pub fn with_temp_vault() -> io::Result<Self> {
        let temp_vault = TempDir::new()?;
        let vault_path = temp_vault.path().join("vault");

        // Create the vault
        let _vault_ops = VaultCreator::new(&vault_path, TEST_PASSWORD)
            .create()
            .map_err(|e| io::Error::other(format!("Failed to create vault: {e}")))?;

        Self::mount_vault(&vault_path, TEST_PASSWORD, Some(temp_vault))
    }

    /// Start a mount with the shared test_vault.
    ///
    /// Uses the repository's test_vault directory. Good for read-only tests.
    pub fn with_test_vault() -> io::Result<Self> {
        let test_vault_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_vault");

        if !test_vault_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("test_vault not found at {test_vault_path:?}"),
            ));
        }

        // The test vault password
        Self::mount_vault(&test_vault_path, "test", None)
    }

    /// Mount a vault at the given path.
    fn mount_vault(vault_path: &Path, password: &str, temp_vault: Option<TempDir>) -> io::Result<Self> {
        // Clean up any stale test mounts from previous runs
        cleanup_stale_test_mounts();

        // Create runtime
        let runtime = Arc::new(Runtime::new()?);

        // Open vault for NFS
        let ops = Arc::new(
            oxcrypt_core::vault::operations_async::VaultOperationsAsync::open(vault_path, password)
                .map_err(|e| io::Error::other(format!("Failed to open vault: {e}")))?,
        );

        // Create NFS filesystem
        let fs = CryptomatorNFS::new(ops);

        // Find available port
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.local_addr()?.port()
        };

        // Create mount point
        let temp_mount = TempDir::new()?;
        let mount_point = temp_mount.path().to_path_buf();

        // Start NFS server
        let bind_addr = format!("127.0.0.1:{port}");
        let server_handle = {
            let _guard = runtime.enter();
            runtime.spawn(async move {
                match nfsserve::tcp::NFSTcpListener::bind(&bind_addr, fs).await {
                    Ok(listener) => {
                        let _ = listener.handle_forever().await;
                    }
                    Err(e) => {
                        eprintln!("NFS server error: {e}");
                    }
                }
            })
        };

        // Give server time to start
        std::thread::sleep(Duration::from_millis(200));

        // Try to mount
        let mounted = match Self::run_mount_command(port, &mount_point) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("[nfs-test-harness] Warning: mount failed: {e}");
                false
            }
        };

        if mounted {
            // Wait for mount to be ready
            Self::wait_for_mount(&mount_point)?;
        }

        Ok(Self {
            runtime,
            server_handle: Some(server_handle),
            port,
            mount_point,
            mounted,
            _temp_vault: temp_vault,
            _temp_mount: Some(temp_mount),
        })
    }

    /// Run the mount command (platform-specific).
    #[cfg(target_os = "macos")]
    fn run_mount_command(port: u16, mountpoint: &Path) -> io::Result<()> {
        let port_str = port.to_string();
        let options = format!(
            "nolocks,vers=3,tcp,rsize=131072,actimeo=120,port={port_str},mountport={port_str}"
        );

        let output = Command::new("mount_nfs")
            .args(["-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let direct_err = String::from_utf8_lossy(&output.stderr).to_string();
        let wants_sudo = std::env::var_os("OXCRYPT_NFS_SUDO").is_some();
        if wants_sudo {
            let sudo_output = Command::new("sudo")
                .args(["-n", "mount_nfs", "-o", &options, "localhost:/"])
                .arg(mountpoint)
                .output()?;
            if sudo_output.status.success() {
                return Ok(());
            }

            if io::stdin().is_terminal() && io::stdout().is_terminal() {
                let status = Command::new("sudo")
                    .args(["mount_nfs", "-o", &options, "localhost:/"])
                    .arg(mountpoint)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()?;
                if status.success() {
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "mount_nfs failed (direct: {direct_err}; sudo: exit {status})"
                )));
            }

            return Err(io::Error::other(format!(
                "mount_nfs failed (direct: {direct_err}; sudo: non-interactive denied; run `sudo -v` before tests)"
            )));
        }

        let sudo_output = Command::new("sudo")
            .args(["-n", "mount_nfs", "-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()?;

        if sudo_output.status.success() {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "mount_nfs failed (direct: {}; sudo: {})",
            direct_err,
            String::from_utf8_lossy(&sudo_output.stderr)
        )))
    }

    #[cfg(target_os = "linux")]
    fn run_mount_command(port: u16, mountpoint: &Path) -> io::Result<()> {
        let port_str = port.to_string();
        let options = format!(
            "user,noacl,nolock,vers=3,tcp,wsize=1048576,rsize=131072,actimeo=120,port={},mountport={}",
            port_str, port_str
        );

        let output = Command::new("mount.nfs")
            .args(["-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let direct_err = String::from_utf8_lossy(&output.stderr).to_string();
        let wants_sudo = std::env::var_os("OXCRYPT_NFS_SUDO").is_some();
        if wants_sudo {
            let sudo_output = Command::new("sudo")
                .args(["-n", "mount.nfs", "-o", &options, "localhost:/"])
                .arg(mountpoint)
                .output()?;
            if sudo_output.status.success() {
                return Ok(());
            }

            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                let status = Command::new("sudo")
                    .args(["mount.nfs", "-o", &options, "localhost:/"])
                    .arg(mountpoint)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()?;
                if status.success() {
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "mount.nfs failed (direct: {}; sudo: exit {})",
                    direct_err, status
                )));
            }

            return Err(io::Error::other(format!(
                "mount.nfs failed (direct: {}; sudo: non-interactive denied; run `sudo -v` before tests)",
                direct_err
            )));
        }

        let sudo_output = Command::new("sudo")
            .args(["-n", "mount.nfs", "-o", &options, "localhost:/"])
            .arg(mountpoint)
            .output()?;

        if sudo_output.status.success() {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "mount.nfs failed (direct: {}; sudo: {})",
            direct_err,
            String::from_utf8_lossy(&sudo_output.stderr)
        )))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn run_mount_command(_port: u16, _mountpoint: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NFS mount not supported on this platform",
        ))
    }

    /// Wait for mount to become ready.
    fn wait_for_mount(mountpoint: &Path) -> io::Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < MOUNT_READY_TIMEOUT {
            if fs::read_dir(mountpoint).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Mount did not become ready in time",
        ))
    }

    /// Run unmount command.
    #[cfg(target_os = "macos")]
    fn run_unmount(&self) -> io::Result<()> {
        // Try diskutil first
        let output = Command::new("diskutil")
            .args(["unmount", "force"])
            .arg(&self.mount_point)
            .output();

        match output {
            Ok(out) if out.status.success() => Ok(()),
            _ => {
                // Fallback to umount
                let output = Command::new("umount").arg(&self.mount_point).output()?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "umount failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn run_unmount(&self) -> io::Result<()> {
        let output = Command::new("umount")
            .args(["-l"])
            .arg(&self.mount_point)
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "umount failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn run_unmount(&self) -> io::Result<()> {
        Ok(()) // No-op on unsupported platforms
    }

    /// Check if we're actually mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Get the mount point path.
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Get the NFS server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    // ========== Filesystem Operations ==========

    /// Build full path from relative path.
    fn full_path(&self, path: &str) -> PathBuf {
        let path = path.trim_start_matches('/');
        self.mount_point.join(path)
    }

    /// Read a file's contents.
    pub fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(self.full_path(path))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(contents)
    }

    /// Write contents to a file.
    pub fn write(&self, path: &str, contents: &[u8]) -> io::Result<()> {
        let mut file = File::create(self.full_path(path))?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    }

    /// Delete a file.
    pub fn delete(&self, path: &str) -> io::Result<()> {
        fs::remove_file(self.full_path(path))
    }

    /// Create a directory.
    pub fn mkdir(&self, path: &str) -> io::Result<()> {
        fs::create_dir(self.full_path(path))
    }

    /// Create directories recursively.
    pub fn mkdir_all(&self, path: &str) -> io::Result<()> {
        fs::create_dir_all(self.full_path(path))
    }

    /// Remove an empty directory.
    pub fn rmdir(&self, path: &str) -> io::Result<()> {
        fs::remove_dir(self.full_path(path))
    }

    /// Remove a directory and all its contents.
    pub fn rmdir_all(&self, path: &str) -> io::Result<()> {
        fs::remove_dir_all(self.full_path(path))
    }

    /// List directory contents.
    pub fn list_dir(&self, path: &str) -> io::Result<Vec<String>> {
        let entries = fs::read_dir(self.full_path(path))?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        Ok(entries)
    }

    /// Get file/directory metadata.
    pub fn metadata(&self, path: &str) -> io::Result<Metadata> {
        fs::metadata(self.full_path(path))
    }

    /// Rename/move a file or directory.
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.full_path(from), self.full_path(to))
    }

    /// Copy a file.
    ///
    /// We explicitly read and write to avoid NFS caching issues with fs::copy.
    pub fn copy(&self, from: &str, to: &str) -> io::Result<u64> {
        let content = self.read(from)?;
        self.write(to, &content)?;
        Ok(content.len() as u64)
    }

    /// Check if a path exists.
    pub fn exists(&self, path: &str) -> bool {
        self.full_path(path).exists()
    }
}

impl Drop for TestMount {
    fn drop(&mut self) {
        // Abort server task first to stop accepting new requests
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }

        // Unmount if mounted, using force_unmount from mount-common
        if self.mounted {
            // Try graceful unmount first
            if self.run_unmount().is_err() {
                // Fall back to force_unmount from mount-common
                if let Err(e) = force_unmount(&self.mount_point) {
                    eprintln!(
                        "[nfs-test-harness] Warning: Failed to unmount {}: {}",
                        self.mount_point.display(),
                        e
                    );
                }
            }
        }
    }
}
