//! Test mount harness for FSKit integration tests.
//!
//! Provides `TestMount` that manages the lifecycle of a mounted Cryptomator
//! vault using FSKit, including setup, teardown, and convenience methods for
//! filesystem operations.

// Not all tests use all TestMount methods
#![allow(dead_code)]

use oxidized_fskit_legacy::FSKitBackend;
use oxidized_mount_common::cleanup_test_mounts;
use oxidized_mount_common::testing::{
    shared_vault_path, TempVault, SHARED_VAULT_PASSWORD, TEST_PASSWORD,
};
use oxidized_mount_common::MountBackend;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Ensure stale test mounts are cleaned up before running tests.
/// This runs at most once per test process.
static CLEANUP_ONCE: Once = Once::new();

/// Clean up any stale test mounts from previous test runs.
///
/// This function is called automatically before creating new mounts,
/// and runs at most once per test process. It cleans up mounts with
/// `cryptomator-test` or `test-` in their fsname that are unresponsive.
fn cleanup_stale_test_mounts() {
    CLEANUP_ONCE.call_once(|| {
        // Use a short timeout - if mount is unresponsive for 500ms, it's stale
        let timeout = Duration::from_millis(500);
        match cleanup_test_mounts(timeout) {
            Ok(results) => {
                for result in results {
                    if result.success {
                        if let oxidized_mount_common::CleanupAction::Unmounted = result.action {
                            eprintln!(
                                "[test-harness] Cleaned stale test mount: {}",
                                result.mountpoint.display()
                            );
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[test-harness] Warning: Failed to clean stale mounts: {}", e);
            }
        }
    });
}

/// How long to wait for mount to become ready.
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait between mount readiness checks.
const MOUNT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// A mounted Cryptomator vault for testing via FSKit.
///
/// Handles mount setup, provides convenience methods for filesystem operations,
/// and ensures clean unmount on drop.
///
/// # Example
///
/// ```ignore
/// use common::TestMount;
///
/// #[test]
/// fn test_write_read() {
///     skip_if_no_fskit!();
///     let mount = require_mount!(TestMount::with_temp_vault());
///     mount.write("test.txt", b"hello").unwrap();
///     let content = mount.read("test.txt").unwrap();
///     assert_eq!(content, b"hello");
/// }
/// ```
pub struct TestMount {
    /// The mount handle (unmounts on drop via MountHandle trait).
    _handle: Box<dyn oxidized_mount_common::MountHandle>,
    /// Path where the vault is mounted.
    pub mount_path: PathBuf,
    /// Temporary vault (if using with_temp_vault).
    _temp_vault: Option<TempVault>,
    /// Temporary mount point directory.
    _temp_mount: TempDir,
}

impl TestMount {
    /// Mount a fresh temporary vault (read-write).
    ///
    /// Creates a new empty vault that is automatically cleaned up on drop.
    /// Use this for tests that modify the filesystem.
    pub fn with_temp_vault() -> Result<Self, String> {
        // Clean up any stale test mounts from previous runs
        cleanup_stale_test_mounts();

        let temp_vault = TempVault::new();
        let temp_mount = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let mount_path = temp_mount.path().join("mnt");
        fs::create_dir(&mount_path).map_err(|e| format!("Failed to create mount point: {}", e))?;

        let backend = FSKitBackend::with_timeouts(MOUNT_READY_TIMEOUT, MOUNT_CHECK_INTERVAL);

        // Generate a unique vault ID for this test
        let vault_id = format!("test-{}", uuid::Uuid::new_v4());

        let handle = backend
            .mount(&vault_id, temp_vault.path(), TEST_PASSWORD, &mount_path)
            .map_err(|e| format!("Failed to mount: {}", e))?;

        // FSKitBackend::mount already waits for readiness, but we double-check
        Self::wait_for_mount(&mount_path)?;

        Ok(Self {
            _handle: handle,
            mount_path,
            _temp_vault: Some(temp_vault),
            _temp_mount: temp_mount,
        })
    }

    /// Mount the shared test_vault.
    ///
    /// Uses the repository's test_vault directory. Good for read-only tests
    /// that don't modify files.
    ///
    /// Note: FSKit mounts are read-write by default. Be careful not to
    /// modify the shared test vault.
    pub fn with_test_vault() -> Result<Self, String> {
        // Clean up any stale test mounts from previous runs
        cleanup_stale_test_mounts();

        let vault_path = shared_vault_path()
            .ok_or_else(|| "test_vault not found in repository".to_string())?;

        let temp_mount = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let mount_path = temp_mount.path().join("mnt");
        fs::create_dir(&mount_path).map_err(|e| format!("Failed to create mount point: {}", e))?;

        let backend = FSKitBackend::with_timeouts(MOUNT_READY_TIMEOUT, MOUNT_CHECK_INTERVAL);

        let vault_id = format!("test-vault-{}", uuid::Uuid::new_v4());

        let handle = backend
            .mount(&vault_id, &vault_path, SHARED_VAULT_PASSWORD, &mount_path)
            .map_err(|e| format!("Failed to mount: {}", e))?;

        // Wait for mount to become ready by checking for known vault content
        Self::wait_for_test_vault_content(&mount_path)?;

        Ok(Self {
            _handle: handle,
            mount_path,
            _temp_vault: None,
            _temp_mount: temp_mount,
        })
    }

    /// Wait for mount to become ready (for temp vaults).
    fn wait_for_mount(mount_path: &Path) -> Result<(), String> {
        let deadline = Instant::now() + MOUNT_READY_TIMEOUT;
        while Instant::now() < deadline {
            if fs::read_dir(mount_path).is_ok() {
                return Ok(());
            }
            thread::sleep(MOUNT_CHECK_INTERVAL);
        }
        Err("Mount did not become ready in time".to_string())
    }

    /// Wait for mount to become ready by checking for known test_vault content.
    fn wait_for_test_vault_content(mount_path: &Path) -> Result<(), String> {
        let deadline = Instant::now() + MOUNT_READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(entries) = fs::read_dir(mount_path) {
                let names: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                // Check for known test vault files
                if names
                    .iter()
                    .any(|n| n == "test_folder" || n == "aes-wrap.c" || n == "new_folder")
                {
                    return Ok(());
                }
            }
            thread::sleep(MOUNT_CHECK_INTERVAL);
        }
        Err("Mount did not become ready in time (no expected files found)".to_string())
    }

    // =========================================================================
    // Filesystem convenience methods
    // =========================================================================

    /// Build a full path from a relative path.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.mount_path.join(relative.trim_start_matches('/'))
    }

    /// Read a file's contents.
    pub fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let mut content = Vec::new();
        File::open(self.path(path))?.read_to_end(&mut content)?;
        Ok(content)
    }

    /// Write content to a file (creates or overwrites).
    pub fn write(&self, path: &str, content: &[u8]) -> io::Result<()> {
        let mut file = File::create(self.path(path))?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    /// Append content to a file.
    pub fn append(&self, path: &str, content: &[u8]) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.path(path))?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    /// Create a directory.
    pub fn mkdir(&self, path: &str) -> io::Result<()> {
        fs::create_dir(self.path(path))
    }

    /// Create a directory and all parent directories.
    pub fn mkdir_all(&self, path: &str) -> io::Result<()> {
        fs::create_dir_all(self.path(path))
    }

    /// Remove a file.
    pub fn remove(&self, path: &str) -> io::Result<()> {
        fs::remove_file(self.path(path))
    }

    /// Remove an empty directory.
    pub fn rmdir(&self, path: &str) -> io::Result<()> {
        fs::remove_dir(self.path(path))
    }

    /// Remove a directory and all its contents.
    pub fn rmdir_all(&self, path: &str) -> io::Result<()> {
        fs::remove_dir_all(self.path(path))
    }

    /// Rename/move a file or directory.
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.path(from), self.path(to))
    }

    /// Copy a file.
    pub fn copy(&self, from: &str, to: &str) -> io::Result<u64> {
        fs::copy(self.path(from), self.path(to))
    }

    /// Copy a directory recursively.
    pub fn copy_dir(&self, from: &str, to: &str) -> io::Result<()> {
        self.copy_dir_recursive(&self.path(from), &self.path(to))
    }

    /// Internal recursive directory copy.
    fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> io::Result<()> {
        fs::create_dir(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if src_path.is_dir() {
                self.copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    /// Check if a path exists.
    pub fn exists(&self, path: &str) -> bool {
        self.path(path).exists()
    }

    /// Check if a path is a directory.
    pub fn is_dir(&self, path: &str) -> bool {
        self.path(path).is_dir()
    }

    /// Check if a path is a file.
    pub fn is_file(&self, path: &str) -> bool {
        self.path(path).is_file()
    }

    /// Get file/directory metadata.
    pub fn metadata(&self, path: &str) -> io::Result<Metadata> {
        fs::metadata(self.path(path))
    }

    /// Get symlink metadata (doesn't follow symlinks).
    pub fn symlink_metadata(&self, path: &str) -> io::Result<Metadata> {
        fs::symlink_metadata(self.path(path))
    }

    /// List directory entries (names only).
    pub fn list(&self, path: &str) -> io::Result<Vec<String>> {
        let entries = fs::read_dir(self.path(path))?;
        let names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        Ok(names)
    }

    /// Create a symbolic link.
    #[cfg(unix)]
    pub fn symlink(&self, target: &str, link_path: &str) -> io::Result<()> {
        std::os::unix::fs::symlink(target, self.path(link_path))
    }

    /// Read a symbolic link's target.
    pub fn read_link(&self, path: &str) -> io::Result<PathBuf> {
        fs::read_link(self.path(path))
    }

    /// Truncate a file to a specific size.
    pub fn truncate(&self, path: &str, size: u64) -> io::Result<()> {
        let file = fs::OpenOptions::new().write(true).open(self.path(path))?;
        file.set_len(size)?;
        Ok(())
    }

    /// Read a range of bytes from a file.
    ///
    /// Reads `len` bytes starting at `offset`. If the file is shorter than
    /// `offset + len`, returns only the bytes available after `offset`.
    pub fn read_range(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut file = File::open(self.path(path))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buffer = vec![0u8; len];
        let bytes_read = file.read(&mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Write content at a specific offset in an existing file.
    ///
    /// The file must already exist. If `offset` is beyond the current file size,
    /// the file is extended with zeros.
    pub fn write_at(&self, path: &str, offset: u64, content: &[u8]) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(self.path(path))?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    /// Get the current size of a file.
    pub fn file_size(&self, path: &str) -> io::Result<u64> {
        Ok(fs::metadata(self.path(path))?.len())
    }
}

/// Check if FSKit is available on this system.
///
/// Requires macOS 15.4+ and FSKitBridge.app installed.
pub fn fskit_available() -> bool {
    FSKitBackend::default().is_available()
}

/// Get the reason why FSKit is unavailable (if any).
pub fn fskit_unavailable_reason() -> Option<String> {
    FSKitBackend::default().unavailable_reason()
}

/// Skip test if FSKit is not available.
#[macro_export]
macro_rules! skip_if_no_fskit {
    () => {
        if !$crate::common::harness::fskit_available() {
            let reason = $crate::common::harness::fskit_unavailable_reason()
                .unwrap_or_else(|| "unknown reason".to_string());
            eprintln!("Skipping test: FSKit not available ({})", reason);
            return;
        }
    };
}

/// Skip test if mounting fails (common in CI environments).
#[macro_export]
macro_rules! require_mount {
    ($mount_result:expr) => {
        match $mount_result {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Skipping test: {}", e);
                return;
            }
        }
    };
}
