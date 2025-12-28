//! Test mount harness for FUSE integration tests.
//!
//! Provides `TestMount` that manages the lifecycle of a mounted Cryptomator
//! vault, including setup, teardown, and convenience methods for filesystem
//! operations.

// Not all tests use all TestMount methods
#![allow(dead_code)]

use fuser::{BackgroundSession, MountOption};
use oxidized_fuse::filesystem::CryptomatorFS;
use oxidized_mount_common::testing::{
    shared_vault_path, TempVault, SHARED_VAULT_PASSWORD, TEST_PASSWORD,
};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// How long to wait for mount to become ready.
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait between mount readiness checks.
const MOUNT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// A mounted Cryptomator vault for testing.
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
///     let mount = TestMount::with_temp_vault().unwrap();
///     mount.write("test.txt", b"hello").unwrap();
///     let content = mount.read("test.txt").unwrap();
///     assert_eq!(content, b"hello");
/// }
/// ```
pub struct TestMount {
    /// The FUSE session (unmounts on drop).
    _session: BackgroundSession,
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
        let temp_vault = TempVault::new();
        let temp_mount = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let mount_path = temp_mount.path().join("mnt");
        fs::create_dir(&mount_path).map_err(|e| format!("Failed to create mount point: {}", e))?;

        let fs = CryptomatorFS::new(temp_vault.path(), TEST_PASSWORD)
            .map_err(|e| format!("Failed to create CryptomatorFS: {}", e))?;

        let options = vec![
            MountOption::FSName("cryptomator-test".to_string()),
            MountOption::AutoUnmount,
        ];

        let session = fuser::spawn_mount2(fs, &mount_path, &options)
            .map_err(|e| format!("Failed to mount: {}", e))?;

        // Wait for mount to become ready
        Self::wait_for_mount(&mount_path)?;

        Ok(Self {
            _session: session,
            mount_path,
            _temp_vault: Some(temp_vault),
            _temp_mount: temp_mount,
        })
    }

    /// Mount the shared test_vault (read-only).
    ///
    /// Uses the repository's test_vault directory. Good for read-only tests
    /// that don't modify files.
    pub fn with_test_vault() -> Result<Self, String> {
        Self::with_test_vault_inner(true)
    }

    /// Mount the shared test_vault with read-write access.
    ///
    /// **Warning**: Modifications will persist in the test_vault directory.
    /// Use `with_temp_vault()` for write tests unless you specifically need
    /// to test against existing vault content.
    pub fn with_test_vault_rw() -> Result<Self, String> {
        Self::with_test_vault_inner(false)
    }

    fn with_test_vault_inner(read_only: bool) -> Result<Self, String> {
        let vault_path = shared_vault_path()
            .ok_or_else(|| "test_vault not found in repository".to_string())?;

        let temp_mount = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let mount_path = temp_mount.path().join("mnt");
        fs::create_dir(&mount_path).map_err(|e| format!("Failed to create mount point: {}", e))?;

        let fs = CryptomatorFS::new(&vault_path, SHARED_VAULT_PASSWORD)
            .map_err(|e| format!("Failed to create CryptomatorFS: {}", e))?;

        let mut options = vec![
            MountOption::FSName("cryptomator-test".to_string()),
            MountOption::AutoUnmount,
        ];
        if read_only {
            options.push(MountOption::RO);
        }

        let session = fuser::spawn_mount2(fs, &mount_path, &options)
            .map_err(|e| format!("Failed to mount: {}", e))?;

        // Wait for mount to become ready by checking for known vault content
        Self::wait_for_test_vault_content(&mount_path)?;

        Ok(Self {
            _session: session,
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
}

/// Check if FUSE is available on this system.
pub fn fuse_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/fuse").exists()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Filesystems/macfuse.fs").exists()
            || Path::new("/Library/Filesystems/osxfuse.fs").exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Skip test if FUSE is not available.
#[macro_export]
macro_rules! skip_if_no_fuse {
    () => {
        if !$crate::common::harness::fuse_available() {
            eprintln!("Skipping test: FUSE not available on this system");
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
