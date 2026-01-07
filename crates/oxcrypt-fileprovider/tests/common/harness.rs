//! Test harness for File Provider integration tests.
//!
//! Provides utilities for mounting temporary vaults via File Provider
//! and running tests against them.

use oxcrypt_core::vault::VaultCreator;
use oxcrypt_fileprovider::FileProviderBackend;
use oxcrypt_mount::MountBackend;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;

/// Global counter for unique test names
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Check if File Provider backend is available.
///
/// Returns false if:
/// - Not running on macOS
/// - File Provider extension is not enabled
/// - Feature flag not enabled
///
/// Note: Even if this returns true, the actual mount may still fail if
/// the test vault location is not accessible to the sandboxed host app.
/// Integration tests should handle mount failures gracefully.
pub fn fileprovider_available() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
    #[cfg(target_os = "macos")]
    {
        let backend = FileProviderBackend::new();
        backend.is_available()
    }
}

/// Check if an error message indicates a bookmark/sandbox permission issue.
/// These errors occur when the sandboxed host app can't access the vault path.
pub fn is_bookmark_error(error: &str) -> bool {
    error.contains("BookmarkError")
        || error.contains("security-scoped")
        || error.contains("accessDenied")
        || error.contains("sandbox")
}

/// Skip test macro - prints message and returns early if File Provider unavailable.
#[macro_export]
macro_rules! skip_if_no_fileprovider {
    () => {
        if !$crate::common::harness::fileprovider_available() {
            eprintln!(
                "Skipping: File Provider not available (extension not enabled or not macOS)"
            );
            return;
        }
    };
}

/// Create a test mount or skip if sandbox permissions prevent it.
/// Use this macro instead of `.expect()` to handle bookmark errors gracefully.
#[macro_export]
macro_rules! test_mount_or_skip {
    ($test_name:expr) => {
        match $crate::common::harness::TestMount::with_temp_vault($test_name) {
            Ok(mount) => mount,
            Err(e) if $crate::common::harness::is_bookmark_error(&e) => {
                eprintln!(
                    "Skipping: File Provider sandbox cannot access test vault directory. \
                     Tests require vault to be in an accessible location (e.g., ~/Documents). \
                     Error: {e}"
                );
                return;
            }
            Err(e) => panic!("Failed to create mount: {e}"),
        }
    };
}

/// A temporary Cryptomator vault for testing.
pub struct TempVault {
    /// Directory containing the vault
    _temp_dir: TempDir,
    /// Path to the vault root
    pub vault_path: PathBuf,
    /// Vault password
    pub password: String,
}

impl TempVault {
    /// Create a new temporary vault with the given test name.
    ///
    /// Uses OXCRYPT_FAST_KDF=1 for faster key derivation in tests.
    pub fn new(test_name: &str) -> Result<Self, String> {
        // Set fast KDF for tests
        // SAFETY: We're in single-threaded test initialization, no concurrent access to env vars
        unsafe { std::env::set_var("OXCRYPT_FAST_KDF", "1") };

        let temp_dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {e}"))?;
        let vault_path = temp_dir.path().join(format!("vault_{test_name}"));

        let password = "test-password-123".to_string();

        // Create vault using VaultCreator
        let _vault_ops = VaultCreator::new(&vault_path, &password)
            .create()
            .map_err(|e| format!("Failed to create vault: {e}"))?;

        Ok(Self {
            _temp_dir: temp_dir,
            vault_path,
            password,
        })
    }
}

/// A mounted File Provider test environment.
pub struct TestMount {
    /// The mount handle (unmounts on drop)
    handle: Box<dyn oxcrypt_mount::MountHandle>,
    /// Path to the mounted filesystem
    pub mount_path: PathBuf,
    /// The temporary vault (cleaned up on drop)
    _temp_vault: TempVault,
    /// Test name for debugging
    #[allow(dead_code)]
    test_name: String,
}

impl TestMount {
    /// Create a new test mount with a fresh temporary vault.
    ///
    /// Returns Err if File Provider is not available or mounting fails.
    pub fn with_temp_vault(test_name: &str) -> Result<Self, String> {
        // Generate unique name to avoid domain conflicts
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let unique_name = format!("{test_name}_{counter}");

        // Create temporary vault
        let temp_vault = TempVault::new(&unique_name)?;

        // Create backend and check availability
        let backend = FileProviderBackend::new();
        if !backend.is_available() {
            return Err(backend.unavailable_reason().unwrap_or_else(|| {
                "File Provider extension not available".to_string()
            }));
        }

        // Mount the vault
        // Note: File Provider ignores mountpoint and uses ~/Library/CloudStorage/
        let dummy_mountpoint = PathBuf::from("/tmp/fp_test_mount");
        let handle = backend
            .mount(
                &unique_name,
                &temp_vault.vault_path,
                &temp_vault.password,
                &dummy_mountpoint,
            )
            .map_err(|e| format!("Failed to mount: {e}"))?;

        let mount_path = handle.mountpoint().to_path_buf();

        // Wait for mount to be ready
        Self::wait_for_mount(&mount_path)?;

        Ok(Self {
            handle,
            mount_path,
            _temp_vault: temp_vault,
            test_name: unique_name,
        })
    }

    /// Wait for the mount point to become accessible.
    fn wait_for_mount(path: &Path) -> Result<(), String> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);

        while start.elapsed() < timeout {
            if path.exists() && fs::read_dir(path).is_ok() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Err(format!(
            "Timed out waiting for mount at {}",
            path.display()
        ))
    }

    /// Get the mount point path.
    pub fn path(&self) -> &Path {
        &self.mount_path
    }

    /// Write a file with the given content.
    pub fn write_file(&self, name: &str, content: &[u8]) -> Result<(), String> {
        let path = self.mount_path.join(name);
        fs::write(&path, content).map_err(|e| format!("Failed to write {name}: {e}"))
    }

    /// Read a file's content.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, String> {
        let path = self.mount_path.join(name);
        fs::read(&path).map_err(|e| format!("Failed to read {name}: {e}"))
    }

    /// Create a directory.
    pub fn mkdir(&self, name: &str) -> Result<(), String> {
        let path = self.mount_path.join(name);
        fs::create_dir(&path).map_err(|e| format!("Failed to mkdir {name}: {e}"))
    }

    /// Create nested directories.
    pub fn mkdir_all(&self, name: &str) -> Result<(), String> {
        let path = self.mount_path.join(name);
        fs::create_dir_all(&path).map_err(|e| format!("Failed to mkdir_all {name}: {e}"))
    }

    /// Remove a file.
    pub fn remove_file(&self, name: &str) -> Result<(), String> {
        let path = self.mount_path.join(name);
        fs::remove_file(&path).map_err(|e| format!("Failed to remove {name}: {e}"))
    }

    /// Remove a directory.
    pub fn remove_dir(&self, name: &str) -> Result<(), String> {
        let path = self.mount_path.join(name);
        fs::remove_dir(&path).map_err(|e| format!("Failed to rmdir {name}: {e}"))
    }

    /// List directory contents.
    pub fn list_dir(&self, name: &str) -> Result<Vec<String>, String> {
        let path = if name.is_empty() {
            self.mount_path.clone()
        } else {
            self.mount_path.join(name)
        };

        let entries = fs::read_dir(&path).map_err(|e| format!("Failed to list {name}: {e}"))?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Check if a path exists.
    pub fn exists(&self, name: &str) -> bool {
        self.mount_path.join(name).exists()
    }

    /// Get file metadata.
    pub fn metadata(&self, name: &str) -> Result<fs::Metadata, String> {
        let path = self.mount_path.join(name);
        fs::metadata(&path).map_err(|e| format!("Failed to get metadata for {name}: {e}"))
    }

    /// Rename/move a file or directory.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let from_path = self.mount_path.join(from);
        let to_path = self.mount_path.join(to);
        fs::rename(&from_path, &to_path)
            .map_err(|e| format!("Failed to rename {from} to {to}: {e}"))
    }

    /// Copy a file.
    pub fn copy_file(&self, from: &str, to: &str) -> Result<u64, String> {
        let from_path = self.mount_path.join(from);
        let to_path = self.mount_path.join(to);
        fs::copy(&from_path, &to_path).map_err(|e| format!("Failed to copy {from} to {to}: {e}"))
    }
}

impl Drop for TestMount {
    fn drop(&mut self) {
        // Handle will unmount on drop
        // Give a moment for cleanup
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Generate random bytes for testing.
pub fn random_bytes(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random::<u8>()).collect()
}

/// Generate a test file with specific size.
pub fn generate_test_data(size: usize) -> Vec<u8> {
    // Use a pattern that's easy to verify
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}
