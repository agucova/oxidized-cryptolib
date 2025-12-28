//! Temporary vault creation for integration tests.
//!
//! Provides utilities for creating fresh Cryptomator vaults that are
//! automatically cleaned up when dropped.

use std::path::{Path, PathBuf};
use tempfile::TempDir;

use oxidized_cryptolib::vault::VaultCreator;

/// Test password used for temporary vaults.
pub const TEST_PASSWORD: &str = "test-password-12345";

/// Password for the shared test_vault in the repository.
pub const SHARED_VAULT_PASSWORD: &str = "123456789";

/// A temporary Cryptomator vault that is cleaned up on drop.
///
/// Use this for write tests that need a fresh, isolated vault.
pub struct TempVault {
    /// Path to the vault directory.
    pub path: PathBuf,
    /// Temp directory that holds the vault (cleaned up on drop).
    _temp_dir: TempDir,
}

impl TempVault {
    /// Create a new empty temporary vault.
    ///
    /// The vault is created in a temporary directory and will be
    /// automatically deleted when this struct is dropped.
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        VaultCreator::new(&vault_path, TEST_PASSWORD)
            .create()
            .expect("Failed to create test vault");

        Self {
            path: vault_path,
            _temp_dir: temp_dir,
        }
    }

    /// Create a new temporary vault with a custom password.
    pub fn with_password(password: &str) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        VaultCreator::new(&vault_path, password)
            .create()
            .expect("Failed to create test vault");

        Self {
            path: vault_path,
            _temp_dir: temp_dir,
        }
    }

    /// Get the password for this vault.
    pub fn password() -> &'static str {
        TEST_PASSWORD
    }

    /// Get the path to the vault directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for TempVault {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the path to the shared test_vault in the repository.
///
/// This vault is read-only and shared across tests. Use for read
/// operations or when you don't need to modify the vault.
///
/// Returns `None` if the test_vault cannot be found.
pub fn shared_vault_path() -> Option<PathBuf> {
    // Try to find test_vault relative to common locations
    let candidates = [
        // From within a crate's tests directory
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("test_vault")),
        // Direct path from workspace root
        Some(PathBuf::from("test_vault")),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.exists() && candidate.join("vault.cryptomator").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_vault_creation() {
        let vault = TempVault::new();
        assert!(vault.path.exists());
        assert!(vault.path.join("vault.cryptomator").exists());
        // VaultCreator puts masterkey in a subdirectory
        assert!(vault.path.join("masterkey/masterkey.cryptomator").exists());
    }

    #[test]
    fn test_temp_vault_cleanup() {
        let path = {
            let vault = TempVault::new();
            vault.path.clone()
        };
        // After drop, the vault should be cleaned up
        assert!(!path.exists());
    }

    #[test]
    fn test_shared_vault_path() {
        // This test may fail if run from a non-standard location
        if let Some(path) = shared_vault_path() {
            assert!(path.exists());
            assert!(path.join("vault.cryptomator").exists());
        }
    }
}
