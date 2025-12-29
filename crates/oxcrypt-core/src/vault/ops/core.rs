//! Core vault state and operations shared between sync and async implementations.
//!
//! This module provides `VaultCore`, a struct containing the common state and
//! pure methods that both `VaultOperations` (sync) and `VaultOperationsAsync`
//! can delegate to.

use std::path::{Path, PathBuf};

use crate::crypto::keys::MasterKey;
use crate::fs::name::{
    create_c9s_filename, decrypt_filename, encrypt_filename, hash_dir_id, NameError,
};
use crate::fs::symlink::{decrypt_symlink_target, encrypt_symlink_target, SymlinkError};
use crate::vault::config::CipherCombo;
use crate::vault::path::DirId;

use super::helpers::{self, StoragePathError};

/// Default shortening threshold for filenames (220 characters).
///
/// Encrypted filenames longer than this threshold will use the `.c9s` format
/// with a SHA-1 hash instead of the full encrypted name.
pub const DEFAULT_SHORTENING_THRESHOLD: usize = 220;

/// Core vault state shared between sync and async implementations.
///
/// This struct holds the configuration and provides pure methods that don't
/// require I/O. Both `VaultOperations` and `VaultOperationsAsync` contain
/// a `VaultCore` and delegate appropriate operations to it.
///
/// # Design
///
/// The `VaultCore` deliberately does not store the `MasterKey`. Instead,
/// methods that need cryptographic operations take `&MasterKey` as a parameter.
/// This allows:
/// - Sync wrappers to own `MasterKey` directly
/// - Async wrappers to use `Arc<MasterKey>` for sharing across tasks
/// - Avoiding complex trait bounds for key access
#[derive(Debug, Clone)]
pub struct VaultCore {
    /// Path to the vault root directory.
    vault_path: PathBuf,
    /// The cipher combination used by this vault.
    cipher_combo: CipherCombo,
    /// Threshold for shortening encrypted filenames.
    shortening_threshold: usize,
}

impl VaultCore {
    /// Create a new `VaultCore` with the given configuration.
    pub fn new(vault_path: PathBuf, cipher_combo: CipherCombo) -> Self {
        Self {
            vault_path,
            cipher_combo,
            shortening_threshold: DEFAULT_SHORTENING_THRESHOLD,
        }
    }

    /// Create a new `VaultCore` with a custom shortening threshold.
    pub fn with_shortening_threshold(
        vault_path: PathBuf,
        cipher_combo: CipherCombo,
        shortening_threshold: usize,
    ) -> Self {
        Self {
            vault_path,
            cipher_combo,
            shortening_threshold,
        }
    }

    /// Get the vault root path.
    #[inline]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Get the cipher combination.
    #[inline]
    pub fn cipher_combo(&self) -> CipherCombo {
        self.cipher_combo
    }

    /// Get the shortening threshold.
    #[inline]
    pub fn shortening_threshold(&self) -> usize {
        self.shortening_threshold
    }

    // ========================================================================
    // Path Calculation Methods
    // ========================================================================

    /// Calculate the storage path for a directory given its ID.
    ///
    /// The path is constructed as: `vault_path/d/{first_two_chars}/{remaining_chars}`
    /// where the hash is derived from the directory ID using the master key.
    pub fn calculate_directory_storage_path(
        &self,
        dir_id: &DirId,
        master_key: &MasterKey,
    ) -> Result<PathBuf, StoragePathError> {
        helpers::calculate_directory_storage_path(&self.vault_path, dir_id, master_key)
    }

    /// Calculate the path for a regular encrypted file (`.c9r` format).
    pub fn calculate_file_path(
        &self,
        dir_id: &DirId,
        encrypted_name: &str,
        master_key: &MasterKey,
    ) -> Result<PathBuf, StoragePathError> {
        let dir_path = self.calculate_directory_storage_path(dir_id, master_key)?;
        Ok(dir_path.join(format!("{encrypted_name}.c9r")))
    }

    /// Calculate the path for a shortened encrypted file (`.c9s` format).
    pub fn calculate_shortened_file_path(
        &self,
        dir_id: &DirId,
        encrypted_name: &str,
        master_key: &MasterKey,
    ) -> Result<PathBuf, StoragePathError> {
        let dir_path = self.calculate_directory_storage_path(dir_id, master_key)?;
        let hash = create_c9s_filename(encrypted_name);
        Ok(dir_path.join(format!("{hash}.c9s")).join("contents.c9r"))
    }

    // ========================================================================
    // Filename Encryption/Decryption
    // ========================================================================

    /// Encrypt a filename for storage in the vault.
    ///
    /// The filename is encrypted using AES-SIV with the parent directory ID
    /// as associated data.
    pub fn encrypt_filename(
        &self,
        name: &str,
        dir_id: &DirId,
        master_key: &MasterKey,
    ) -> Result<String, NameError> {
        encrypt_filename(name, dir_id.as_str(), master_key)
    }

    /// Decrypt an encrypted filename.
    ///
    /// The filename is decrypted using AES-SIV with the parent directory ID
    /// as associated data.
    pub fn decrypt_filename(
        &self,
        encrypted_name: &str,
        dir_id: &DirId,
        master_key: &MasterKey,
    ) -> Result<String, NameError> {
        decrypt_filename(encrypted_name, dir_id.as_str(), master_key)
    }

    /// Check if an encrypted filename needs shortening.
    #[inline]
    pub fn needs_shortening(&self, encrypted_name: &str) -> bool {
        helpers::needs_shortening(encrypted_name, self.shortening_threshold)
    }

    /// Generate a shortened filename hash for a long encrypted name.
    #[inline]
    pub fn create_shortened_hash(&self, encrypted_name: &str) -> String {
        create_c9s_filename(encrypted_name)
    }

    // ========================================================================
    // Symlink Encryption/Decryption
    // ========================================================================

    /// Encrypt a symlink target for storage.
    pub fn encrypt_symlink_target(
        &self,
        target: &str,
        master_key: &MasterKey,
    ) -> Result<Vec<u8>, SymlinkError> {
        encrypt_symlink_target(target, master_key)
    }

    /// Decrypt a symlink target.
    pub fn decrypt_symlink_target(
        &self,
        encrypted: &[u8],
        master_key: &MasterKey,
    ) -> Result<String, SymlinkError> {
        decrypt_symlink_target(encrypted, master_key)
    }

    // ========================================================================
    // Directory ID Operations
    // ========================================================================

    /// Hash a directory ID for storage path calculation.
    pub fn hash_dir_id(&self, dir_id: &DirId, master_key: &MasterKey) -> Result<String, NameError> {
        hash_dir_id(dir_id.as_str(), master_key)
    }

    /// Generate a new random directory ID.
    pub fn generate_dir_id(&self) -> DirId {
        DirId::from_raw(uuid::Uuid::new_v4().to_string())
    }

    // ========================================================================
    // Path Utilities
    // ========================================================================

    /// Parse a vault path into its components.
    #[inline]
    pub fn parse_path_components(path: &str) -> Vec<&str> {
        helpers::parse_path_components(path)
    }

    /// Check if a filename represents a shortened entry.
    #[inline]
    pub fn is_shortened_entry(filename: &str) -> bool {
        helpers::is_shortened_entry(filename)
    }

    /// Check if a filename represents a regular encrypted entry.
    #[inline]
    pub fn is_regular_entry(filename: &str) -> bool {
        helpers::is_regular_entry(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_core_creation() {
        let core = VaultCore::new(PathBuf::from("/vault"), CipherCombo::SivGcm);
        assert_eq!(core.vault_path(), Path::new("/vault"));
        assert_eq!(core.cipher_combo(), CipherCombo::SivGcm);
        assert_eq!(core.shortening_threshold(), DEFAULT_SHORTENING_THRESHOLD);
    }

    #[test]
    fn test_vault_core_with_custom_threshold() {
        let core = VaultCore::with_shortening_threshold(
            PathBuf::from("/vault"),
            CipherCombo::SivGcm,
            150,
        );
        assert_eq!(core.shortening_threshold(), 150);
    }

    #[test]
    fn test_needs_shortening() {
        let core = VaultCore::new(PathBuf::from("/vault"), CipherCombo::SivGcm);
        assert!(!core.needs_shortening("short"));
        assert!(!core.needs_shortening(&"a".repeat(220)));
        assert!(core.needs_shortening(&"a".repeat(221)));
    }

    #[test]
    fn test_static_path_utilities() {
        assert!(VaultCore::is_shortened_entry("abc.c9s"));
        assert!(!VaultCore::is_shortened_entry("abc.c9r"));
        assert!(VaultCore::is_regular_entry("abc.c9r"));
        assert!(!VaultCore::is_regular_entry("abc.c9s"));
    }
}
