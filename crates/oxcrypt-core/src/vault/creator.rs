//! Vault creation functionality
//!
//! This module provides the `VaultCreator` struct for creating new Cryptomator vaults
//! from scratch.

use crate::{
    crypto::keys::{MasterKey, KeyAccessError},
    vault::{
        config::{create_vault_config, CiphertextDir, VaultConfig, VaultConfigCreationError, DEFAULT_SHORTENING_THRESHOLD},
        master_key::create_masterkey_file,
        operations::VaultOperations,
        path::DirId,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Errors that can occur during vault creation
#[derive(Error, Debug)]
pub enum VaultCreationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Vault already exists at path: {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("Failed to create masterkey file: {0}")]
    MasterkeyCreation(String),

    #[error("Failed to create vault config: {0}")]
    ConfigCreation(#[from] VaultConfigCreationError),

    #[error("Key access error: {0}")]
    KeyAccess(#[from] KeyAccessError),

    #[error("Vault operation error: {0}")]
    VaultOperation(Box<crate::vault::operations::VaultOperationError>),
}

impl From<crate::vault::operations::VaultOperationError> for VaultCreationError {
    fn from(e: crate::vault::operations::VaultOperationError) -> Self {
        VaultCreationError::VaultOperation(Box::new(e))
    }
}

/// Builder for creating new Cryptomator vaults
///
/// # Example
///
/// ```no_run
/// use oxcrypt_core::vault::{VaultCreator, DirId};
/// use std::path::Path;
///
/// let vault_ops = VaultCreator::new(Path::new("/path/to/new/vault"), "my-secure-passphrase")
///     .create()
///     .expect("Failed to create vault");
///
/// // Now you can use vault_ops to write files
/// vault_ops.write_file(&DirId::root(), "hello.txt", b"Hello, World!").unwrap();
/// ```
pub struct VaultCreator {
    vault_path: PathBuf,
    passphrase: String,
    vault_id: String,
    shortening_threshold: usize,
}

impl VaultCreator {
    /// Create a new VaultCreator
    ///
    /// # Arguments
    /// * `vault_path` - Path where the new vault will be created
    /// * `passphrase` - Password to encrypt the master keys
    pub fn new(vault_path: &Path, passphrase: &str) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            passphrase: passphrase.to_string(),
            vault_id: uuid::Uuid::new_v4().to_string(),
            shortening_threshold: DEFAULT_SHORTENING_THRESHOLD,
        }
    }

    /// Set a custom vault ID (defaults to random UUID)
    ///
    /// This is primarily useful for testing or migrating vaults.
    pub fn with_vault_id(mut self, id: &str) -> Self {
        self.vault_id = id.to_string();
        self
    }

    /// Set a custom shortening threshold (defaults to 220)
    ///
    /// The shortening threshold determines when encrypted filenames are shortened
    /// to use the .c9s format. Filenames longer than this threshold will be
    /// replaced with a SHA-1 hash.
    ///
    /// Lower thresholds may be useful for cloud storage providers with strict
    /// path length limits.
    pub fn with_shortening_threshold(mut self, threshold: usize) -> Self {
        self.shortening_threshold = threshold;
        self
    }

    /// Create the vault and return a VaultOperations handle
    ///
    /// This will:
    /// 1. Create the vault directory structure (`/d/`, `/masterkey/`)
    /// 2. Generate a new random master key
    /// 3. Create `masterkey/masterkey.cryptomator` with the encrypted keys
    /// 4. Create `vault.cryptomator` JWT configuration
    /// 5. Create the root directory storage path
    ///
    /// # Returns
    /// A `VaultOperations` instance ready to read/write files
    ///
    /// # Errors
    /// * `VaultCreationError::VaultAlreadyExists` if vault.cryptomator already exists
    /// * `VaultCreationError::Io` for filesystem errors
    /// * `VaultCreationError::MasterkeyCreation` if key wrapping fails
    /// * `VaultCreationError::ConfigCreation` if JWT creation fails
    pub fn create(self) -> Result<VaultOperations, VaultCreationError> {
        // Check vault doesn't already exist
        if self.vault_path.join("vault.cryptomator").exists() {
            return Err(VaultCreationError::VaultAlreadyExists(
                self.vault_path.clone(),
            ));
        }

        // Create directory structure
        fs::create_dir_all(self.vault_path.join("d"))?;
        fs::create_dir_all(self.vault_path.join("masterkey"))?;

        // Generate master key
        let master_key = MasterKey::random()?;

        // Create vault.cryptomator JWT
        let config = VaultConfig {
            jti: self.vault_id,
            format: 8,
            shortening_threshold: self.shortening_threshold as i32,
            ciphertext_dir: Some(CiphertextDir("d".to_string())),
            payload: None,
        };
        let jwt = create_vault_config(&config, &master_key)?;
        fs::write(self.vault_path.join("vault.cryptomator"), &jwt)?;

        // Create masterkey.cryptomator
        let masterkey_content = create_masterkey_file(&master_key, &self.passphrase)
            .map_err(|e| VaultCreationError::MasterkeyCreation(e.to_string()))?;
        fs::write(
            self.vault_path.join("masterkey").join("masterkey.cryptomator"),
            &masterkey_content,
        )?;

        // Create root directory storage path
        let vault_ops = VaultOperations::with_shortening_threshold(
            &self.vault_path,
            master_key,
            self.shortening_threshold,
        );
        let root_storage_path = vault_ops.calculate_directory_storage_path(&DirId::root())?;
        fs::create_dir_all(&root_storage_path)?;

        Ok(vault_ops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_vault_creation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("test_vault");

        // Create vault
        let vault_ops = VaultCreator::new(&vault_path, "test-password")
            .create()
            .expect("Failed to create vault");

        // Verify structure exists
        assert!(vault_path.join("vault.cryptomator").exists());
        assert!(vault_path.join("masterkey/masterkey.cryptomator").exists());
        assert!(vault_path.join("d").exists());

        // Write a file
        vault_ops
            .write_file(&DirId::root(), "test.txt", b"Hello, World!")
            .expect("Failed to write file");

        // Read it back
        let decrypted = vault_ops
            .read_file(&DirId::root(), "test.txt")
            .expect("Failed to read file");
        assert_eq!(decrypted.content, b"Hello, World!");
    }

    #[test]
    fn test_vault_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("existing_vault");

        // Create vault first time
        VaultCreator::new(&vault_path, "password")
            .create()
            .expect("Failed to create vault");

        // Try to create again - should fail
        let result = VaultCreator::new(&vault_path, "password").create();
        assert!(matches!(
            result,
            Err(VaultCreationError::VaultAlreadyExists(_))
        ));
    }

    #[test]
    fn test_vault_with_custom_id() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("custom_id_vault");
        let custom_id = "my-custom-vault-id";

        VaultCreator::new(&vault_path, "password")
            .with_vault_id(custom_id)
            .create()
            .expect("Failed to create vault");

        // Read vault.cryptomator and verify the jti
        let jwt = fs::read_to_string(vault_path.join("vault.cryptomator")).unwrap();
        assert!(jwt.contains("my-custom-vault-id") || {
            // The ID is in the JWT claims, decode to verify
            let parts: Vec<&str> = jwt.split('.').collect();
            let claims = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                parts[1],
            )
            .unwrap();
            let claims_str = String::from_utf8(claims).unwrap();
            claims_str.contains(custom_id)
        });
    }

    #[test]
    fn test_vault_with_custom_shortening_threshold() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("custom_threshold_vault");

        // Create vault with custom shortening threshold
        let vault_ops = VaultCreator::new(&vault_path, "password")
            .with_shortening_threshold(100)
            .create()
            .expect("Failed to create vault");

        // Verify the vault ops has the correct threshold
        assert_eq!(vault_ops.shortening_threshold(), 100);

        // Verify the threshold is persisted in vault.cryptomator
        let jwt = fs::read_to_string(vault_path.join("vault.cryptomator")).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1],
        )
        .unwrap();
        let claims_str = String::from_utf8(claims).unwrap();
        assert!(claims_str.contains("\"shorteningThreshold\":100"));
    }

    #[test]
    fn test_vault_default_shortening_threshold() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("default_threshold_vault");

        // Create vault with default settings
        let vault_ops = VaultCreator::new(&vault_path, "password")
            .create()
            .expect("Failed to create vault");

        // Verify the vault ops has the default threshold (220)
        assert_eq!(vault_ops.shortening_threshold(), DEFAULT_SHORTENING_THRESHOLD);
    }
}
