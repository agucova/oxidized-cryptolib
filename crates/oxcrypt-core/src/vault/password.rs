//! Password validation for vault unlocking.
//!
//! This module provides a two-phase unlock mechanism:
//! 1. Validate the password (CPU-intensive scrypt, but can timeout on file I/O)
//! 2. Mount the vault with the validated password (no more password validation)
//!
//! This separation allows the GUI to show immediate feedback on password errors
//! without waiting for mount operations, and prevents blocking on stale mounts
//! during the validation phase.
//!
//! # Example
//!
//! ```no_run
//! use oxcrypt_core::vault::{PasswordValidator, VaultOperationsAsync};
//! use std::time::Duration;
//!
//! // Phase 1: Validate password (with I/O timeout)
//! let validator = PasswordValidator::new("/path/to/vault");
//! let validated = validator.validate("password", Duration::from_secs(5))?;
//!
//! // Phase 2: Create operations (uses already-validated key)
//! let ops = VaultOperationsAsync::from_validated(validated);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::crypto::CryptoError;
use crate::crypto::keys::MasterKey;

use super::config::{CipherCombo, validate_vault_claims};
use super::master_key::MasterKeyFile;

/// Default timeout for filesystem operations during password validation.
pub const DEFAULT_VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors that can occur during password validation.
#[derive(Error, Debug)]
pub enum PasswordValidationError {
    /// The password was incorrect.
    #[error("Incorrect password")]
    IncorrectPassword,

    /// Filesystem operation timed out (path may be on stale mount).
    #[error("Filesystem operation timed out - path may be on a stale mount")]
    Timeout,

    /// Vault configuration file not found.
    #[error("Vault configuration not found: {0}")]
    ConfigNotFound(PathBuf),

    /// Master key file not found.
    #[error("Master key file not found: {0}")]
    MasterKeyNotFound(PathBuf),

    /// Invalid vault format.
    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),

    /// Filesystem I/O error.
    #[error("Filesystem error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing error.
    #[error("Failed to parse vault file: {0}")]
    Parse(#[from] serde_json::Error),

    /// JWT validation error.
    #[error("Vault configuration validation failed: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
}

/// A validated password with the derived master key.
///
/// This is proof that the password was validated successfully. It contains
/// the unlocked master key and vault configuration, ready for mounting.
///
/// This type intentionally does not implement `Clone` to ensure the master key
/// is only used once.
#[derive(Debug)]
pub struct ValidatedPassword {
    /// Path to the vault.
    pub(crate) vault_path: PathBuf,
    /// The unlocked master key.
    pub(crate) master_key: Arc<MasterKey>,
    /// The cipher combination from vault config.
    pub(crate) cipher_combo: CipherCombo,
    /// The shortening threshold from vault config.
    pub(crate) shortening_threshold: usize,
}

impl ValidatedPassword {
    /// Get the vault path.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Get the cipher combination.
    pub fn cipher_combo(&self) -> CipherCombo {
        self.cipher_combo
    }

    /// Get the shortening threshold.
    pub fn shortening_threshold(&self) -> usize {
        self.shortening_threshold
    }

    /// Get a reference to the master key.
    ///
    /// This is primarily for internal use by the vault operations.
    pub(crate) fn master_key(&self) -> Arc<MasterKey> {
        Arc::clone(&self.master_key)
    }
}

/// Validates passwords for vault unlocking.
///
/// This struct provides timeout-protected password validation that separates
/// the password check from mount operations. This allows:
/// - Fast feedback on wrong passwords
/// - Timeout protection against stale mounts
/// - Clean separation of concerns
#[derive(Debug, Clone)]
pub struct PasswordValidator {
    vault_path: PathBuf,
}

impl PasswordValidator {
    /// Create a new password validator for a vault.
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault_path: vault_path.as_ref().to_path_buf(),
        }
    }

    /// Validate a password with the default timeout.
    ///
    /// This is equivalent to calling `validate(password, DEFAULT_VALIDATION_TIMEOUT)`.
    pub fn validate_default(
        &self,
        password: &str,
    ) -> Result<ValidatedPassword, PasswordValidationError> {
        self.validate(password, DEFAULT_VALIDATION_TIMEOUT)
    }

    /// Validate a password with a custom timeout.
    ///
    /// This method:
    /// 1. Reads vault configuration files with timeout protection
    /// 2. Derives the key encryption key (KEK) using scrypt (CPU-bound, ~1-2 seconds)
    /// 3. Unwraps the master keys to verify the password
    /// 4. Validates the vault JWT signature
    ///
    /// If any filesystem operation takes longer than `timeout`, returns `PasswordValidationError::Timeout`.
    ///
    /// # Arguments
    ///
    /// * `password` - The vault password to validate
    /// * `timeout` - Maximum time to wait for filesystem operations
    ///
    /// # Errors
    ///
    /// * `PasswordValidationError::IncorrectPassword` - Wrong password
    /// * `PasswordValidationError::Timeout` - Filesystem operation timed out
    /// * `PasswordValidationError::ConfigNotFound` - vault.cryptomator not found
    /// * `PasswordValidationError::MasterKeyNotFound` - masterkey.cryptomator not found
    pub fn validate(
        &self,
        password: &str,
        timeout: Duration,
    ) -> Result<ValidatedPassword, PasswordValidationError> {
        tracing::info!(
            "PasswordValidator::validate() starting for {:?}",
            self.vault_path
        );

        // Read vault.cryptomator with timeout
        let vault_config_path = self.vault_path.join("vault.cryptomator");
        tracing::info!("Reading vault.cryptomator...");
        let vault_config_jwt =
            read_with_timeout(&vault_config_path, timeout).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    PasswordValidationError::ConfigNotFound(vault_config_path.clone())
                }
                std::io::ErrorKind::TimedOut => PasswordValidationError::Timeout,
                _ => PasswordValidationError::Io(e),
            })?;
        tracing::info!("vault.cryptomator read successfully");

        // Parse JWT header to find masterkey file path
        let header = jsonwebtoken::decode_header(&vault_config_jwt)?;
        let kid = header.kid.ok_or_else(|| {
            PasswordValidationError::InvalidFormat("Missing 'kid' in vault config JWT".to_string())
        })?;

        let masterkey_uri = url::Url::parse(&kid).map_err(|e| {
            PasswordValidationError::InvalidFormat(format!("Invalid masterkey URI: {e}"))
        })?;

        if masterkey_uri.scheme() != "masterkeyfile" {
            return Err(PasswordValidationError::InvalidFormat(format!(
                "Unsupported masterkey scheme: {}",
                masterkey_uri.scheme()
            )));
        }

        // Read masterkey.cryptomator with timeout
        let masterkey_path = self.vault_path.join(Path::new(masterkey_uri.path()));
        tracing::info!("Reading masterkey.cryptomator...");
        let masterkey_json =
            read_with_timeout(&masterkey_path, timeout).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    PasswordValidationError::MasterKeyNotFound(masterkey_path.clone())
                }
                std::io::ErrorKind::TimedOut => PasswordValidationError::Timeout,
                _ => PasswordValidationError::Io(e),
            })?;
        tracing::info!("masterkey.cryptomator read successfully");

        // Parse masterkey file
        let masterkey_file: MasterKeyFile = serde_json::from_str(&masterkey_json)?;

        // Unlock (this is CPU-bound scrypt + key unwrap, not I/O bound)
        // Note: This is intentionally NOT wrapped in a timeout because scrypt is CPU-bound
        // and needs to complete to verify the password
        tracing::info!("Starting scrypt key derivation (this takes ~1-2 seconds)...");
        let start = std::time::Instant::now();
        let master_key = masterkey_file.unlock(password).map_err(|e| {
            tracing::info!("Key unlock FAILED after {:?}: {:?}", start.elapsed(), e);
            match e {
                CryptoError::KeyUnwrapIntegrityFailed => PasswordValidationError::IncorrectPassword,
                other => PasswordValidationError::Crypto(other),
            }
        })?;
        tracing::info!("Key unlock succeeded after {:?}", start.elapsed());

        // Validate vault JWT signature (verifies vault integrity)
        let claims = validate_vault_claims(&vault_config_jwt, &master_key).map_err(|e| {
            PasswordValidationError::InvalidFormat(format!("Vault JWT validation failed: {e}"))
        })?;

        let cipher_combo = claims.cipher_combo().ok_or_else(|| {
            PasswordValidationError::InvalidFormat(
                "Unsupported cipher combo in vault config".to_string(),
            )
        })?;

        let shortening_threshold = claims.shortening_threshold();

        Ok(ValidatedPassword {
            vault_path: self.vault_path.clone(),
            master_key: Arc::new(master_key),
            cipher_combo,
            shortening_threshold,
        })
    }
}

/// Read a file with timeout protection.
///
/// Spawns a thread to perform the read, returning an error if it doesn't
/// complete within the timeout.
fn read_with_timeout(path: &Path, timeout: Duration) -> std::io::Result<String> {
    let path = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = std::fs::read_to_string(&path);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Filesystem operation timed out - path may be on a stale mount",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::other(
            "Filesystem read thread terminated unexpectedly",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_validator_nonexistent_vault() {
        let validator = PasswordValidator::new("/nonexistent/vault/path");
        let result = validator.validate("password", Duration::from_secs(1));
        assert!(matches!(
            result,
            Err(PasswordValidationError::ConfigNotFound(_))
        ));
    }

    #[test]
    fn test_read_with_timeout_existing_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let result = read_with_timeout(&file_path, Duration::from_secs(1));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_read_with_timeout_nonexistent_file() {
        let result = read_with_timeout(Path::new("/nonexistent/file"), Duration::from_secs(1));
        assert!(matches!(result, Err(e) if e.kind() == std::io::ErrorKind::NotFound));
    }
}
