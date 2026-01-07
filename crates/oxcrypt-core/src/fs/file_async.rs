//! Async file encryption and decryption operations.
//!
//! This module provides async versions of file operations for use with tokio.

use std::ffi::OsStr;
use std::path::Path;

use tokio::fs;
use tracing::{debug, instrument, trace, warn};

use crate::crypto::keys::MasterKey;
use crate::fs::file::{
    DecryptedFile, FileContext, FileDecryptionError, FileError, decrypt_file_content_with_context,
    decrypt_file_header_with_context,
};

/// Async version of `decrypt_file`.
///
/// Reads and decrypts a Cryptomator encrypted file asynchronously.
///
/// # Example
///
/// ```no_run
/// use oxcrypt_core::crypto::keys::MasterKey;
/// use oxcrypt_core::fs::file_async::decrypt_file_async;
/// use std::path::Path;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let master_key: MasterKey = todo!("load master key");
/// let decrypted = decrypt_file_async(Path::new("/path/to/file.c9r"), &master_key).await?;
/// println!("Decrypted content length: {}", decrypted.content.len());
/// # Ok(())
/// # }
/// ```
#[instrument(level = "info", skip(master_key), fields(path = %path.as_ref().display()))]
pub async fn decrypt_file_async(
    path: impl AsRef<Path>,
    master_key: &MasterKey,
) -> Result<DecryptedFile, FileError> {
    decrypt_file_with_context_async(path, master_key, None, None).await
}

/// Async version of `decrypt_file_with_context`.
///
/// Reads and decrypts a Cryptomator encrypted file asynchronously with full context
/// for error messages.
///
/// # Arguments
///
/// * `path` - Path to the encrypted file
/// * `master_key` - The vault's master key
/// * `filename` - Optional cleartext filename for error context
/// * `dir_id` - Optional parent directory ID for error context
#[instrument(level = "info", skip(master_key), fields(path = %path.as_ref().display()))]
pub async fn decrypt_file_with_context_async(
    path: impl AsRef<Path>,
    master_key: &MasterKey,
    filename: Option<&str>,
    dir_id: Option<&str>,
) -> Result<DecryptedFile, FileError> {
    let path = path.as_ref();
    let mut context = FileContext::new().with_path(path);
    if let Some(name) = filename {
        context = context.with_filename(name);
    }
    if let Some(id) = dir_id {
        context = context.with_dir_id(id);
    }

    // Check for directory marker files
    if path.file_name() == Some(OsStr::new("dir.c9r")) {
        warn!("Attempted to decrypt directory marker file");
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: "cannot decrypt directory marker files (dir.c9r) as regular files".to_string(),
            context,
        }));
    }

    // Read file asynchronously
    debug!("Reading encrypted file");
    let encrypted = fs::read(path)
        .await
        .map_err(|e| FileError::io_with_context(e, context.clone()))?;
    trace!(encrypted_size = encrypted.len(), "Read encrypted file");

    // Validate minimum file size
    if encrypted.len() < 68 {
        warn!(
            actual_size = encrypted.len(),
            "File too small for valid encrypted file"
        );
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: format!(
                "file too small: expected at least 68 bytes, got {}",
                encrypted.len()
            ),
            context,
        }));
    }

    // Decryption is CPU-bound, so we do it synchronously
    // (could use spawn_blocking for very large files, but chunk processing is already efficient)
    debug!("Decrypting header");
    let header = decrypt_file_header_with_context(&encrypted[0..68], master_key, &context)?;

    debug!("Decrypting content");
    let content = decrypt_file_content_with_context(
        &encrypted[68..],
        &header.content_key,
        &encrypted[0..12],
        &context,
    )?;

    Ok(DecryptedFile { header, content })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_decrypt_file_async_not_found() {
        // Create a dummy master key for testing - this test should fail on IO, not key
        let master_key = MasterKey::random().expect("Failed to create random key");
        let result = decrypt_file_async("/nonexistent/path.c9r", &master_key).await;
        assert!(matches!(result, Err(FileError::Io { .. })));
    }

    #[tokio::test]
    async fn test_decrypt_dir_marker_rejected() {
        let master_key = MasterKey::random().expect("Failed to create random key");
        let result = decrypt_file_async("/some/path/dir.c9r", &master_key).await;
        match result {
            Err(FileError::Decryption(FileDecryptionError::InvalidHeader { reason, .. })) => {
                assert!(reason.contains("dir.c9r"));
            }
            _ => panic!("Expected InvalidHeader error for dir.c9r"),
        }
    }
}
