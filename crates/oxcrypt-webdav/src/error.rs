//! Error handling and mapping for the WebDAV server.
//!
//! This module provides conversion from vault errors to WebDAV/HTTP errors
//! that the dav-server crate can return to clients. Uses the shared
//! [`VaultErrorCategory`](oxcrypt_mount::VaultErrorCategory) for
//! consistent error mapping across backends.

use dav_server::fs::FsError;
use oxcrypt_core::error::{VaultOperationError, VaultWriteError};
use oxcrypt_mount::VaultErrorCategory;
use std::io;
use thiserror::Error;

/// WebDAV-specific errors that can occur during filesystem operations.
#[derive(Debug, Error)]
pub enum WebDavError {
    /// Vault operation error (boxed to reduce enum size).
    #[error("Vault operation failed: {0}")]
    Vault(Box<VaultOperationError>),

    /// Vault write error (boxed to reduce enum size).
    #[error("Vault write failed: {0}")]
    Write(Box<VaultWriteError>),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Invalid path.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Path not found.
    #[error("Path not found: {0}")]
    NotFound(String),

    /// File already exists.
    #[error("File already exists: {0}")]
    AlreadyExists(String),

    /// Directory not empty.
    #[error("Directory not empty: {0}")]
    NotEmpty(String),

    /// Operation not supported.
    #[error("Operation not supported")]
    NotSupported,

    /// Server error.
    #[error("Server error: {0}")]
    Server(String),
}

impl WebDavError {
    /// Converts this error to a dav-server FsError.
    pub fn to_fs_error(&self) -> FsError {
        match self {
            WebDavError::Vault(e) => vault_error_to_fs_error_ref(e.as_ref()),
            WebDavError::Write(e) => write_error_to_fs_error_ref(e.as_ref()),
            WebDavError::Io(e) => io_error_to_fs_error(e),
            WebDavError::InvalidPath(_) | WebDavError::Server(_) => FsError::GeneralFailure,
            WebDavError::NotFound(_) => FsError::NotFound,
            WebDavError::AlreadyExists(_) => FsError::Exists,
            WebDavError::NotEmpty(_) => FsError::Forbidden,
            WebDavError::NotSupported => FsError::NotImplemented,
        }
    }
}

/// Convert VaultErrorCategory to dav-server FsError.
///
/// This is the WebDAV-specific mapping from our shared error categories.
fn category_to_fs_error(category: VaultErrorCategory) -> FsError {
    match category {
        VaultErrorCategory::NotFound => FsError::NotFound,
        VaultErrorCategory::AlreadyExists => FsError::Exists,
        VaultErrorCategory::NotEmpty
        | VaultErrorCategory::IsDirectory
        | VaultErrorCategory::NotDirectory
        | VaultErrorCategory::PermissionDenied => FsError::Forbidden,
        VaultErrorCategory::InvalidArgument | VaultErrorCategory::IoError => {
            FsError::GeneralFailure
        }
        VaultErrorCategory::NotSupported => FsError::NotImplemented,
    }
}

/// Helper that takes a reference (for use in WebDavError::to_fs_error).
fn vault_error_to_fs_error_ref(e: &VaultOperationError) -> FsError {
    category_to_fs_error(VaultErrorCategory::from(e))
}

/// Helper that takes a reference (for use in WebDavError::to_fs_error).
fn write_error_to_fs_error_ref(e: &VaultWriteError) -> FsError {
    category_to_fs_error(VaultErrorCategory::from(e))
}

/// Converts a vault operation error to a dav-server FsError.
///
/// Takes ownership to work with `.map_err()` - the error is moved, not consumed.
#[allow(clippy::needless_pass_by_value)]
pub fn vault_error_to_fs_error(e: VaultOperationError) -> FsError {
    category_to_fs_error(VaultErrorCategory::from(&e))
}

/// Converts a vault write error to a dav-server FsError.
///
/// Takes ownership to work with `.map_err()` - the error is moved, not consumed.
#[allow(clippy::needless_pass_by_value)]
pub fn write_error_to_fs_error(e: VaultWriteError) -> FsError {
    category_to_fs_error(VaultErrorCategory::from(&e))
}

/// Converts an IO error to a dav-server FsError.
pub fn io_error_to_fs_error(e: &io::Error) -> FsError {
    category_to_fs_error(VaultErrorCategory::from(e))
}

/// Result type for WebDAV operations.
pub type WebDavResult<T> = Result<T, WebDavError>;

// Manual From implementations to box errors for smaller enum size
impl From<VaultOperationError> for WebDavError {
    fn from(e: VaultOperationError) -> Self {
        WebDavError::Vault(Box::new(e))
    }
}

impl From<VaultWriteError> for WebDavError {
    fn from(e: VaultWriteError) -> Self {
        WebDavError::Write(Box::new(e))
    }
}

impl From<WebDavError> for FsError {
    fn from(e: WebDavError) -> Self {
        e.to_fs_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webdav_error_to_fs_error() {
        assert!(matches!(
            WebDavError::NotFound("test".to_string()).to_fs_error(),
            FsError::NotFound
        ));
        assert!(matches!(
            WebDavError::AlreadyExists("test".to_string()).to_fs_error(),
            FsError::Exists
        ));
        assert!(matches!(
            WebDavError::NotSupported.to_fs_error(),
            FsError::NotImplemented
        ));
    }

    #[test]
    fn test_io_error_mapping() {
        let e = io::Error::new(io::ErrorKind::NotFound, "not found");
        assert!(matches!(io_error_to_fs_error(&e), FsError::NotFound));

        let e = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert!(matches!(io_error_to_fs_error(&e), FsError::Forbidden));

        let e = io::Error::new(io::ErrorKind::AlreadyExists, "exists");
        assert!(matches!(io_error_to_fs_error(&e), FsError::Exists));
    }
}
