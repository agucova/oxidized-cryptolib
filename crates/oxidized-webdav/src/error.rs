//! Error handling and mapping for the WebDAV server.
//!
//! This module provides conversion from vault errors to WebDAV/HTTP errors
//! that the dav-server crate can return to clients.

use dav_server::fs::FsError;
use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
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
            WebDavError::Vault(e) => vault_error_to_fs_error(e.as_ref()),
            WebDavError::Write(e) => write_error_to_fs_error(e.as_ref()),
            WebDavError::Io(e) => io_error_to_fs_error(e),
            WebDavError::InvalidPath(_) => FsError::GeneralFailure,
            WebDavError::NotFound(_) => FsError::NotFound,
            WebDavError::AlreadyExists(_) => FsError::Exists,
            WebDavError::NotEmpty(_) => FsError::Forbidden,
            WebDavError::NotSupported => FsError::NotImplemented,
            WebDavError::Server(_) => FsError::GeneralFailure,
        }
    }
}

/// Converts a vault operation error to a dav-server FsError.
pub fn vault_error_to_fs_error(e: &VaultOperationError) -> FsError {
    match e {
        VaultOperationError::Io { source, .. } => io_error_to_fs_error(source),
        VaultOperationError::FileDecryption(_) => FsError::GeneralFailure,
        VaultOperationError::FileContentDecryption(_) => FsError::GeneralFailure,
        VaultOperationError::Filename(_) => FsError::GeneralFailure,
        VaultOperationError::DirectoryNotFound { .. } => FsError::NotFound,
        VaultOperationError::InvalidVaultStructure { .. } => FsError::GeneralFailure,
        VaultOperationError::PathNotFound { .. } => FsError::NotFound,
        VaultOperationError::NotAFile { .. } => FsError::Forbidden,
        VaultOperationError::NotADirectory { .. } => FsError::Forbidden,
        VaultOperationError::EmptyPath => FsError::GeneralFailure,
        VaultOperationError::FileNotFound { .. } => FsError::NotFound,
        VaultOperationError::Symlink(_) => FsError::GeneralFailure,
        VaultOperationError::SymlinkNotFound { .. } => FsError::NotFound,
        VaultOperationError::NotASymlink { .. } => FsError::GeneralFailure,
        VaultOperationError::Streaming { .. } => FsError::GeneralFailure,
    }
}

/// Converts a vault write error to a dav-server FsError.
pub fn write_error_to_fs_error(e: &VaultWriteError) -> FsError {
    match e {
        VaultWriteError::Io { source, .. } => io_error_to_fs_error(source),
        VaultWriteError::Encryption(_) => FsError::GeneralFailure,
        VaultWriteError::Filename(_) => FsError::GeneralFailure,
        VaultWriteError::DirectoryNotFound { .. } => FsError::NotFound,
        VaultWriteError::FileAlreadyExists { .. } => FsError::Exists,
        VaultWriteError::DirectoryAlreadyExists { .. } => FsError::Exists,
        VaultWriteError::DirectoryNotEmpty { .. } => FsError::Forbidden,
        VaultWriteError::AtomicWriteFailed { .. } => FsError::GeneralFailure,
        VaultWriteError::FileNotFound { .. } => FsError::NotFound,
        VaultWriteError::SameSourceAndDestination { .. } => FsError::GeneralFailure,
        VaultWriteError::Symlink(_) => FsError::GeneralFailure,
        VaultWriteError::SymlinkAlreadyExists { .. } => FsError::Exists,
        VaultWriteError::Streaming { .. } => FsError::GeneralFailure,
    }
}

/// Converts an IO error to a dav-server FsError.
pub fn io_error_to_fs_error(e: &io::Error) -> FsError {
    match e.kind() {
        io::ErrorKind::NotFound => FsError::NotFound,
        io::ErrorKind::PermissionDenied => FsError::Forbidden,
        io::ErrorKind::AlreadyExists => FsError::Exists,
        _ => FsError::GeneralFailure,
    }
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
