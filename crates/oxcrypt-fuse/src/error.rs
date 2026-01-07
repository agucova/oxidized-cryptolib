//! Error handling and mapping for the FUSE filesystem.
//!
//! This module provides conversion from vault errors to POSIX error codes
//! that FUSE can return to the kernel. It uses the shared
//! [`VaultErrorCategory`](oxcrypt_mount::VaultErrorCategory) for
//! consistent error mapping.

use crate::async_bridge::BridgeError;
use oxcrypt_core::error::{VaultOperationError, VaultWriteError};
use oxcrypt_mount::{io_error_to_errno, VaultErrorCategory};
use std::io;
use thiserror::Error;

/// FUSE-specific errors that can occur during filesystem operations.
#[derive(Debug, Error)]
pub enum FuseError {
    /// Vault operation error (boxed to reduce enum size).
    #[error("Vault operation failed: {0}")]
    Vault(Box<VaultOperationError>),

    /// Vault write error (boxed to reduce enum size).
    #[error("Vault write failed: {0}")]
    Write(Box<VaultWriteError>),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Async bridge error (timeout, cancelled, etc.).
    #[error("Async bridge error: {0}")]
    Bridge(#[from] BridgeError),

    /// Invalid inode.
    #[error("Invalid inode: {0}")]
    InvalidInode(u64),

    /// Invalid file handle.
    #[error("Invalid file handle: {0}")]
    InvalidHandle(u64),

    /// Wrong handle type (e.g., tried to read from a write handle).
    #[error("Wrong handle type for operation")]
    WrongHandleType,

    /// Path resolution failed.
    #[error("Path resolution failed: {0}")]
    PathResolution(String),

    /// File already exists.
    #[error("File already exists: {0}")]
    AlreadyExists(String),

    /// Directory not empty.
    #[error("Directory not empty: {0}")]
    NotEmpty(String),

    /// Operation not supported.
    #[error("Operation not supported")]
    NotSupported,
}

impl FuseError {
    /// Converts this error to a libc error code for FUSE.
    pub fn to_errno(&self) -> i32 {
        match self {
            FuseError::Vault(e) => vault_error_to_errno(e.as_ref()),
            FuseError::Write(e) => write_error_to_errno(e.as_ref()),
            FuseError::Io(e) => io_error_to_errno(e),
            FuseError::Bridge(e) => e.to_errno(),
            FuseError::InvalidInode(_) | FuseError::PathResolution(_) => libc::ENOENT,
            FuseError::InvalidHandle(_) | FuseError::WrongHandleType => libc::EBADF,
            FuseError::AlreadyExists(_) => libc::EEXIST,
            FuseError::NotEmpty(_) => libc::ENOTEMPTY,
            FuseError::NotSupported => libc::ENOTSUP,
        }
    }
}

/// Converts a vault operation error to a libc error code.
///
/// Uses the shared [`VaultErrorCategory`] for consistent mapping.
pub fn vault_error_to_errno(e: &VaultOperationError) -> i32 {
    VaultErrorCategory::from(e).to_errno()
}

/// Converts a vault write error to a libc error code.
///
/// Uses the shared [`VaultErrorCategory`] for consistent mapping.
pub fn write_error_to_errno(e: &VaultWriteError) -> i32 {
    VaultErrorCategory::from(e).to_errno()
}

/// Result type for FUSE operations.
pub type FuseResult<T> = Result<T, FuseError>;

/// Extension trait to convert errors to errno.
pub trait ToErrno {
    /// Converts this error to a libc error code.
    fn to_errno(&self) -> i32;
}

impl ToErrno for VaultOperationError {
    fn to_errno(&self) -> i32 {
        vault_error_to_errno(self)
    }
}

impl ToErrno for VaultWriteError {
    fn to_errno(&self) -> i32 {
        write_error_to_errno(self)
    }
}

impl ToErrno for io::Error {
    fn to_errno(&self) -> i32 {
        io_error_to_errno(self)
    }
}

// Manual From implementations to box errors for smaller enum size
impl From<VaultOperationError> for FuseError {
    fn from(e: VaultOperationError) -> Self {
        FuseError::Vault(Box::new(e))
    }
}

impl From<VaultWriteError> for FuseError {
    fn from(e: VaultWriteError) -> Self {
        FuseError::Write(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_mapping() {
        let e = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(io_error_to_errno(&e), libc::ENOENT);

        let e = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(io_error_to_errno(&e), libc::EACCES);
    }

    #[test]
    fn test_io_error_mapping_without_os_error() {
        let e = io::Error::other("custom error");
        // Should return EIO when no raw OS error
        assert_eq!(io_error_to_errno(&e), libc::EIO);
    }

    #[test]
    fn test_fuse_error_conversion() {
        let e = FuseError::InvalidInode(42);
        assert_eq!(e.to_errno(), libc::ENOENT);

        let e = FuseError::InvalidHandle(1);
        assert_eq!(e.to_errno(), libc::EBADF);

        let e = FuseError::AlreadyExists("test".to_string());
        assert_eq!(e.to_errno(), libc::EEXIST);

        let e = FuseError::NotEmpty("dir".to_string());
        assert_eq!(e.to_errno(), libc::ENOTEMPTY);
    }

    #[test]
    fn test_fuse_error_all_variants() {
        // Test all FuseError variants map to reasonable errno values

        assert_eq!(
            FuseError::InvalidInode(1).to_errno(),
            libc::ENOENT,
            "InvalidInode should map to ENOENT"
        );

        assert_eq!(
            FuseError::InvalidHandle(1).to_errno(),
            libc::EBADF,
            "InvalidHandle should map to EBADF"
        );

        assert_eq!(
            FuseError::WrongHandleType.to_errno(),
            libc::EBADF,
            "WrongHandleType should map to EBADF"
        );

        assert_eq!(
            FuseError::PathResolution("path".to_string()).to_errno(),
            libc::ENOENT,
            "PathResolution should map to ENOENT"
        );

        assert_eq!(
            FuseError::AlreadyExists("file".to_string()).to_errno(),
            libc::EEXIST,
            "AlreadyExists should map to EEXIST"
        );

        assert_eq!(
            FuseError::NotEmpty("dir".to_string()).to_errno(),
            libc::ENOTEMPTY,
            "NotEmpty should map to ENOTEMPTY"
        );

        assert_eq!(
            FuseError::NotSupported.to_errno(),
            libc::ENOTSUP,
            "NotSupported should map to ENOTSUP"
        );
    }

    #[test]
    fn test_fuse_error_io_passthrough() {
        let io_err = io::Error::from_raw_os_error(libc::EPERM);
        let e = FuseError::Io(io_err);
        assert_eq!(e.to_errno(), libc::EPERM);

        let io_err = io::Error::from_raw_os_error(libc::ENOSPC);
        let e = FuseError::Io(io_err);
        assert_eq!(e.to_errno(), libc::ENOSPC);
    }

    #[test]
    fn test_fuse_error_display() {
        let e = FuseError::InvalidInode(42);
        assert!(e.to_string().contains("42"));

        let e = FuseError::AlreadyExists("myfile.txt".to_string());
        assert!(e.to_string().contains("myfile.txt"));

        let e = FuseError::PathResolution("some/path".to_string());
        assert!(e.to_string().contains("some/path"));
    }

    #[test]
    fn test_to_errno_trait_io_error() {
        let e = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(e.to_errno(), libc::ENOENT);
    }

    #[test]
    fn test_fuse_result_type() {
        fn returns_ok() -> FuseResult<i32> {
            Ok(42)
        }

        fn returns_err() -> FuseResult<i32> {
            Err(FuseError::NotSupported)
        }

        assert_eq!(returns_ok().unwrap(), 42);
        assert!(returns_err().is_err());
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::from_raw_os_error(libc::EACCES);
        let fuse_err: FuseError = io_err.into();
        assert_eq!(fuse_err.to_errno(), libc::EACCES);
    }

    #[test]
    fn test_common_io_error_mappings() {
        // Test a variety of common IO error codes
        let error_codes = [
            libc::ENOENT,    // No such file or directory
            libc::EACCES,    // Permission denied
            libc::EEXIST,    // File exists
            libc::ENOTDIR,   // Not a directory
            libc::EISDIR,    // Is a directory
            libc::EINVAL,    // Invalid argument
            libc::ENOSPC,    // No space left on device
            libc::EROFS,     // Read-only file system
            libc::ENOTEMPTY, // Directory not empty
        ];

        for code in error_codes {
            let e = io::Error::from_raw_os_error(code);
            assert_eq!(
                io_error_to_errno(&e),
                code,
                "IO error code {code} should map to same errno"
            );
        }
    }

    #[test]
    fn test_vault_error_category_mapping() {
        // Test that VaultErrorCategory correctly maps vault errors
        use oxcrypt_core::vault::operations::VaultOpContext;

        // PathNotFound -> ENOENT
        let err = VaultOperationError::PathNotFound {
            path: "/test".to_string(),
        };
        assert_eq!(vault_error_to_errno(&err), libc::ENOENT);

        // FileNotFound -> ENOENT
        let err = VaultOperationError::FileNotFound {
            filename: "test.txt".to_string(),
            context: VaultOpContext::new(),
        };
        assert_eq!(vault_error_to_errno(&err), libc::ENOENT);

        // NotAFile -> EISDIR
        let err = VaultOperationError::NotAFile {
            path: "/dir".to_string(),
        };
        assert_eq!(vault_error_to_errno(&err), libc::EISDIR);

        // NotADirectory -> ENOTDIR
        let err = VaultOperationError::NotADirectory {
            path: "/file".to_string(),
        };
        assert_eq!(vault_error_to_errno(&err), libc::ENOTDIR);

        // EmptyPath -> EINVAL
        let err = VaultOperationError::EmptyPath;
        assert_eq!(vault_error_to_errno(&err), libc::EINVAL);
    }

    #[test]
    fn test_write_error_category_mapping() {
        // Test that VaultErrorCategory correctly maps write errors
        use oxcrypt_core::vault::operations::VaultOpContext;

        // FileAlreadyExists -> EEXIST
        let err = VaultWriteError::FileAlreadyExists {
            filename: "test.txt".to_string(),
            context: Box::new(VaultOpContext::new()),
        };
        assert_eq!(write_error_to_errno(&err), libc::EEXIST);

        // DirectoryNotEmpty -> ENOTEMPTY
        let err = VaultWriteError::DirectoryNotEmpty {
            context: Box::new(VaultOpContext::new()),
        };
        assert_eq!(write_error_to_errno(&err), libc::ENOTEMPTY);

        // DirectoryNotFound -> ENOENT
        let err = VaultWriteError::DirectoryNotFound {
            name: "test".to_string(),
            context: Box::new(VaultOpContext::new()),
        };
        assert_eq!(write_error_to_errno(&err), libc::ENOENT);
    }
}
