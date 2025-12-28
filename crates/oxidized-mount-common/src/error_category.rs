//! Error category mapping for vault errors.
//!
//! This module provides a unified error classification for vault errors,
//! enabling backend-specific conversion to errno (FUSE/FSKit) or HTTP status codes (WebDAV).
//!
//! # Overview
//!
//! Different mount backends need different error representations:
//! - **FUSE/FSKit**: POSIX errno values (e.g., `ENOENT`, `EEXIST`)
//! - **WebDAV**: HTTP status codes via `dav_server::fs::FsError`
//!
//! This module provides [`VaultErrorCategory`] as an intermediate representation
//! that can be converted to either format.

use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
use std::io;

/// Semantic category for vault errors.
///
/// This enum classifies vault errors into semantic categories that can be
/// mapped to appropriate error codes for each backend.
///
/// # Example
///
/// ```
/// use oxidized_mount_common::VaultErrorCategory;
/// use oxidized_cryptolib::error::VaultOperationError;
///
/// let err = VaultOperationError::PathNotFound { path: "/test".to_string() };
/// let category = VaultErrorCategory::from(&err);
///
/// assert_eq!(category, VaultErrorCategory::NotFound);
/// assert_eq!(category.to_errno(), libc::ENOENT);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultErrorCategory {
    /// Resource not found (ENOENT, HTTP 404)
    NotFound,
    /// Resource already exists (EEXIST, HTTP 412)
    AlreadyExists,
    /// Directory not empty (ENOTEMPTY)
    NotEmpty,
    /// Type mismatch: expected file but got directory (EISDIR)
    IsDirectory,
    /// Type mismatch: expected directory but got file (ENOTDIR)
    NotDirectory,
    /// Invalid path or argument (EINVAL)
    InvalidArgument,
    /// I/O or crypto error (EIO)
    IoError,
    /// Permission denied (EACCES)
    PermissionDenied,
    /// Operation not supported (ENOTSUP)
    NotSupported,
}

impl VaultErrorCategory {
    /// Converts this error category to a POSIX errno value.
    ///
    /// This is used by FUSE and FSKit backends.
    #[inline]
    pub fn to_errno(self) -> i32 {
        match self {
            Self::NotFound => libc::ENOENT,
            Self::AlreadyExists => libc::EEXIST,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::IsDirectory => libc::EISDIR,
            Self::NotDirectory => libc::ENOTDIR,
            Self::InvalidArgument => libc::EINVAL,
            Self::IoError => libc::EIO,
            Self::PermissionDenied => libc::EACCES,
            Self::NotSupported => libc::ENOTSUP,
        }
    }

    /// Returns a human-readable name for this error category.
    pub fn name(&self) -> &'static str {
        match self {
            Self::NotFound => "NotFound",
            Self::AlreadyExists => "AlreadyExists",
            Self::NotEmpty => "NotEmpty",
            Self::IsDirectory => "IsDirectory",
            Self::NotDirectory => "NotDirectory",
            Self::InvalidArgument => "InvalidArgument",
            Self::IoError => "IoError",
            Self::PermissionDenied => "PermissionDenied",
            Self::NotSupported => "NotSupported",
        }
    }
}

impl From<&VaultOperationError> for VaultErrorCategory {
    fn from(e: &VaultOperationError) -> Self {
        match e {
            VaultOperationError::PathNotFound { .. } => Self::NotFound,
            VaultOperationError::FileNotFound { .. } => Self::NotFound,
            VaultOperationError::DirectoryNotFound { .. } => Self::NotFound,
            VaultOperationError::SymlinkNotFound { .. } => Self::NotFound,
            VaultOperationError::NotADirectory { .. } => Self::NotDirectory,
            VaultOperationError::NotAFile { .. } => Self::IsDirectory,
            VaultOperationError::NotASymlink { .. } => Self::InvalidArgument,
            VaultOperationError::EmptyPath => Self::InvalidArgument,
            VaultOperationError::Filename(_) => Self::InvalidArgument,
            VaultOperationError::Io { source, .. } => io_error_category(source),
            // Crypto/decryption errors are I/O errors from the caller's perspective
            VaultOperationError::FileDecryption(_) => Self::IoError,
            VaultOperationError::FileContentDecryption(_) => Self::IoError,
            VaultOperationError::InvalidVaultStructure { .. } => Self::IoError,
            VaultOperationError::Symlink(_) => Self::IoError,
            VaultOperationError::Streaming { .. } => Self::IoError,
        }
    }
}

impl From<VaultOperationError> for VaultErrorCategory {
    fn from(e: VaultOperationError) -> Self {
        Self::from(&e)
    }
}

impl From<&VaultWriteError> for VaultErrorCategory {
    fn from(e: &VaultWriteError) -> Self {
        match e {
            VaultWriteError::DirectoryNotFound { .. } => Self::NotFound,
            VaultWriteError::FileNotFound { .. } => Self::NotFound,
            VaultWriteError::FileAlreadyExists { .. } => Self::AlreadyExists,
            VaultWriteError::DirectoryAlreadyExists { .. } => Self::AlreadyExists,
            VaultWriteError::SymlinkAlreadyExists { .. } => Self::AlreadyExists,
            VaultWriteError::PathExists { .. } => Self::AlreadyExists,
            VaultWriteError::DirectoryNotEmpty { .. } => Self::NotEmpty,
            VaultWriteError::SameSourceAndDestination { .. } => Self::InvalidArgument,
            VaultWriteError::Filename(_) => Self::InvalidArgument,
            VaultWriteError::Io { source, .. } => io_error_category(source),
            // Crypto/encryption errors are I/O errors from the caller's perspective
            VaultWriteError::Encryption(_) => Self::IoError,
            VaultWriteError::AtomicWriteFailed { .. } => Self::IoError,
            VaultWriteError::Symlink(_) => Self::IoError,
            VaultWriteError::Streaming { .. } => Self::IoError,
        }
    }
}

impl From<VaultWriteError> for VaultErrorCategory {
    fn from(e: VaultWriteError) -> Self {
        Self::from(&e)
    }
}

impl From<&io::Error> for VaultErrorCategory {
    fn from(e: &io::Error) -> Self {
        io_error_category(e)
    }
}

impl From<io::Error> for VaultErrorCategory {
    fn from(e: io::Error) -> Self {
        io_error_category(&e)
    }
}

/// Categorizes an I/O error based on its kind.
fn io_error_category(e: &io::Error) -> VaultErrorCategory {
    match e.kind() {
        io::ErrorKind::NotFound => VaultErrorCategory::NotFound,
        io::ErrorKind::PermissionDenied => VaultErrorCategory::PermissionDenied,
        io::ErrorKind::AlreadyExists => VaultErrorCategory::AlreadyExists,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
            VaultErrorCategory::InvalidArgument
        }
        io::ErrorKind::Unsupported => VaultErrorCategory::NotSupported,
        _ => VaultErrorCategory::IoError,
    }
}

/// Converts an I/O error to a POSIX errno value.
///
/// This extracts the raw OS error if available, otherwise returns `EIO`.
#[inline]
pub fn io_error_to_errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::vault::operations::VaultOpContext;

    #[test]
    fn test_vault_operation_error_not_found() {
        let err = VaultOperationError::PathNotFound {
            path: "/test".to_string(),
        };
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::NotFound);
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::ENOENT);
    }

    #[test]
    fn test_vault_operation_error_file_not_found() {
        let err = VaultOperationError::FileNotFound {
            filename: "test.txt".to_string(),
            context: VaultOpContext::new(),
        };
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::NotFound);
    }

    #[test]
    fn test_vault_operation_error_directory_not_found() {
        let err = VaultOperationError::DirectoryNotFound {
            name: "test".to_string(),
            context: VaultOpContext::new(),
        };
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::NotFound);
    }

    #[test]
    fn test_vault_operation_error_not_a_file() {
        let err = VaultOperationError::NotAFile {
            path: "/test".to_string(),
        };
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::IsDirectory
        );
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::EISDIR);
    }

    #[test]
    fn test_vault_operation_error_not_a_directory() {
        let err = VaultOperationError::NotADirectory {
            path: "/test".to_string(),
        };
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::NotDirectory
        );
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn test_vault_operation_error_empty_path() {
        let err = VaultOperationError::EmptyPath;
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::InvalidArgument
        );
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::EINVAL);
    }

    #[test]
    fn test_vault_write_error_already_exists() {
        let err = VaultWriteError::FileAlreadyExists {
            filename: "test.txt".to_string(),
            context: VaultOpContext::new(),
        };
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::AlreadyExists
        );
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::EEXIST);
    }

    #[test]
    fn test_vault_write_error_directory_not_empty() {
        let err = VaultWriteError::DirectoryNotEmpty {
            context: VaultOpContext::new(),
        };
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::NotEmpty);
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::ENOTEMPTY);
    }

    #[test]
    fn test_vault_write_error_directory_already_exists() {
        let err = VaultWriteError::DirectoryAlreadyExists {
            name: "test".to_string(),
            context: VaultOpContext::new(),
        };
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::AlreadyExists
        );
    }

    #[test]
    fn test_vault_write_error_same_source_and_destination() {
        let err = VaultWriteError::SameSourceAndDestination {
            context: VaultOpContext::new(),
        };
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::InvalidArgument
        );
    }

    #[test]
    fn test_io_error_not_found() {
        let err = io::Error::new(io::ErrorKind::NotFound, "not found");
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::NotFound);
    }

    #[test]
    fn test_io_error_permission_denied() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::PermissionDenied
        );
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::EACCES);
    }

    #[test]
    fn test_io_error_already_exists() {
        let err = io::Error::new(io::ErrorKind::AlreadyExists, "exists");
        assert_eq!(
            VaultErrorCategory::from(&err),
            VaultErrorCategory::AlreadyExists
        );
    }

    #[test]
    fn test_io_error_other() {
        let err = io::Error::new(io::ErrorKind::Other, "other");
        assert_eq!(VaultErrorCategory::from(&err), VaultErrorCategory::IoError);
        assert_eq!(VaultErrorCategory::from(&err).to_errno(), libc::EIO);
    }

    #[test]
    fn test_io_error_to_errno() {
        let err = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(io_error_to_errno(&err), libc::ENOENT);

        let err = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(io_error_to_errno(&err), libc::EACCES);

        // Error without raw OS error returns EIO
        let err = io::Error::new(io::ErrorKind::Other, "custom error");
        assert_eq!(io_error_to_errno(&err), libc::EIO);
    }

    #[test]
    fn test_category_name() {
        assert_eq!(VaultErrorCategory::NotFound.name(), "NotFound");
        assert_eq!(VaultErrorCategory::AlreadyExists.name(), "AlreadyExists");
        assert_eq!(VaultErrorCategory::NotEmpty.name(), "NotEmpty");
        assert_eq!(VaultErrorCategory::IsDirectory.name(), "IsDirectory");
        assert_eq!(VaultErrorCategory::NotDirectory.name(), "NotDirectory");
        assert_eq!(VaultErrorCategory::InvalidArgument.name(), "InvalidArgument");
        assert_eq!(VaultErrorCategory::IoError.name(), "IoError");
        assert_eq!(
            VaultErrorCategory::PermissionDenied.name(),
            "PermissionDenied"
        );
        assert_eq!(VaultErrorCategory::NotSupported.name(), "NotSupported");
    }

    #[test]
    fn test_all_errno_mappings() {
        assert_eq!(VaultErrorCategory::NotFound.to_errno(), libc::ENOENT);
        assert_eq!(VaultErrorCategory::AlreadyExists.to_errno(), libc::EEXIST);
        assert_eq!(VaultErrorCategory::NotEmpty.to_errno(), libc::ENOTEMPTY);
        assert_eq!(VaultErrorCategory::IsDirectory.to_errno(), libc::EISDIR);
        assert_eq!(VaultErrorCategory::NotDirectory.to_errno(), libc::ENOTDIR);
        assert_eq!(VaultErrorCategory::InvalidArgument.to_errno(), libc::EINVAL);
        assert_eq!(VaultErrorCategory::IoError.to_errno(), libc::EIO);
        assert_eq!(VaultErrorCategory::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(VaultErrorCategory::NotSupported.to_errno(), libc::ENOTSUP);
    }

    #[test]
    fn test_from_owned_errors() {
        // Test that From works for owned errors too (not just references)
        let err = VaultOperationError::PathNotFound {
            path: "/test".to_string(),
        };
        let category: VaultErrorCategory = err.into();
        assert_eq!(category, VaultErrorCategory::NotFound);

        let err = VaultWriteError::DirectoryNotEmpty {
            context: VaultOpContext::new(),
        };
        let category: VaultErrorCategory = err.into();
        assert_eq!(category, VaultErrorCategory::NotEmpty);

        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let category: VaultErrorCategory = err.into();
        assert_eq!(category, VaultErrorCategory::PermissionDenied);
    }
}
