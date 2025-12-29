//! Error handling and conversion to POSIX errno codes for FSKit.
//!
//! This module provides conversion from vault errors to POSIX error codes
//! that FSKit can return. It uses the shared
//! [`VaultErrorCategory`](oxidized_mount_common::VaultErrorCategory) for
//! consistent error mapping.

use fskit_rs::Error as FsKitError;
use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
use oxidized_mount_common::VaultErrorCategory;

/// Convert a VaultOperationError to a POSIX errno code.
///
/// Uses the shared [`VaultErrorCategory`] for consistent mapping.
pub fn operation_error_to_errno(err: &VaultOperationError) -> i32 {
    VaultErrorCategory::from(err).to_errno()
}

/// Convert a VaultWriteError to a POSIX errno code.
///
/// Uses the shared [`VaultErrorCategory`] for consistent mapping.
pub fn write_error_to_errno(err: &VaultWriteError) -> i32 {
    VaultErrorCategory::from(err).to_errno()
}

/// Convert VaultOperationError to FSKit error.
pub fn operation_error_to_fskit(err: VaultOperationError) -> FsKitError {
    FsKitError::Posix(operation_error_to_errno(&err))
}

/// Convert VaultWriteError to FSKit error.
pub fn write_error_to_fskit(err: VaultWriteError) -> FsKitError {
    FsKitError::Posix(write_error_to_errno(&err))
}

/// Macro to convert Result<T, VaultOperationError> to Result<T, FsKitError>.
#[macro_export]
macro_rules! map_op_err {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::error::operation_error_to_fskit(e))
    };
}

/// Macro to convert Result<T, VaultWriteError> to Result<T, FsKitError>.
#[macro_export]
macro_rules! map_write_err {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::error::write_error_to_fskit(e))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::error::{NameError, VaultOpContext};
    use oxidized_cryptolib::fs::symlink::{SymlinkContext, SymlinkError};

    // Helper to create a default VaultOpContext for testing
    fn ctx() -> VaultOpContext {
        VaultOpContext::new()
    }

    // Helper to create a default SymlinkContext for testing
    fn symlink_ctx() -> SymlinkContext {
        SymlinkContext::new()
    }

    #[test]
    fn test_operation_error_not_found_variants() {
        // All "not found" variants should map to ENOENT
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::PathNotFound {
                path: "test".into()
            }),
            libc::ENOENT
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::FileNotFound {
                filename: "test".into(),
                context: ctx(),
            }),
            libc::ENOENT
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::DirectoryNotFound {
                name: "test".into(),
                context: ctx(),
            }),
            libc::ENOENT
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::SymlinkNotFound {
                name: "test".into(),
                context: ctx(),
            }),
            libc::ENOENT
        );
    }

    #[test]
    fn test_operation_error_type_mismatch() {
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::NotADirectory {
                path: "test".into()
            }),
            libc::ENOTDIR
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::NotAFile {
                path: "test".into()
            }),
            libc::EISDIR
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::NotASymlink {
                path: "test".into()
            }),
            libc::EINVAL
        );
    }

    #[test]
    fn test_operation_error_invalid_input() {
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::EmptyPath),
            libc::EINVAL
        );
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::Filename(NameError::DirIdHashFailed {
                dir_id: "test".into()
            })),
            libc::EINVAL
        );
    }

    #[test]
    fn test_operation_error_io_errors() {
        // InvalidVaultStructure should map to EIO
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::InvalidVaultStructure {
                reason: "test".into(),
                context: ctx(),
            }),
            libc::EIO
        );
        // Symlink errors should map to EIO
        assert_eq!(
            operation_error_to_errno(&VaultOperationError::Symlink(Box::new(
                SymlinkError::DecryptionFailed {
                    reason: "test".into(),
                    context: symlink_ctx(),
                }
            ))),
            libc::EIO
        );
    }

    #[test]
    fn test_write_error_not_found_variants() {
        assert_eq!(
            write_error_to_errno(&VaultWriteError::DirectoryNotFound {
                name: "test".into(),
                context: ctx(),
            }),
            libc::ENOENT
        );
        assert_eq!(
            write_error_to_errno(&VaultWriteError::FileNotFound {
                filename: "test".into(),
                context: ctx(),
            }),
            libc::ENOENT
        );
    }

    #[test]
    fn test_write_error_already_exists() {
        assert_eq!(
            write_error_to_errno(&VaultWriteError::FileAlreadyExists {
                filename: "test".into(),
                context: ctx(),
            }),
            libc::EEXIST
        );
        assert_eq!(
            write_error_to_errno(&VaultWriteError::DirectoryAlreadyExists {
                name: "test".into(),
                context: ctx(),
            }),
            libc::EEXIST
        );
        assert_eq!(
            write_error_to_errno(&VaultWriteError::SymlinkAlreadyExists {
                name: "test".into(),
                context: ctx(),
            }),
            libc::EEXIST
        );
    }

    #[test]
    fn test_write_error_directory_not_empty() {
        assert_eq!(
            write_error_to_errno(&VaultWriteError::DirectoryNotEmpty { context: ctx() }),
            libc::ENOTEMPTY
        );
    }

    #[test]
    fn test_write_error_invalid_input() {
        assert_eq!(
            write_error_to_errno(&VaultWriteError::SameSourceAndDestination { context: ctx() }),
            libc::EINVAL
        );
        assert_eq!(
            write_error_to_errno(&VaultWriteError::Filename(NameError::DirIdHashFailed {
                dir_id: "test".into()
            })),
            libc::EINVAL
        );
    }

    #[test]
    fn test_write_error_io_errors() {
        assert_eq!(
            write_error_to_errno(&VaultWriteError::AtomicWriteFailed {
                reason: "test".into(),
                context: ctx(),
            }),
            libc::EIO
        );
    }

    #[test]
    fn test_operation_error_to_fskit() {
        let err = VaultOperationError::FileNotFound {
            filename: "test".into(),
            context: ctx(),
        };
        let fskit_err = operation_error_to_fskit(err);
        assert!(matches!(fskit_err, FsKitError::Posix(libc::ENOENT)));
    }

    #[test]
    fn test_write_error_to_fskit() {
        let err = VaultWriteError::FileAlreadyExists {
            filename: "test".into(),
            context: ctx(),
        };
        let fskit_err = write_error_to_fskit(err);
        assert!(matches!(fskit_err, FsKitError::Posix(libc::EEXIST)));
    }
}
