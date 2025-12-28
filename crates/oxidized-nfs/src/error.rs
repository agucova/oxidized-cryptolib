//! Error mapping for NFS operations.
//!
//! This module converts vault errors to NFS status codes using the shared
//! `VaultErrorCategory` from `oxidized-mount-common`.

use nfsserve::nfs::nfsstat3;
use oxidized_mount_common::VaultErrorCategory;
use thiserror::Error;

/// NFS-specific errors.
#[derive(Debug, Error)]
pub enum NfsError {
    /// Invalid file handle.
    #[error("invalid file handle")]
    InvalidHandle,

    /// File ID not found in inode table.
    #[error("file ID {0} not found")]
    FileIdNotFound(u64),

    /// Not a directory.
    #[error("not a directory")]
    NotDirectory,

    /// Not a file.
    #[error("not a file")]
    NotFile,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Vault operation error.
    #[error("vault error: {0}")]
    Vault(String),

    /// Server error.
    #[error("server error: {0}")]
    Server(String),
}

impl From<NfsError> for nfsstat3 {
    fn from(e: NfsError) -> Self {
        match e {
            NfsError::InvalidHandle => nfsstat3::NFS3ERR_BADHANDLE,
            NfsError::FileIdNotFound(_) => nfsstat3::NFS3ERR_STALE,
            NfsError::NotDirectory => nfsstat3::NFS3ERR_NOTDIR,
            NfsError::NotFile => nfsstat3::NFS3ERR_ISDIR,
            NfsError::Io(_) => nfsstat3::NFS3ERR_IO,
            NfsError::Vault(_) => nfsstat3::NFS3ERR_SERVERFAULT,
            NfsError::Server(_) => nfsstat3::NFS3ERR_SERVERFAULT,
        }
    }
}

/// Converts a `VaultErrorCategory` to an NFS status code.
///
/// This uses the shared error classification from `oxidized-mount-common`,
/// ensuring consistent error handling across all mount backends.
#[inline]
pub fn category_to_nfsstat(cat: VaultErrorCategory) -> nfsstat3 {
    match cat {
        VaultErrorCategory::NotFound => nfsstat3::NFS3ERR_NOENT,
        VaultErrorCategory::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        VaultErrorCategory::NotEmpty => nfsstat3::NFS3ERR_NOTEMPTY,
        VaultErrorCategory::IsDirectory => nfsstat3::NFS3ERR_ISDIR,
        VaultErrorCategory::NotDirectory => nfsstat3::NFS3ERR_NOTDIR,
        VaultErrorCategory::InvalidArgument => nfsstat3::NFS3ERR_INVAL,
        VaultErrorCategory::IoError => nfsstat3::NFS3ERR_IO,
        VaultErrorCategory::PermissionDenied => nfsstat3::NFS3ERR_ACCES,
        VaultErrorCategory::NotSupported => nfsstat3::NFS3ERR_NOTSUPP,
    }
}

/// Converts any vault error to an NFS status code.
///
/// This is a generic wrapper that first converts the error to a
/// `VaultErrorCategory`, then to an `nfsstat3`.
#[inline]
pub fn vault_error_to_nfsstat<E>(e: &E) -> nfsstat3
where
    VaultErrorCategory: for<'a> From<&'a E>,
{
    category_to_nfsstat(VaultErrorCategory::from(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
    use oxidized_cryptolib::vault::operations::VaultOpContext;
    use std::mem::discriminant;

    /// Helper macro to compare nfsstat3 variants (nfsstat3 doesn't implement PartialEq)
    macro_rules! assert_nfsstat_eq {
        ($left:expr, $right:expr) => {
            assert_eq!(discriminant(&$left), discriminant(&$right));
        };
    }

    #[test]
    fn test_category_to_nfsstat() {
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::NotFound),
            nfsstat3::NFS3ERR_NOENT
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::AlreadyExists),
            nfsstat3::NFS3ERR_EXIST
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::NotEmpty),
            nfsstat3::NFS3ERR_NOTEMPTY
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::IsDirectory),
            nfsstat3::NFS3ERR_ISDIR
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::NotDirectory),
            nfsstat3::NFS3ERR_NOTDIR
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::InvalidArgument),
            nfsstat3::NFS3ERR_INVAL
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::IoError),
            nfsstat3::NFS3ERR_IO
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::PermissionDenied),
            nfsstat3::NFS3ERR_ACCES
        );
        assert_nfsstat_eq!(
            category_to_nfsstat(VaultErrorCategory::NotSupported),
            nfsstat3::NFS3ERR_NOTSUPP
        );
    }

    #[test]
    fn test_vault_operation_error_to_nfsstat() {
        let err = VaultOperationError::PathNotFound {
            path: "/test".to_string(),
        };
        assert_nfsstat_eq!(vault_error_to_nfsstat(&err), nfsstat3::NFS3ERR_NOENT);

        let err = VaultOperationError::NotADirectory {
            path: "/file".to_string(),
        };
        assert_nfsstat_eq!(vault_error_to_nfsstat(&err), nfsstat3::NFS3ERR_NOTDIR);

        let err = VaultOperationError::NotAFile {
            path: "/dir".to_string(),
        };
        assert_nfsstat_eq!(vault_error_to_nfsstat(&err), nfsstat3::NFS3ERR_ISDIR);
    }

    #[test]
    fn test_vault_write_error_to_nfsstat() {
        let err = VaultWriteError::FileAlreadyExists {
            filename: "test.txt".to_string(),
            context: VaultOpContext::new(),
        };
        assert_nfsstat_eq!(vault_error_to_nfsstat(&err), nfsstat3::NFS3ERR_EXIST);

        let err = VaultWriteError::DirectoryNotEmpty {
            context: VaultOpContext::new(),
        };
        assert_nfsstat_eq!(vault_error_to_nfsstat(&err), nfsstat3::NFS3ERR_NOTEMPTY);
    }

    #[test]
    fn test_nfs_error_to_nfsstat() {
        assert_nfsstat_eq!(nfsstat3::from(NfsError::InvalidHandle), nfsstat3::NFS3ERR_BADHANDLE);
        assert_nfsstat_eq!(nfsstat3::from(NfsError::FileIdNotFound(42)), nfsstat3::NFS3ERR_STALE);
        assert_nfsstat_eq!(nfsstat3::from(NfsError::NotDirectory), nfsstat3::NFS3ERR_NOTDIR);
        assert_nfsstat_eq!(nfsstat3::from(NfsError::NotFile), nfsstat3::NFS3ERR_ISDIR);
    }
}
