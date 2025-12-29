//! Error handling and conversion for the FFI layer.

use crate::ffi;
use oxidized_cryptolib::error::{VaultOperationError, VaultWriteError};
use oxidized_mount_common::VaultErrorCategory;

/// FFI-safe error type that maps to POSIX errno values.
pub type FsError = ffi::FsError;

impl FsError {
    /// Converts this error to a POSIX errno value.
    pub fn to_errno(&self) -> i32 {
        match self {
            FsError::NotFound => libc::ENOENT,
            FsError::AlreadyExists => libc::EEXIST,
            FsError::NotEmpty => libc::ENOTEMPTY,
            FsError::IsDirectory => libc::EISDIR,
            FsError::NotDirectory => libc::ENOTDIR,
            FsError::InvalidArgument => libc::EINVAL,
            FsError::IoError => libc::EIO,
            FsError::PermissionDenied => libc::EACCES,
            FsError::NotSupported => libc::ENOTSUP,
        }
    }
}

impl From<VaultOperationError> for FsError {
    fn from(e: VaultOperationError) -> Self {
        VaultErrorCategory::from(&e).into()
    }
}

impl From<VaultWriteError> for FsError {
    fn from(e: VaultWriteError) -> Self {
        VaultErrorCategory::from(&e).into()
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        VaultErrorCategory::from(&e).into()
    }
}

impl From<VaultErrorCategory> for FsError {
    fn from(cat: VaultErrorCategory) -> Self {
        match cat {
            VaultErrorCategory::NotFound => FsError::NotFound,
            VaultErrorCategory::AlreadyExists => FsError::AlreadyExists,
            VaultErrorCategory::NotEmpty => FsError::NotEmpty,
            VaultErrorCategory::IsDirectory => FsError::IsDirectory,
            VaultErrorCategory::NotDirectory => FsError::NotDirectory,
            VaultErrorCategory::InvalidArgument => FsError::InvalidArgument,
            VaultErrorCategory::IoError => FsError::IoError,
            VaultErrorCategory::PermissionDenied => FsError::PermissionDenied,
            VaultErrorCategory::NotSupported => FsError::NotSupported,
        }
    }
}
