//! FUSE filesystem for Cryptomator vaults.
//!
//! This crate provides a FUSE (Filesystem in Userspace) implementation
//! for mounting Cryptomator vaults as native filesystems.
//!
//! # Features
//!
//! - Full read/write support for files and directories
//! - Symlink support
//! - Attribute caching for improved performance
//! - Thread-safe concurrent access via the underlying vault lock manager
//! - Timeout-based I/O to prevent cloud storage from blocking the filesystem
//! - Background directory refresh for responsive UI with slow backends
//!
//! # Usage
//!
//! ```ignore
//! use oxcrypt_fuse::{CryptomatorFS, mount};
//!
//! let fs = CryptomatorFS::new(vault_path, password)?;
//! mount(fs, mountpoint, options)?;
//! ```

pub mod attr;
pub mod backend;
pub mod config;
pub mod error;
pub mod executor;
pub mod filesystem;
pub mod handles;
pub mod inode;

pub use attr::{AttrCache, CachedAttr, DirCache, DirListingEntry};
pub use backend::{FuseBackend, FuseMountHandle};
pub use config::MountConfig;
pub use error::{FuseError, FuseResult, ToErrno};
pub use executor::{AsyncExecutor, ExecutorError, ExecutorResult, ExecutorStats};
pub use filesystem::CryptomatorFS;
pub use handles::{FuseHandle, FuseHandleTable, WriteBuffer};
pub use inode::{InodeEntry, InodeKind, InodeTable, ROOT_INODE};
