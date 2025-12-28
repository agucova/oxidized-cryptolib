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
//!
//! # Usage
//!
//! ```ignore
//! use oxidized_fuse::{CryptomatorFS, mount};
//!
//! let fs = CryptomatorFS::new(vault_path, password)?;
//! mount(fs, mountpoint, options)?;
//! ```

pub mod attr;
pub mod error;
pub mod filesystem;
pub mod handles;
pub mod inode;

pub use attr::{AttrCache, CachedAttr, DirCache, DirListingEntry};
pub use error::{FuseError, FuseResult, ToErrno};
pub use filesystem::CryptomatorFS;
pub use handles::{FuseHandle, FuseHandleTable, WriteBuffer};
pub use inode::{InodeEntry, InodeKind, InodeTable, ROOT_INODE};
