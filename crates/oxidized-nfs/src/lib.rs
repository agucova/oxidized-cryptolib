//! NFS mount backend for Cryptomator vaults.
//!
//! This crate provides an NFS-based mount backend for Cryptomator vaults using
//! the `nfsserve` crate. It follows the same architecture as `oxidized-fuse` and
//! `oxidized-fskit`, leveraging shared utilities from `oxidized-mount-common`.
//!
//! # Features
//!
//! - **No kernel extensions**: Works via userspace NFS server
//! - **Native async**: Uses tokio for all I/O operations
//! - **Stateless protocol**: NFSv3 simplifies server implementation
//! - **macOS/Linux support**: Uses platform mount commands
//!
//! # Architecture
//!
//! ```text
//! NFS Client (OS) ←TCP→ CryptomatorNFS (nfsserve) ←→ VaultOperationsAsync
//!                              │
//!                              ├── NfsInodeTable (fileid ↔ VaultPath)
//!                              ├── HandleTable<u64, WriteBuffer>
//!                              └── VaultErrorCategory → nfsstat3
//! ```
//!
//! # Example
//!
//! ```ignore
//! use oxidized_nfs::NfsBackend;
//! use oxidized_cryptolib::mount::MountBackend;
//!
//! let backend = NfsBackend::default();
//! if backend.is_available() {
//!     let handle = backend.mount(
//!         "my-vault",
//!         Path::new("/path/to/vault"),
//!         "password",
//!         Path::new("/mnt/vault"),
//!     )?;
//!     // Vault is now mounted at /mnt/vault via NFS
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![cfg(unix)]

mod backend;
mod error;
mod filesystem;
mod inode;

pub use backend::{NfsBackend, NfsMountHandle};
pub use error::{category_to_nfsstat, vault_error_to_nfsstat, NfsError};
pub use filesystem::CryptomatorNFS;
pub use inode::{InodeEntry, InodeKind, NfsInodeTable, ROOT_FILEID};
