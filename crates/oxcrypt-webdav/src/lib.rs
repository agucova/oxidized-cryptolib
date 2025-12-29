//! WebDAV server backend for Cryptomator vaults.
//!
//! This crate provides a WebDAV-based mount backend as an alternative to
//! FUSE and FSKit for mounting Cryptomator vaults as filesystems.
//!
//! # How It Works
//!
//! Instead of kernel-level filesystem mounting, this backend:
//! 1. Starts a local HTTP server implementing the WebDAV protocol
//! 2. Users mount via macOS Finder (Cmd+K), Windows Explorer, or Linux file managers
//! 3. The server translates WebDAV requests to vault operations
//!
//! # Advantages
//!
//! - **No kernel extensions**: Works without macFUSE installation
//! - **No macOS version requirements**: Unlike FSKit (macOS 15.4+)
//! - **Cross-platform**: Works anywhere with a WebDAV client
//! - **Easier debugging**: Standard HTTP tools (curl, browser DevTools)
//!
//! # Example
//!
//! ```ignore
//! use oxcrypt_webdav::WebDavBackend;
//! use oxcrypt_mount::MountBackend;
//!
//! let backend = WebDavBackend::new();
//!
//! if backend.is_available() {
//!     let handle = backend.mount(
//!         "my-vault",
//!         Path::new("/path/to/vault"),
//!         "password",
//!         Path::new("/mnt/vault"),
//!     )?;
//!
//!     println!("Mount via: {}", handle.url());
//!     // ... use the mounted filesystem ...
//!
//!     handle.unmount()?;
//! }
//! ```
//!
//! # Security
//!
//! By default, the server binds to localhost (127.0.0.1) only.
//! No authentication is required since only local connections are accepted.

mod backend;
mod dir_entry;
mod error;
mod file;
mod filesystem;
mod metadata;
mod server;

// Public exports
pub use backend::{WebDavBackend, WebDavMountHandle};
pub use error::{WebDavError, WebDavResult};
pub use filesystem::CryptomatorWebDav;
pub use server::{ServerConfig, WebDavServer};
