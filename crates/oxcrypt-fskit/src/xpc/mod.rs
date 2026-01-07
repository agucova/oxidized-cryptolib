//! XPC client for communicating with the FSKit extension.
//!
//! This module provides a high-level Rust client for the XPC service exposed by
//! the OxVaultFSExtension. It handles connection management, message serialization,
//! and provides a type-safe interface for mount operations.
//!
//! # Example
//!
//! ```no_run
//! use oxcrypt_fskit::xpc::{FskitClient, FskitError};
//! use secrecy::ExposeSecret;
//!
//! fn mount_vault() -> Result<(), FskitError> {
//!     let client = FskitClient::connect()?;
//!     let password = secrecy::SecretString::from("my-password");
//!
//!     let mount_info = client.mount(
//!         std::path::Path::new("/path/to/vault"),
//!         password,
//!     )?;
//!
//!     println!("Mounted at: {}", mount_info.mountpoint.display());
//!     Ok(())
//! }
//! ```

mod client;
mod connection;
mod error;
mod protocol;

pub use client::{FskitClient, MountInfo, VaultStats};
pub use error::FskitError;
pub use protocol::{XpcMessage, XpcResponse};
