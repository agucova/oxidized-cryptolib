//! FSKit filesystem for Cryptomator vaults on macOS 15.4+.
//!
//! This crate provides a native macOS filesystem implementation for Cryptomator vaults
//! using Apple's FSKit framework. It requires macOS 15.4 or later and the FSKitBridge
//! application to be installed and enabled.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         macOS (15.4+)                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  VFS (Kernel)                                                   │
//! │       │ XPC                                                     │
//! │       ▼                                                         │
//! │  FSKitBridge.app/FSKitExt.appex (Swift, sandboxed)              │
//! │       │ TCP + Protobuf (127.0.0.1:35367)                        │
//! │       ▼                                                         │
//! │  oxidized-fskit (Rust)                                          │
//! │       │                                                         │
//! │       ▼                                                         │
//! │  VaultOperationsAsync (oxidized-cryptolib)                      │
//! │       │                                                         │
//! │       ▼                                                         │
//! │  Cryptomator Vault (encrypted files)                            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Prerequisites
//!
//! 1. macOS 15.4 or later
//! 2. FSKitBridge.app installed from [releases](https://github.com/debox-network/FSKitBridge/releases)
//! 3. FSKit extension enabled in System Settings:
//!    - Go to System Settings → General → Login Items & Extensions
//!    - Enable "File System Extensions"
//!    - Enable "FSKitBridge" extension
//!
//! # Usage
//!
//! ```ignore
//! use oxidized_fskit::CryptomatorFSKit;
//! use fskit_rs::{mount, MountOptions};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Open the vault
//!     let fs = CryptomatorFSKit::new("/path/to/vault", "password")?;
//!
//!     // Mount it
//!     let opts = MountOptions {
//!         mount_point: "/tmp/vault".into(),
//!         ..Default::default()
//!     };
//!     let session = mount(fs, opts).await?;
//!
//!     // Keep mounted until dropped
//!     tokio::signal::ctrl_c().await?;
//!     drop(session);
//!
//!     Ok(())
//! }
//! ```
//!
//! # CLI Tool
//!
//! The `oxmount-fskit` binary provides a command-line interface:
//!
//! ```text
//! oxmount-fskit /path/to/vault --mount-point /tmp/vault
//! ```

pub mod attr;
pub mod backend;
pub mod error;
pub mod filesystem;
pub mod item_table;
pub mod setup;

pub use backend::{FSKitBackend, FSKitMountHandle};
pub use filesystem::CryptomatorFSKit;
pub use item_table::{ItemEntry, ItemKind, ItemTable, ROOT_ITEM_ID};
pub use setup::{BridgeStatus, get_status, get_status_sync};
