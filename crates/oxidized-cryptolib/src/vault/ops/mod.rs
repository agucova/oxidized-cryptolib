//! Shared operations infrastructure for vault implementations.
//!
//! This module contains the shared infrastructure used by both sync and async
//! vault operations:
//!
//! - [`core`] - `VaultCore` with shared state and pure methods
//! - [`helpers`] - Pure helper functions used by both implementations
//! - [`info_builders`] - Canonical constructors for info structs
//!
//! The actual sync and async implementations are in sibling modules:
//! - `vault::operations` (sync `VaultOperations`) - for CLI and blocking contexts
//! - `vault::operations_async` (async `VaultOperationsAsync`) - for FUSE, WebDAV, and concurrent contexts
//!
//! # Architecture
//!
//! ```text
//! VaultOperations (sync)          VaultOperationsAsync (async)
//!         │                                │
//!         ├── ops::VaultCore ◄─────────────┤
//!         │      │                         │
//!         │      ├── ops::helpers          │
//!         │      ├── ops::info_builders    │
//!         │      └── (pure functions)      │
//!         │                                │
//!         └── std::fs                      └── tokio::fs + locking
//! ```

pub mod core;
pub mod helpers;
pub mod info_builders;

// Re-export commonly used types from core
pub use core::{VaultCore, DEFAULT_SHORTENING_THRESHOLD};
pub use helpers::{
    calculate_directory_lookup_paths, calculate_directory_storage_path,
    calculate_file_lookup_paths, classify_entry_format, extract_encrypted_base_name,
    is_regular_entry, is_shortened_entry, needs_shortening, parse_path_components,
    C9rEntryType, EntryFormat, EntryPaths, StoragePathError, CONTENTS_FILE, DIR_MARKER,
    NAME_FILE, SYMLINK_MARKER,
};
pub use info_builders::{build_directory_info, build_file_info, build_symlink_info};
