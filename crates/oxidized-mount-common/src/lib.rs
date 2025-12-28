//! Shared utilities for Cryptomator vault mount backends.
//!
//! This crate provides common functionality shared between the FUSE, FSKit,
//! and WebDAV mount backends for Cryptomator vaults.
//!
//! # Components
//!
//! - [`WriteBuffer`] - Read-modify-write buffer for random-access file writes
//! - [`TtlCache`] - Generic TTL-based cache with optional negative caching
//! - [`VaultErrorCategory`] - Error classification for vault operations
//! - [`HandleTable`] - Thread-safe handle management
//!
//! # Why These Components?
//!
//! ## WriteBuffer
//!
//! Cryptomator's encryption format uses AES-GCM with chunk numbers included
//! in the AAD (Additional Authenticated Data). This means individual chunks
//! cannot be modified in place - the entire file must be rewritten.
//!
//! [`WriteBuffer`] provides a read-modify-write pattern:
//! 1. On open: read existing content into memory
//! 2. On write: modify the in-memory buffer
//! 3. On close: write the entire buffer back to the vault
//!
//! ## TtlCache
//!
//! Mount backends need efficient caching of file metadata to reduce repeated
//! vault operations. [`TtlCache`] provides:
//! - Time-based expiration (default 1 second)
//! - Negative caching (for ENOENT results)
//! - Bulk invalidation (by predicate or prefix)
//! - Automatic cleanup when threshold exceeded
//!
//! ## VaultErrorCategory
//!
//! Different backends need different error representations:
//! - FUSE/FSKit: POSIX errno values
//! - WebDAV: HTTP status codes
//!
//! [`VaultErrorCategory`] provides a unified classification that can be
//! converted to either representation.
//!
//! ## HandleTable
//!
//! All backends need to track open file handles. [`HandleTable`] provides
//! a thread-safe map with optional auto-incrementing IDs.
//!
//! # Example
//!
//! ```
//! use oxidized_mount_common::{WriteBuffer, TtlCache, VaultErrorCategory, HandleTable};
//! use oxidized_cryptolib::vault::DirId;
//! use std::time::Duration;
//!
//! // Create a write buffer for a new file
//! let buffer = WriteBuffer::new_for_create(DirId::root(), "example.txt".to_string());
//!
//! // Create a cache with negative caching
//! let cache: TtlCache<u64, String> = TtlCache::with_negative_cache(
//!     Duration::from_secs(1),
//!     Duration::from_millis(500),
//! );
//!
//! // Create a handle table with auto-incrementing IDs
//! let handles: HandleTable<u64, String> = HandleTable::new_auto_id();
//! let id = handles.insert_auto("file content".to_string());
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

mod error_category;
mod handle_table;
mod ttl_cache;
mod write_buffer;

pub use error_category::{io_error_to_errno, VaultErrorCategory};
pub use handle_table::HandleTable;
pub use ttl_cache::{CachedEntry, NegativeEntry, TtlCache, DEFAULT_NEGATIVE_TTL, DEFAULT_TTL};
pub use write_buffer::WriteBuffer;
