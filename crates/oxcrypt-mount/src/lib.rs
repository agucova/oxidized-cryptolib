//! Shared utilities for Cryptomator vault mount backends.
//!
//! This crate provides common functionality shared between the FUSE, FSKit,
//! and WebDAV mount backends for Cryptomator vaults.
//!
//! # Components
//!
//! ## Backend Abstraction
//!
//! - [`MountBackend`] - Trait for mounting mechanisms (FUSE, FSKit, WebDAV, NFS)
//! - [`MountHandle`] - Handle to control a mounted filesystem's lifecycle
//! - [`BackendType`] - Enum of available backend types
//! - [`MountError`] - Error type for mount operations
//!
//! ## Implementation Utilities
//!
//! - [`WriteBuffer`] - Read-modify-write buffer for random-access file writes
//! - [`moka_cache`] - TTL-based caching backed by Moka
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
//! ## moka_cache
//!
//! Mount backends need efficient caching of file metadata to reduce repeated
//! vault operations. The [`moka_cache`] module provides:
//! - [`moka_cache::SyncTtlCache`] for synchronous contexts (FUSE, FSKit, NFS)
//! - [`moka_cache::AsyncTtlCache`] for async contexts (WebDAV with tokio)
//! - Per-entry TTL support via Moka's `Expiry` trait
//! - Negative caching (for ENOENT results)
//! - Bulk invalidation (by predicate or prefix)
//! - Thundering herd prevention via `get_with()`
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
//! use oxcrypt_mount::{WriteBuffer, VaultErrorCategory, HandleTable};
//! use oxcrypt_mount::moka_cache::SyncTtlCache;
//! use oxcrypt_core::vault::DirId;
//! use std::time::Duration;
//!
//! // Create a write buffer for a new file
//! let buffer = WriteBuffer::new_for_create(DirId::root(), "example.txt".to_string());
//!
//! // Create a cache with negative caching
//! let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_negative_cache(
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

mod backend;
mod cleanup;
mod error_category;
mod force_unmount;
mod handle_table;
mod mount_markers;
mod mount_utils;
pub mod path_mapper;
mod process_detection;
pub mod stale_detection;
pub mod stats;
mod timeout_fs;
mod write_buffer;

/// TTL-based caching backed by Moka.
///
/// Provides [`moka_cache::SyncTtlCache`] for synchronous contexts (FUSE, FSKit, NFS)
/// and [`moka_cache::AsyncTtlCache`] for async contexts (WebDAV with tokio).
pub mod moka_cache;

// Backend abstraction exports
pub use backend::{
    first_available_backend, list_backend_info, safe_sync, select_backend, BackendInfo,
    BackendType, MountBackend, MountError, MountHandle, MountOptions,
};
pub use mount_utils::{
    check_mountpoint_status, find_available_mountpoint, is_directory_readable, is_on_fuse_mount,
    is_path_accessible, MountPointError, MountPointStatus, DEFAULT_ACCESS_TIMEOUT,
};
pub use process_detection::{find_processes_using_mount, ProcessInfo};
pub use timeout_fs::{TimeoutFs, DEFAULT_FS_TIMEOUT};

// Stale mount cleanup exports
pub use cleanup::{
    cleanup_stale_mounts, cleanup_test_mounts, CleanupAction, CleanupOptions, CleanupResult,
    TrackedMountInfo, DEFAULT_CHECK_TIMEOUT,
};
pub use force_unmount::{force_unmount, lazy_unmount};
pub use mount_markers::{
    find_fuse_mounts, find_our_mounts, get_system_mounts_detailed, is_fuse_fstype, is_our_mount,
    SystemMount,
};
pub use stale_detection::{
    check_mount_status, find_orphaned_mounts, is_process_alive, MountStatus, StaleReason,
    TrackedMount,
};

// Implementation utility exports
pub use error_category::{io_error_to_errno, VaultErrorCategory};
pub use handle_table::HandleTable;
pub use stats::{ActivityStatus, CacheStats, VaultStats, VaultStatsSnapshot, format_bytes};
pub use moka_cache::{
    CacheHealth, CacheHealthThresholds, CacheWarning, CachedEntry, NegativeEntry,
    DEFAULT_NEGATIVE_TTL, DEFAULT_TTL, LOCAL_NEGATIVE_TTL, LOCAL_TTL,
};
pub use write_buffer::WriteBuffer;

/// Testing utilities for mount backend integration tests.
///
/// Provides shared test infrastructure for FUSE, FSKit, and WebDAV backends:
/// - Chunk-aware test data generators
/// - Content verification assertions
/// - Temporary vault creation
pub mod testing;
