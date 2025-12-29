//! Shared types for the FFI layer.
//!
//! These types are defined in the swift-bridge module and re-exported here
//! for convenience.

use crate::ffi;

/// File type enum.
pub type FileType = ffi::FileType;

/// File attributes.
pub type FileAttr = ffi::FileAttr;

/// Directory entry.
pub type DirEntry = ffi::DirEntry;

/// Volume statistics.
pub type VolumeStats = ffi::VolumeStats;

/// Directory enumeration result.
pub type EnumerationResult = ffi::EnumerationResult;

impl FileAttr {
    /// Creates file attributes for a regular file.
    pub fn file(item_id: u64, size: u64, uid: u32, gid: u32) -> Self {
        Self {
            item_id,
            file_type: FileType::Regular,
            size,
            mode: 0o644,
            uid,
            gid,
        }
    }

    /// Creates file attributes for a directory.
    pub fn directory(item_id: u64, uid: u32, gid: u32) -> Self {
        Self {
            item_id,
            file_type: FileType::Directory,
            size: 0,
            mode: 0o755,
            uid,
            gid,
        }
    }

    /// Creates file attributes for a symlink.
    pub fn symlink(item_id: u64, target_len: u64, uid: u32, gid: u32) -> Self {
        Self {
            item_id,
            file_type: FileType::Symlink,
            size: target_len,
            mode: 0o777,
            uid,
            gid,
        }
    }
}

impl DirEntry {
    /// Creates a new directory entry.
    pub fn new(name: String, attrs: FileAttr) -> Self {
        Self { name, attrs }
    }
}

impl VolumeStats {
    /// Creates volume stats from statvfs-like values.
    pub fn new(
        total_bytes: u64,
        available_bytes: u64,
        total_inodes: u64,
        available_inodes: u64,
        block_size: u32,
    ) -> Self {
        Self {
            total_bytes,
            available_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            total_inodes,
            available_inodes,
            block_size,
        }
    }
}

impl EnumerationResult {
    /// Creates an enumeration result with entries and next cookie.
    pub fn new(entries: Vec<DirEntry>, next_cookie: u64) -> Self {
        Self {
            entries,
            next_cookie,
        }
    }

    /// Creates an enumeration result indicating end of directory.
    pub fn end(entries: Vec<DirEntry>) -> Self {
        Self {
            entries,
            next_cookie: 0,
        }
    }
}
