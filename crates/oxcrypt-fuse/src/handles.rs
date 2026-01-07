//! FUSE-specific file handles with write buffering.
//!
//! This module provides handle management for FUSE file operations,
//! using the shared [`WriteBuffer`] from `oxcrypt-mount` for
//! random-access writes, and [`HandleTable`] for thread-safe handle management.

use dashmap::DashMap;
use oxcrypt_core::vault::DirId;

// Re-export shared types for convenience
pub use oxcrypt_mount::{HandleTable, WriteBuffer};

/// Handle type for FUSE file operations.
///
/// This wraps the underlying vault handles with additional buffering for writes.
#[derive(Debug)]
pub enum FuseHandle {
    /// Read-only handle using streaming reader (preferred).
    ///
    /// Opened via `open_file_unlocked()` which releases vault locks after
    /// opening the OS file handle. This allows:
    /// - Streaming reads without loading entire file into memory
    /// - No vault locks held for handle lifetime
    /// - Concurrent directory operations (unlink, rename, etc.)
    ///
    /// The OS file handle keeps data accessible even after vault-level unlink
    /// (standard POSIX behavior).
    ///
    /// Boxed to reduce enum size difference between variants.
    Reader(Box<oxcrypt_core::fs::streaming::VaultFileReaderSync>),

    /// Temporary placeholder while reader is loaned to the scheduler.
    ///
    /// When a read request is submitted to the async scheduler, the reader
    /// is temporarily moved out of the handle. This variant marks that the
    /// reader is being used and will be returned after the read completes.
    ///
    /// If a second read arrives while the first is in flight, it should
    /// return EAGAIN to indicate the resource is temporarily busy.
    ReaderLoaned,

    /// Read-only handle with in-memory buffer (legacy).
    ///
    /// Reads entire file content at open time. Only kept for potential
    /// edge cases; prefer Reader for normal operations.
    #[allow(dead_code)]
    ReadBuffer(Vec<u8>),

    /// Write handle with in-memory buffer.
    ///
    /// Uses read-modify-write pattern for random access writes.
    WriteBuffer(WriteBuffer),
}

impl FuseHandle {
    /// Check if this is a streaming reader handle.
    pub fn is_reader(&self) -> bool {
        matches!(self, FuseHandle::Reader(_))
    }

    /// Check if this is a read buffer handle.
    pub fn is_read_buffer(&self) -> bool {
        matches!(self, FuseHandle::ReadBuffer(_))
    }

    /// Check if this is a write buffer handle.
    pub fn is_write_buffer(&self) -> bool {
        matches!(self, FuseHandle::WriteBuffer(_))
    }

    /// Get a reference to the read buffer content, if this is a read buffer.
    pub fn as_read_buffer(&self) -> Option<&[u8]> {
        match self {
            FuseHandle::ReadBuffer(content) => Some(content),
            _ => None,
        }
    }

    /// Get a mutable reference to the reader, if this is a streaming reader.
    pub fn as_reader_mut(
        &mut self,
    ) -> Option<&mut oxcrypt_core::fs::streaming::VaultFileReaderSync> {
        match self {
            FuseHandle::Reader(r) => Some(r.as_mut()),
            _ => None,
        }
    }

    /// Get a mutable reference to the write buffer, if this is one.
    pub fn as_write_buffer_mut(&mut self) -> Option<&mut WriteBuffer> {
        match self {
            FuseHandle::WriteBuffer(b) => Some(b),
            _ => None,
        }
    }

    /// Consume and return the write buffer, if this is one.
    pub fn into_write_buffer(self) -> Option<WriteBuffer> {
        match self {
            FuseHandle::WriteBuffer(b) => Some(b),
            _ => None,
        }
    }
}

/// Thread-safe table for FUSE file handles.
///
/// This is a type alias for [`HandleTable`] with auto-incrementing u64 keys.
/// Maps 64-bit handle IDs to their underlying file operations.
pub type FuseHandleTable = HandleTable<u64, FuseHandle>;

/// Information about a file marked for deletion.
#[derive(Debug, Clone)]
pub struct DeferredDeletion {
    /// Directory ID containing the file
    pub dir_id: DirId,
    /// Name of the file
    pub name: String,
}

/// Tracks open handles per inode for POSIX-compliant deferred deletion.
///
/// POSIX semantics require that unlink() removes the directory entry immediately,
/// but the file itself should not be deleted until all open handles are closed.
/// This tracker maintains counts of open handles and deferred deletion state.
#[derive(Debug, Default)]
pub struct OpenHandleTracker {
    /// Maps inode -> open handle count
    open_counts: DashMap<u64, usize>,
    /// Maps inode -> deferred deletion info (if unlinked while open)
    deferred_deletions: DashMap<u64, DeferredDeletion>,
}

impl OpenHandleTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            open_counts: DashMap::new(),
            deferred_deletions: DashMap::new(),
        }
    }

    /// Increment the open handle count for an inode.
    pub fn add_handle(&self, ino: u64) {
        self.open_counts
            .entry(ino)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Decrement the open handle count for an inode and return deferred deletion info if any.
    ///
    /// Returns `Some(DeferredDeletion)` if this was the last handle and the file was unlinked.
    pub fn remove_handle(&self, ino: u64) -> Option<DeferredDeletion> {
        let mut should_delete = false;

        // Decrement count
        if let Some(mut entry) = self.open_counts.get_mut(&ino) {
            *entry -= 1;
            if *entry == 0 {
                should_delete = true;
            }
        }

        if should_delete {
            self.open_counts.remove(&ino);
            // Check if file was marked for deletion
            self.deferred_deletions.remove(&ino).map(|(_, v)| v)
        } else {
            None
        }
    }

    /// Mark a file for deletion when all handles are closed.
    ///
    /// This is called by unlink() when a file still has open handles.
    pub fn mark_for_deletion(&self, ino: u64, dir_id: DirId, name: String) {
        self.deferred_deletions
            .insert(ino, DeferredDeletion { dir_id, name });
    }

    /// Check if a file has open handles.
    pub fn has_open_handles(&self, ino: u64) -> bool {
        self.open_counts.get(&ino).is_some_and(|count| *count > 0)
    }

    /// Check if an inode is marked for deferred deletion.
    pub fn is_marked_for_deletion(&self, ino: u64) -> bool {
        self.deferred_deletions.contains_key(&ino)
    }

    /// Get the current open handle count for an inode.
    #[allow(dead_code)]
    pub fn get_count(&self, ino: u64) -> usize {
        self.open_counts.get(&ino).map_or(0, |c| *c)
    }
}

/// Extension trait for FUSE-specific handle table operations.
pub trait FuseHandleTableExt {
    /// Create a new empty handle table with auto-incrementing IDs.
    fn new_fuse() -> Self;
}

impl FuseHandleTableExt for FuseHandleTable {
    fn new_fuse() -> Self {
        HandleTable::new_auto_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_core::vault::DirId;

    fn test_dir_id() -> DirId {
        DirId::from_raw("test-dir-id")
    }

    // Note: WriteBuffer tests are in oxcrypt-mount.
    // These tests focus on FUSE-specific handle behavior.

    #[test]
    fn test_fuse_handle_type_checks() {
        let write_buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let handle = FuseHandle::WriteBuffer(write_buf);
        assert!(!handle.is_reader());
        assert!(handle.is_write_buffer());
    }

    #[test]
    fn test_fuse_handle_table_operations() {
        let table = FuseHandleTable::new_auto_id();
        assert!(table.is_empty());

        let buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let id = table.insert_auto(FuseHandle::WriteBuffer(buf));

        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        let handle_ref = table.get_mut(&id);
        assert!(handle_ref.is_some());
        drop(handle_ref);

        let removed = table.remove(&id);
        assert!(removed.is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn test_fuse_handle_table_unique_ids() {
        let table = FuseHandleTable::new_auto_id();
        let mut ids = Vec::new();

        for i in 0..10 {
            let buf = WriteBuffer::new_empty(test_dir_id(), format!("file{i}.txt"));
            ids.push(table.insert_auto(FuseHandle::WriteBuffer(buf)));
        }

        // All IDs should be unique
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn test_fuse_handle_table_ext_trait() {
        // Test the extension trait for creating FUSE handle tables
        let table = FuseHandleTable::new_fuse();
        assert!(table.is_empty());

        let buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let id = table.insert_auto(FuseHandle::WriteBuffer(buf));
        assert_eq!(id, 1); // First ID should be 1
    }
}
