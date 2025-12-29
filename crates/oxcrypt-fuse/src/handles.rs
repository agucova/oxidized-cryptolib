//! FUSE-specific file handles with write buffering.
//!
//! This module provides handle management for FUSE file operations,
//! using the shared [`WriteBuffer`] from `oxcrypt-mount` for
//! random-access writes, and [`HandleTable`] for thread-safe handle management.

// Re-export shared types for convenience
pub use oxcrypt_mount::{HandleTable, WriteBuffer};

/// Handle type for FUSE file operations.
///
/// This wraps the underlying vault handles with additional buffering for writes.
#[derive(Debug)]
pub enum FuseHandle {
    /// Read-only handle using streaming reader.
    ///
    /// Boxed to reduce enum size difference between variants.
    Reader(Box<oxcrypt_core::fs::streaming::VaultFileReader>),

    /// Write handle with in-memory buffer.
    ///
    /// Uses read-modify-write pattern for random access writes.
    WriteBuffer(WriteBuffer),
}

impl FuseHandle {
    /// Check if this is a reader handle.
    pub fn is_reader(&self) -> bool {
        matches!(self, FuseHandle::Reader(_))
    }

    /// Check if this is a write buffer handle.
    pub fn is_write_buffer(&self) -> bool {
        matches!(self, FuseHandle::WriteBuffer(_))
    }

    /// Get a mutable reference to the reader, if this is a reader.
    pub fn as_reader_mut(
        &mut self,
    ) -> Option<&mut oxcrypt_core::fs::streaming::VaultFileReader> {
        match self {
            FuseHandle::Reader(r) => Some(r.as_mut()),
            FuseHandle::WriteBuffer(_) => None,
        }
    }

    /// Get a mutable reference to the write buffer, if this is one.
    pub fn as_write_buffer_mut(&mut self) -> Option<&mut WriteBuffer> {
        match self {
            FuseHandle::WriteBuffer(b) => Some(b),
            FuseHandle::Reader(_) => None,
        }
    }

    /// Consume and return the write buffer, if this is one.
    pub fn into_write_buffer(self) -> Option<WriteBuffer> {
        match self {
            FuseHandle::WriteBuffer(b) => Some(b),
            FuseHandle::Reader(_) => None,
        }
    }
}

/// Thread-safe table for FUSE file handles.
///
/// This is a type alias for [`HandleTable`] with auto-incrementing u64 keys.
/// Maps 64-bit handle IDs to their underlying file operations.
pub type FuseHandleTable = HandleTable<u64, FuseHandle>;

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
            let buf = WriteBuffer::new_empty(test_dir_id(), format!("file{}.txt", i));
            ids.push(table.insert_auto(FuseHandle::WriteBuffer(buf)));
        }

        // All IDs should be unique
        let mut sorted = ids.clone();
        sorted.sort();
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
