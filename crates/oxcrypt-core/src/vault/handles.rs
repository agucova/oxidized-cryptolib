//! File handle table for FUSE compatibility.
//!
//! This module provides a thread-safe handle table for tracking open files,
//! mapping 64-bit handles to their underlying readers or writers.
//! This pattern is commonly used in FUSE filesystem implementations.
//!
//! # Example
//!
//! ```ignore
//! use oxcrypt_core::vault::handles::{VaultHandleTable, OpenHandle};
//!
//! let table = VaultHandleTable::new();
//!
//! // Insert a reader and get a handle
//! let handle = table.insert(OpenHandle::Reader(reader));
//!
//! // Later, retrieve and use it
//! if let Some(mut entry) = table.get_mut(handle) {
//!     if let OpenHandle::Reader(ref mut reader) = *entry {
//!         let data = reader.read_range(0, 100).await?;
//!     }
//! }
//!
//! // On close, remove the handle
//! table.remove(handle);
//! ```

use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::fs::streaming::{VaultFileReader, VaultFileWriter};

/// An open file handle, either a reader or a writer.
#[derive(Debug)]
pub enum OpenHandle {
    /// A file opened for reading (random access supported).
    Reader(VaultFileReader),
    /// A file opened for writing (streaming/sequential writes).
    Writer(VaultFileWriter),
}

impl OpenHandle {
    /// Check if this is a reader.
    pub fn is_reader(&self) -> bool {
        matches!(self, OpenHandle::Reader(_))
    }

    /// Check if this is a writer.
    pub fn is_writer(&self) -> bool {
        matches!(self, OpenHandle::Writer(_))
    }

    /// Get a reference to the reader, if this is a reader.
    pub fn as_reader(&self) -> Option<&VaultFileReader> {
        match self {
            OpenHandle::Reader(r) => Some(r),
            OpenHandle::Writer(_) => None,
        }
    }

    /// Get a mutable reference to the reader, if this is a reader.
    pub fn as_reader_mut(&mut self) -> Option<&mut VaultFileReader> {
        match self {
            OpenHandle::Reader(r) => Some(r),
            OpenHandle::Writer(_) => None,
        }
    }

    /// Get a reference to the writer, if this is a writer.
    pub fn as_writer(&self) -> Option<&VaultFileWriter> {
        match self {
            OpenHandle::Writer(w) => Some(w),
            OpenHandle::Reader(_) => None,
        }
    }

    /// Get a mutable reference to the writer, if this is a writer.
    pub fn as_writer_mut(&mut self) -> Option<&mut VaultFileWriter> {
        match self {
            OpenHandle::Writer(w) => Some(w),
            OpenHandle::Reader(_) => None,
        }
    }

    /// Consume this handle and return the reader, if this is a reader.
    pub fn into_reader(self) -> Option<VaultFileReader> {
        match self {
            OpenHandle::Reader(r) => Some(r),
            OpenHandle::Writer(_) => None,
        }
    }

    /// Consume this handle and return the writer, if this is a writer.
    pub fn into_writer(self) -> Option<VaultFileWriter> {
        match self {
            OpenHandle::Writer(w) => Some(w),
            OpenHandle::Reader(_) => None,
        }
    }
}

/// Thread-safe table mapping 64-bit handles to open files.
///
/// Handles are assigned incrementally and are unique for the lifetime
/// of the table. This provides a simple, fast lookup mechanism suitable
/// for FUSE's file handle (`fh`) field.
#[derive(Debug)]
pub struct VaultHandleTable {
    /// The handle map.
    handles: DashMap<u64, OpenHandle>,
    /// Next handle ID to assign (monotonically increasing).
    next_id: AtomicU64,
}

impl Default for VaultHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultHandleTable {
    /// Create a new empty handle table.
    ///
    /// Handle IDs start at 1 (0 is often used as an invalid/null handle).
    pub fn new() -> Self {
        Self {
            handles: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Insert a handle and return its ID.
    ///
    /// The ID is guaranteed to be unique for the lifetime of this table.
    pub fn insert(&self, handle: OpenHandle) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(id, handle);
        id
    }

    /// Get a reference to a handle by ID.
    ///
    /// Returns `None` if the handle doesn't exist.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, OpenHandle>> {
        self.handles.get(&id)
    }

    /// Get a mutable reference to a handle by ID.
    ///
    /// Returns `None` if the handle doesn't exist.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, OpenHandle>> {
        self.handles.get_mut(&id)
    }

    /// Remove a handle by ID and return it.
    ///
    /// Returns `None` if the handle doesn't exist.
    /// The returned handle should typically be dropped or finalized.
    pub fn remove(&self, id: u64) -> Option<OpenHandle> {
        self.handles.remove(&id).map(|(_, handle)| handle)
    }

    /// Check if a handle exists.
    pub fn contains(&self, id: u64) -> bool {
        self.handles.contains_key(&id)
    }

    /// Get the number of open handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Clear all handles from the table.
    ///
    /// This will drop all open readers and writers.
    /// Writers that haven't been finalized will abort their writes.
    pub fn clear(&self) {
        self.handles.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Note: We can't easily create VaultFileReader/VaultFileWriter in tests
    // without a real vault, so we test the table mechanics with a mock approach
    // using the public API indirectly through integration tests.

    #[test]
    fn test_handle_table_new() {
        let table = VaultHandleTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_handle_table_default() {
        let table = VaultHandleTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        // Default should start IDs at 1
        assert_eq!(table.next_id.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_handle_id_increments() {
        let table = VaultHandleTable::new();

        // We can't insert actual handles without a vault, but we can check
        // the atomic counter behavior
        let id1 = table.next_id.fetch_add(1, Ordering::Relaxed);
        let id2 = table.next_id.fetch_add(1, Ordering::Relaxed);
        let id3 = table.next_id.fetch_add(1, Ordering::Relaxed);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_handle_table_contains() {
        let table = VaultHandleTable::new();
        assert!(!table.contains(1));
        assert!(!table.contains(0));
        assert!(!table.contains(999));
    }

    #[test]
    fn test_handle_table_get_nonexistent() {
        let table = VaultHandleTable::new();
        assert!(table.get(1).is_none());
        assert!(table.get_mut(1).is_none());
        assert!(table.remove(1).is_none());
    }

    #[test]
    fn test_handle_table_clear_empty() {
        let table = VaultHandleTable::new();
        // Clear on empty table should not panic
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn test_handle_id_starts_at_one() {
        // Handle IDs should start at 1, not 0 (0 is often used as invalid/null handle)
        let table = VaultHandleTable::new();
        assert_eq!(table.next_id.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_handle_id_monotonically_increasing() {
        let table = VaultHandleTable::new();

        // Simulate multiple insertions by incrementing the counter
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(table.next_id.fetch_add(1, Ordering::Relaxed));
        }

        // Verify all IDs are unique
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        sorted_ids.dedup();
        assert_eq!(ids.len(), sorted_ids.len(), "All handle IDs should be unique");

        // Verify IDs are in ascending order
        for i in 1..ids.len() {
            assert!(
                ids[i] > ids[i - 1],
                "Handle IDs should be monotonically increasing"
            );
        }
    }

    #[test]
    fn test_concurrent_id_generation() {
        use std::thread;

        let table = Arc::new(VaultHandleTable::new());
        let mut handles = Vec::new();

        // Spawn multiple threads to fetch IDs concurrently
        for _ in 0..10 {
            let table_clone = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                let mut thread_ids = Vec::new();
                for _ in 0..100 {
                    thread_ids.push(table_clone.next_id.fetch_add(1, Ordering::Relaxed));
                }
                thread_ids
            }));
        }

        // Collect all IDs
        let mut all_ids: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        // Verify all IDs are unique (no duplicates from concurrent access)
        let count_before = all_ids.len();
        all_ids.sort_unstable();
        all_ids.dedup();
        assert_eq!(
            count_before,
            all_ids.len(),
            "Concurrent ID generation should not produce duplicates"
        );
    }

    #[test]
    fn test_handle_table_debug_format() {
        let table = VaultHandleTable::new();
        let debug_str = format!("{table:?}");
        assert!(debug_str.contains("VaultHandleTable"));
        assert!(debug_str.contains("handles"));
        assert!(debug_str.contains("next_id"));
    }

    #[test]
    fn test_remove_nonexistent_returns_none() {
        let table = VaultHandleTable::new();

        // Try to remove handles that don't exist
        assert!(table.remove(0).is_none());
        assert!(table.remove(1).is_none());
        assert!(table.remove(u64::MAX).is_none());

        // Table should still be empty
        assert!(table.is_empty());
    }

    #[test]
    fn test_contains_after_id_generation() {
        let table = VaultHandleTable::new();

        // Generate an ID (simulating what insert would do)
        let id = table.next_id.fetch_add(1, Ordering::Relaxed);

        // But since we didn't actually insert, contains should be false
        assert!(!table.contains(id));
    }
}

/// Integration tests that require creating actual file handles
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::crypto::keys::MasterKey;
    use crate::fs::streaming::VaultFileWriter;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_master_key() -> MasterKey {
        // Create a deterministic test key
        let enc_key = [0x42u8; 32];
        let mac_key = [0x43u8; 32];
        MasterKey::new(enc_key, mac_key).expect("Failed to create master key")
    }

    async fn create_test_writer(
        temp_dir: &TempDir,
        filename: &str,
        master_key: &MasterKey,
    ) -> VaultFileWriter {
        let dest = temp_dir.path().join(filename);
        VaultFileWriter::create(dest, master_key)
            .await
            .expect("Failed to create writer")
    }

    #[tokio::test]
    async fn test_insert_and_get_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        // Create a writer and insert it
        let writer = create_test_writer(&temp_dir, "test.c9r", &master_key).await;
        let handle_id = table.insert(OpenHandle::Writer(writer));

        // Verify handle exists
        assert!(table.contains(handle_id));
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        // Verify we can get the handle
        let handle_ref = table.get(handle_id);
        assert!(handle_ref.is_some());
        let handle = handle_ref.unwrap();
        assert!(handle.is_writer());
        assert!(!handle.is_reader());

        // Clean up - remove and abort the writer
        drop(handle);
        let removed = table.remove(handle_id);
        assert!(removed.is_some());
        if let Some(OpenHandle::Writer(w)) = removed {
            w.abort().await.expect("Failed to abort writer");
        }
    }

    #[tokio::test]
    async fn test_insert_multiple_handles() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        // Insert multiple writers
        let mut handle_ids = Vec::new();
        for i in 0..5 {
            let writer =
                create_test_writer(&temp_dir, &format!("test_{i}.c9r"), &master_key).await;
            let id = table.insert(OpenHandle::Writer(writer));
            handle_ids.push(id);
        }

        // All handles should exist
        assert_eq!(table.len(), 5);
        for &id in &handle_ids {
            assert!(table.contains(id));
        }

        // All IDs should be unique
        let mut sorted_ids = handle_ids.clone();
        sorted_ids.sort_unstable();
        sorted_ids.dedup();
        assert_eq!(handle_ids.len(), sorted_ids.len());

        // Clean up
        for id in handle_ids {
            if let Some(OpenHandle::Writer(w)) = table.remove(id) {
                w.abort().await.expect("Failed to abort writer");
            }
        }
    }

    #[tokio::test]
    async fn test_get_mut_and_modify() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        let writer = create_test_writer(&temp_dir, "test.c9r", &master_key).await;
        let handle_id = table.insert(OpenHandle::Writer(writer));

        // Get mutable reference and use the writer
        {
            let mut handle_ref = table.get_mut(handle_id).expect("Handle should exist");
            if let Some(writer) = handle_ref.as_writer_mut() {
                // Write some data
                writer.write(b"Hello, World!").await.expect("Write failed");
            }
        }

        // Clean up
        if let Some(OpenHandle::Writer(w)) = table.remove(handle_id) {
            w.abort().await.expect("Failed to abort writer");
        }
    }

    #[tokio::test]
    async fn test_remove_returns_handle() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        let writer = create_test_writer(&temp_dir, "test.c9r", &master_key).await;
        let handle_id = table.insert(OpenHandle::Writer(writer));

        // Remove the handle
        let removed = table.remove(handle_id);
        assert!(removed.is_some());

        // Verify table is now empty
        assert!(table.is_empty());
        assert!(!table.contains(handle_id));

        // Trying to remove again should return None
        assert!(table.remove(handle_id).is_none());

        // Clean up the removed writer
        if let Some(OpenHandle::Writer(w)) = removed {
            w.abort().await.expect("Failed to abort writer");
        }
    }

    #[tokio::test]
    async fn test_clear_removes_all_handles() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        // Insert multiple handles
        let mut handle_ids = Vec::new();
        for i in 0..3 {
            let writer =
                create_test_writer(&temp_dir, &format!("test_{i}.c9r"), &master_key).await;
            handle_ids.push(table.insert(OpenHandle::Writer(writer)));
        }

        assert_eq!(table.len(), 3);

        // Clear all handles (this will drop the writers without proper cleanup,
        // but the temp files will be cleaned up by the drop impl)
        table.clear();

        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        // All handles should be gone
        for id in handle_ids {
            assert!(!table.contains(id));
            assert!(table.get(id).is_none());
        }
    }

    #[tokio::test]
    async fn test_handle_ids_never_reused() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        // Insert and remove handles, tracking all IDs
        let mut all_ids = Vec::new();

        for i in 0..5 {
            let writer =
                create_test_writer(&temp_dir, &format!("test_{i}.c9r"), &master_key).await;
            let id = table.insert(OpenHandle::Writer(writer));
            all_ids.push(id);

            // Remove immediately
            if let Some(OpenHandle::Writer(w)) = table.remove(id) {
                w.abort().await.expect("Failed to abort");
            }
        }

        // Insert more handles
        for i in 5..10 {
            let writer =
                create_test_writer(&temp_dir, &format!("test_{i}.c9r"), &master_key).await;
            let id = table.insert(OpenHandle::Writer(writer));
            all_ids.push(id);

            if let Some(OpenHandle::Writer(w)) = table.remove(id) {
                w.abort().await.expect("Failed to abort");
            }
        }

        // All IDs should be unique (no reuse)
        let mut sorted_ids = all_ids.clone();
        sorted_ids.sort_unstable();
        sorted_ids.dedup();
        assert_eq!(
            all_ids.len(),
            sorted_ids.len(),
            "Handle IDs should never be reused"
        );
    }

    // NOTE: test_concurrent_insert_remove is disabled because MasterKey uses RefCell
    // internally which is not Send/Sync. This test would need MasterKey to be redesigned
    // to use RwLock or similar for concurrent use cases.
    //
    // TODO: Redesign MasterKey for thread-safety and re-enable this test

    #[tokio::test]
    async fn test_interleaved_insert_get_remove() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        // Insert first handle
        let writer1 = create_test_writer(&temp_dir, "file1.c9r", &master_key).await;
        let id1 = table.insert(OpenHandle::Writer(writer1));

        // Insert second handle
        let writer2 = create_test_writer(&temp_dir, "file2.c9r", &master_key).await;
        let id2 = table.insert(OpenHandle::Writer(writer2));

        // Get first handle (immutable)
        assert!(table.get(id1).is_some());

        // Insert third handle while first is accessible
        let writer3 = create_test_writer(&temp_dir, "file3.c9r", &master_key).await;
        let id3 = table.insert(OpenHandle::Writer(writer3));

        // Remove second handle
        let removed2 = table.remove(id2);
        assert!(removed2.is_some());
        if let Some(OpenHandle::Writer(w)) = removed2 {
            w.abort().await.expect("Failed to abort");
        }

        // First and third should still exist
        assert!(table.contains(id1));
        assert!(!table.contains(id2));
        assert!(table.contains(id3));
        assert_eq!(table.len(), 2);

        // Cleanup
        for id in [id1, id3] {
            if let Some(OpenHandle::Writer(w)) = table.remove(id) {
                w.abort().await.expect("Failed to abort");
            }
        }
    }

    #[tokio::test]
    async fn test_table_with_shared_arc() {
        // Test that table can be shared across multiple references
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = Arc::new(VaultHandleTable::new());

        // Insert using one reference
        let writer = create_test_writer(&temp_dir, "shared.c9r", &master_key).await;
        let id = table.insert(OpenHandle::Writer(writer));

        // Get using another reference
        let table_ref = Arc::clone(&table);
        assert!(table_ref.contains(id));
        assert_eq!(table_ref.len(), 1);

        // Remove using yet another reference
        let table_ref2 = Arc::clone(&table);
        let removed = table_ref2.remove(id);
        assert!(removed.is_some());

        // All references should see the same state
        assert!(!table.contains(id));
        assert!(!table_ref.contains(id));
        assert!(table.is_empty());

        if let Some(OpenHandle::Writer(w)) = removed {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_remove_same_id_twice() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        let writer = create_test_writer(&temp_dir, "test.c9r", &master_key).await;
        let id = table.insert(OpenHandle::Writer(writer));

        // First remove should succeed
        let removed = table.remove(id);
        assert!(removed.is_some());

        // Second remove should return None
        assert!(table.remove(id).is_none());

        // Third remove should also return None
        assert!(table.remove(id).is_none());

        if let Some(OpenHandle::Writer(w)) = removed {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_get_after_remove() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let master_key = create_test_master_key();
        let table = VaultHandleTable::new();

        let writer = create_test_writer(&temp_dir, "test.c9r", &master_key).await;
        let id = table.insert(OpenHandle::Writer(writer));

        // Get should work before remove
        assert!(table.get(id).is_some());
        assert!(table.get_mut(id).is_some());

        // Remove the handle
        let removed = table.remove(id);

        // Get should fail after remove
        assert!(table.get(id).is_none());
        assert!(table.get_mut(id).is_none());

        if let Some(OpenHandle::Writer(w)) = removed {
            w.abort().await.expect("Failed to abort");
        }
    }
}

/// Tests for the OpenHandle enum methods
#[cfg(test)]
mod open_handle_tests {
    use super::*;
    use crate::crypto::keys::MasterKey;
    use crate::fs::streaming::VaultFileWriter;
    use tempfile::TempDir;

    fn create_test_master_key() -> MasterKey {
        let enc_key = [0x42u8; 32];
        let mac_key = [0x43u8; 32];
        MasterKey::new(enc_key, mac_key).expect("Failed to create master key")
    }

    async fn create_test_writer(temp_dir: &TempDir, filename: &str) -> VaultFileWriter {
        let master_key = create_test_master_key();
        let dest = temp_dir.path().join(filename);
        VaultFileWriter::create(dest, &master_key)
            .await
            .expect("Failed to create writer")
    }

    #[tokio::test]
    async fn test_open_handle_is_reader_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let handle = OpenHandle::Writer(writer);

        assert!(!handle.is_reader());
        assert!(handle.is_writer());

        // Clean up
        if let OpenHandle::Writer(w) = handle {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_open_handle_as_reader_on_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let handle = OpenHandle::Writer(writer);

        // as_reader should return None for a Writer
        assert!(handle.as_reader().is_none());

        // as_writer should return Some for a Writer
        assert!(handle.as_writer().is_some());

        // Clean up
        if let OpenHandle::Writer(w) = handle {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_open_handle_as_reader_mut_on_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let mut handle = OpenHandle::Writer(writer);

        // as_reader_mut should return None for a Writer
        assert!(handle.as_reader_mut().is_none());

        // as_writer_mut should return Some for a Writer
        assert!(handle.as_writer_mut().is_some());

        // Clean up
        if let OpenHandle::Writer(w) = handle {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_open_handle_into_reader_on_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let handle = OpenHandle::Writer(writer);

        // into_reader should return None for a Writer
        // This also tests that the handle is consumed
        let reader_opt = handle.into_reader();
        assert!(reader_opt.is_none());
        // handle is now consumed, can't use it anymore
    }

    #[tokio::test]
    async fn test_open_handle_into_writer_on_writer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let handle = OpenHandle::Writer(writer);

        // into_writer should return Some for a Writer
        let writer_opt = handle.into_writer();
        assert!(writer_opt.is_some());

        // Clean up
        if let Some(w) = writer_opt {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_open_handle_debug_format() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let handle = OpenHandle::Writer(writer);
        let debug_str = format!("{handle:?}");

        // Should contain "Writer" for a Writer handle
        assert!(debug_str.contains("Writer"));

        // Clean up
        if let OpenHandle::Writer(w) = handle {
            w.abort().await.expect("Failed to abort");
        }
    }

    #[tokio::test]
    async fn test_open_handle_as_writer_allows_write() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let writer = create_test_writer(&temp_dir, "test.c9r").await;

        let mut handle = OpenHandle::Writer(writer);

        // Use as_writer_mut to write data
        if let Some(w) = handle.as_writer_mut() {
            let bytes_written = w.write(b"Hello, World!").await.expect("Write failed");
            assert_eq!(bytes_written, 13);
        } else {
            panic!("Expected Writer handle");
        }

        // Clean up
        if let OpenHandle::Writer(w) = handle {
            w.abort().await.expect("Failed to abort");
        }
    }
}
