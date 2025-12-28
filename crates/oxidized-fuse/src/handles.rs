//! FUSE-specific file handles with write buffering.
//!
//! This module provides write buffer support for random-access writes to vault files.
//! Since the underlying vault format uses AES-GCM with chunk numbers in AAD,
//! chunks cannot be modified individually - the entire file must be rewritten.
//!
//! The [`WriteBuffer`] implements a read-modify-write pattern:
//! 1. On open (without truncate): existing content is read into memory
//! 2. On write: data is copied into the buffer at the specified offset
//! 3. On release: if modified, the entire buffer is written back to the vault

use oxidized_cryptolib::vault::DirId;

/// A buffer for random-access writes to vault files.
///
/// This implements the read-modify-write pattern required because the vault's
/// authenticated encryption (AES-GCM with chunk numbers) prevents in-place updates.
#[derive(Debug)]
pub struct WriteBuffer {
    /// The buffered file content.
    content: Vec<u8>,
    /// Whether the buffer has been modified since creation.
    dirty: bool,
    /// Directory ID containing the file (for write-back).
    dir_id: DirId,
    /// Filename (for write-back).
    filename: String,
}

impl WriteBuffer {
    /// Create a new write buffer for a file.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - Directory containing the file
    /// * `filename` - Name of the file
    /// * `existing_content` - Current file content, or empty for new files
    pub fn new(dir_id: DirId, filename: String, existing_content: Vec<u8>) -> Self {
        Self {
            content: existing_content,
            dirty: false,
            dir_id,
            filename,
        }
    }

    /// Create a new empty write buffer (for truncated files).
    pub fn new_empty(dir_id: DirId, filename: String) -> Self {
        Self::new(dir_id, filename, Vec::new())
    }

    /// Create a new write buffer for a newly created file.
    ///
    /// Unlike `new_empty`, this marks the buffer as dirty so the file
    /// is written to the vault even if empty (creating an empty file).
    pub fn new_for_create(dir_id: DirId, filename: String) -> Self {
        Self {
            content: Vec::new(),
            dirty: true, // Must write to create the file
            dir_id,
            filename,
        }
    }

    /// Write data at the specified offset.
    ///
    /// The buffer is automatically expanded if the write extends past the current end.
    /// Gaps between the current end and the write offset are filled with zeros.
    ///
    /// # Returns
    ///
    /// The number of bytes written (always equals `data.len()`).
    pub fn write(&mut self, offset: u64, data: &[u8]) -> usize {
        let offset = offset as usize;
        let end = offset + data.len();

        // Expand buffer if needed
        if end > self.content.len() {
            self.content.resize(end, 0);
        }

        // Copy data into buffer
        self.content[offset..end].copy_from_slice(data);
        self.dirty = true;

        data.len()
    }

    /// Read data from the buffer at the specified offset.
    ///
    /// # Returns
    ///
    /// A slice of the buffer contents. Returns an empty slice if offset is past end.
    pub fn read(&self, offset: u64, size: usize) -> &[u8] {
        let offset = offset as usize;
        if offset >= self.content.len() {
            return &[];
        }
        let end = (offset + size).min(self.content.len());
        &self.content[offset..end]
    }

    /// Truncate the buffer to the specified size.
    ///
    /// If the new size is larger than current, the buffer is extended with zeros.
    pub fn truncate(&mut self, size: u64) {
        let size = size as usize;
        if size != self.content.len() {
            self.content.resize(size, 0);
            self.dirty = true;
        }
    }

    /// Get the current size of the buffer.
    pub fn len(&self) -> u64 {
        self.content.len() as u64
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Check if the buffer has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Get the directory ID.
    pub fn dir_id(&self) -> &DirId {
        &self.dir_id
    }

    /// Get the filename.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Consume the buffer and return its content.
    ///
    /// Use this when writing the buffer back to the vault.
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }

    /// Get a reference to the content for writing back.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Mark the buffer as clean (after successful write-back).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Mark the buffer as dirty (for re-marking after failed flush).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Take the content for flushing, leaving the buffer temporarily empty.
    ///
    /// This moves the Vec instead of copying it. After the write operation,
    /// call [`restore_content`] to put the content back.
    ///
    /// This is an optimization for the `flush` operation which may be called
    /// multiple times before `release`. It avoids a full Vec copy.
    pub fn take_content_for_flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.content)
    }

    /// Restore content after a successful flush.
    ///
    /// This puts the content back and marks the buffer as clean.
    pub fn restore_content(&mut self, content: Vec<u8>) {
        self.content = content;
        self.dirty = false;
    }
}

/// Handle type for FUSE file operations.
///
/// This wraps the underlying vault handles with additional buffering for writes.
#[derive(Debug)]
pub enum FuseHandle {
    /// Read-only handle using streaming reader.
    Reader(oxidized_cryptolib::fs::streaming::VaultFileReader),

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
    pub fn as_reader_mut(&mut self) -> Option<&mut oxidized_cryptolib::fs::streaming::VaultFileReader> {
        match self {
            FuseHandle::Reader(r) => Some(r),
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
/// Maps 64-bit handles to their underlying file operations.
#[derive(Debug)]
pub struct FuseHandleTable {
    /// The handle map.
    handles: dashmap::DashMap<u64, FuseHandle>,
    /// Next handle ID to assign.
    next_id: std::sync::atomic::AtomicU64,
}

impl Default for FuseHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseHandleTable {
    /// Create a new empty handle table.
    pub fn new() -> Self {
        Self {
            handles: dashmap::DashMap::new(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Insert a handle and return its ID.
    pub fn insert(&self, handle: FuseHandle) -> u64 {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.handles.insert(id, handle);
        id
    }

    /// Get a mutable reference to a handle by ID.
    pub fn get_mut(&self, id: u64) -> Option<dashmap::mapref::one::RefMut<'_, u64, FuseHandle>> {
        self.handles.get_mut(&id)
    }

    /// Remove a handle by ID and return it.
    pub fn remove(&self, id: u64) -> Option<FuseHandle> {
        self.handles.remove(&id).map(|(_, handle)| handle)
    }

    /// Get the number of open handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir_id() -> DirId {
        DirId::from_raw("test-dir-id")
    }

    #[test]
    fn test_write_buffer_new() {
        let buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), vec![1, 2, 3]);
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_dirty());
        assert_eq!(buf.filename(), "test.txt");
    }

    #[test]
    fn test_write_buffer_new_empty() {
        let buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(!buf.is_dirty());
    }

    #[test]
    fn test_write_buffer_new_for_create() {
        // new_for_create marks buffer as dirty even when empty
        // so the file will be written to vault on release
        let buf = WriteBuffer::new_for_create(test_dir_id(), "new_file.txt".to_string());
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(buf.is_dirty()); // Key difference from new_empty
        assert_eq!(buf.filename(), "new_file.txt");
    }

    #[test]
    fn test_write_buffer_write_at_start() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), vec![0; 10]);
        let written = buf.write(0, b"hello");
        assert_eq!(written, 5);
        assert!(buf.is_dirty());
        assert_eq!(&buf.content()[..5], b"hello");
    }

    #[test]
    fn test_write_buffer_write_in_middle() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), vec![0; 10]);
        let written = buf.write(3, b"abc");
        assert_eq!(written, 3);
        assert_eq!(&buf.content()[3..6], b"abc");
    }

    #[test]
    fn test_write_buffer_write_extends_buffer() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), vec![1, 2, 3]);
        let written = buf.write(5, b"xyz");
        assert_eq!(written, 3);
        assert_eq!(buf.len(), 8);
        // Original content preserved
        assert_eq!(&buf.content()[..3], &[1, 2, 3]);
        // Gap filled with zeros
        assert_eq!(&buf.content()[3..5], &[0, 0]);
        // New content
        assert_eq!(&buf.content()[5..8], b"xyz");
    }

    #[test]
    fn test_write_buffer_read() {
        let buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hello world".to_vec());
        assert_eq!(buf.read(0, 5), b"hello");
        assert_eq!(buf.read(6, 5), b"world");
        assert_eq!(buf.read(6, 100), b"world"); // Clamped to end
    }

    #[test]
    fn test_write_buffer_read_past_end() {
        let buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hello".to_vec());
        assert_eq!(buf.read(100, 10), b"");
    }

    #[test]
    fn test_write_buffer_truncate_smaller() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hello world".to_vec());
        buf.truncate(5);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.content(), b"hello");
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_write_buffer_truncate_larger() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hi".to_vec());
        buf.truncate(5);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.content(), &[b'h', b'i', 0, 0, 0]);
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_write_buffer_truncate_same_size() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hi".to_vec());
        buf.truncate(2);
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_dirty()); // No change, not dirty
    }

    #[test]
    fn test_write_buffer_mark_clean() {
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        buf.write(0, b"data");
        assert!(buf.is_dirty());
        buf.mark_clean();
        assert!(!buf.is_dirty());
    }

    #[test]
    fn test_write_buffer_into_content() {
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        buf.write(0, b"content");
        let content = buf.into_content();
        assert_eq!(content, b"content");
    }

    #[test]
    fn test_write_buffer_take_and_restore_content() {
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        buf.write(0, b"content");
        assert!(buf.is_dirty());

        // Take content for flush (moves Vec, doesn't copy)
        let content = buf.take_content_for_flush();
        assert_eq!(content, b"content");
        assert!(buf.is_empty()); // Buffer is empty after take

        // Simulate successful write, restore content
        buf.restore_content(content);
        assert!(!buf.is_dirty()); // Marked clean after restore
        assert_eq!(buf.content(), b"content"); // Content is back
    }

    #[test]
    fn test_fuse_handle_type_checks() {
        let write_buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let handle = FuseHandle::WriteBuffer(write_buf);
        assert!(!handle.is_reader());
        assert!(handle.is_write_buffer());
    }

    #[test]
    fn test_fuse_handle_table_operations() {
        let table = FuseHandleTable::new();
        assert!(table.is_empty());

        let buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let id = table.insert(FuseHandle::WriteBuffer(buf));

        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        let handle_ref = table.get_mut(id);
        assert!(handle_ref.is_some());
        drop(handle_ref);

        let removed = table.remove(id);
        assert!(removed.is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn test_fuse_handle_table_unique_ids() {
        let table = FuseHandleTable::new();
        let mut ids = Vec::new();

        for i in 0..10 {
            let buf = WriteBuffer::new_empty(test_dir_id(), format!("file{}.txt", i));
            ids.push(table.insert(FuseHandle::WriteBuffer(buf)));
        }

        // All IDs should be unique
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }
}
