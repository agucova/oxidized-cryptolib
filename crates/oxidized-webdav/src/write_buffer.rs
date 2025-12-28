//! Write buffering for WebDAV PUT operations.
//!
//! This module provides write buffer support for random-access writes to vault files.
//! Since the underlying vault format uses AES-GCM with chunk numbers in AAD,
//! chunks cannot be modified individually - the entire file must be rewritten.
//!
//! The pattern is identical to the FUSE write buffer implementation.

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
}

/// Thread-safe table for WebDAV write buffers.
///
/// Maps path strings to their write buffers.
#[derive(Debug, Default)]
pub struct WriteBufferTable {
    /// The buffer map (path -> buffer).
    buffers: dashmap::DashMap<String, WriteBuffer>,
}

impl WriteBufferTable {
    /// Create a new empty buffer table.
    pub fn new() -> Self {
        Self {
            buffers: dashmap::DashMap::new(),
        }
    }

    /// Insert a buffer for a path.
    pub fn insert(&self, path: String, buffer: WriteBuffer) {
        self.buffers.insert(path, buffer);
    }

    /// Get a mutable reference to a buffer by path.
    pub fn get_mut(
        &self,
        path: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, WriteBuffer>> {
        self.buffers.get_mut(path)
    }

    /// Remove a buffer by path and return it.
    pub fn remove(&self, path: &str) -> Option<WriteBuffer> {
        self.buffers.remove(path).map(|(_, buffer)| buffer)
    }

    /// Check if a buffer exists for a path.
    pub fn contains(&self, path: &str) -> bool {
        self.buffers.contains_key(path)
    }

    /// Get the number of active buffers.
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
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
    fn test_write_buffer_write() {
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        let written = buf.write(0, b"hello");
        assert_eq!(written, 5);
        assert!(buf.is_dirty());
        assert_eq!(buf.content(), b"hello");
    }

    #[test]
    fn test_write_buffer_write_extends() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), vec![1, 2, 3]);
        buf.write(5, b"xyz");
        assert_eq!(buf.len(), 8);
        // Gap filled with zeros
        assert_eq!(&buf.content()[3..5], &[0, 0]);
    }

    #[test]
    fn test_write_buffer_read() {
        let buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hello world".to_vec());
        assert_eq!(buf.read(0, 5), b"hello");
        assert_eq!(buf.read(6, 5), b"world");
        assert_eq!(buf.read(100, 10), b""); // Past end
    }

    #[test]
    fn test_write_buffer_truncate() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"hello world".to_vec());
        buf.truncate(5);
        assert_eq!(buf.content(), b"hello");
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_write_buffer_table() {
        let table = WriteBufferTable::new();
        assert!(table.is_empty());

        let buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        table.insert("/test.txt".to_string(), buf);

        assert_eq!(table.len(), 1);
        assert!(table.contains("/test.txt"));

        let removed = table.remove("/test.txt");
        assert!(removed.is_some());
        assert!(table.is_empty());
    }
}
