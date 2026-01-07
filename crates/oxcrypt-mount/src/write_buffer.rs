//! Write buffer for random-access writes to vault files.
//!
//! This module provides a buffer for handling random-access writes to vault files.
//! Since the underlying vault format uses AES-GCM with chunk numbers in AAD,
//! chunks cannot be modified individually - the entire file must be rewritten.
//!
//! The [`WriteBuffer`] implements a read-modify-write pattern:
//! 1. On open (without truncate): existing content is read into memory
//! 2. On write: data is copied into the buffer at the specified offset
//! 3. On release: if modified, the entire buffer is written back to the vault

use oxcrypt_core::vault::DirId;

/// A buffer for random-access writes to vault files.
///
/// This implements the read-modify-write pattern required because the vault's
/// authenticated encryption (AES-GCM with chunk numbers) prevents in-place updates.
///
/// # Example
///
/// ```
/// use oxcrypt_mount::WriteBuffer;
/// use oxcrypt_core::vault::DirId;
///
/// // Create a buffer for a new file
/// let mut buf = WriteBuffer::new_for_create(DirId::root(), "test.txt".to_string());
///
/// // Write some data
/// buf.write(0, b"Hello, World!");
/// assert_eq!(buf.len(), 13);
/// assert!(buf.is_dirty());
///
/// // Read the data back
/// assert_eq!(buf.read(0, 5), b"Hello");
/// ```
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

    /// Create a new write buffer with pre-allocated capacity.
    ///
    /// Use this when the expected file size is known to avoid reallocations
    /// during writes. The buffer starts empty but has space pre-allocated.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - Directory containing the file
    /// * `filename` - Name of the file
    /// * `capacity` - Expected maximum size of the file
    pub fn with_capacity(dir_id: DirId, filename: String, capacity: usize) -> Self {
        Self {
            content: Vec::with_capacity(capacity),
            dirty: true, // New file needs to be written
            dir_id,
            filename,
        }
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
    /// Uses 1.5x geometric growth when expanding to reduce reallocations during
    /// sequential writes. This trades ~50% extra memory for O(n) total allocation
    /// cost instead of O(n²) with exact-fit resizing.
    ///
    /// # Returns
    ///
    /// The number of bytes written (always equals `data.len()`).
    pub fn write(&mut self, offset: u64, data: &[u8]) -> usize {
        // Safe cast: offset comes from file operations and is always within file size limits
        #[allow(clippy::cast_possible_truncation)]
        let offset = offset as usize;
        let end = offset + data.len();

        // Expand buffer if needed, using geometric growth to reduce reallocations
        if end > self.content.len() {
            // Use 1.5x growth factor, but at least fit the required end position
            let new_capacity = std::cmp::max(end, (self.content.capacity() * 3) / 2);
            if new_capacity > self.content.capacity() {
                self.content.reserve(new_capacity - self.content.capacity());
            }
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
        // Safe cast: offset comes from file operations and is always checked
        #[allow(clippy::cast_possible_truncation)]
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
        // Safe cast: size is validated by the caller
        #[allow(clippy::cast_possible_truncation)]
        let size = size as usize;
        if size != self.content.len() {
            self.content.resize(size, 0);
            self.dirty = true;
        }
    }

    /// Get the current size of the buffer.
    #[inline]
    pub fn len(&self) -> u64 {
        self.content.len() as u64
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Check if the buffer has been modified.
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Get the directory ID.
    #[inline]
    pub fn dir_id(&self) -> &DirId {
        &self.dir_id
    }

    /// Get the filename.
    #[inline]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Get a reference to the content for writing back.
    #[inline]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Consume the buffer and return its content.
    ///
    /// Use this when writing the buffer back to the vault.
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }

    /// Mark the buffer as clean (after successful write-back).
    #[inline]
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Mark the buffer as dirty (for re-marking after failed flush).
    #[inline]
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Take the content for flushing, leaving the buffer temporarily empty.
    ///
    /// This moves the Vec instead of copying it. After the write operation,
    /// call [`restore_content`](Self::restore_content) to put the content back.
    ///
    /// This is an optimization for the `flush` operation which may be called
    /// multiple times before `release`. It avoids a full Vec copy.
    #[inline]
    pub fn take_content_for_flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.content)
    }

    /// Restore content after a successful flush.
    ///
    /// This puts the content back and marks the buffer as clean.
    #[inline]
    pub fn restore_content(&mut self, content: Vec<u8>) {
        self.content = content;
        self.dirty = false;
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
        let mut buf = WriteBuffer::new(
            test_dir_id(),
            "test.txt".to_string(),
            b"hello world".to_vec(),
        );
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
    fn test_write_buffer_mark_dirty() {
        let mut buf = WriteBuffer::new(test_dir_id(), "test.txt".to_string(), b"data".to_vec());
        assert!(!buf.is_dirty());
        buf.mark_dirty();
        assert!(buf.is_dirty());
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
    fn test_write_buffer_dir_id() {
        let dir_id = test_dir_id();
        let buf = WriteBuffer::new_empty(dir_id.clone(), "test.txt".to_string());
        assert_eq!(buf.dir_id(), &dir_id);
    }

    #[test]
    fn test_write_buffer_large_gap() {
        // Test writing with a large gap (sparse file behavior)
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "test.txt".to_string());
        buf.write(1000, b"end");
        assert_eq!(buf.len(), 1003);
        // First 1000 bytes should be zeros
        assert!(buf.content()[..1000].iter().all(|&b| b == 0));
        assert_eq!(&buf.content()[1000..], b"end");
    }

    #[test]
    fn test_write_buffer_overwrite() {
        let mut buf = WriteBuffer::new(
            test_dir_id(),
            "test.txt".to_string(),
            b"hello world".to_vec(),
        );
        buf.write(6, b"rust!");
        assert_eq!(buf.content(), b"hello rust!");
    }

    // ========================================================================
    // Edge case tests targeting specific bug classes
    // ========================================================================

    #[test]
    fn test_zero_length_write_behavior() {
        // Bug class: Zero-length writes might have unexpected side effects
        // Current behavior: zero-length write marks dirty but doesn't extend buffer
        let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), vec![1, 2, 3]);

        // Zero-length write within buffer
        buf.write(1, &[]);
        assert_eq!(buf.len(), 3, "Zero-length write should not change length");
        assert_eq!(buf.content(), &[1, 2, 3], "Content should be unchanged");
        // Note: Current impl marks dirty even on zero-length write (line 102)
        assert!(buf.is_dirty(), "Current behavior: zero-length write marks dirty");

        // Zero-length write past end should NOT extend buffer
        let mut buf2 = WriteBuffer::new(test_dir_id(), "f".into(), vec![1, 2, 3]);
        buf2.write(10, &[]);
        // With empty data, end = 10 + 0 = 10, and resize is called with 10
        // This IS a potential bug - empty write at offset 10 extends buffer!
        // Document current behavior:
        assert_eq!(
            buf2.len(),
            10,
            "Current behavior: zero-length write at offset 10 extends buffer to 10"
        );
    }

    #[test]
    fn test_write_at_exact_end() {
        // Bug class: Off-by-one at buffer boundaries
        let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), vec![1, 2, 3]);
        buf.write(3, &[4, 5]); // Write starting exactly at len()
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.content(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_overlapping_writes_preserve_surrounding() {
        // Bug class: Second write corrupts bytes it shouldn't touch
        let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), vec![1, 2, 3, 4, 5]);
        buf.write(1, &[10, 11]); // Overwrite positions 1,2
        buf.write(2, &[20]); // Overwrite position 2 only
        assert_eq!(
            buf.content(),
            &[1, 10, 20, 4, 5],
            "Position 1 should retain value from first write, position 3,4 untouched"
        );
    }

    #[test]
    fn test_read_during_flush_window() {
        // Bug class: Data loss if read occurs during flush
        // Documents that buffer is empty during take/restore window
        let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), b"data".to_vec());
        let taken = buf.take_content_for_flush();

        // During flush window, buffer appears empty
        assert_eq!(buf.read(0, 10), &[] as &[u8], "Read returns empty during flush window");
        assert_eq!(buf.len(), 0, "Length is 0 during flush window");
        assert!(buf.is_empty(), "is_empty() true during flush window");
        // Note: dirty flag is preserved during window
        // (was set before take, restore_content clears it)

        buf.restore_content(taken);
        assert_eq!(buf.read(0, 10), b"data", "Data restored after flush");
    }

    #[test]
    fn test_multiple_flush_cycles_maintain_invariants() {
        // Bug class: State machine corruption over multiple flush cycles
        let mut buf = WriteBuffer::new_for_create(test_dir_id(), "f".into());

        for i in 0u8..5 {
            buf.write(0, &[i]);
            assert!(buf.is_dirty(), "Should be dirty after write");
            assert_eq!(buf.len(), 1);

            let content = buf.take_content_for_flush();
            assert_eq!(content, &[i], "Content should match written value");
            assert!(buf.is_empty(), "Buffer empty after take");

            buf.restore_content(content);
            assert!(!buf.is_dirty(), "Should be clean after restore");
            assert_eq!(buf.len(), 1);
            assert_eq!(buf.content(), &[i], "Content preserved after restore");
        }
    }

    #[test]
    fn test_truncate_to_zero() {
        // Bug class: Edge case of truncating to empty
        let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), b"data".to_vec());
        buf.truncate(0);
        assert!(buf.is_empty());
        assert!(buf.is_dirty());
        assert_eq!(buf.content(), &[] as &[u8]);
        assert_eq!(buf.read(0, 10), &[] as &[u8]);
    }

    #[test]
    fn test_write_then_truncate_then_write() {
        // Bug class: State corruption in multi-operation sequences
        let mut buf = WriteBuffer::new_empty(test_dir_id(), "f".into());

        buf.write(0, b"hello");
        assert_eq!(buf.content(), b"hello");

        buf.truncate(2);
        assert_eq!(buf.content(), b"he");

        buf.write(2, b"lp");
        assert_eq!(buf.content(), b"help");

        buf.truncate(10);
        assert_eq!(buf.len(), 10);
        assert_eq!(&buf.content()[..4], b"help");
        assert!(buf.content()[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_read_exactly_at_boundary() {
        // Bug class: Off-by-one in read boundary calculations
        let buf = WriteBuffer::new(test_dir_id(), "f".into(), b"abcde".to_vec());

        // Read starting at last byte
        assert_eq!(buf.read(4, 1), b"e");
        assert_eq!(buf.read(4, 10), b"e"); // Clamped

        // Read starting exactly at end
        assert_eq!(buf.read(5, 1), b"" as &[u8]);

        // Read starting past end
        assert_eq!(buf.read(100, 1), b"" as &[u8]);
    }
}

/// Property-based tests using proptest.
/// These catch edge cases that manual tests miss by generating random inputs.
#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn test_dir_id() -> DirId {
        DirId::from_raw("test-dir-id")
    }

    proptest! {
        /// Verify that any sequence of writes produces the same result as
        /// applying the same operations to a reference Vec<u8>.
        #[test]
        fn write_sequence_matches_reference(
            initial in prop::collection::vec(any::<u8>(), 0..100),
            ops in prop::collection::vec(
                (0usize..200, prop::collection::vec(any::<u8>(), 0..50)),
                0..20
            )
        ) {
            let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), initial.clone());
            let mut reference = initial;

            for (offset, data) in ops {
                buf.write(offset as u64, &data);

                // Apply same operation to reference Vec
                let end = offset + data.len();
                if end > reference.len() {
                    reference.resize(end, 0);
                }
                if !data.is_empty() {
                    reference[offset..end].copy_from_slice(&data);
                }
            }

            prop_assert_eq!(buf.content(), reference.as_slice());
        }

        /// Verify that truncate + write sequences produce consistent results.
        #[test]
        fn truncate_write_sequence_matches_reference(
            initial in prop::collection::vec(any::<u8>(), 0..50),
            ops in prop::collection::vec(
                prop_oneof![
                    // Truncate operation
                    (0usize..100).prop_map(|size| (true, size, vec![])),
                    // Write operation
                    (0usize..100, prop::collection::vec(any::<u8>(), 0..30))
                        .prop_map(|(off, data)| (false, off, data))
                ],
                0..15
            )
        ) {
            let mut buf = WriteBuffer::new(test_dir_id(), "f".into(), initial.clone());
            let mut reference = initial;

            for (is_truncate, offset_or_size, data) in ops {
                if is_truncate {
                    buf.truncate(offset_or_size as u64);
                    reference.resize(offset_or_size, 0);
                } else {
                    buf.write(offset_or_size as u64, &data);
                    let end = offset_or_size + data.len();
                    if end > reference.len() {
                        reference.resize(end, 0);
                    }
                    if !data.is_empty() {
                        reference[offset_or_size..end].copy_from_slice(&data);
                    }
                }
            }

            prop_assert_eq!(buf.content(), reference.as_slice());
        }

        /// Verify that read always returns the correct slice.
        #[test]
        fn read_returns_correct_slice(
            content in prop::collection::vec(any::<u8>(), 0..100),
            offset in 0u64..150,
            size in 0usize..100
        ) {
            let buf = WriteBuffer::new(test_dir_id(), "f".into(), content.clone());
            let result = buf.read(offset, size);

            // Test range is small (0..150), safe to cast
            #[allow(clippy::cast_possible_truncation)]
            let offset_usize = offset as usize;
            if offset_usize >= content.len() {
                prop_assert_eq!(result, &[] as &[u8]);
            } else {
                let expected_end = (offset_usize + size).min(content.len());
                prop_assert_eq!(result, &content[offset_usize..expected_end]);
            }
        }
    }
}
