//! Test data generators for mount backend integration tests.
//!
//! Provides chunk-aware test data generation that exercises Cryptomator's
//! encryption boundaries. All mount backends should use these generators
//! to ensure consistent testing of edge cases.

use rand::Rng;

/// Cryptomator chunk size (32KB).
///
/// Files are encrypted in 32KB chunks with AES-GCM. Testing at chunk
/// boundaries catches off-by-one errors and buffer handling bugs.
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Cryptomator filename length threshold for `.c9s` shortening.
///
/// Encrypted filenames longer than 220 characters trigger the shortening
/// mechanism that creates `{sha1-hash}.c9s/name.c9s` directories.
pub const FILENAME_THRESHOLD: usize = 220;

/// Generate random bytes of specified size.
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random()).collect()
}

/// Generate content of exactly one chunk (32KB).
pub fn one_chunk_content() -> Vec<u8> {
    random_bytes(CHUNK_SIZE)
}

/// Generate content one byte less than a chunk (32KB - 1).
///
/// Tests boundary condition where content fits in one chunk but is
/// not exactly chunk-aligned.
pub fn chunk_minus_one() -> Vec<u8> {
    random_bytes(CHUNK_SIZE - 1)
}

/// Generate content one byte more than a chunk (32KB + 1).
///
/// Tests boundary condition that triggers second chunk allocation
/// for just a single byte.
pub fn chunk_plus_one() -> Vec<u8> {
    random_bytes(CHUNK_SIZE + 1)
}

/// Generate content that spans exactly N chunks.
///
/// Returns exactly `chunks * 32KB` bytes.
pub fn multi_chunk_content(chunks: usize) -> Vec<u8> {
    random_bytes(chunks * CHUNK_SIZE)
}

/// Generate content containing all 256 possible byte values.
///
/// Essential for detecting byte-value filtering or encoding issues
/// in the encryption/decryption pipeline.
pub fn all_byte_values() -> Vec<u8> {
    (0u8..=255).collect()
}

/// Generate binary content with patterns that might break text processing.
///
/// Includes null bytes, newlines, and control characters that could
/// cause issues if content is incorrectly handled as text.
pub fn problematic_binary() -> Vec<u8> {
    let mut data = Vec::with_capacity(1024);
    // Null bytes
    data.extend_from_slice(&[0, 0, 0]);
    // Newlines (various formats)
    data.extend_from_slice(b"\n\r\n\r");
    // Control characters
    for i in 0..32 {
        data.push(i);
    }
    // High bytes
    for i in 128..=255 {
        data.push(i);
    }
    // Some normal text
    data.extend_from_slice(b"normal text here");
    // More nulls
    data.extend_from_slice(&[0, 0, 0]);
    data
}

/// Generate Unicode content with multiple scripts.
///
/// Tests UTF-8 handling across the encryption layer.
pub fn unicode_content() -> Vec<u8> {
    "Hello, \u{4e16}\u{754c}! \u{393}\u{3b5}\u{3b9}\u{3ac} \u{3c3}\u{3bf}\u{3c5} \u{3ba}\u{3cc}\u{3c3}\u{3bc}\u{3b5}! \u{645}\u{631}\u{62d}\u{628}\u{627} \u{628}\u{627}\u{644}\u{639}\u{627}\u{644}\u{645} \u{1f30d}\u{1f30e}\u{1f30f}".as_bytes().to_vec()
}

/// Generate a filename with Unicode characters.
pub fn unicode_filename() -> String {
    "\u{6587}\u{4ef6}-\u{3b1}\u{3b2}\u{3b3}-emoji\u{1f389}.txt".to_string()
}

/// Generate a filename with special characters.
///
/// Tests filesystem handling of spaces, symbols, and punctuation.
pub fn special_filename() -> String {
    "file with spaces & (special) chars!.txt".to_string()
}

/// Generate a long filename near the 255 character limit.
pub fn long_filename() -> String {
    format!("{}.txt", "a".repeat(250))
}

/// Generate a filename that triggers Cryptomator's `.c9s` shortening.
///
/// When encrypted, this filename will exceed 220 characters and be
/// stored as `{sha1-hash}.c9s/name.c9s`.
pub fn filename_over_threshold() -> String {
    // After Base64 encoding and encryption overhead, this will exceed 220 chars
    format!("{}.txt", "long_name_".repeat(15))
}

/// Generate a deep nested path.
///
/// Returns something like "dir0/dir1/dir2/..." with `depth` levels.
pub fn deep_path(depth: usize) -> String {
    (0..depth)
        .map(|i| format!("dir{i}"))
        .collect::<Vec<_>>()
        .join("/")
}

/// Generate content with distinct bytes per chunk for verification.
///
/// Each chunk starts with a different byte value, making it easy to
/// detect chunk ordering or boundary issues.
pub fn patterned_chunks(num_chunks: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(num_chunks * CHUNK_SIZE);
    for chunk_num in 0..num_chunks {
        // Safe cast: modulo 256 always produces values 0-255 that fit in u8
        #[allow(clippy::cast_possible_truncation)]
        let fill_byte = (chunk_num % 256) as u8;
        data.extend(std::iter::repeat_n(fill_byte, CHUNK_SIZE));
    }
    data
}

/// Generate content for testing partial final chunk.
///
/// Returns `full_chunks * CHUNK_SIZE + partial_bytes` bytes.
pub fn partial_final_chunk(full_chunks: usize, partial_bytes: usize) -> Vec<u8> {
    assert!(partial_bytes < CHUNK_SIZE, "partial_bytes must be less than CHUNK_SIZE");
    random_bytes(full_chunks * CHUNK_SIZE + partial_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        assert_eq!(random_bytes(100).len(), 100);
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(CHUNK_SIZE).len(), CHUNK_SIZE);
    }

    #[test]
    fn test_chunk_content_sizes() {
        assert_eq!(one_chunk_content().len(), CHUNK_SIZE);
        assert_eq!(chunk_minus_one().len(), CHUNK_SIZE - 1);
        assert_eq!(chunk_plus_one().len(), CHUNK_SIZE + 1);
        assert_eq!(multi_chunk_content(3).len(), 3 * CHUNK_SIZE);
    }

    #[test]
    fn test_all_byte_values_complete() {
        let bytes = all_byte_values();
        assert_eq!(bytes.len(), 256);
        for i in 0u8..=255 {
            assert!(bytes.contains(&i), "Missing byte value: {i}");
        }
    }

    #[test]
    fn test_deep_path() {
        assert_eq!(deep_path(0), "");
        assert_eq!(deep_path(1), "dir0");
        assert_eq!(deep_path(3), "dir0/dir1/dir2");
    }

    #[test]
    fn test_patterned_chunks() {
        let data = patterned_chunks(3);
        assert_eq!(data.len(), 3 * CHUNK_SIZE);
        // First byte of each chunk should be the chunk number
        assert_eq!(data[0], 0);
        assert_eq!(data[CHUNK_SIZE], 1);
        assert_eq!(data[2 * CHUNK_SIZE], 2);
    }

    #[test]
    fn test_partial_final_chunk() {
        let data = partial_final_chunk(2, 100);
        assert_eq!(data.len(), 2 * CHUNK_SIZE + 100);
    }
}
