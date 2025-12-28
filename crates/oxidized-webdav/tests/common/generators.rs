//! Test data generators for WebDAV integration tests.

use rand::Rng;

/// Cryptomator chunk size (32KB).
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Generate random bytes of specified size.
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Generate content that spans exactly N chunks.
///
/// Returns exactly `chunks * 32KB` bytes.
pub fn multi_chunk_content(chunks: usize) -> Vec<u8> {
    random_bytes(chunks * CHUNK_SIZE)
}

/// Generate content of exactly one chunk (32KB).
pub fn one_chunk_content() -> Vec<u8> {
    random_bytes(CHUNK_SIZE)
}

/// Generate content one byte less than a chunk (32KB - 1).
pub fn chunk_minus_one() -> Vec<u8> {
    random_bytes(CHUNK_SIZE - 1)
}

/// Generate content one byte more than a chunk (32KB + 1).
pub fn chunk_plus_one() -> Vec<u8> {
    random_bytes(CHUNK_SIZE + 1)
}

/// Generate content containing all 256 possible byte values.
pub fn all_byte_values() -> Vec<u8> {
    (0u8..=255).collect()
}

/// Generate a filename with special characters.
///
/// Returns something like "file with spaces & (special) chars!.txt"
pub fn special_filename() -> String {
    "file with spaces & (special) chars!.txt".to_string()
}

/// Generate a filename with Unicode characters.
pub fn unicode_filename() -> String {
    "文件-αβγ-emoji🎉.txt".to_string()
}

/// Generate a long filename (near 255 char limit).
pub fn long_filename() -> String {
    format!("{}.txt", "a".repeat(250))
}

/// Generate a deep nested path.
///
/// Returns something like "/a/b/c/d/e/..." with `depth` levels.
pub fn deep_path(depth: usize) -> String {
    (0..depth)
        .map(|i| format!("dir{}", i))
        .collect::<Vec<_>>()
        .join("/")
}

/// Generate Unicode content.
pub fn unicode_content() -> Vec<u8> {
    "Hello, 世界! Γειά σου κόσμε! مرحبا بالعالم 🌍🌎🌏".as_bytes().to_vec()
}

/// Generate binary content with patterns that might break text processing.
///
/// Includes null bytes, newlines, and control characters.
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
    for i in 128..256 {
        data.push(i as u8);
    }
    // Some normal text
    data.extend_from_slice(b"normal text here");
    // More nulls
    data.extend_from_slice(&[0, 0, 0]);
    data
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
            assert!(bytes.contains(&i), "Missing byte value: {}", i);
        }
    }

    #[test]
    fn test_deep_path() {
        assert_eq!(deep_path(0), "");
        assert_eq!(deep_path(1), "dir0");
        assert_eq!(deep_path(3), "dir0/dir1/dir2");
    }
}
