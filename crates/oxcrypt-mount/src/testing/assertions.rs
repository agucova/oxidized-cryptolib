//! Custom assertions for mount backend integration tests.
//!
//! Provides reusable assertion functions for verifying file content,
//! hashes, and common test patterns across FUSE, FSKit, and WebDAV backends.

use sha2::{Digest, Sha256};

/// Calculate SHA-256 hash of data.
///
/// Use for efficient comparison of large files where byte-by-byte
/// comparison would be too expensive or produce unwieldy error messages.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Assert that two byte slices are equal with helpful error messages.
///
/// On failure, shows sizes and first differing position rather than
/// dumping potentially huge byte arrays.
pub fn assert_bytes_equal(actual: &[u8], expected: &[u8], context: &str) {
    if actual.len() != expected.len() {
        panic!(
            "{}: size mismatch - expected {} bytes, got {} bytes",
            context,
            expected.len(),
            actual.len()
        );
    }

    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        if a != e {
            panic!(
                "{}: content mismatch at byte {} - expected 0x{:02x}, got 0x{:02x}",
                context, i, e, a
            );
        }
    }
}

/// Assert that data's SHA-256 hash matches expected.
///
/// Preferred for large file verification where showing the actual
/// content in error messages would be impractical.
pub fn assert_hash_equal(actual: &[u8], expected_hash: &[u8; 32], context: &str) {
    let actual_hash = sha256(actual);
    if &actual_hash != expected_hash {
        panic!(
            "{}: hash mismatch\n  expected: {:02x?}\n  got:      {:02x?}\n  (data size: {} bytes)",
            context, expected_hash, actual_hash, actual.len()
        );
    }
}

/// Assert that an I/O result is an error with a specific errno.
///
/// Works with `std::io::Result` from filesystem operations.
#[cfg(unix)]
pub fn assert_errno<T: std::fmt::Debug>(
    result: std::io::Result<T>,
    expected_errno: i32,
    context: &str,
) {
    match result {
        Ok(value) => {
            panic!(
                "{}: expected errno {} but got success with {:?}",
                context, expected_errno, value
            );
        }
        Err(err) => {
            let actual_errno = err.raw_os_error().unwrap_or(0);
            if actual_errno != expected_errno {
                panic!(
                    "{}: expected errno {} ({}), got errno {} ({})",
                    context,
                    expected_errno,
                    errno_name(expected_errno),
                    actual_errno,
                    errno_name(actual_errno)
                );
            }
        }
    }
}

/// Get a human-readable name for common errno values.
#[cfg(unix)]
fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::ENOENT => "ENOENT",
        libc::EEXIST => "EEXIST",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::ENOSPC => "ENOSPC",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ELOOP => "ELOOP",
        libc::ENOTSUP => "ENOTSUP",
        libc::EROFS => "EROFS",
        libc::EBUSY => "EBUSY",
        libc::EXDEV => "EXDEV",
        _ => "UNKNOWN",
    }
}

/// Assert that an I/O result is Ok.
pub fn assert_io_ok<T>(result: std::io::Result<T>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => {
            #[cfg(unix)]
            {
                let errno = err.raw_os_error().unwrap_or(0);
                panic!(
                    "{}: expected success but got error: {} (errno {} = {})",
                    context,
                    err,
                    errno,
                    errno_name(errno)
                );
            }
            #[cfg(not(unix))]
            {
                panic!("{}: expected success but got error: {}", context, err);
            }
        }
    }
}

/// Assert that an I/O result is an error (any error).
pub fn assert_io_err<T: std::fmt::Debug>(result: std::io::Result<T>, context: &str) {
    if let Ok(value) = result {
        panic!(
            "{}: expected error but got success with {:?}",
            context, value
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello world");
        // Known hash for "hello world"
        let expected: [u8; 32] = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_assert_bytes_equal_success() {
        assert_bytes_equal(&[1, 2, 3], &[1, 2, 3], "test");
    }

    #[test]
    #[should_panic(expected = "size mismatch")]
    fn test_assert_bytes_equal_size_mismatch() {
        assert_bytes_equal(&[1, 2], &[1, 2, 3], "test");
    }

    #[test]
    #[should_panic(expected = "content mismatch at byte 1")]
    fn test_assert_bytes_equal_content_mismatch() {
        assert_bytes_equal(&[1, 9, 3], &[1, 2, 3], "test");
    }

    #[test]
    fn test_assert_hash_equal_success() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_hash_equal(data, &hash, "test");
    }
}
