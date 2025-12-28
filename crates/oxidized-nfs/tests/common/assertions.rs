//! Custom assertions for NFS integration tests.

use crate::common::{sha256, TestMount};
use std::io::ErrorKind;

/// Assert that a file contains the expected content.
pub fn assert_file_content(mount: &TestMount, path: &str, expected: &[u8]) {
    let actual = mount
        .read(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    assert_eq!(
        actual, expected,
        "Content mismatch for {}. Expected {} bytes, got {} bytes",
        path,
        expected.len(),
        actual.len()
    );
}

/// Assert that a file contains content with the expected SHA-256 hash.
pub fn assert_file_hash(mount: &TestMount, path: &str, expected_hash: &[u8]) {
    let content = mount
        .read(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let actual_hash = sha256(&content);
    assert_eq!(
        actual_hash, expected_hash,
        "Hash mismatch for {}",
        path
    );
}

/// Assert that a path does not exist.
pub fn assert_not_found(mount: &TestMount, path: &str) {
    match mount.read(path) {
        Ok(_) => panic!("Expected {} to not exist, but it does", path),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => panic!("Expected NotFound for {}, got: {}", path, e),
    }
}

/// Assert that a directory contains exactly the expected entries.
pub fn assert_dir_entries(mount: &TestMount, path: &str, expected: &[&str]) {
    let actual = mount
        .list_dir(path)
        .unwrap_or_else(|e| panic!("Failed to list {}: {}", path, e));

    let expected_set: std::collections::HashSet<_> = expected.iter().map(|s| s.to_string()).collect();
    let actual_set: std::collections::HashSet<_> = actual.iter().cloned().collect();

    // Filter out . and ..
    let actual_set: std::collections::HashSet<_> = actual_set
        .into_iter()
        .filter(|s| s != "." && s != "..")
        .collect();

    assert_eq!(
        actual_set, expected_set,
        "Directory entries mismatch for {}. Expected {:?}, got {:?}",
        path, expected, actual
    );
}

/// Assert that a path is a directory.
pub fn assert_is_dir(mount: &TestMount, path: &str) {
    let meta = mount
        .metadata(path)
        .unwrap_or_else(|e| panic!("Failed to get metadata for {}: {}", path, e));
    assert!(
        meta.is_dir(),
        "Expected {} to be a directory, but it's not",
        path
    );
}

/// Assert that a path is a file.
pub fn assert_is_file(mount: &TestMount, path: &str) {
    let meta = mount
        .metadata(path)
        .unwrap_or_else(|e| panic!("Failed to get metadata for {}: {}", path, e));
    assert!(
        meta.is_file(),
        "Expected {} to be a file, but it's not",
        path
    );
}

/// Assert that a file has the expected size.
pub fn assert_file_size(mount: &TestMount, path: &str, expected_size: u64) {
    let meta = mount
        .metadata(path)
        .unwrap_or_else(|e| panic!("Failed to get metadata for {}: {}", path, e));
    assert_eq!(
        meta.len(),
        expected_size,
        "Size mismatch for {}. Expected {}, got {}",
        path,
        expected_size,
        meta.len()
    );
}
