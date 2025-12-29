//! FSKit-specific assertions for integration tests.
//!
//! Provides assertions that work with `TestMount` and verify filesystem
//! behavior through the mounted FSKit interface.

// Not all tests use all assertions
#![allow(dead_code)]

use super::harness::TestMount;
use oxidized_mount_common::testing::{assert_bytes_equal, sha256};
use std::collections::HashSet;

/// Assert that a file exists and has the expected content.
pub fn assert_file_content(mount: &TestMount, path: &str, expected: &[u8]) {
    let actual = mount
        .read(path)
        .unwrap_or_else(|e| panic!("Failed to read file '{}': {}", path, e));
    assert_bytes_equal(&actual, expected, &format!("file '{}'", path));
}

/// Assert that a file exists and its SHA-256 hash matches.
///
/// More efficient than comparing full content for large files.
pub fn assert_file_hash(mount: &TestMount, path: &str, expected_hash: &[u8; 32]) {
    let actual = mount
        .read(path)
        .unwrap_or_else(|e| panic!("Failed to read file '{}': {}", path, e));
    let actual_hash = sha256(&actual);
    assert_eq!(
        &actual_hash, expected_hash,
        "File '{}' hash mismatch:\n  expected: {:02x?}\n  got:      {:02x?}",
        path, expected_hash, actual_hash
    );
}

/// Assert that a path does not exist.
pub fn assert_not_found(mount: &TestMount, path: &str) {
    assert!(
        !mount.exists(path),
        "Expected '{}' to not exist, but it does",
        path
    );
}

/// Assert that a path exists.
pub fn assert_exists(mount: &TestMount, path: &str) {
    assert!(mount.exists(path), "Expected '{}' to exist, but it doesn't", path);
}

/// Assert that a path is a directory.
pub fn assert_is_directory(mount: &TestMount, path: &str) {
    assert!(
        mount.is_dir(path),
        "Expected '{}' to be a directory, but it isn't",
        path
    );
}

/// Assert that a path is a file (not a directory).
pub fn assert_is_file(mount: &TestMount, path: &str) {
    assert!(
        mount.is_file(path),
        "Expected '{}' to be a file, but it isn't",
        path
    );
}

/// Assert that a file has a specific size.
pub fn assert_file_size(mount: &TestMount, path: &str, expected_size: u64) {
    let metadata = mount
        .metadata(path)
        .unwrap_or_else(|e| panic!("Failed to get metadata for '{}': {}", path, e));
    assert_eq!(
        metadata.len(),
        expected_size,
        "File '{}' size mismatch: expected {} bytes, got {} bytes",
        path,
        expected_size,
        metadata.len()
    );
}

/// Assert that a directory contains exactly the expected entries.
pub fn assert_dir_entries(mount: &TestMount, path: &str, expected: &[&str]) {
    let actual = mount
        .list(path)
        .unwrap_or_else(|e| panic!("Failed to list directory '{}': {}", path, e));

    let expected_set: HashSet<&str> = expected.iter().copied().collect();
    let actual_set: HashSet<&str> = actual.iter().map(|s| s.as_str()).collect();

    let missing: Vec<_> = expected_set.difference(&actual_set).collect();
    let extra: Vec<_> = actual_set.difference(&expected_set).collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "Directory '{}' entries mismatch:\n  missing: {:?}\n  extra: {:?}\n  expected: {:?}\n  actual: {:?}",
        path, missing, extra, expected, actual
    );
}

/// Assert that a directory contains at least the specified entries.
pub fn assert_dir_contains(mount: &TestMount, path: &str, expected: &[&str]) {
    let actual = mount
        .list(path)
        .unwrap_or_else(|e| panic!("Failed to list directory '{}': {}", path, e));

    let actual_set: HashSet<&str> = actual.iter().map(|s| s.as_str()).collect();

    for entry in expected {
        assert!(
            actual_set.contains(entry),
            "Directory '{}' missing expected entry '{}'. Found: {:?}",
            path,
            entry,
            actual
        );
    }
}

/// Assert that an I/O operation fails with a specific errno.
#[cfg(unix)]
pub fn assert_errno<T: std::fmt::Debug>(
    result: std::io::Result<T>,
    expected_errno: i32,
    context: &str,
) {
    oxidized_mount_common::testing::assertions::assert_errno(result, expected_errno, context);
}

/// Assert that a symlink points to the expected target.
#[cfg(unix)]
pub fn assert_symlink_target(mount: &TestMount, link_path: &str, expected_target: &str) {
    let actual = mount
        .read_link(link_path)
        .unwrap_or_else(|e| panic!("Failed to read symlink '{}': {}", link_path, e));
    assert_eq!(
        actual.to_string_lossy(),
        expected_target,
        "Symlink '{}' target mismatch: expected '{}', got '{}'",
        link_path,
        expected_target,
        actual.display()
    );
}

/// Assert that a file is empty.
pub fn assert_file_empty(mount: &TestMount, path: &str) {
    assert_file_size(mount, path, 0);
}

/// Assert that a directory is empty.
pub fn assert_dir_empty(mount: &TestMount, path: &str) {
    assert_dir_entries(mount, path, &[]);
}
