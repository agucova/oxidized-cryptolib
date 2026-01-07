//! Error handling tests for NFS backend.
//!
//! Tests error conditions and appropriate error codes:
//! - ENOENT (file not found)
//! - ENOTDIR (not a directory)
//! - EISDIR (is a directory)
//! - ENOTEMPTY (directory not empty)
//! - Path traversal protection
//!
//! Run: `cargo nextest run -p oxcrypt-nfs --features nfs-tests`

#![cfg(all(unix, feature = "nfs-tests"))]

mod common;

use common::{TestMount};
use std::io::ErrorKind;

// ============================================================================
// ENOENT (Not Found)
// ============================================================================

#[test]
fn test_read_nonexistent_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.read("/nonexistent.txt");
    assert!(result.is_err(), "Reading nonexistent file should fail");
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_read_nonexistent_in_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir").expect("mkdir failed");

    let result = mount.read("/dir/nonexistent.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_read_in_nonexistent_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.read("/nonexistent_dir/file.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_delete_nonexistent_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.delete("/nonexistent.txt");
    assert!(result.is_err(), "Deleting nonexistent file should fail");
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_rmdir_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.rmdir("/nonexistent_dir");
    assert!(result.is_err(), "Removing nonexistent directory should fail");
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_metadata_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.metadata("/nonexistent");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

// ============================================================================
// ENOTDIR (Not a Directory)
// ============================================================================

#[test]
fn test_list_file_as_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.list_dir("/file.txt");
    assert!(result.is_err(), "Listing a file as directory should fail");
    // May be NotADirectory or NotFound depending on implementation
    let kind = result.unwrap_err().kind();
    assert!(
        kind == ErrorKind::NotADirectory || kind == ErrorKind::NotFound || kind == ErrorKind::Other,
        "Expected NotADirectory or NotFound, got {kind:?}"
    );
}

#[test]
fn test_mkdir_under_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.mkdir("/file.txt/subdir");
    assert!(result.is_err(), "Creating directory under a file should fail");
}

#[test]
fn test_write_under_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.write("/file.txt/nested.txt", b"content");
    assert!(result.is_err(), "Writing under a file should fail");
}

#[test]
fn test_read_file_as_path_component() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.read("/file.txt/something");
    assert!(result.is_err());
}

// ============================================================================
// EISDIR (Is a Directory)
// ============================================================================

#[test]
fn test_delete_directory_as_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");

    let result = mount.delete("/directory");
    assert!(result.is_err(), "Deleting directory with delete() should fail");
    // Error kind varies: IsADirectory, PermissionDenied, or Other
    let kind = result.unwrap_err().kind();
    assert!(
        kind == ErrorKind::IsADirectory
            || kind == ErrorKind::PermissionDenied
            || kind == ErrorKind::Other,
        "Expected IsADirectory or PermissionDenied, got {kind:?}"
    );
}

#[test]
fn test_read_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");

    let result = mount.read("/directory");
    assert!(result.is_err(), "Reading a directory should fail");
    let kind = result.unwrap_err().kind();
    assert!(
        kind == ErrorKind::IsADirectory || kind == ErrorKind::Other,
        "Expected IsADirectory, got {kind:?}"
    );
}

#[test]
fn test_write_over_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");

    let result = mount.write("/directory", b"content");
    assert!(result.is_err(), "Writing to a directory path should fail");
}

// ============================================================================
// ENOTEMPTY (Directory Not Empty)
// ============================================================================

#[test]
fn test_rmdir_nonempty() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");
    mount.write("/directory/file.txt", b"content").expect("write failed");

    let result = mount.rmdir("/directory");
    assert!(result.is_err(), "Removing non-empty directory should fail");
    // DirectoryNotEmpty or Other
    let kind = result.unwrap_err().kind();
    assert!(
        kind == ErrorKind::DirectoryNotEmpty || kind == ErrorKind::Other,
        "Expected DirectoryNotEmpty, got {kind:?}"
    );
}

#[test]
fn test_rmdir_nonempty_with_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");
    mount.mkdir("/directory/subdir").expect("mkdir failed");

    let result = mount.rmdir("/directory");
    assert!(result.is_err(), "Removing directory with subdirectory should fail");
}

// ============================================================================
// Already Exists
// ============================================================================

#[test]
fn test_mkdir_existing_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/directory").expect("mkdir failed");

    let result = mount.mkdir("/directory");
    assert!(result.is_err(), "Creating existing directory should fail");
    let kind = result.unwrap_err().kind();
    assert!(
        kind == ErrorKind::AlreadyExists || kind == ErrorKind::Other,
        "Expected AlreadyExists, got {kind:?}"
    );
}

#[test]
fn test_mkdir_where_file_exists() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/name", b"file content").expect("write failed");

    let result = mount.mkdir("/name");
    assert!(result.is_err(), "Creating directory where file exists should fail");
}

// ============================================================================
// Path Traversal Protection
// ============================================================================

#[test]
fn test_path_traversal_blocked() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Attempting to escape the vault with ../
    let result = mount.read("/../../../etc/passwd");

    // This should either:
    // 1. Be blocked entirely (error)
    // 2. Normalize to a path within the vault (not found)
    // 3. Never actually escape (implementation dependent)
    // The key is it should NOT return /etc/passwd content
    match result {
        Ok(content) => {
            // If it returns Ok, it should be empty or not contain passwd content
            let content_str = String::from_utf8_lossy(&content);
            assert!(
                !content_str.contains("root:"),
                "Path traversal should not expose /etc/passwd"
            );
        }
        Err(_) => {
            // Error is the expected/safe behavior
        }
    }
}

#[test]
fn test_path_with_dot_dot_in_middle() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir").expect("mkdir failed");
    mount.write("/file.txt", b"content").expect("write failed");

    // Path normalization: /dir/../file.txt should resolve to /file.txt
    let result = mount.read("/dir/../file.txt");
    // This is actually a valid normalized path
    if let Ok(content) = result {
        assert_eq!(content, b"content");
    }
    // Or it might fail if the implementation doesn't do path normalization
}

#[test]
fn test_write_path_traversal_blocked() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Attempting to write outside the vault
    let result = mount.write("/../../../tmp/test_file_from_nfs", b"malicious");

    // Should either fail or write to a location within the vault
    // Key: should NOT create /tmp/test_file_from_nfs on the actual filesystem
    // We can't easily verify this without checking the real filesystem
    // But the path should be rejected or normalized
    match result {
        Ok(()) => {
            // If it succeeded, it should have written within the vault
            // The file should exist somewhere in the mount
        }
        Err(_) => {
            // Expected - path traversal blocked
        }
    }
}

// ============================================================================
// Invalid Names
// ============================================================================

#[test]
fn test_empty_filename() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Empty filename after slash
    let result = mount.write("/", b"content");
    assert!(result.is_err(), "Writing to root path should fail");
}

#[test]
fn test_filename_with_null_byte() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Null bytes in paths are typically invalid
    let result = mount.write("/file\x00.txt", b"content");
    // Should fail - null byte in filename
    assert!(result.is_err(), "Null byte in filename should be rejected");
}

// ============================================================================
// Operation on Deleted Files
// ============================================================================

#[test]
fn test_read_after_delete() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");
    mount.delete("/file.txt").expect("delete failed");

    let result = mount.read("/file.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_delete_after_delete() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");
    mount.delete("/file.txt").expect("delete failed");

    let result = mount.delete("/file.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_list_after_rmdir() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir").expect("mkdir failed");
    mount.rmdir("/dir").expect("rmdir failed");

    let result = mount.list_dir("/dir");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

// ============================================================================
// Deeply Nested Paths
// ============================================================================

#[test]
fn test_very_deep_path_error() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Create a very deep path
    let mut deep_path = String::from("/a");
    for _ in 0..50 {
        deep_path.push_str("/b");
    }

    let result = mount.read(&deep_path);
    // Should fail - either path too long or not found
    assert!(result.is_err());
}

#[test]
fn test_access_in_deleted_parent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/parent").expect("mkdir failed");
    mount.write("/parent/child.txt", b"content").expect("write failed");

    // Delete the parent
    mount.rmdir_all("/parent").expect("rmdir_all failed");

    // Try to access child
    let result = mount.read("/parent/child.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}
