//! CRUD operation tests for NFS backend.
//!
//! Tests basic Create, Read, Update, Delete operations with focus on:
//! - Encryption/decryption correctness
//! - Chunk boundary handling (32KB chunks)
//! - Cache invalidation on overwrites
//! - Error semantics
//!
//! Run: `cargo nextest run -p oxidized-nfs --features nfs-tests`
//!
//! Note: These tests require NFS mounting which may need elevated permissions.

#![cfg(all(unix, feature = "nfs-tests"))]

mod common;

use common::{
    assert_file_content, assert_file_hash, assert_not_found, chunk_minus_one, chunk_plus_one,
    multi_chunk_content, one_chunk_content, random_bytes, sha256, TestMount, CHUNK_SIZE,
};
use std::io::ErrorKind;

// ============================================================================
// PUT/GET Roundtrip Tests
// ============================================================================

#[test]
fn test_put_get_roundtrip() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"Hello, NFS!";
    mount.write("/test.txt", content).expect("write failed");

    assert_file_content(&mount, "/test.txt", content);
}

#[test]
fn test_put_overwrite() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Write initial content
    mount.write("/file.txt", b"version1").expect("write failed");
    assert_file_content(&mount, "/file.txt", b"version1");

    // Overwrite with different content
    mount.write("/file.txt", b"version2").expect("overwrite failed");

    // Must see new content (cache invalidation)
    assert_file_content(&mount, "/file.txt", b"version2");
}

#[test]
fn test_put_empty_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/empty.txt", &[]).expect("write failed");

    assert_file_content(&mount, "/empty.txt", b"");
}

#[test]
fn test_put_one_byte() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/one.bin", &[0x42]).expect("write failed");

    assert_file_content(&mount, "/one.bin", &[0x42]);
}

// ============================================================================
// Chunk Boundary Tests (32KB boundaries - critical for Cryptomator)
// ============================================================================

#[test]
fn test_put_exactly_one_chunk() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = one_chunk_content();
    assert_eq!(content.len(), CHUNK_SIZE);

    let expected_hash = sha256(&content);
    mount.write("/one_chunk.bin", &content).expect("write failed");

    assert_file_hash(&mount, "/one_chunk.bin", &expected_hash);
}

#[test]
fn test_put_chunk_boundary_minus_one() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = chunk_minus_one();
    assert_eq!(content.len(), CHUNK_SIZE - 1);

    let expected_hash = sha256(&content);
    mount.write("/chunk_minus.bin", &content).expect("write failed");

    let retrieved = mount.read("/chunk_minus.bin").expect("read failed");
    assert_eq!(retrieved.len(), CHUNK_SIZE - 1);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[test]
fn test_put_chunk_boundary_plus_one() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = chunk_plus_one();
    assert_eq!(content.len(), CHUNK_SIZE + 1);

    let expected_hash = sha256(&content);
    mount.write("/chunk_plus.bin", &content).expect("write failed");

    let retrieved = mount.read("/chunk_plus.bin").expect("read failed");
    assert_eq!(retrieved.len(), CHUNK_SIZE + 1);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[test]
fn test_put_large_file_multi_chunk() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // 5 chunks = 160KB
    let content = multi_chunk_content(5);
    assert_eq!(content.len(), 5 * CHUNK_SIZE);

    let expected_hash = sha256(&content);
    mount.write("/large.bin", &content).expect("write failed");

    let retrieved = mount.read("/large.bin").expect("read failed");
    assert_eq!(retrieved.len(), 5 * CHUNK_SIZE);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[test]
fn test_put_exactly_two_chunks() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = multi_chunk_content(2);
    assert_eq!(content.len(), 2 * CHUNK_SIZE);

    let expected_hash = sha256(&content);
    mount.write("/two_chunks.bin", &content).expect("write failed");

    let retrieved = mount.read("/two_chunks.bin").expect("read failed");
    assert_eq!(sha256(&retrieved), expected_hash);
}

// ============================================================================
// GET Tests
// ============================================================================

#[test]
fn test_get_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.read("/does_not_exist.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_get_after_delete() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/temp.txt", b"temporary").expect("write failed");
    assert_file_content(&mount, "/temp.txt", b"temporary");

    mount.delete("/temp.txt").expect("delete failed");

    assert_not_found(&mount, "/temp.txt");
}

// ============================================================================
// DELETE Tests
// ============================================================================

#[test]
fn test_delete_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/to_delete.txt", b"delete me").expect("write failed");
    assert_file_content(&mount, "/to_delete.txt", b"delete me");

    mount.delete("/to_delete.txt").expect("delete failed");

    assert_not_found(&mount, "/to_delete.txt");
}

#[test]
fn test_delete_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.delete("/nonexistent.txt");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

// ============================================================================
// MKDIR Tests
// ============================================================================

#[test]
fn test_mkdir_simple() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/newdir").expect("mkdir failed");

    assert!(mount.exists("/newdir"));
    let meta = mount.metadata("/newdir").expect("metadata failed");
    assert!(meta.is_dir());
}

#[test]
fn test_mkdir_nested_should_fail() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Creating /a/b when /a doesn't exist should fail
    let result = mount.mkdir("/nonexistent/nested");
    assert!(result.is_err());
}

#[test]
fn test_mkdir_exists() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/existingdir").expect("first mkdir failed");

    // Create again - should fail
    let result = mount.mkdir("/existingdir");
    assert!(result.is_err());
}

#[test]
fn test_mkdir_then_put_file_inside() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/mydir").expect("mkdir failed");
    mount.write("/mydir/file.txt", b"inside dir").expect("write failed");

    assert_file_content(&mount, "/mydir/file.txt", b"inside dir");
}

// ============================================================================
// Directory Deletion Tests
// ============================================================================

#[test]
fn test_rmdir_empty() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/emptydir").expect("mkdir failed");
    mount.rmdir("/emptydir").expect("rmdir failed");

    assert!(!mount.exists("/emptydir"));
}

#[test]
fn test_rmdir_nonempty_should_fail() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/nonempty").expect("mkdir failed");
    mount.write("/nonempty/file.txt", b"content").expect("write failed");

    // Deleting non-empty directory should fail
    let result = mount.rmdir("/nonempty");
    assert!(result.is_err());

    // Directory should still exist
    assert!(mount.exists("/nonempty"));
}

// ============================================================================
// Files in Subdirectories
// ============================================================================

#[test]
fn test_put_get_in_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/subdir").expect("mkdir failed");
    mount.write("/subdir/nested.txt", b"nested content").expect("write failed");

    assert_file_content(&mount, "/subdir/nested.txt", b"nested content");
}

#[test]
fn test_deep_directory_structure() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Create nested directories one by one
    mount.mkdir("/a").expect("mkdir /a failed");
    mount.mkdir("/a/b").expect("mkdir /a/b failed");
    mount.mkdir("/a/b/c").expect("mkdir /a/b/c failed");

    mount.write("/a/b/c/deep.txt", b"deep file").expect("write failed");

    assert_file_content(&mount, "/a/b/c/deep.txt", b"deep file");
}

// ============================================================================
// Multiple Files
// ============================================================================

#[test]
fn test_multiple_files_independence() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Create multiple files
    mount.write("/file1.txt", b"content 1").expect("write 1 failed");
    mount.write("/file2.txt", b"content 2").expect("write 2 failed");
    mount.write("/file3.txt", b"content 3").expect("write 3 failed");

    // Verify all have correct content
    assert_file_content(&mount, "/file1.txt", b"content 1");
    assert_file_content(&mount, "/file2.txt", b"content 2");
    assert_file_content(&mount, "/file3.txt", b"content 3");

    // Modify one
    mount.write("/file2.txt", b"modified 2").expect("overwrite failed");

    // Others should be unchanged
    assert_file_content(&mount, "/file1.txt", b"content 1");
    assert_file_content(&mount, "/file2.txt", b"modified 2");
    assert_file_content(&mount, "/file3.txt", b"content 3");
}

#[test]
fn test_overwrite_with_different_size() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Start with small content
    mount.write("/resize.bin", b"small").expect("write 1 failed");
    assert_file_content(&mount, "/resize.bin", b"small");

    // Overwrite with larger content
    let large = random_bytes(10000);
    let hash = sha256(&large);
    mount.write("/resize.bin", &large).expect("write 2 failed");

    let retrieved = mount.read("/resize.bin").expect("read failed");
    assert_eq!(retrieved.len(), 10000);
    assert_eq!(sha256(&retrieved), hash);

    // Overwrite with smaller content again
    mount.write("/resize.bin", b"small again").expect("write 3 failed");
    assert_file_content(&mount, "/resize.bin", b"small again");
}
