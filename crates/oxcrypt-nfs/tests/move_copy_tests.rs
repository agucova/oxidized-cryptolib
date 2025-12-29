//! Move and copy operation tests for NFS backend.
//!
//! Tests file and directory rename/move operations:
//! - Basic file rename
//! - Cross-directory moves
//! - Directory renaming
//! - Copy operations and content preservation
//! - Overwrite behavior
//!
//! Run: `cargo nextest run -p oxcrypt-nfs --features nfs-tests`

#![cfg(all(unix, feature = "nfs-tests"))]

mod common;

use common::{
    assert_file_content, assert_file_hash, assert_is_dir, assert_is_file, assert_not_found,
    multi_chunk_content, random_bytes, sha256, TestMount, CHUNK_SIZE,
};
use std::io::ErrorKind;

// ============================================================================
// Basic File Rename
// ============================================================================

#[test]
fn test_rename_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/old.txt", b"content").expect("write failed");
    mount.rename("/old.txt", "/new.txt").expect("rename failed");

    assert_not_found(&mount, "/old.txt");
    assert_file_content(&mount, "/new.txt", b"content");
}

#[test]
fn test_rename_file_preserves_content() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = random_bytes(10000);
    let hash = sha256(&content);
    mount.write("/original.bin", &content).expect("write failed");

    mount
        .rename("/original.bin", "/renamed.bin")
        .expect("rename failed");

    assert_file_hash(&mount, "/renamed.bin", &hash);
}

#[test]
fn test_rename_file_large() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Multi-chunk file
    let content = multi_chunk_content(3);
    let hash = sha256(&content);
    mount.write("/large.bin", &content).expect("write failed");

    mount
        .rename("/large.bin", "/large_renamed.bin")
        .expect("rename failed");

    assert_file_hash(&mount, "/large_renamed.bin", &hash);
}

#[test]
fn test_rename_file_change_extension() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");
    mount
        .rename("/file.txt", "/file.md")
        .expect("rename failed");

    assert_not_found(&mount, "/file.txt");
    assert_file_content(&mount, "/file.md", b"content");
}

// ============================================================================
// Move to Subdirectory
// ============================================================================

#[test]
fn test_move_file_to_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/subdir").expect("mkdir failed");
    mount.write("/file.txt", b"content").expect("write failed");

    mount
        .rename("/file.txt", "/subdir/file.txt")
        .expect("move failed");

    assert_not_found(&mount, "/file.txt");
    assert_file_content(&mount, "/subdir/file.txt", b"content");
}

#[test]
fn test_move_file_from_subdirectory_to_root() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/subdir").expect("mkdir failed");
    mount
        .write("/subdir/file.txt", b"content")
        .expect("write failed");

    mount
        .rename("/subdir/file.txt", "/file.txt")
        .expect("move failed");

    assert_not_found(&mount, "/subdir/file.txt");
    assert_file_content(&mount, "/file.txt", b"content");
}

#[test]
fn test_move_file_cross_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir_a").expect("mkdir failed");
    mount.mkdir("/dir_b").expect("mkdir failed");
    mount
        .write("/dir_a/file.txt", b"content")
        .expect("write failed");

    mount
        .rename("/dir_a/file.txt", "/dir_b/file.txt")
        .expect("move failed");

    assert_not_found(&mount, "/dir_a/file.txt");
    assert_file_content(&mount, "/dir_b/file.txt", b"content");
}

#[test]
fn test_move_file_nested_directories() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir_all("/a/b/c").expect("mkdir_all failed");
    mount.mkdir_all("/x/y/z").expect("mkdir_all failed");
    mount.write("/a/b/c/file.txt", b"deep content").expect("write failed");

    mount
        .rename("/a/b/c/file.txt", "/x/y/z/file.txt")
        .expect("move failed");

    assert_not_found(&mount, "/a/b/c/file.txt");
    assert_file_content(&mount, "/x/y/z/file.txt", b"deep content");
}

// ============================================================================
// Directory Rename
// ============================================================================

#[test]
fn test_rename_empty_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/old_dir").expect("mkdir failed");
    mount
        .rename("/old_dir", "/new_dir")
        .expect("rename failed");

    assert!(!mount.exists("/old_dir"));
    assert_is_dir(&mount, "/new_dir");
}

#[test]
fn test_rename_directory_with_files() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/project").expect("mkdir failed");
    mount
        .write("/project/file1.txt", b"content1")
        .expect("write failed");
    mount
        .write("/project/file2.txt", b"content2")
        .expect("write failed");

    mount
        .rename("/project", "/project_renamed")
        .expect("rename failed");

    assert!(!mount.exists("/project"));
    assert_is_dir(&mount, "/project_renamed");
    assert_file_content(&mount, "/project_renamed/file1.txt", b"content1");
    assert_file_content(&mount, "/project_renamed/file2.txt", b"content2");
}

#[test]
fn test_rename_directory_with_subdirectories() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir_all("/root/sub1/sub2").expect("mkdir_all failed");
    mount
        .write("/root/sub1/sub2/file.txt", b"deep")
        .expect("write failed");

    mount
        .rename("/root", "/root_renamed")
        .expect("rename failed");

    assert!(!mount.exists("/root"));
    assert_file_content(&mount, "/root_renamed/sub1/sub2/file.txt", b"deep");
}

// ============================================================================
// Copy Operations
// ============================================================================

#[test]
fn test_copy_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"content to copy";
    mount.write("/original.txt", content).expect("write failed");

    mount
        .copy("/original.txt", "/copy.txt")
        .expect("copy failed");

    // Both should exist
    assert_file_content(&mount, "/original.txt", content);
    assert_file_content(&mount, "/copy.txt", content);
}

#[test]
fn test_copy_preserves_content() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = random_bytes(20000);
    let hash = sha256(&content);
    mount.write("/source.bin", &content).expect("write failed");

    mount.copy("/source.bin", "/dest.bin").expect("copy failed");

    assert_file_hash(&mount, "/source.bin", &hash);
    assert_file_hash(&mount, "/dest.bin", &hash);
}

#[test]
fn test_copy_large_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Multi-chunk file
    let content = multi_chunk_content(4);
    let hash = sha256(&content);
    mount.write("/large.bin", &content).expect("write failed");

    mount
        .copy("/large.bin", "/large_copy.bin")
        .expect("copy failed");

    assert_file_hash(&mount, "/large.bin", &hash);
    assert_file_hash(&mount, "/large_copy.bin", &hash);
}

#[test]
fn test_copy_to_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/backup").expect("mkdir failed");
    mount.write("/file.txt", b"important").expect("write failed");

    mount
        .copy("/file.txt", "/backup/file.txt")
        .expect("copy failed");

    assert_file_content(&mount, "/file.txt", b"important");
    assert_file_content(&mount, "/backup/file.txt", b"important");
}

#[test]
fn test_copy_independence() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"original").expect("write failed");
    mount.copy("/file.txt", "/copy.txt").expect("copy failed");

    // Modify original
    mount.write("/file.txt", b"modified").expect("write failed");

    // Copy should be unchanged
    assert_file_content(&mount, "/file.txt", b"modified");
    assert_file_content(&mount, "/copy.txt", b"original");
}

// ============================================================================
// Overwrite Behavior
// ============================================================================

#[test]
fn test_rename_overwrites_existing() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/source.txt", b"new content").expect("write failed");
    mount
        .write("/target.txt", b"old content")
        .expect("write failed");

    mount
        .rename("/source.txt", "/target.txt")
        .expect("rename should overwrite");

    assert_not_found(&mount, "/source.txt");
    assert_file_content(&mount, "/target.txt", b"new content");
}

#[test]
fn test_copy_overwrites_existing() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/source.txt", b"new content").expect("write failed");
    mount
        .write("/target.txt", b"old content")
        .expect("write failed");

    mount
        .copy("/source.txt", "/target.txt")
        .expect("copy should overwrite");

    assert_file_content(&mount, "/source.txt", b"new content");
    assert_file_content(&mount, "/target.txt", b"new content");
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_rename_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.rename("/nonexistent.txt", "/new.txt");
    assert!(
        result.is_err(),
        "Renaming nonexistent file should fail"
    );
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_copy_nonexistent() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let result = mount.copy("/nonexistent.txt", "/copy.txt");
    assert!(
        result.is_err(),
        "Copying nonexistent file should fail"
    );
    assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn test_move_to_nonexistent_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.rename("/file.txt", "/nonexistent/file.txt");
    assert!(
        result.is_err(),
        "Moving to nonexistent directory should fail"
    );
}

#[test]
fn test_copy_to_nonexistent_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"content").expect("write failed");

    let result = mount.copy("/file.txt", "/nonexistent/file.txt");
    assert!(
        result.is_err(),
        "Copying to nonexistent directory should fail"
    );
}

// ============================================================================
// Move Chain and Multiple Operations
// ============================================================================

#[test]
fn test_move_chain() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file.txt", b"moving around").expect("write failed");

    // Move multiple times
    mount.rename("/file.txt", "/step1.txt").expect("move 1 failed");
    mount.rename("/step1.txt", "/step2.txt").expect("move 2 failed");
    mount.rename("/step2.txt", "/final.txt").expect("move 3 failed");

    assert_not_found(&mount, "/file.txt");
    assert_not_found(&mount, "/step1.txt");
    assert_not_found(&mount, "/step2.txt");
    assert_file_content(&mount, "/final.txt", b"moving around");
}

#[test]
fn test_copy_then_modify_original() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/original.txt", b"version 1").expect("write failed");
    mount.copy("/original.txt", "/backup.txt").expect("copy failed");

    // Modify original multiple times
    mount.write("/original.txt", b"version 2").expect("write failed");
    mount.write("/original.txt", b"version 3").expect("write failed");

    // Backup unchanged
    assert_file_content(&mount, "/backup.txt", b"version 1");
    assert_file_content(&mount, "/original.txt", b"version 3");
}

#[test]
fn test_swap_files_via_rename() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/file_a.txt", b"A content").expect("write failed");
    mount.write("/file_b.txt", b"B content").expect("write failed");

    // Swap using temp name
    mount.rename("/file_a.txt", "/temp.txt").expect("move 1 failed");
    mount.rename("/file_b.txt", "/file_a.txt").expect("move 2 failed");
    mount.rename("/temp.txt", "/file_b.txt").expect("move 3 failed");

    assert_file_content(&mount, "/file_a.txt", b"B content");
    assert_file_content(&mount, "/file_b.txt", b"A content");
}

// ============================================================================
// Rename Within Same Directory
// ============================================================================

#[test]
fn test_rename_in_subdirectory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir").expect("mkdir failed");
    mount.write("/dir/old.txt", b"content").expect("write failed");

    mount
        .rename("/dir/old.txt", "/dir/new.txt")
        .expect("rename failed");

    assert_not_found(&mount, "/dir/old.txt");
    assert_file_content(&mount, "/dir/new.txt", b"content");
}

#[test]
fn test_multiple_files_same_directory() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/dir").expect("mkdir failed");
    mount.write("/dir/file1.txt", b"content1").expect("write failed");
    mount.write("/dir/file2.txt", b"content2").expect("write failed");

    // Rename one, copy another
    mount
        .rename("/dir/file1.txt", "/dir/renamed.txt")
        .expect("rename failed");
    mount
        .copy("/dir/file2.txt", "/dir/copied.txt")
        .expect("copy failed");

    assert_not_found(&mount, "/dir/file1.txt");
    assert_file_content(&mount, "/dir/renamed.txt", b"content1");
    assert_file_content(&mount, "/dir/file2.txt", b"content2");
    assert_file_content(&mount, "/dir/copied.txt", b"content2");
}
