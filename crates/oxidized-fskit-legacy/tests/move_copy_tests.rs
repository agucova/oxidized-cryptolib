//! Move and copy tests for FSKit filesystem.
//!
//! Tests rename, move across directories, and copy operations.
//! These operations involve multiple filesystem calls that must remain
//! consistent during the operation.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests move_copy_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Basic Rename
// =============================================================================

#[test]
fn test_rename_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"File to rename";
    mount.write("original.txt", content).expect("write failed");

    mount.rename("original.txt", "renamed.txt").expect("rename failed");

    assert_not_found(&mount, "original.txt");
    assert_file_content(&mount, "renamed.txt", content);
}

#[test]
fn test_rename_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("original_dir").expect("mkdir failed");
    mount.write("original_dir/file.txt", b"content").expect("write failed");

    mount.rename("original_dir", "renamed_dir").expect("rename failed");

    assert_not_found(&mount, "original_dir");
    assert_is_directory(&mount, "renamed_dir");
    assert_file_content(&mount, "renamed_dir/file.txt", b"content");
}

#[test]
fn test_rename_preserves_content() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Use multi-chunk content to ensure all data survives rename
    let content = multi_chunk_content(3);
    let expected_hash = sha256(&content);

    mount.write("before.bin", &content).expect("write failed");
    mount.rename("before.bin", "after.bin").expect("rename failed");

    assert_file_hash(&mount, "after.bin", &expected_hash);
}

// =============================================================================
// Move Across Directories
// =============================================================================

#[test]
fn test_move_file_to_subdirectory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");
    mount.mkdir("subdir").expect("mkdir failed");

    mount.rename("file.txt", "subdir/file.txt").expect("move failed");

    assert_not_found(&mount, "file.txt");
    assert_file_content(&mount, "subdir/file.txt", b"content");
}

#[test]
fn test_move_file_to_parent_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("subdir/file.txt", b"content").expect("write failed");

    mount.rename("subdir/file.txt", "file.txt").expect("move failed");

    assert_not_found(&mount, "subdir/file.txt");
    assert_file_content(&mount, "file.txt", b"content");
}

#[test]
fn test_move_file_between_directories() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir_a").expect("mkdir a failed");
    mount.mkdir("dir_b").expect("mkdir b failed");
    mount.write("dir_a/file.txt", b"content").expect("write failed");

    mount.rename("dir_a/file.txt", "dir_b/file.txt").expect("move failed");

    assert_not_found(&mount, "dir_a/file.txt");
    assert_file_content(&mount, "dir_b/file.txt", b"content");
    assert_dir_empty(&mount, "dir_a");
    assert_dir_contains(&mount, "dir_b", &["file.txt"]);
}

#[test]
fn test_move_directory_with_contents() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("parent").expect("mkdir parent failed");
    mount.mkdir("source_dir").expect("mkdir source failed");
    mount.write("source_dir/a.txt", b"a").expect("write a failed");
    mount.write("source_dir/b.txt", b"b").expect("write b failed");
    mount.mkdir("source_dir/nested").expect("mkdir nested failed");
    mount.write("source_dir/nested/c.txt", b"c").expect("write c failed");

    mount.rename("source_dir", "parent/moved_dir").expect("move failed");

    assert_not_found(&mount, "source_dir");
    assert_is_directory(&mount, "parent/moved_dir");
    assert_file_content(&mount, "parent/moved_dir/a.txt", b"a");
    assert_file_content(&mount, "parent/moved_dir/b.txt", b"b");
    assert_file_content(&mount, "parent/moved_dir/nested/c.txt", b"c");
}

// =============================================================================
// Rename with Overwrite
// =============================================================================

#[test]
fn test_rename_overwrites_existing_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("source.txt", b"new content").expect("write source failed");
    mount.write("dest.txt", b"old content").expect("write dest failed");

    mount.rename("source.txt", "dest.txt").expect("rename failed");

    assert_not_found(&mount, "source.txt");
    assert_file_content(&mount, "dest.txt", b"new content");
}

#[test]
fn test_rename_self() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // Renaming to self should succeed (no-op)
    mount.rename("file.txt", "file.txt").expect("rename to self failed");

    assert_file_content(&mount, "file.txt", b"content");
}

// =============================================================================
// Copy Operations
// =============================================================================

#[test]
fn test_copy_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"Content to copy";
    mount.write("source.txt", content).expect("write failed");

    mount.copy("source.txt", "copy.txt").expect("copy failed");

    // Both files should exist with same content
    assert_file_content(&mount, "source.txt", content);
    assert_file_content(&mount, "copy.txt", content);
}

#[test]
fn test_copy_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Multi-chunk file
    let content = multi_chunk_content(5);
    let expected_hash = sha256(&content);

    mount.write("large.bin", &content).expect("write failed");
    mount.copy("large.bin", "large_copy.bin").expect("copy failed");

    assert_file_hash(&mount, "large.bin", &expected_hash);
    assert_file_hash(&mount, "large_copy.bin", &expected_hash);
}

#[test]
fn test_copy_to_subdirectory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("source.txt", b"content").expect("write failed");
    mount.mkdir("subdir").expect("mkdir failed");

    mount.copy("source.txt", "subdir/copy.txt").expect("copy failed");

    assert_file_content(&mount, "source.txt", b"content");
    assert_file_content(&mount, "subdir/copy.txt", b"content");
}

#[test]
fn test_copy_preserves_independence() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("original.txt", b"original").expect("write failed");
    mount.copy("original.txt", "copy.txt").expect("copy failed");

    // Modify the copy
    mount.write("copy.txt", b"modified copy").expect("modify copy failed");

    // Original should be unchanged
    assert_file_content(&mount, "original.txt", b"original");
    assert_file_content(&mount, "copy.txt", b"modified copy");
}

// =============================================================================
// Copy Directory (Recursive)
// =============================================================================

#[test]
fn test_copy_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("source").expect("mkdir failed");
    mount.write("source/a.txt", b"a").expect("write a failed");
    mount.write("source/b.txt", b"b").expect("write b failed");
    mount.mkdir("source/nested").expect("mkdir nested failed");
    mount.write("source/nested/c.txt", b"c").expect("write c failed");

    mount.copy_dir("source", "dest").expect("copy_dir failed");

    // Original should still exist
    assert_is_directory(&mount, "source");
    assert_file_content(&mount, "source/a.txt", b"a");

    // Copy should have same structure
    assert_is_directory(&mount, "dest");
    assert_file_content(&mount, "dest/a.txt", b"a");
    assert_file_content(&mount, "dest/b.txt", b"b");
    assert_file_content(&mount, "dest/nested/c.txt", b"c");
}

// =============================================================================
// Unicode in Move/Copy
// =============================================================================

#[test]
fn test_rename_unicode_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let original = "原始文件.txt";
    let renamed = "重命名文件.txt";
    let content = b"Chinese filename content";

    mount.write(original, content).expect("write failed");
    mount.rename(original, renamed).expect("rename failed");

    assert_not_found(&mount, original);
    assert_file_content(&mount, renamed, content);
}

#[test]
fn test_copy_to_unicode_path() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("source.txt", b"content").expect("write failed");
    mount.mkdir("目录").expect("mkdir failed");

    mount.copy("source.txt", "目录/副本.txt").expect("copy failed");

    assert_file_content(&mount, "目录/副本.txt", b"content");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_move_empty_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("empty").expect("mkdir failed");
    mount.rename("empty", "moved_empty").expect("rename failed");

    assert_not_found(&mount, "empty");
    assert_is_directory(&mount, "moved_empty");
    assert_dir_empty(&mount, "moved_empty");
}

#[test]
fn test_rename_changes_parent_listing() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file1.txt", b"1").expect("write 1 failed");
    mount.write("file2.txt", b"2").expect("write 2 failed");

    let before = mount.list("/").expect("list before failed");
    assert!(before.contains(&"file1.txt".to_string()));
    assert!(before.contains(&"file2.txt".to_string()));

    mount.rename("file1.txt", "file1_renamed.txt").expect("rename failed");

    let after = mount.list("/").expect("list after failed");
    assert!(!after.contains(&"file1.txt".to_string()));
    assert!(after.contains(&"file1_renamed.txt".to_string()));
    assert!(after.contains(&"file2.txt".to_string()));
}

#[test]
fn test_move_updates_both_directories() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir_a").expect("mkdir a failed");
    mount.mkdir("dir_b").expect("mkdir b failed");
    mount.write("dir_a/file.txt", b"content").expect("write failed");

    assert_dir_contains(&mount, "dir_a", &["file.txt"]);
    assert_dir_empty(&mount, "dir_b");

    mount.rename("dir_a/file.txt", "dir_b/file.txt").expect("move failed");

    assert_dir_empty(&mount, "dir_a");
    assert_dir_contains(&mount, "dir_b", &["file.txt"]);
}
