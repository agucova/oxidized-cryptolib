//! Move and copy tests for FUSE filesystem.
//!
//! Tests rename operations including same-directory rename, cross-directory
//! move, and content integrity preservation during moves.
//!
//! Note: FUSE doesn't have a native copy operation - copies are done via
//! read + write. The copy tests here verify that pattern works correctly.
//!
//! Run: `cargo nextest run -p oxidized-fuse --features fuse-tests move_copy_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Basic Rename (Same Directory)
// =============================================================================

#[test]
fn test_rename_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"rename test content";
    mount.write("original.txt", content).expect("write failed");

    mount.rename("original.txt", "renamed.txt").expect("rename failed");

    assert_not_found(&mount, "original.txt");
    assert_file_content(&mount, "renamed.txt", content);
}

#[test]
fn test_rename_empty_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("empty.txt", b"").expect("write failed");
    mount.rename("empty.txt", "still_empty.txt").expect("rename failed");

    assert_not_found(&mount, "empty.txt");
    assert_file_size(&mount, "still_empty.txt", 0);
}

#[test]
fn test_rename_large_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(5);
    let expected_hash = sha256(&content);

    mount.write("large.bin", &content).expect("write failed");
    mount.rename("large.bin", "large_renamed.bin").expect("rename failed");

    assert_not_found(&mount, "large.bin");
    assert_file_hash(&mount, "large_renamed.bin", &expected_hash);
}

#[test]
fn test_rename_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("old_dir").expect("mkdir failed");
    mount.write("old_dir/file.txt", b"content").expect("write failed");

    mount.rename("old_dir", "new_dir").expect("rename failed");

    assert_not_found(&mount, "old_dir");
    assert_is_directory(&mount, "new_dir");
    assert_file_content(&mount, "new_dir/file.txt", b"content");
}

// =============================================================================
// Cross-Directory Move
// =============================================================================

#[test]
fn test_move_file_to_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");
    mount.mkdir("subdir").expect("mkdir failed");

    mount.rename("file.txt", "subdir/file.txt").expect("move failed");

    assert_not_found(&mount, "file.txt");
    assert_file_content(&mount, "subdir/file.txt", b"content");
}

#[test]
fn test_move_file_from_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("subdir/file.txt", b"content").expect("write failed");

    mount.rename("subdir/file.txt", "file.txt").expect("move failed");

    assert_not_found(&mount, "subdir/file.txt");
    assert_file_content(&mount, "file.txt", b"content");
}

#[test]
fn test_move_file_between_subdirectories() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("src").expect("mkdir src failed");
    mount.mkdir("dst").expect("mkdir dst failed");
    mount.write("src/file.txt", b"content").expect("write failed");

    mount.rename("src/file.txt", "dst/file.txt").expect("move failed");

    assert_not_found(&mount, "src/file.txt");
    assert_file_content(&mount, "dst/file.txt", b"content");
}

#[test]
fn test_move_directory_with_contents() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("parent").expect("mkdir parent failed");
    mount.mkdir("parent/child").expect("mkdir child failed");
    mount.write("parent/child/file.txt", b"nested").expect("write failed");

    mount.rename("parent", "moved_parent").expect("move failed");

    assert_not_found(&mount, "parent");
    assert_is_directory(&mount, "moved_parent");
    assert_is_directory(&mount, "moved_parent/child");
    assert_file_content(&mount, "moved_parent/child/file.txt", b"nested");
}

// =============================================================================
// Rename with Overwrite
// =============================================================================

#[test]
fn test_rename_overwrite_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("source.txt", b"source content").expect("write source failed");
    mount.write("target.txt", b"target content").expect("write target failed");

    mount.rename("source.txt", "target.txt").expect("rename failed");

    assert_not_found(&mount, "source.txt");
    assert_file_content(&mount, "target.txt", b"source content");
}

#[test]
fn test_move_overwrite_in_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir").expect("mkdir failed");
    mount.write("new.txt", b"new content").expect("write new failed");
    mount.write("dir/old.txt", b"old content").expect("write old failed");

    mount.rename("new.txt", "dir/old.txt").expect("move failed");

    assert_not_found(&mount, "new.txt");
    assert_file_content(&mount, "dir/old.txt", b"new content");
}

// =============================================================================
// Content Integrity During Move
// =============================================================================

#[test]
fn test_move_preserves_all_bytes() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = all_byte_values();
    mount.write("source.bin", &content).expect("write failed");

    mount.rename("source.bin", "dest.bin").expect("rename failed");

    assert_file_content(&mount, "dest.bin", &content);
}

#[test]
fn test_move_preserves_chunk_content() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = patterned_chunks(4);
    let expected_hash = sha256(&content);

    mount.write("chunked.bin", &content).expect("write failed");
    mount.rename("chunked.bin", "moved_chunked.bin").expect("rename failed");

    assert_file_hash(&mount, "moved_chunked.bin", &expected_hash);
}

#[test]
fn test_move_unicode_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let unicode_name = unicode_filename();
    mount.write(&unicode_name, b"content").expect("write failed");

    let new_name = "renamed_文件.txt";
    mount.rename(&unicode_name, new_name).expect("rename failed");

    assert_not_found(&mount, &unicode_name);
    assert_file_content(&mount, new_name, b"content");
}

// =============================================================================
// Rename Chains
// =============================================================================

#[test]
fn test_rename_chain() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"chain content";
    mount.write("a.txt", content).expect("write failed");

    mount.rename("a.txt", "b.txt").expect("a->b failed");
    mount.rename("b.txt", "c.txt").expect("b->c failed");
    mount.rename("c.txt", "d.txt").expect("c->d failed");

    assert_not_found(&mount, "a.txt");
    assert_not_found(&mount, "b.txt");
    assert_not_found(&mount, "c.txt");
    assert_file_content(&mount, "d.txt", content);
}

#[test]
fn test_rename_swap() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file_a.txt", b"content A").expect("write a failed");
    mount.write("file_b.txt", b"content B").expect("write b failed");

    // Swap via temporary
    mount.rename("file_a.txt", "file_temp.txt").expect("a->temp failed");
    mount.rename("file_b.txt", "file_a.txt").expect("b->a failed");
    mount.rename("file_temp.txt", "file_b.txt").expect("temp->b failed");

    assert_file_content(&mount, "file_a.txt", b"content B");
    assert_file_content(&mount, "file_b.txt", b"content A");
}

// =============================================================================
// Copy Operations (via read + write)
// =============================================================================

#[test]
fn test_copy_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"copy test content";
    mount.write("original.txt", content).expect("write failed");

    mount.copy("original.txt", "copy.txt").expect("copy failed");

    // Both should exist with same content
    assert_file_content(&mount, "original.txt", content);
    assert_file_content(&mount, "copy.txt", content);
}

#[test]
fn test_copy_large_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(5);
    let expected_hash = sha256(&content);

    mount.write("large.bin", &content).expect("write failed");
    mount.copy("large.bin", "large_copy.bin").expect("copy failed");

    assert_file_hash(&mount, "large.bin", &expected_hash);
    assert_file_hash(&mount, "large_copy.bin", &expected_hash);
}

#[test]
fn test_copy_independence() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("original.txt", b"original").expect("write failed");
    mount.copy("original.txt", "copy.txt").expect("copy failed");

    // Modify original
    mount.write("original.txt", b"modified original").expect("modify failed");

    // Copy should be unchanged
    assert_file_content(&mount, "copy.txt", b"original");
    assert_file_content(&mount, "original.txt", b"modified original");
}

#[test]
fn test_copy_to_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");
    mount.mkdir("subdir").expect("mkdir failed");

    mount.copy("file.txt", "subdir/file.txt").expect("copy failed");

    assert_file_content(&mount, "file.txt", b"content");
    assert_file_content(&mount, "subdir/file.txt", b"content");
}

#[test]
fn test_copy_chain() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"chain content";
    mount.write("original.txt", content).expect("write failed");

    mount.copy("original.txt", "copy1.txt").expect("copy1 failed");
    mount.copy("original.txt", "copy2.txt").expect("copy2 failed");
    mount.copy("original.txt", "copy3.txt").expect("copy3 failed");

    // All should have same content
    assert_file_content(&mount, "original.txt", content);
    assert_file_content(&mount, "copy1.txt", content);
    assert_file_content(&mount, "copy2.txt", content);
    assert_file_content(&mount, "copy3.txt", content);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_rename_to_self() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // Rename to self should be a no-op or succeed
    let result = mount.rename("file.txt", "file.txt");
    // Either succeeds or fails gracefully
    if result.is_ok() {
        assert_file_content(&mount, "file.txt", b"content");
    }
}

#[test]
fn test_move_into_own_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("parent").expect("mkdir failed");
    mount.mkdir("parent/child").expect("mkdir child failed");

    // Moving parent into parent/child should fail (would create a cycle)
    let result = mount.rename("parent", "parent/child/parent");
    assert!(result.is_err(), "Moving directory into itself should fail");
}
