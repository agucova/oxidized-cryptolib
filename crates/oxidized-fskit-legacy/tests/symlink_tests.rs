//! Symlink edge case tests for FSKit filesystem.
//!
//! Tests symbolic link handling including dangling links, circular references,
//! symlink chains, and operations through symlinks. Cryptomator stores symlinks
//! in `.c9r/symlink.c9r` format.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests symlink_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::io::ErrorKind;

// =============================================================================
// Basic Symlink Operations
// =============================================================================

#[test]
fn test_symlink_to_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"content").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Reading through symlink should get target content
    assert_file_content(&mount, "link.txt", b"content");
}

#[test]
fn test_symlink_to_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("target_dir").expect("mkdir failed");
    mount.write("target_dir/file.txt", b"inside").expect("write failed");
    mount.symlink("target_dir", "link_dir").expect("symlink failed");

    // Should be able to access files through directory symlink
    assert_file_content(&mount, "link_dir/file.txt", b"inside");
}

#[test]
fn test_symlink_preserves_target_path() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("actual_file.txt", b"data").expect("write failed");
    mount.symlink("actual_file.txt", "my_link").expect("symlink failed");

    assert_symlink_target(&mount, "my_link", "actual_file.txt");
}

#[test]
fn test_symlink_with_relative_path() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("subdir/target.txt", b"content").expect("write failed");

    // Create symlink with relative path
    mount.symlink("subdir/target.txt", "link_to_subdir_file").expect("symlink failed");

    assert_file_content(&mount, "link_to_subdir_file", b"content");
}

#[test]
fn test_symlink_with_parent_reference() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("root_file.txt", b"at root").expect("write failed");
    mount.mkdir("subdir").expect("mkdir failed");

    // Create symlink in subdir pointing to parent
    mount.symlink("../root_file.txt", "subdir/link_to_parent").expect("symlink failed");

    assert_file_content(&mount, "subdir/link_to_parent", b"at root");
}

// =============================================================================
// Dangling Symlinks
// =============================================================================

#[test]
fn test_dangling_symlink_creation() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create symlink to non-existent target
    mount.symlink("nonexistent.txt", "dangling_link").expect("symlink creation failed");

    // Symlink itself should exist
    let meta = mount.symlink_metadata("dangling_link").expect("symlink_metadata failed");
    assert!(meta.file_type().is_symlink());

    // But reading through it should fail
    let result = mount.read("dangling_link");
    assert!(result.is_err());
}

#[test]
fn test_dangling_symlink_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.symlink("does_not_exist", "dangling").expect("symlink failed");

    // Should still be able to read the target path
    assert_symlink_target(&mount, "dangling", "does_not_exist");
}

#[test]
fn test_symlink_becomes_dangling() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("will_be_deleted.txt", b"temporary").expect("write failed");
    mount.symlink("will_be_deleted.txt", "link").expect("symlink failed");

    // Verify symlink works
    assert_file_content(&mount, "link", b"temporary");

    // Delete target
    mount.remove("will_be_deleted.txt").expect("remove failed");

    // Symlink should still exist but be dangling
    let meta = mount.symlink_metadata("link").expect("symlink_metadata failed");
    assert!(meta.file_type().is_symlink());

    // Reading through it should fail
    let result = mount.read("link");
    assert!(result.is_err());
}

#[test]
fn test_fix_dangling_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create dangling symlink
    mount.symlink("future_file.txt", "preemptive_link").expect("symlink failed");

    // Verify it's dangling
    assert!(mount.read("preemptive_link").is_err());

    // Create the target file
    mount.write("future_file.txt", b"now exists").expect("write failed");

    // Symlink should now work
    assert_file_content(&mount, "preemptive_link", b"now exists");
}

// =============================================================================
// Symlink Chains
// =============================================================================

#[test]
fn test_symlink_chain_depth_2() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("actual.txt", b"final content").expect("write failed");
    mount.symlink("actual.txt", "link1").expect("symlink 1 failed");
    mount.symlink("link1", "link2").expect("symlink 2 failed");

    // Reading through chain should work
    assert_file_content(&mount, "link2", b"final content");
}

#[test]
fn test_symlink_chain_depth_5() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"deep content").expect("write failed");

    let mut prev = "target.txt".to_string();
    for i in 1..=5 {
        let link_name = format!("link{}", i);
        mount.symlink(&prev, &link_name).expect(&format!("symlink {} failed", i));
        prev = link_name;
    }

    // Should resolve through all 5 links
    assert_file_content(&mount, "link5", b"deep content");
}

#[test]
fn test_symlink_chain_with_directories() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir_a").expect("mkdir failed");
    mount.write("dir_a/file.txt", b"nested").expect("write failed");

    mount.symlink("dir_a", "link_to_dir").expect("symlink 1 failed");
    mount.symlink("link_to_dir/file.txt", "link_to_file").expect("symlink 2 failed");

    assert_file_content(&mount, "link_to_file", b"nested");
}

// =============================================================================
// Circular Symlinks
// =============================================================================

#[test]
fn test_self_referential_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create symlink pointing to itself
    mount.symlink("self_link", "self_link").expect("symlink failed");

    // Attempting to read should fail (loop detected)
    let result = mount.read("self_link");
    assert!(result.is_err());
    if let Err(e) = result {
        // Should be ELOOP or similar
        assert!(
            e.kind() == ErrorKind::Other ||
            e.raw_os_error() == Some(libc::ELOOP) ||
            e.raw_os_error() == Some(libc::ENOENT),
            "Expected loop error, got: {:?}", e
        );
    }
}

#[test]
fn test_circular_symlink_pair() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create circular reference: a -> b -> a
    mount.symlink("link_b", "link_a").expect("symlink a failed");
    mount.symlink("link_a", "link_b").expect("symlink b failed");

    // Both should fail to resolve
    assert!(mount.read("link_a").is_err());
    assert!(mount.read("link_b").is_err());
}

#[test]
fn test_circular_symlink_triangle() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create circular reference: a -> b -> c -> a
    mount.symlink("link_b", "link_a").expect("symlink a failed");
    mount.symlink("link_c", "link_b").expect("symlink b failed");
    mount.symlink("link_a", "link_c").expect("symlink c failed");

    // All should fail to resolve
    assert!(mount.read("link_a").is_err());
    assert!(mount.read("link_b").is_err());
    assert!(mount.read("link_c").is_err());
}

// =============================================================================
// Operations Through Symlinks
// =============================================================================

#[test]
fn test_write_through_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"original").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Write through symlink
    mount.write("link.txt", b"modified via link").expect("write through link failed");

    // Both paths should see new content
    assert_file_content(&mount, "target.txt", b"modified via link");
    assert_file_content(&mount, "link.txt", b"modified via link");
}

#[test]
fn test_append_through_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"start").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Append through symlink
    mount.append("link.txt", b"_end").expect("append through link failed");

    assert_file_content(&mount, "target.txt", b"start_end");
}

#[test]
fn test_truncate_through_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"long content here").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    mount.truncate("link.txt", 4).expect("truncate through link failed");

    assert_file_content(&mount, "target.txt", b"long");
}

#[test]
fn test_metadata_through_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"content for metadata test";
    mount.write("target.txt", content).expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // metadata() follows symlinks
    let meta = mount.metadata("link.txt").expect("metadata failed");
    assert!(meta.is_file());
    assert_eq!(meta.len(), content.len() as u64);

    // symlink_metadata() doesn't follow symlinks
    let link_meta = mount.symlink_metadata("link.txt").expect("symlink_metadata failed");
    assert!(link_meta.file_type().is_symlink());
}

#[test]
fn test_create_file_in_symlinked_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("real_dir").expect("mkdir failed");
    mount.symlink("real_dir", "link_dir").expect("symlink failed");

    // Create file through directory symlink
    mount.write("link_dir/new_file.txt", b"created through link").expect("write failed");

    // Should exist via both paths
    assert_file_content(&mount, "real_dir/new_file.txt", b"created through link");
    assert_file_content(&mount, "link_dir/new_file.txt", b"created through link");
}

// =============================================================================
// Symlink Rename and Delete
// =============================================================================

#[test]
fn test_rename_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"content").expect("write failed");
    mount.symlink("target.txt", "old_link").expect("symlink failed");

    mount.rename("old_link", "new_link").expect("rename failed");

    assert_not_found(&mount, "old_link");
    assert_file_content(&mount, "new_link", b"content");
    // Target unchanged
    assert_file_content(&mount, "target.txt", b"content");
}

#[test]
fn test_delete_symlink_preserves_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"keep this").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Delete the symlink
    mount.remove("link.txt").expect("remove failed");

    // Symlink gone but target preserved
    assert_not_found(&mount, "link.txt");
    assert_file_content(&mount, "target.txt", b"keep this");
}

#[test]
fn test_delete_target_preserves_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"temporary").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Delete the target
    mount.remove("target.txt").expect("remove failed");

    // Symlink still exists (now dangling)
    let meta = mount.symlink_metadata("link.txt").expect("symlink_metadata failed");
    assert!(meta.file_type().is_symlink());
    assert_symlink_target(&mount, "link.txt", "target.txt");
}

#[test]
fn test_overwrite_symlink_with_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"original target").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Overwrite symlink with regular file
    mount.remove("link.txt").expect("remove link failed");
    mount.write("link.txt", b"now a regular file").expect("write failed");

    let meta = mount.symlink_metadata("link.txt").expect("symlink_metadata failed");
    assert!(meta.is_file());
    assert!(!meta.file_type().is_symlink());

    // Target unchanged
    assert_file_content(&mount, "target.txt", b"original target");
}

// =============================================================================
// Symlinks in Listings
// =============================================================================

#[test]
fn test_symlink_appears_in_listing() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"content").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    let entries = mount.list("/").expect("list failed");
    assert!(entries.contains(&"target.txt".to_string()));
    assert!(entries.contains(&"link.txt".to_string()));
}

#[test]
fn test_dangling_symlink_appears_in_listing() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.symlink("nonexistent", "dangling_link").expect("symlink failed");

    let entries = mount.list("/").expect("list failed");
    assert!(entries.contains(&"dangling_link".to_string()));
}

// =============================================================================
// Symlinks with Special Names
// =============================================================================

#[test]
fn test_symlink_with_long_name() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("t.txt", b"content").expect("write failed");

    // Long symlink name (above 220 char threshold for .c9s format)
    let long_link_name: String = (0..250).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    mount.symlink("t.txt", &long_link_name).expect("symlink failed");

    assert_file_content(&mount, &long_link_name, b"content");
}

#[test]
fn test_symlink_with_long_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Long target path
    let long_target: String = (0..300).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    let long_target_file = format!("{}.txt", long_target);

    mount.write(&long_target_file, b"long named target").expect("write failed");
    mount.symlink(&long_target_file, "link_to_long").expect("symlink failed");

    assert_file_content(&mount, "link_to_long", b"long named target");
}

#[test]
fn test_symlink_with_unicode_name() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"unicode test").expect("write failed");
    mount.symlink("target.txt", "链接文件").expect("symlink failed");

    assert_file_content(&mount, "链接文件", b"unicode test");
}

#[test]
fn test_symlink_to_unicode_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("目标文件.txt", b"unicode target").expect("write failed");
    mount.symlink("目标文件.txt", "link").expect("symlink failed");

    assert_file_content(&mount, "link", b"unicode target");
}

// =============================================================================
// Cross-Directory Symlinks
// =============================================================================

#[test]
fn test_symlink_across_directories() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir_a").expect("mkdir a failed");
    mount.mkdir("dir_b").expect("mkdir b failed");
    mount.write("dir_a/file.txt", b"in dir_a").expect("write failed");

    mount.symlink("../dir_a/file.txt", "dir_b/link_to_a").expect("symlink failed");

    assert_file_content(&mount, "dir_b/link_to_a", b"in dir_a");
}

#[test]
fn test_symlink_to_parent_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("parent").expect("mkdir parent failed");
    mount.mkdir("parent/child").expect("mkdir child failed");
    mount.write("parent/sibling.txt", b"sibling content").expect("write failed");

    mount.symlink("..", "parent/child/up").expect("symlink failed");

    // Navigate through symlink
    assert_file_content(&mount, "parent/child/up/sibling.txt", b"sibling content");
}

#[test]
fn test_deeply_nested_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir_all("a/b/c/d").expect("mkdir_all failed");
    mount.write("root_file.txt", b"at root").expect("write failed");

    // Symlink from deep in tree back to root
    mount.symlink("../../../../root_file.txt", "a/b/c/d/link").expect("symlink failed");

    assert_file_content(&mount, "a/b/c/d/link", b"at root");
}

// =============================================================================
// Symlink Edge Cases
// =============================================================================

#[test]
fn test_multiple_symlinks_to_same_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("shared_target.txt", b"shared").expect("write failed");

    for i in 0..5 {
        let link_name = format!("link_{}", i);
        mount.symlink("shared_target.txt", &link_name).expect("symlink failed");
    }

    // All links should resolve to same content
    for i in 0..5 {
        let link_name = format!("link_{}", i);
        assert_file_content(&mount, &link_name, b"shared");
    }

    // Modify through one link
    mount.write("link_2", b"modified").expect("write failed");

    // All should see the change
    assert_file_content(&mount, "shared_target.txt", b"modified");
    for i in 0..5 {
        let link_name = format!("link_{}", i);
        assert_file_content(&mount, &link_name, b"modified");
    }
}

#[test]
fn test_symlink_to_symlink_to_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("real_dir").expect("mkdir failed");
    mount.write("real_dir/file.txt", b"nested").expect("write failed");

    mount.symlink("real_dir", "link1").expect("symlink 1 failed");
    mount.symlink("link1", "link2").expect("symlink 2 failed");

    // Should traverse both symlinks to directory
    assert_file_content(&mount, "link2/file.txt", b"nested");
}

#[test]
fn test_replace_file_with_symlink() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("regular.txt", b"original file").expect("write failed");
    mount.write("other.txt", b"other content").expect("write other failed");

    // Remove file and replace with symlink
    mount.remove("regular.txt").expect("remove failed");
    mount.symlink("other.txt", "regular.txt").expect("symlink failed");

    let meta = mount.symlink_metadata("regular.txt").expect("symlink_metadata failed");
    assert!(meta.file_type().is_symlink());
    assert_file_content(&mount, "regular.txt", b"other content");
}

#[test]
fn test_absolute_vs_relative_symlink_target() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("subdir/target.txt", b"target content").expect("write failed");

    // Relative symlink
    mount.symlink("subdir/target.txt", "relative_link").expect("symlink failed");

    // The symlink target is stored as-is
    assert_symlink_target(&mount, "relative_link", "subdir/target.txt");
    assert_file_content(&mount, "relative_link", b"target content");
}
