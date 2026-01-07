//! Metadata tests for FUSE filesystem.
//!
//! Verifies that stat() and readdir() return accurate information,
//! especially file sizes at chunk boundaries and directory listings.
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests metadata_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::os::unix::fs::PermissionsExt;

// =============================================================================
// File Size Accuracy
// =============================================================================

#[test]
fn test_size_empty_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("empty.txt", b"").expect("write failed");
    assert_file_size(&mount, "empty.txt", 0);
}

#[test]
fn test_size_small_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"Hello, World!";
    mount.write("small.txt", content).expect("write failed");
    assert_file_size(&mount, "small.txt", content.len() as u64);
}

#[test]
fn test_size_exactly_one_chunk() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = one_chunk_content();
    mount.write("one_chunk.bin", &content).expect("write failed");
    assert_file_size(&mount, "one_chunk.bin", CHUNK_SIZE as u64);
}

#[test]
fn test_size_chunk_minus_one() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = chunk_minus_one();
    mount.write("chunk_m1.bin", &content).expect("write failed");
    assert_file_size(&mount, "chunk_m1.bin", (CHUNK_SIZE - 1) as u64);
}

#[test]
fn test_size_chunk_plus_one() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = chunk_plus_one();
    mount.write("chunk_p1.bin", &content).expect("write failed");
    assert_file_size(&mount, "chunk_p1.bin", (CHUNK_SIZE + 1) as u64);
}

#[test]
fn test_size_multi_chunk() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(5);
    mount.write("multi.bin", &content).expect("write failed");
    assert_file_size(&mount, "multi.bin", (5 * CHUNK_SIZE) as u64);
}

#[test]
fn test_size_after_overwrite() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("overwrite.txt", b"short").expect("write 1 failed");
    assert_file_size(&mount, "overwrite.txt", 5);

    mount.write("overwrite.txt", b"much longer content").expect("write 2 failed");
    assert_file_size(&mount, "overwrite.txt", 19);

    mount.write("overwrite.txt", b"tiny").expect("write 3 failed");
    assert_file_size(&mount, "overwrite.txt", 4);
}

#[test]
fn test_size_after_truncate() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("truncate.txt", b"some content").expect("write failed");
    assert_file_size(&mount, "truncate.txt", 12);

    mount.truncate("truncate.txt", 5).expect("truncate failed");
    assert_file_size(&mount, "truncate.txt", 5);

    mount.truncate("truncate.txt", 20).expect("extend failed");
    assert_file_size(&mount, "truncate.txt", 20);
}

// =============================================================================
// Directory Listing
// =============================================================================

#[test]
fn test_list_empty_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("empty_dir").expect("mkdir failed");
    assert_dir_empty(&mount, "empty_dir");
}

#[test]
fn test_list_root_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file1.txt", b"1").expect("write 1 failed");
    mount.write("file2.txt", b"2").expect("write 2 failed");
    mount.mkdir("subdir").expect("mkdir failed");

    assert_dir_contains(&mount, "/", &["file1.txt", "file2.txt", "subdir"]);
}

#[test]
fn test_list_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("parent").expect("mkdir failed");
    mount.write("parent/a.txt", b"a").expect("write a failed");
    mount.write("parent/b.txt", b"b").expect("write b failed");
    mount.mkdir("parent/child").expect("mkdir child failed");

    assert_dir_entries(&mount, "parent", &["a.txt", "b.txt", "child"]);
}

#[test]
fn test_listing_updates_after_create() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Initially empty
    let initial = mount.list("/").expect("list failed");
    let initial_count = initial.len();

    // Add a file
    mount.write("new_file.txt", b"content").expect("write failed");

    // Listing should update
    let after = mount.list("/").expect("list failed");
    assert_eq!(after.len(), initial_count + 1);
    assert!(after.contains(&"new_file.txt".to_string()));
}

#[test]
fn test_listing_updates_after_delete() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("to_delete.txt", b"content").expect("write failed");
    assert!(mount.list("/").unwrap().contains(&"to_delete.txt".to_string()));

    mount.remove("to_delete.txt").expect("delete failed");
    assert!(!mount.list("/").unwrap().contains(&"to_delete.txt".to_string()));
}

#[test]
fn test_listing_updates_after_rename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("old_name.txt", b"content").expect("write failed");
    assert!(mount.list("/").unwrap().contains(&"old_name.txt".to_string()));

    mount.rename("old_name.txt", "new_name.txt").expect("rename failed");

    let entries = mount.list("/").expect("list failed");
    assert!(!entries.contains(&"old_name.txt".to_string()));
    assert!(entries.contains(&"new_name.txt".to_string()));
}

// =============================================================================
// File Type Detection
// =============================================================================

#[test]
fn test_is_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("regular.txt", b"content").expect("write failed");

    assert!(mount.is_file("regular.txt"));
    assert!(!mount.is_dir("regular.txt"));
}

#[test]
fn test_is_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("a_directory").expect("mkdir failed");

    assert!(mount.is_dir("a_directory"));
    assert!(!mount.is_file("a_directory"));
}

#[test]
fn test_root_is_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    assert!(mount.is_dir("/"));
    assert!(!mount.is_file("/"));
}

// =============================================================================
// Permissions
// =============================================================================

#[test]
fn test_file_readable() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("readable.txt", b"content").expect("write failed");

    let metadata = mount.metadata("readable.txt").expect("stat failed");
    let mode = metadata.permissions().mode();

    // Should have read permission for owner
    assert!(mode & 0o400 != 0, "File should be readable by owner");
}

#[test]
fn test_directory_executable() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("exec_dir").expect("mkdir failed");

    let metadata = mount.metadata("exec_dir").expect("stat failed");
    let mode = metadata.permissions().mode();

    // Directories should have execute (search) permission
    assert!(
        mode & 0o100 != 0,
        "Directory should be executable by owner"
    );
}

// =============================================================================
// Symlink Metadata
// =============================================================================

#[cfg(unix)]
#[test]
fn test_symlink_metadata() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("target.txt", b"target content").expect("write failed");
    mount.symlink("target.txt", "link.txt").expect("symlink failed");

    // Regular metadata follows the link
    let meta = mount.metadata("link.txt").expect("metadata failed");
    assert!(meta.is_file());
    assert_eq!(meta.len(), 14);

    // Symlink metadata doesn't follow
    let link_meta = mount.symlink_metadata("link.txt").expect("symlink_metadata failed");
    assert!(link_meta.file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn test_symlink_target() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.symlink("target_path", "my_link").expect("symlink failed");
    assert_symlink_target(&mount, "my_link", "target_path");
}

// =============================================================================
// Unicode in Listings
// =============================================================================

#[test]
fn test_unicode_files_in_listing() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let unicode_name = unicode_filename();
    mount.write(&unicode_name, b"content").expect("write failed");

    let entries = mount.list("/").expect("list failed");
    assert!(entries.contains(&unicode_name));
}

#[test]
fn test_mixed_ascii_unicode_listing() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("ascii.txt", b"a").expect("write ascii failed");
    mount.write("中文.txt", b"b").expect("write chinese failed");
    mount.write("emoji_🎉.txt", b"c").expect("write emoji failed");

    let entries = mount.list("/").expect("list failed");
    assert!(entries.contains(&"ascii.txt".to_string()));
    assert!(entries.contains(&"中文.txt".to_string()));
    assert!(entries.contains(&"emoji_🎉.txt".to_string()));
}

// =============================================================================
// Nested Directory Metadata
// =============================================================================

#[test]
fn test_deep_directory_metadata() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir_all("a/b/c/d/e").expect("mkdir_all failed");

    // Each level should be a directory
    assert_is_directory(&mount, "a");
    assert_is_directory(&mount, "a/b");
    assert_is_directory(&mount, "a/b/c");
    assert_is_directory(&mount, "a/b/c/d");
    assert_is_directory(&mount, "a/b/c/d/e");
}

#[test]
fn test_file_in_deep_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir_all("deep/path/to/dir").expect("mkdir_all failed");
    mount.write("deep/path/to/dir/file.txt", b"content").expect("write failed");

    assert_is_file(&mount, "deep/path/to/dir/file.txt");
    assert_file_size(&mount, "deep/path/to/dir/file.txt", 7);
}

// =============================================================================
// Timestamps
// =============================================================================

#[test]
fn test_mtime_is_not_current_time() {
    // Tests that getattr returns actual mtime from the encrypted file,
    // not the current time. This is critical for `ls -lt`, `rsync --update`,
    // and incremental backup tools.
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file
    mount.write("timestamp_test.txt", b"content").expect("write failed");

    // Wait a bit to ensure any clock drift is noticeable
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Get metadata
    let metadata = mount.metadata("timestamp_test.txt").expect("stat failed");
    let mtime = metadata.modified().expect("mtime unavailable");

    // The mtime should be in the past (when file was created), not now
    let now = std::time::SystemTime::now();
    let age = now.duration_since(mtime).expect("mtime is in the future");

    // File was created 200ms+ ago, so mtime should reflect that
    // (Allow some tolerance for filesystem granularity)
    assert!(
        age.as_millis() >= 100,
        "mtime should reflect actual creation time, not current time. Age: {:?}",
        age
    );
}

#[test]
fn test_mtime_changes_on_write() {
    // Tests that mtime is updated when file content is modified
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial file
    mount.write("mtime_write.txt", b"initial").expect("write 1 failed");
    let meta1 = mount.metadata("mtime_write.txt").expect("stat 1 failed");
    let mtime1 = meta1.modified().expect("mtime1 unavailable");

    // Wait to ensure mtime difference is detectable
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Modify file
    mount.write("mtime_write.txt", b"modified content").expect("write 2 failed");
    let meta2 = mount.metadata("mtime_write.txt").expect("stat 2 failed");
    let mtime2 = meta2.modified().expect("mtime2 unavailable");

    // mtime should have changed
    assert!(
        mtime2 > mtime1,
        "mtime should increase after write: mtime1={:?}, mtime2={:?}",
        mtime1,
        mtime2
    );
}

#[test]
fn test_different_files_have_different_mtimes() {
    // Tests that multiple files created at different times have different mtimes
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create first file
    mount.write("file1.txt", b"one").expect("write 1 failed");
    let meta1 = mount.metadata("file1.txt").expect("stat 1 failed");
    let mtime1 = meta1.modified().expect("mtime1 unavailable");

    // Wait to ensure mtime difference
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Create second file
    mount.write("file2.txt", b"two").expect("write 2 failed");
    let meta2 = mount.metadata("file2.txt").expect("stat 2 failed");
    let mtime2 = meta2.modified().expect("mtime2 unavailable");

    // Files created at different times should have different mtimes
    assert!(
        mtime2 > mtime1,
        "Files created at different times should have different mtimes"
    );
}

#[cfg(unix)]
#[test]
fn test_touch_updates_mtime() {
    // Tests that touch (utimens setattr) updates mtime
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file
    mount.write("touch_test.txt", b"content").expect("write failed");
    let meta1 = mount.metadata("touch_test.txt").expect("stat 1 failed");
    let mtime1 = meta1.modified().expect("mtime1 unavailable");

    // Wait to ensure mtime difference
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Touch the file (update mtime to now)
    use filetime::{set_file_mtime, FileTime};
    let new_mtime = FileTime::now();
    set_file_mtime(mount.path("touch_test.txt"), new_mtime).expect("touch failed");

    // Read mtime again
    let meta2 = mount.metadata("touch_test.txt").expect("stat 2 failed");
    let mtime2 = meta2.modified().expect("mtime2 unavailable");

    // mtime should have been updated
    assert!(
        mtime2 > mtime1,
        "touch should update mtime: mtime1={:?}, mtime2={:?}",
        mtime1,
        mtime2
    );
}

#[test]
fn test_mtime_persists_across_close_reopen() {
    // Tests that mtime from encrypted file is read correctly after close/reopen
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file and record mtime
    mount.write("persist_mtime.txt", b"content").expect("write failed");
    let meta1 = mount.metadata("persist_mtime.txt").expect("stat 1 failed");
    let mtime1 = meta1.modified().expect("mtime1 unavailable");

    // Read it again (forces a fresh getattr after cache expires)
    std::thread::sleep(std::time::Duration::from_secs(2));
    let meta2 = mount.metadata("persist_mtime.txt").expect("stat 2 failed");
    let mtime2 = meta2.modified().expect("mtime2 unavailable");

    // mtime should remain the same (within 1 second tolerance for granularity)
    let diff = if mtime1 > mtime2 {
        mtime1.duration_since(mtime2).unwrap_or_default()
    } else {
        mtime2.duration_since(mtime1).unwrap_or_default()
    };

    assert!(
        diff.as_secs() < 2,
        "mtime should persist: mtime1={:?}, mtime2={:?}, diff={:?}",
        mtime1,
        mtime2,
        diff
    );
}
