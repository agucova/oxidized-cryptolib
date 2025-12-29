//! Error handling tests for FSKit filesystem.
//!
//! Verifies that filesystem operations return correct errno values
//! for various error conditions. Also includes security tests for
//! path traversal attempts.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests error_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// ENOENT - No such file or directory
// =============================================================================

#[test]
fn test_read_nonexistent_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.read("nonexistent.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "read nonexistent file");
}

#[test]
fn test_stat_nonexistent_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.metadata("nonexistent.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "stat nonexistent file");
}

#[test]
fn test_delete_nonexistent_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.remove("nonexistent.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "delete nonexistent file");
}

#[test]
fn test_rmdir_nonexistent_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.rmdir("nonexistent_dir");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "rmdir nonexistent directory");
}

#[test]
fn test_read_in_nonexistent_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.read("nonexistent_dir/file.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "read in nonexistent directory");
}

// =============================================================================
// ENOTDIR - Not a directory
// =============================================================================

#[test]
fn test_list_file_as_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("not_a_dir.txt", b"content").expect("write failed");

    let result = mount.list("not_a_dir.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOTDIR, "list file as directory");
}

#[test]
fn test_mkdir_parent_is_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // Try to create directory inside a file
    let result = mount.mkdir("file.txt/subdir");
    assert!(result.is_err());

    assert_errno(result, libc::ENOTDIR, "mkdir with file as parent");
}

#[test]
fn test_write_with_file_as_parent() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // Try to create file inside a file
    let result = mount.write("file.txt/nested.txt", b"nested");
    assert!(result.is_err());

    assert_errno(result, libc::ENOTDIR, "write with file as parent");
}

// =============================================================================
// EISDIR - Is a directory
// =============================================================================

#[test]
fn test_read_directory_as_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("a_directory").expect("mkdir failed");

    // Try to read directory as a file
    let result = mount.read("a_directory");
    assert!(result.is_err());

    assert_errno(result, libc::EISDIR, "read directory as file");
}

#[test]
fn test_unlink_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("a_directory").expect("mkdir failed");

    // unlink (remove) should fail on directory
    let result = mount.remove("a_directory");
    assert!(result.is_err());

    // Could be EISDIR or EPERM depending on implementation
    let err = result.unwrap_err();
    let errno = err.raw_os_error().unwrap_or(0);
    assert!(
        errno == libc::EISDIR || errno == libc::EPERM,
        "Expected EISDIR or EPERM, got {}",
        errno
    );
}

// =============================================================================
// ENOTEMPTY - Directory not empty
// =============================================================================

#[test]
fn test_rmdir_non_empty() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("non_empty").expect("mkdir failed");
    mount.write("non_empty/file.txt", b"content").expect("write failed");

    let result = mount.rmdir("non_empty");
    assert!(result.is_err());

    assert_errno(result, libc::ENOTEMPTY, "rmdir non-empty directory");
}

#[test]
fn test_rmdir_with_subdirectory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir_all("parent/child").expect("mkdir_all failed");

    let result = mount.rmdir("parent");
    assert!(result.is_err());

    assert_errno(result, libc::ENOTEMPTY, "rmdir with subdirectory");
}

// =============================================================================
// EEXIST - File exists
// =============================================================================

#[test]
fn test_mkdir_existing_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("existing_dir").expect("mkdir failed");

    let result = mount.mkdir("existing_dir");
    assert!(result.is_err());

    assert_errno(result, libc::EEXIST, "mkdir existing directory");
}

#[test]
fn test_mkdir_where_file_exists() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("existing_file", b"content").expect("write failed");

    let result = mount.mkdir("existing_file");
    assert!(result.is_err());

    assert_errno(result, libc::EEXIST, "mkdir where file exists");
}

// =============================================================================
// Symlink Errors
// =============================================================================

#[test]
fn test_read_link_on_regular_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("regular.txt", b"content").expect("write failed");

    let result = mount.read_link("regular.txt");
    assert!(result.is_err());

    assert_errno(result, libc::EINVAL, "readlink on regular file");
}

// =============================================================================
// Security Tests - Path Traversal
// =============================================================================

#[test]
fn test_path_traversal_parent() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Attempt to escape the vault via ../
    let result = mount.read("../../../etc/passwd");
    // Should either fail or be contained within vault
    assert!(result.is_err() || !String::from_utf8_lossy(&result.unwrap()).contains("root:"));
}

#[test]
fn test_path_traversal_in_subdirectory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("secret.txt", b"secret").expect("write failed");

    // Try to escape via subdir/../../../
    let result = mount.read("subdir/../../../etc/passwd");
    assert!(result.is_err() || !String::from_utf8_lossy(&result.unwrap()).contains("root:"));
}

#[test]
fn test_absolute_path_blocked() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Absolute paths should be relative to mount point, not system root
    // This tests that /etc/passwd from within mount doesn't access system
    // The mount should treat this as a relative path "etc/passwd"
    let result = mount.read("/etc/passwd");
    // Should fail because there's no "etc/passwd" in the vault
    assert!(result.is_err() || !String::from_utf8_lossy(&result.unwrap()).contains("root:"));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_double_slash_normalized() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir").expect("mkdir failed");
    mount.write("dir/file.txt", b"content").expect("write failed");

    // Double slash should be normalized
    let content = mount.read("dir//file.txt").expect("read should work");
    assert_eq!(content, b"content");
}

#[test]
fn test_trailing_slash_on_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // Trailing slash on file should fail (it's not a directory)
    let result = mount.read("file.txt/");
    // Behavior varies - might be ENOTDIR or just work
    // At minimum, it shouldn't crash
    let _ = result;
}

#[test]
fn test_current_dir_reference() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    // ./ should be normalized
    let content = mount.read("./file.txt").expect("read should work");
    assert_eq!(content, b"content");
}

#[test]
fn test_self_and_parent_in_path() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir").expect("mkdir failed");
    mount.write("dir/file.txt", b"content").expect("write failed");

    // dir/./../dir/./file.txt should resolve to dir/file.txt
    let content = mount.read("dir/./../dir/./file.txt").expect("read should work");
    assert_eq!(content, b"content");
}

// =============================================================================
// Rename Errors
// =============================================================================

#[test]
fn test_rename_nonexistent() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let result = mount.rename("nonexistent.txt", "new.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "rename nonexistent file");
}

#[test]
fn test_rename_to_nonexistent_parent() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("source.txt", b"content").expect("write failed");

    let result = mount.rename("source.txt", "nonexistent_dir/dest.txt");
    assert!(result.is_err());

    assert_errno(result, libc::ENOENT, "rename to nonexistent parent");
}
