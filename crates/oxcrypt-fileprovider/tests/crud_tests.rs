//! CRUD (Create, Read, Update, Delete) integration tests for File Provider.
//!
//! Tests basic file and directory operations through the File Provider mount.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::{generate_test_data, TestMount};

/// Cryptomator chunk size (32KB)
const CHUNK_SIZE: usize = 32 * 1024;

// ============================================================================
// File Read/Write Tests
// ============================================================================

#[test]
fn put_get_roundtrip() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("put_get");

    let content = b"Hello, File Provider!";
    mount.write_file("test.txt", content).expect("Write failed");

    let read_back = mount.read_file("test.txt").expect("Read failed");
    assert_eq!(read_back, content, "Content mismatch after roundtrip");
}

#[test]
fn put_overwrite() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("put_overwrite");

    // Write initial content
    mount
        .write_file("overwrite.txt", b"original content")
        .expect("Initial write failed");

    // Overwrite with new content
    mount
        .write_file("overwrite.txt", b"new content")
        .expect("Overwrite failed");

    let read_back = mount.read_file("overwrite.txt").expect("Read failed");
    assert_eq!(read_back, b"new content", "Overwrite did not work");
}

#[test]
fn put_empty_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("put_empty");

    mount.write_file("empty.txt", b"").expect("Write failed");

    let read_back = mount.read_file("empty.txt").expect("Read failed");
    assert!(read_back.is_empty(), "Empty file should have no content");

    let meta = mount.metadata("empty.txt").expect("Metadata failed");
    assert_eq!(meta.len(), 0, "Empty file should have size 0");
}

#[test]
fn put_exactly_one_chunk() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("one_chunk");

    let content = generate_test_data(CHUNK_SIZE);
    mount
        .write_file("one_chunk.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("one_chunk.bin").expect("Read failed");
    assert_eq!(read_back.len(), CHUNK_SIZE, "Size mismatch");
    assert_eq!(read_back, content, "Content mismatch at chunk boundary");
}

#[test]
fn put_chunk_boundary_minus_one() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("chunk_minus");

    let size = CHUNK_SIZE - 1;
    let content = generate_test_data(size);
    mount
        .write_file("chunk_minus.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("chunk_minus.bin").expect("Read failed");
    assert_eq!(read_back.len(), size, "Size mismatch");
    assert_eq!(read_back, content, "Content mismatch at chunk boundary - 1");
}

#[test]
fn put_chunk_boundary_plus_one() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("chunk_plus");

    let size = CHUNK_SIZE + 1;
    let content = generate_test_data(size);
    mount
        .write_file("chunk_plus.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("chunk_plus.bin").expect("Read failed");
    assert_eq!(read_back.len(), size, "Size mismatch");
    assert_eq!(read_back, content, "Content mismatch at chunk boundary + 1");
}

#[test]
fn put_multi_chunk_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("multi_chunk");

    // 3.5 chunks
    let size = CHUNK_SIZE * 3 + CHUNK_SIZE / 2;
    let content = generate_test_data(size);
    mount
        .write_file("multi_chunk.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("multi_chunk.bin").expect("Read failed");
    assert_eq!(read_back.len(), size, "Size mismatch");
    assert_eq!(read_back, content, "Content mismatch in multi-chunk file");
}

// ============================================================================
// File Deletion Tests
// ============================================================================

#[test]
fn delete_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("delete_file");

    mount
        .write_file("to_delete.txt", b"delete me")
        .expect("Write failed");
    assert!(mount.exists("to_delete.txt"), "File should exist");

    mount.remove_file("to_delete.txt").expect("Delete failed");
    assert!(!mount.exists("to_delete.txt"), "File should be deleted");
}

#[test]
fn delete_nonexistent_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("delete_nonexistent");

    let result = mount.remove_file("does_not_exist.txt");
    assert!(result.is_err(), "Deleting nonexistent file should fail");
}

// ============================================================================
// Directory Tests
// ============================================================================

#[test]
fn mkdir_simple() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("mkdir");

    mount.mkdir("new_dir").expect("mkdir failed");
    assert!(mount.exists("new_dir"), "Directory should exist");

    let meta = mount.metadata("new_dir").expect("Metadata failed");
    assert!(meta.is_dir(), "Should be a directory");
}

#[test]
fn mkdir_nested() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("mkdir_nested");

    mount
        .mkdir_all("a/b/c/d")
        .expect("mkdir_all failed");

    assert!(mount.exists("a"), "a should exist");
    assert!(mount.exists("a/b"), "a/b should exist");
    assert!(mount.exists("a/b/c"), "a/b/c should exist");
    assert!(mount.exists("a/b/c/d"), "a/b/c/d should exist");
}

#[test]
fn rmdir_empty() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rmdir");

    mount.mkdir("empty_dir").expect("mkdir failed");
    assert!(mount.exists("empty_dir"), "Directory should exist");

    mount.remove_dir("empty_dir").expect("rmdir failed");
    assert!(!mount.exists("empty_dir"), "Directory should be deleted");
}

#[test]
fn rmdir_nonempty_fails() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rmdir_nonempty");

    mount.mkdir("nonempty_dir").expect("mkdir failed");
    mount
        .write_file("nonempty_dir/file.txt", b"content")
        .expect("Write failed");

    let result = mount.remove_dir("nonempty_dir");
    assert!(
        result.is_err(),
        "Removing non-empty directory should fail"
    );
}

#[test]
fn file_in_subdirectory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("subdir_file");

    mount.mkdir("subdir").expect("mkdir failed");
    mount
        .write_file("subdir/nested.txt", b"nested content")
        .expect("Write failed");

    let read_back = mount.read_file("subdir/nested.txt").expect("Read failed");
    assert_eq!(read_back, b"nested content");
}

// ============================================================================
// Directory Listing Tests
// ============================================================================

#[test]
fn list_root() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("list_root");

    mount.write_file("file1.txt", b"1").expect("Write failed");
    mount.write_file("file2.txt", b"2").expect("Write failed");
    mount.mkdir("dir1").expect("mkdir failed");

    let entries = mount.list_dir("").expect("List failed");
    assert!(entries.contains(&"file1.txt".to_string()));
    assert!(entries.contains(&"file2.txt".to_string()));
    assert!(entries.contains(&"dir1".to_string()));
}

#[test]
fn list_subdirectory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("list_subdir");

    mount.mkdir("parent").expect("mkdir failed");
    mount
        .write_file("parent/child1.txt", b"1")
        .expect("Write failed");
    mount
        .write_file("parent/child2.txt", b"2")
        .expect("Write failed");
    mount.mkdir("parent/subdir").expect("mkdir failed");

    let entries = mount.list_dir("parent").expect("List failed");
    assert!(entries.contains(&"child1.txt".to_string()));
    assert!(entries.contains(&"child2.txt".to_string()));
    assert!(entries.contains(&"subdir".to_string()));
    assert_eq!(entries.len(), 3);
}
