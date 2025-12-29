//! CRUD integration tests for the FSKit FFI layer.
//!
//! These tests verify that all basic Create, Read, Update, Delete operations
//! work correctly through the FFI boundary.

mod common;

use common::{
    assert_bytes_equal, chunk_minus_one, chunk_plus_one, multi_chunk_content, one_chunk_content,
    random_bytes, sha256, TestFilesystem, CHUNK_SIZE,
};

// ============================================================================
// File Creation Tests
// ============================================================================

#[test]
fn test_create_empty_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_file(root, "empty.txt").unwrap();
    assert!(attrs.attr_is_file());
    assert_eq!(attrs.attr_size(), 0);
    assert_eq!(attrs.attr_mode(), 0o644);
}

#[test]
fn test_create_file_returns_correct_item_id() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_file(root, "test.txt").unwrap();
    let item_id = attrs.attr_item_id();

    // Lookup should return the same item ID
    let lookup_attrs = fs.lookup(root, "test.txt").unwrap();
    assert_eq!(lookup_attrs.attr_item_id(), item_id);
}

#[test]
fn test_create_file_duplicate_fails() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    fs.create_file(root, "dup.txt").unwrap();

    let result = fs.create_file(root, "dup.txt");
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), libc::EEXIST);
}

#[test]
fn test_create_file_in_nonexistent_parent() {
    let fs = TestFilesystem::new();

    // Use a random high item_id that doesn't exist
    let result = fs.create_file(999999, "test.txt");
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), libc::ENOENT);
}

// ============================================================================
// File Read/Write Tests
// ============================================================================

#[test]
fn test_write_and_read_small_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"Hello, FSKit FFI!";
    let item_id = fs.write_new_file(root, "small.txt", content).unwrap();

    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, content, "small file content");
}

#[test]
fn test_write_and_read_one_chunk() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = one_chunk_content();
    let item_id = fs.write_new_file(root, "one_chunk.bin", &content).unwrap();

    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, &content, "one chunk content");
}

#[test]
fn test_write_and_read_chunk_minus_one() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = chunk_minus_one();
    assert_eq!(content.len(), CHUNK_SIZE - 1);

    let item_id = fs.write_new_file(root, "chunk_minus.bin", &content).unwrap();
    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, &content, "chunk-1 content");
}

#[test]
fn test_write_and_read_chunk_plus_one() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = chunk_plus_one();
    assert_eq!(content.len(), CHUNK_SIZE + 1);

    let item_id = fs.write_new_file(root, "chunk_plus.bin", &content).unwrap();
    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, &content, "chunk+1 content");
}

#[test]
fn test_write_and_read_multi_chunk() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = multi_chunk_content(3);
    assert_eq!(content.len(), CHUNK_SIZE * 3);

    let item_id = fs.write_new_file(root, "multi_chunk.bin", &content).unwrap();
    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, &content, "multi-chunk content");
}

#[test]
fn test_write_and_read_random_content() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    // Test several different sizes
    for size in [100, 1000, 10000, CHUNK_SIZE / 2, CHUNK_SIZE + 500] {
        let content = random_bytes(size);
        let filename = format!("random_{}.bin", size);

        let item_id = fs.write_new_file(root, &filename, &content).unwrap();
        let read_content = fs.read_entire_file(item_id).unwrap();

        assert_eq!(
            sha256(&read_content),
            sha256(&content),
            "Content mismatch for size {}",
            size
        );
    }
}

#[test]
fn test_partial_read() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"0123456789ABCDEF";
    let item_id = fs.write_new_file(root, "partial.txt", content).unwrap();

    let handle = fs.open_file(item_id, false).unwrap();

    // Read from middle
    let middle = fs.read_file(handle, 4, 4).unwrap();
    assert_eq!(&middle, b"4567");

    // Read from end
    let end = fs.read_file(handle, 12, 4).unwrap();
    assert_eq!(&end, b"CDEF");

    // Read beyond end
    let beyond = fs.read_file(handle, 100, 10).unwrap();
    assert!(beyond.is_empty());

    fs.close_file(handle).unwrap();
}

#[test]
fn test_multiple_writes_accumulate() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_file(root, "accumulate.txt").unwrap();
    let item_id = attrs.attr_item_id();

    let handle = fs.open_file(item_id, true).unwrap();

    fs.write_file(handle, 0, b"Hello").unwrap();
    fs.write_file(handle, 5, b", ").unwrap();
    fs.write_file(handle, 7, b"World!").unwrap();

    fs.close_file(handle).unwrap();

    let content = fs.read_entire_file(item_id).unwrap();
    assert_eq!(&content, b"Hello, World!");
}

#[test]
fn test_overwrite_middle_of_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let item_id = fs.write_new_file(root, "overwrite.txt", b"AAAAAAAAAA").unwrap();

    let handle = fs.open_file(item_id, true).unwrap();
    fs.write_file(handle, 3, b"BBB").unwrap();
    fs.close_file(handle).unwrap();

    let content = fs.read_entire_file(item_id).unwrap();
    assert_eq!(&content, b"AAABBBAAA");
}

// ============================================================================
// Directory Tests
// ============================================================================

#[test]
fn test_create_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_directory(root, "subdir").unwrap();
    assert!(attrs.attr_is_directory());
    assert_eq!(attrs.attr_mode(), 0o755);
}

#[test]
fn test_create_nested_directories() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let dir1 = fs.create_directory(root, "level1").unwrap();
    let dir1_id = dir1.attr_item_id();

    let dir2 = fs.create_directory(dir1_id, "level2").unwrap();
    let dir2_id = dir2.attr_item_id();

    let dir3 = fs.create_directory(dir2_id, "level3").unwrap();
    assert!(dir3.attr_is_directory());
}

#[test]
fn test_create_file_in_subdirectory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let dir_attrs = fs.create_directory(root, "subdir").unwrap();
    let dir_id = dir_attrs.attr_item_id();

    let content = b"File in subdirectory";
    let file_id = fs.write_new_file(dir_id, "nested.txt", content).unwrap();

    let read_content = fs.read_entire_file(file_id).unwrap();
    assert_bytes_equal(&read_content, content, "file in subdirectory");
}

#[test]
fn test_enumerate_empty_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let entries = fs.list_directory(root).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_enumerate_directory_with_files() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    fs.create_file(root, "file1.txt").unwrap();
    fs.create_file(root, "file2.txt").unwrap();
    fs.create_directory(root, "subdir").unwrap();

    let entries = fs.list_directory(root).unwrap();
    assert_eq!(entries.len(), 3);

    let names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8(e.entry_name()).unwrap())
        .collect();

    assert!(names.contains(&"file1.txt".to_string()));
    assert!(names.contains(&"file2.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));
}

// ============================================================================
// Symlink Tests
// ============================================================================

#[test]
fn test_create_symlink() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_symlink(root, "link", "/target/path").unwrap();
    assert!(attrs.attr_is_symlink());
    assert_eq!(attrs.attr_mode(), 0o777);
}

#[test]
fn test_read_symlink_target() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let target = "/some/target/path";
    let attrs = fs.create_symlink(root, "mylink", target).unwrap();
    let item_id = attrs.attr_item_id();

    let read_target = fs.read_symlink(item_id).unwrap();
    assert_eq!(read_target, target);
}

#[test]
fn test_symlink_appears_in_directory_listing() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    fs.create_symlink(root, "testlink", "/target").unwrap();

    let entries = fs.list_directory(root).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].entry_is_symlink());
    assert_eq!(
        String::from_utf8(entries[0].entry_name()).unwrap(),
        "testlink"
    );
}

// ============================================================================
// Removal Tests
// ============================================================================

#[test]
fn test_remove_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_file(root, "to_delete.txt").unwrap();
    let item_id = attrs.attr_item_id();

    assert!(fs.exists(root, "to_delete.txt"));

    fs.remove(root, "to_delete.txt", item_id).unwrap();

    assert!(!fs.exists(root, "to_delete.txt"));
}

#[test]
fn test_remove_empty_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_directory(root, "empty_dir").unwrap();
    let item_id = attrs.attr_item_id();

    fs.remove(root, "empty_dir", item_id).unwrap();

    assert!(!fs.exists(root, "empty_dir"));
}

#[test]
fn test_remove_nonempty_directory_fails() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let dir_attrs = fs.create_directory(root, "nonempty").unwrap();
    let dir_id = dir_attrs.attr_item_id();

    fs.create_file(dir_id, "child.txt").unwrap();

    let result = fs.remove(root, "nonempty", dir_id);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), libc::ENOTEMPTY);
}

#[test]
fn test_remove_symlink() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_symlink(root, "link_to_delete", "/target").unwrap();
    let item_id = attrs.attr_item_id();

    fs.remove(root, "link_to_delete", item_id).unwrap();

    assert!(!fs.exists(root, "link_to_delete"));
}

// ============================================================================
// Rename Tests
// ============================================================================

#[test]
fn test_rename_file_same_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"Rename test content";
    let item_id = fs.write_new_file(root, "old_name.txt", content).unwrap();

    fs.rename(root, "old_name.txt", root, "new_name.txt", item_id)
        .unwrap();

    assert!(!fs.exists(root, "old_name.txt"));
    assert!(fs.exists(root, "new_name.txt"));

    // Content should be preserved
    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_bytes_equal(&read_content, content, "renamed file content");
}

#[test]
fn test_rename_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let attrs = fs.create_directory(root, "old_dir").unwrap();
    let item_id = attrs.attr_item_id();

    fs.rename(root, "old_dir", root, "new_dir", item_id).unwrap();

    assert!(!fs.exists(root, "old_dir"));
    assert!(fs.exists(root, "new_dir"));
}

#[test]
fn test_rename_symlink() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let target = "/my/target";
    let attrs = fs.create_symlink(root, "old_link", target).unwrap();
    let item_id = attrs.attr_item_id();

    fs.rename(root, "old_link", root, "new_link", item_id)
        .unwrap();

    assert!(!fs.exists(root, "old_link"));
    assert!(fs.exists(root, "new_link"));

    // Target should be preserved
    let read_target = fs.read_symlink(item_id).unwrap();
    assert_eq!(read_target, target);
}

// ============================================================================
// Truncate Tests
// ============================================================================

#[test]
fn test_truncate_shrink() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"Hello World!";
    let item_id = fs.write_new_file(root, "truncate.txt", content).unwrap();

    fs.truncate(item_id, 5).unwrap();

    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_eq!(&read_content, b"Hello");
}

#[test]
fn test_truncate_extend() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"Hi";
    let item_id = fs.write_new_file(root, "extend.txt", content).unwrap();

    fs.truncate(item_id, 10).unwrap();

    let read_content = fs.read_entire_file(item_id).unwrap();
    assert_eq!(read_content.len(), 10);
    assert_eq!(&read_content[0..2], b"Hi");
    // Extended portion should be zeros
    assert!(read_content[2..].iter().all(|&b| b == 0));
}

#[test]
fn test_truncate_to_zero() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = one_chunk_content();
    let item_id = fs.write_new_file(root, "zero.bin", &content).unwrap();

    fs.truncate(item_id, 0).unwrap();

    let read_content = fs.read_entire_file(item_id).unwrap();
    assert!(read_content.is_empty());
}

// ============================================================================
// Attribute Tests
// ============================================================================

#[test]
fn test_get_attributes_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let content = b"Test content";
    let item_id = fs.write_new_file(root, "attr_test.txt", content).unwrap();

    let attrs = fs.get_attributes(item_id).unwrap();
    assert!(attrs.attr_is_file());
    assert!(!attrs.attr_is_directory());
    assert!(!attrs.attr_is_symlink());
    assert_eq!(attrs.attr_size(), content.len() as u64);
    assert_eq!(attrs.attr_mode(), 0o644);
}

#[test]
fn test_get_attributes_directory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let dir_attrs = fs.create_directory(root, "attr_dir").unwrap();
    let dir_id = dir_attrs.attr_item_id();

    let attrs = fs.get_attributes(dir_id).unwrap();
    assert!(attrs.attr_is_directory());
    assert!(!attrs.attr_is_file());
    assert!(!attrs.attr_is_symlink());
    assert_eq!(attrs.attr_mode(), 0o755);
}

#[test]
fn test_get_attributes_symlink() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let target = "/some/path";
    let sym_attrs = fs.create_symlink(root, "attr_link", target).unwrap();
    let sym_id = sym_attrs.attr_item_id();

    let attrs = fs.get_attributes(sym_id).unwrap();
    assert!(attrs.attr_is_symlink());
    assert!(!attrs.attr_is_file());
    assert!(!attrs.attr_is_directory());
    assert_eq!(attrs.attr_mode(), 0o777);
}

#[test]
fn test_get_attributes_nonexistent() {
    let fs = TestFilesystem::new();

    let result = fs.get_attributes(999999);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), libc::ENOENT);
}

// ============================================================================
// Lookup Tests
// ============================================================================

#[test]
fn test_lookup_existing_file() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let created = fs.create_file(root, "lookup_test.txt").unwrap();

    let looked_up = fs.lookup(root, "lookup_test.txt").unwrap();
    assert_eq!(looked_up.attr_item_id(), created.attr_item_id());
    assert!(looked_up.attr_is_file());
}

#[test]
fn test_lookup_nonexistent() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let result = fs.lookup(root, "does_not_exist.txt");
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), libc::ENOENT);
}

#[test]
fn test_lookup_in_subdirectory() {
    let fs = TestFilesystem::new();
    let root = fs.root_id();

    let dir = fs.create_directory(root, "subdir").unwrap();
    let dir_id = dir.attr_item_id();

    let file = fs.create_file(dir_id, "nested_file.txt").unwrap();

    let looked_up = fs.lookup(dir_id, "nested_file.txt").unwrap();
    assert_eq!(looked_up.attr_item_id(), file.attr_item_id());
}

// ============================================================================
// Volume Statistics Tests
// ============================================================================

#[test]
fn test_volume_statistics() {
    let fs = TestFilesystem::new();

    let stats = fs.get_volume_stats().unwrap();

    // Basic sanity checks
    assert!(stats.stats_total_bytes() > 0);
    assert!(stats.stats_available_bytes() <= stats.stats_total_bytes());
    assert_eq!(
        stats.stats_used_bytes(),
        stats.stats_total_bytes() - stats.stats_available_bytes()
    );
    assert!(stats.stats_block_size() > 0);
}
