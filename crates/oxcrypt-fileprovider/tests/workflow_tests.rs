//! Workflow tests for File Provider.
//!
//! Tests that verify common workflows and operation sequences work correctly.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::{generate_test_data, TestMount};

#[test]
fn create_populate_delete_cycle() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("cycle");

    // Create directory with files
    mount.mkdir("cycle_dir").expect("mkdir failed");
    mount
        .write_file("cycle_dir/file1.txt", b"content 1")
        .expect("Write 1 failed");
    mount
        .write_file("cycle_dir/file2.txt", b"content 2")
        .expect("Write 2 failed");

    // Verify contents
    let entries = mount.list_dir("cycle_dir").expect("List failed");
    assert_eq!(entries.len(), 2);

    // Delete files
    mount
        .remove_file("cycle_dir/file1.txt")
        .expect("Remove 1 failed");
    mount
        .remove_file("cycle_dir/file2.txt")
        .expect("Remove 2 failed");

    // Verify directory is empty
    let entries = mount.list_dir("cycle_dir").expect("List failed");
    assert!(entries.is_empty());

    // Delete directory
    mount.remove_dir("cycle_dir").expect("rmdir failed");
    assert!(!mount.exists("cycle_dir"));
}

#[test]
fn nested_directory_operations() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("nested");

    // Create nested structure
    mount.mkdir_all("a/b/c/d").expect("mkdir_all failed");

    // Create files at each level
    mount.write_file("a/file.txt", b"level a").expect("Write a failed");
    mount
        .write_file("a/b/file.txt", b"level b")
        .expect("Write b failed");
    mount
        .write_file("a/b/c/file.txt", b"level c")
        .expect("Write c failed");
    mount
        .write_file("a/b/c/d/file.txt", b"level d")
        .expect("Write d failed");

    // Verify all files exist and have correct content
    assert_eq!(mount.read_file("a/file.txt").unwrap(), b"level a");
    assert_eq!(mount.read_file("a/b/file.txt").unwrap(), b"level b");
    assert_eq!(mount.read_file("a/b/c/file.txt").unwrap(), b"level c");
    assert_eq!(mount.read_file("a/b/c/d/file.txt").unwrap(), b"level d");

    // Clean up from deepest level
    mount.remove_file("a/b/c/d/file.txt").expect("Remove d failed");
    mount.remove_dir("a/b/c/d").expect("rmdir d failed");
    mount.remove_file("a/b/c/file.txt").expect("Remove c failed");
    mount.remove_dir("a/b/c").expect("rmdir c failed");
    mount.remove_file("a/b/file.txt").expect("Remove b failed");
    mount.remove_dir("a/b").expect("rmdir b failed");
    mount.remove_file("a/file.txt").expect("Remove a failed");
    mount.remove_dir("a").expect("rmdir a failed");

    assert!(!mount.exists("a"));
}

#[test]
fn file_replace_workflow() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("replace");

    // Create original file
    mount
        .write_file("document.txt", b"original content")
        .expect("Write original failed");

    // Delete and recreate with same name
    mount
        .remove_file("document.txt")
        .expect("Remove failed");
    mount
        .write_file("document.txt", b"new content")
        .expect("Write new failed");

    let content = mount.read_file("document.txt").expect("Read failed");
    assert_eq!(content, b"new content");
}

#[test]
fn move_and_modify_workflow() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_modify");

    // Create initial file
    mount
        .write_file("original.txt", b"initial content")
        .expect("Write failed");

    // Create destination directory
    mount.mkdir("destination").expect("mkdir failed");

    // Move file
    mount
        .rename("original.txt", "destination/moved.txt")
        .expect("Rename failed");

    // Modify content
    mount
        .write_file("destination/moved.txt", b"modified content")
        .expect("Overwrite failed");

    // Verify final state
    assert!(!mount.exists("original.txt"));
    let content = mount.read_file("destination/moved.txt").expect("Read failed");
    assert_eq!(content, b"modified content");
}

#[test]
fn backup_restore_workflow() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("backup");

    // Create original file
    let original_content = generate_test_data(1024);
    mount
        .write_file("important.dat", &original_content)
        .expect("Write original failed");

    // Create backup
    mount.mkdir("backups").expect("mkdir failed");
    mount
        .copy_file("important.dat", "backups/important.dat.bak")
        .expect("Copy failed");

    // Modify original (simulating corruption/changes)
    mount
        .write_file("important.dat", b"corrupted")
        .expect("Write corrupted failed");

    // Verify original is changed
    let corrupted = mount.read_file("important.dat").expect("Read failed");
    assert_eq!(corrupted, b"corrupted");

    // Restore from backup
    mount.remove_file("important.dat").expect("Remove failed");
    mount
        .copy_file("backups/important.dat.bak", "important.dat")
        .expect("Restore failed");

    // Verify restoration
    let restored = mount.read_file("important.dat").expect("Read restored failed");
    assert_eq!(restored, original_content);
}

#[test]
fn reorganize_directory_structure() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("reorganize");

    // Create initial flat structure
    mount.write_file("doc1.txt", b"doc 1").expect("Write 1 failed");
    mount.write_file("doc2.txt", b"doc 2").expect("Write 2 failed");
    mount.write_file("image1.png", b"image 1").expect("Write 3 failed");
    mount.write_file("image2.png", b"image 2").expect("Write 4 failed");

    // Create organized structure
    mount.mkdir("documents").expect("mkdir docs failed");
    mount.mkdir("images").expect("mkdir images failed");

    // Move files to appropriate directories
    mount
        .rename("doc1.txt", "documents/doc1.txt")
        .expect("Move doc1 failed");
    mount
        .rename("doc2.txt", "documents/doc2.txt")
        .expect("Move doc2 failed");
    mount
        .rename("image1.png", "images/image1.png")
        .expect("Move image1 failed");
    mount
        .rename("image2.png", "images/image2.png")
        .expect("Move image2 failed");

    // Verify new structure
    let root_entries = mount.list_dir("").expect("List root failed");
    assert_eq!(root_entries.len(), 2);
    assert!(root_entries.contains(&"documents".to_string()));
    assert!(root_entries.contains(&"images".to_string()));

    let doc_entries = mount.list_dir("documents").expect("List docs failed");
    assert_eq!(doc_entries.len(), 2);
    assert!(doc_entries.contains(&"doc1.txt".to_string()));
    assert!(doc_entries.contains(&"doc2.txt".to_string()));

    let img_entries = mount.list_dir("images").expect("List images failed");
    assert_eq!(img_entries.len(), 2);
    assert!(img_entries.contains(&"image1.png".to_string()));
    assert!(img_entries.contains(&"image2.png".to_string()));
}

#[test]
fn incremental_file_growth() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("growth");

    // Start with empty file
    mount.write_file("growing.log", b"").expect("Write initial failed");

    // Append content in stages (simulating log growth)
    let mut full_content = Vec::new();
    for i in 0..10 {
        let line = format!("Log entry {i}\n");
        full_content.extend_from_slice(line.as_bytes());
        mount
            .write_file("growing.log", &full_content)
            .expect(&format!("Write stage {i} failed"));

        // Verify each stage
        let read_back = mount.read_file("growing.log").expect(&format!("Read stage {i} failed"));
        assert_eq!(read_back, full_content, "Content mismatch at stage {i}");
    }
}

#[test]
fn concurrent_style_operations() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("concurrent");

    // Create multiple files rapidly (simulating concurrent-like access)
    for i in 0..20 {
        let filename = format!("file_{i:03}.txt");
        let content = format!("Content for file {i}");
        mount
            .write_file(&filename, content.as_bytes())
            .expect(&format!("Write {i} failed"));
    }

    // Verify all files exist with correct content
    for i in 0..20 {
        let filename = format!("file_{i:03}.txt");
        let expected = format!("Content for file {i}");
        let actual = mount.read_file(&filename).expect(&format!("Read {i} failed"));
        assert_eq!(
            String::from_utf8_lossy(&actual),
            expected,
            "Content mismatch for file {i}"
        );
    }

    // Delete every other file
    for i in (0..20).step_by(2) {
        let filename = format!("file_{i:03}.txt");
        mount
            .remove_file(&filename)
            .expect(&format!("Remove {i} failed"));
    }

    // Verify correct files remain
    for i in 0..20 {
        let filename = format!("file_{i:03}.txt");
        if i % 2 == 0 {
            assert!(!mount.exists(&filename), "File {i} should be deleted");
        } else {
            assert!(mount.exists(&filename), "File {i} should exist");
        }
    }
}

#[test]
fn empty_directory_workflow() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("empty_dirs");

    // Create multiple empty directories
    mount.mkdir("empty1").expect("mkdir 1 failed");
    mount.mkdir("empty2").expect("mkdir 2 failed");
    mount.mkdir("empty3").expect("mkdir 3 failed");

    // Verify they're empty
    assert!(mount.list_dir("empty1").unwrap().is_empty());
    assert!(mount.list_dir("empty2").unwrap().is_empty());
    assert!(mount.list_dir("empty3").unwrap().is_empty());

    // Delete them all
    mount.remove_dir("empty1").expect("rmdir 1 failed");
    mount.remove_dir("empty2").expect("rmdir 2 failed");
    mount.remove_dir("empty3").expect("rmdir 3 failed");

    // Verify root is empty
    let root_entries = mount.list_dir("").expect("List root failed");
    assert!(root_entries.is_empty());
}
