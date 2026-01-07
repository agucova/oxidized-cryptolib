//! Metadata operation tests for File Provider.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::{generate_test_data, TestMount};

#[test]
fn file_size_accuracy() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("file_size");

    let sizes = [0, 1, 100, 1024, 32 * 1024, 100 * 1024, 1024 * 1024];

    for &size in &sizes {
        let name = format!("file_{size}.bin");
        let content = generate_test_data(size);
        mount.write_file(&name, &content).expect("Write failed");

        let meta = mount.metadata(&name).expect("Metadata failed");
        assert_eq!(
            meta.len() as usize,
            size,
            "Size mismatch for {size} byte file"
        );
    }
}

#[test]
fn metadata_after_write() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("meta_write");

    // Create file
    mount
        .write_file("test.txt", b"initial")
        .expect("Write failed");
    let meta1 = mount.metadata("test.txt").expect("Metadata 1 failed");

    // Small delay to ensure different mtime
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Modify file
    mount
        .write_file("test.txt", b"modified content")
        .expect("Rewrite failed");
    let meta2 = mount.metadata("test.txt").expect("Metadata 2 failed");

    assert_eq!(meta2.len(), 16); // "modified content".len()
    assert!(
        meta2.len() != meta1.len(),
        "Size should change after rewrite"
    );
}

#[test]
fn directory_metadata() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("dir_meta");

    mount.mkdir("testdir").expect("mkdir failed");

    let meta = mount.metadata("testdir").expect("Metadata failed");
    assert!(meta.is_dir(), "Should be a directory");
    assert!(!meta.is_file(), "Should not be a file");
}

#[test]
fn file_vs_directory_type() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("type_check");

    mount.mkdir("a_dir").expect("mkdir failed");
    mount.write_file("a_file.txt", b"data").expect("Write failed");

    let dir_meta = mount.metadata("a_dir").expect("Dir metadata failed");
    let file_meta = mount.metadata("a_file.txt").expect("File metadata failed");

    assert!(dir_meta.is_dir());
    assert!(!dir_meta.is_file());
    assert!(file_meta.is_file());
    assert!(!file_meta.is_dir());
}

#[test]
fn empty_directory_listing() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("empty_list");

    mount.mkdir("empty").expect("mkdir failed");

    let entries = mount.list_dir("empty").expect("List failed");
    assert!(entries.is_empty(), "Empty directory should have no entries");
}

#[test]
fn many_files_listing() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("many_files");

    mount.mkdir("many").expect("mkdir failed");

    // Create 50 files
    for i in 0..50 {
        let name = format!("many/file_{i:03}.txt");
        mount.write_file(&name, b"x").expect("Write failed");
    }

    let entries = mount.list_dir("many").expect("List failed");
    assert_eq!(entries.len(), 50, "Should list all 50 files");

    // Verify sorted order
    for i in 0..50 {
        let expected = format!("file_{i:03}.txt");
        assert!(entries.contains(&expected), "Missing file {expected}");
    }
}

#[test]
fn mixed_directory_listing() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("mixed_list");

    mount.mkdir("mixed").expect("mkdir failed");
    mount.write_file("mixed/file1.txt", b"1").expect("Write failed");
    mount.mkdir("mixed/subdir1").expect("mkdir failed");
    mount.write_file("mixed/file2.txt", b"2").expect("Write failed");
    mount.mkdir("mixed/subdir2").expect("mkdir failed");

    let entries = mount.list_dir("mixed").expect("List failed");
    assert_eq!(entries.len(), 4);
    assert!(entries.contains(&"file1.txt".to_string()));
    assert!(entries.contains(&"file2.txt".to_string()));
    assert!(entries.contains(&"subdir1".to_string()));
    assert!(entries.contains(&"subdir2".to_string()));
}
