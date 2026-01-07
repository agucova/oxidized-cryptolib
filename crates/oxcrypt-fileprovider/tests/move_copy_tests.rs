//! Move and copy operation tests for File Provider.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::TestMount;

#[test]
fn move_file_same_dir() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_same");

    mount
        .write_file("original.txt", b"content")
        .expect("Write failed");

    mount
        .rename("original.txt", "renamed.txt")
        .expect("Rename failed");

    assert!(!mount.exists("original.txt"), "Original should not exist");
    assert!(mount.exists("renamed.txt"), "Renamed should exist");

    let content = mount.read_file("renamed.txt").expect("Read failed");
    assert_eq!(content, b"content");
}

#[test]
fn move_file_different_dir() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_diff");

    mount.mkdir("src").expect("mkdir failed");
    mount.mkdir("dst").expect("mkdir failed");
    mount
        .write_file("src/file.txt", b"moving content")
        .expect("Write failed");

    mount
        .rename("src/file.txt", "dst/file.txt")
        .expect("Move failed");

    assert!(!mount.exists("src/file.txt"), "Source should not exist");
    assert!(mount.exists("dst/file.txt"), "Destination should exist");

    let content = mount.read_file("dst/file.txt").expect("Read failed");
    assert_eq!(content, b"moving content");
}

#[test]
fn move_file_with_rename() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_rename");

    mount.mkdir("src").expect("mkdir failed");
    mount.mkdir("dst").expect("mkdir failed");
    mount
        .write_file("src/old_name.txt", b"content")
        .expect("Write failed");

    mount
        .rename("src/old_name.txt", "dst/new_name.txt")
        .expect("Move+rename failed");

    assert!(!mount.exists("src/old_name.txt"));
    assert!(mount.exists("dst/new_name.txt"));
}

#[test]
fn copy_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("copy_file");

    let content = b"content to copy";
    mount.write_file("source.txt", content).expect("Write failed");

    mount
        .copy_file("source.txt", "copy.txt")
        .expect("Copy failed");

    // Both files should exist
    assert!(mount.exists("source.txt"), "Source should still exist");
    assert!(mount.exists("copy.txt"), "Copy should exist");

    // Both should have same content
    let source_content = mount.read_file("source.txt").expect("Read source failed");
    let copy_content = mount.read_file("copy.txt").expect("Read copy failed");
    assert_eq!(source_content, copy_content);
    assert_eq!(copy_content, content);
}

#[test]
fn copy_file_to_subdir() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("copy_subdir");

    mount.mkdir("subdir").expect("mkdir failed");
    mount
        .write_file("original.txt", b"content")
        .expect("Write failed");

    mount
        .copy_file("original.txt", "subdir/copy.txt")
        .expect("Copy failed");

    assert!(mount.exists("original.txt"));
    assert!(mount.exists("subdir/copy.txt"));
}

#[test]
fn move_directory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_dir");

    mount.mkdir("old_dir").expect("mkdir failed");
    mount
        .write_file("old_dir/file.txt", b"inside")
        .expect("Write failed");

    mount
        .rename("old_dir", "new_dir")
        .expect("Rename dir failed");

    assert!(!mount.exists("old_dir"), "Old dir should not exist");
    assert!(mount.exists("new_dir"), "New dir should exist");
    assert!(
        mount.exists("new_dir/file.txt"),
        "File inside should exist"
    );

    let content = mount.read_file("new_dir/file.txt").expect("Read failed");
    assert_eq!(content, b"inside");
}

#[test]
fn move_directory_to_different_parent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_dir_parent");

    mount.mkdir("parent1").expect("mkdir failed");
    mount.mkdir("parent2").expect("mkdir failed");
    mount.mkdir("parent1/child").expect("mkdir failed");
    mount
        .write_file("parent1/child/file.txt", b"data")
        .expect("Write failed");

    mount
        .rename("parent1/child", "parent2/child")
        .expect("Move dir failed");

    assert!(!mount.exists("parent1/child"));
    assert!(mount.exists("parent2/child"));
    assert!(mount.exists("parent2/child/file.txt"));
}

#[test]
fn rename_overwrites_existing() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rename_overwrite");

    mount
        .write_file("source.txt", b"new content")
        .expect("Write source failed");
    mount
        .write_file("target.txt", b"old content")
        .expect("Write target failed");

    mount
        .rename("source.txt", "target.txt")
        .expect("Rename failed");

    assert!(!mount.exists("source.txt"));
    let content = mount.read_file("target.txt").expect("Read failed");
    assert_eq!(content, b"new content");
}
