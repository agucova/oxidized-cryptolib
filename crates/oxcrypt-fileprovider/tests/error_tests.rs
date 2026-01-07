//! Error handling tests for File Provider.
//!
//! Tests that verify proper error handling for invalid operations.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::TestMount;

#[test]
fn read_nonexistent_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("read_noexist");

    let result = mount.read_file("does_not_exist.txt");
    assert!(result.is_err(), "Reading nonexistent file should fail");
}

#[test]
fn delete_nonexistent_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("delete_noexist");

    let result = mount.remove_file("does_not_exist.txt");
    assert!(result.is_err(), "Deleting nonexistent file should fail");
}

#[test]
fn mkdir_over_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("mkdir_file");

    // Create a file
    mount.write_file("existing", b"content").expect("Write failed");

    // Try to create directory with same name
    let result = mount.mkdir("existing");
    assert!(
        result.is_err(),
        "Creating directory over existing file should fail"
    );
}

#[test]
fn rmdir_nonempty() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rmdir_nonempty");

    // Create directory with file
    mount.mkdir("nonempty").expect("mkdir failed");
    mount
        .write_file("nonempty/file.txt", b"content")
        .expect("Write failed");

    // Try to remove non-empty directory
    let result = mount.remove_dir("nonempty");
    assert!(
        result.is_err(),
        "Removing non-empty directory should fail"
    );
}

#[test]
fn rmdir_nonexistent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rmdir_noexist");

    let result = mount.remove_dir("does_not_exist");
    assert!(result.is_err(), "Removing nonexistent directory should fail");
}

#[test]
fn list_nonexistent_dir() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("list_noexist");

    let result = mount.list_dir("does_not_exist");
    assert!(result.is_err(), "Listing nonexistent directory should fail");
}

#[test]
fn list_file_as_directory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("list_file");

    mount.write_file("afile.txt", b"content").expect("Write failed");

    let result = mount.list_dir("afile.txt");
    assert!(result.is_err(), "Listing a file as directory should fail");
}

#[test]
fn write_to_directory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("write_dir");

    mount.mkdir("adir").expect("mkdir failed");

    // Try to write to directory path
    let result = mount.write_file("adir", b"content");
    assert!(result.is_err(), "Writing to directory should fail");
}

#[test]
fn read_directory_as_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("read_dir");

    mount.mkdir("adir").expect("mkdir failed");

    let result = mount.read_file("adir");
    assert!(result.is_err(), "Reading directory as file should fail");
}

#[test]
fn remove_file_on_directory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("remove_dir_as_file");

    mount.mkdir("adir").expect("mkdir failed");

    let result = mount.remove_file("adir");
    assert!(result.is_err(), "remove_file on directory should fail");
}

#[test]
fn rename_nonexistent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rename_noexist");

    let result = mount.rename("does_not_exist.txt", "new_name.txt");
    assert!(result.is_err(), "Renaming nonexistent file should fail");
}

#[test]
fn copy_nonexistent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("copy_noexist");

    let result = mount.copy_file("does_not_exist.txt", "copy.txt");
    assert!(result.is_err(), "Copying nonexistent file should fail");
}

#[test]
fn metadata_nonexistent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("meta_noexist");

    let result = mount.metadata("does_not_exist.txt");
    assert!(
        result.is_err(),
        "Getting metadata for nonexistent file should fail"
    );
}

#[test]
fn mkdir_in_nonexistent_parent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("mkdir_noparent");

    // Try to create directory in nonexistent parent (not using mkdir_all)
    let result = mount.mkdir("nonexistent/child");
    assert!(
        result.is_err(),
        "Creating directory in nonexistent parent should fail"
    );
}

#[test]
fn write_in_nonexistent_parent() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("write_noparent");

    // Try to write file in nonexistent directory
    let result = mount.write_file("nonexistent/file.txt", b"content");
    assert!(
        result.is_err(),
        "Writing file in nonexistent directory should fail"
    );
}

#[test]
fn double_mkdir() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("double_mkdir");

    mount.mkdir("existing_dir").expect("mkdir failed");

    // Try to create the same directory again
    let result = mount.mkdir("existing_dir");
    assert!(
        result.is_err(),
        "Creating existing directory should fail"
    );
}

#[test]
fn rename_to_existing_directory() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("rename_to_dir");

    mount.mkdir("target_dir").expect("mkdir target failed");
    mount.write_file("source.txt", b"content").expect("Write failed");

    // Try to rename file to existing directory name
    let result = mount.rename("source.txt", "target_dir");
    // Note: This behavior may vary - some systems allow it, some don't
    // Just verify it doesn't crash/hang
    let _ = result;
}

#[test]
fn move_directory_into_itself() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("move_into_self");

    mount.mkdir("parent").expect("mkdir parent failed");
    mount.mkdir("parent/child").expect("mkdir child failed");

    // Try to move directory into its own child
    let result = mount.rename("parent", "parent/child/parent");
    assert!(
        result.is_err(),
        "Moving directory into its own child should fail"
    );
}
