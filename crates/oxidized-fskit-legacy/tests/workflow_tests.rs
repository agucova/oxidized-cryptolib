//! Workflow tests for FSKit filesystem.
//!
//! Tests realistic multi-step sequences that combine multiple operations.
//! These tests catch bugs in state management and operation ordering that
//! simpler unit tests might miss.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests workflow_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// File Editing Workflows
// =============================================================================

#[test]
fn test_edit_file_in_place() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Simulate editing a file: read, modify, write back
    mount.write("document.txt", b"Original content").expect("initial write failed");

    let original = mount.read("document.txt").expect("read failed");
    let mut modified = original;
    modified.extend_from_slice(b"\nAppended line");

    mount.write("document.txt", &modified).expect("rewrite failed");

    assert_file_content(&mount, "document.txt", b"Original content\nAppended line");
}

#[test]
fn test_safe_save_pattern() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Many editors use atomic save: write to temp, rename over original
    mount.write("file.txt", b"original content").expect("initial write failed");

    // Write new content to temp file
    mount.write("file.txt.tmp", b"new content").expect("temp write failed");

    // Atomic rename
    mount.rename("file.txt.tmp", "file.txt").expect("rename failed");

    // Verify atomic update
    assert_file_content(&mount, "file.txt", b"new content");
    assert_not_found(&mount, "file.txt.tmp");
}

#[test]
fn test_backup_before_modify() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Pattern: copy original to backup, then modify
    let original_content = b"Important data that should be backed up";
    mount.write("important.dat", original_content).expect("initial write failed");

    // Create backup
    mount.copy("important.dat", "important.dat.bak").expect("backup failed");

    // Modify original
    mount.write("important.dat", b"Modified data").expect("modify failed");

    // Both should exist with correct content
    assert_file_content(&mount, "important.dat", b"Modified data");
    assert_file_content(&mount, "important.dat.bak", original_content);
}

// =============================================================================
// Directory Organization
// =============================================================================

#[test]
fn test_reorganize_directory_structure() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial flat structure
    mount.write("doc1.txt", b"doc1").expect("write doc1 failed");
    mount.write("doc2.txt", b"doc2").expect("write doc2 failed");
    mount.write("img1.png", b"img1").expect("write img1 failed");
    mount.write("img2.png", b"img2").expect("write img2 failed");

    // Reorganize into subdirectories
    mount.mkdir("documents").expect("mkdir documents failed");
    mount.mkdir("images").expect("mkdir images failed");

    mount.rename("doc1.txt", "documents/doc1.txt").expect("move doc1 failed");
    mount.rename("doc2.txt", "documents/doc2.txt").expect("move doc2 failed");
    mount.rename("img1.png", "images/img1.png").expect("move img1 failed");
    mount.rename("img2.png", "images/img2.png").expect("move img2 failed");

    // Verify new structure
    assert_dir_entries(&mount, "documents", &["doc1.txt", "doc2.txt"]);
    assert_dir_entries(&mount, "images", &["img1.png", "img2.png"]);

    // Old files should not exist in root
    assert_not_found(&mount, "doc1.txt");
    assert_not_found(&mount, "img1.png");
}

#[test]
fn test_create_project_structure() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a typical project directory structure
    mount.mkdir_all("project/src").expect("mkdir src failed");
    mount.mkdir_all("project/tests").expect("mkdir tests failed");
    mount.mkdir_all("project/docs").expect("mkdir docs failed");

    mount.write("project/README.md", b"# Project\n\nDescription here.").expect("write readme failed");
    mount.write("project/src/main.rs", b"fn main() {}").expect("write main failed");
    mount.write("project/src/lib.rs", b"//! Library").expect("write lib failed");
    mount.write("project/tests/test_main.rs", b"#[test] fn test() {}").expect("write test failed");
    mount.write("project/docs/guide.md", b"# Guide").expect("write guide failed");

    // Verify structure
    assert_is_directory(&mount, "project");
    assert_is_directory(&mount, "project/src");
    assert_is_directory(&mount, "project/tests");
    assert_is_directory(&mount, "project/docs");

    assert_file_content(&mount, "project/README.md", b"# Project\n\nDescription here.");
    assert_file_content(&mount, "project/src/main.rs", b"fn main() {}");
}

// =============================================================================
// Cleanup Workflows
// =============================================================================

#[test]
fn test_clean_temporary_files() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create mixed files
    mount.write("document.txt", b"keep").expect("write document failed");
    mount.write("document.txt~", b"temp").expect("write backup failed");
    mount.write("data.bin", b"keep").expect("write data failed");
    mount.write("data.bin.tmp", b"temp").expect("write tmp failed");
    mount.write(".hidden", b"keep").expect("write hidden failed");

    // Clean up temporary files (simulating an editor's cleanup)
    let entries = mount.list("/").expect("list failed");
    for entry in entries {
        if entry.ends_with('~') || entry.ends_with(".tmp") {
            mount.remove(&entry).expect("cleanup failed");
        }
    }

    // Verify cleanup
    assert_exists(&mount, "document.txt");
    assert_exists(&mount, "data.bin");
    assert_exists(&mount, ".hidden");
    assert_not_found(&mount, "document.txt~");
    assert_not_found(&mount, "data.bin.tmp");
}

#[test]
fn test_recursive_directory_cleanup() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create directory with contents
    mount.mkdir_all("cache/images").expect("mkdir failed");
    mount.write("cache/data.json", b"{}").expect("write data failed");
    mount.write("cache/images/thumb1.jpg", b"img1").expect("write img1 failed");
    mount.write("cache/images/thumb2.jpg", b"img2").expect("write img2 failed");

    // Verify structure exists
    assert_is_directory(&mount, "cache");
    assert_file_content(&mount, "cache/data.json", b"{}");

    // Recursive delete
    mount.rmdir_all("cache").expect("rmdir_all failed");

    // Verify complete removal
    assert_not_found(&mount, "cache");
    assert_not_found(&mount, "cache/data.json");
    assert_not_found(&mount, "cache/images");
}

// =============================================================================
// Multi-File Workflows
// =============================================================================

#[test]
fn test_batch_file_processing() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let num_files = 10;

    // Create batch of files
    for i in 0..num_files {
        let filename = format!("input_{:03}.dat", i);
        let content = format!("Data for file {}", i);
        mount.write(&filename, content.as_bytes()).expect("write failed");
    }

    // Process each file (simulate transformation)
    mount.mkdir("output").expect("mkdir output failed");
    for i in 0..num_files {
        let input_name = format!("input_{:03}.dat", i);
        let output_name = format!("output/processed_{:03}.dat", i);

        let data = mount.read(&input_name).expect("read failed");
        let processed: Vec<u8> = data.iter().map(|b| b.to_ascii_uppercase()).collect();
        mount.write(&output_name, &processed).expect("write processed failed");
    }

    // Verify all outputs exist
    for i in 0..num_files {
        let output_name = format!("output/processed_{:03}.dat", i);
        assert_exists(&mount, &output_name);

        let content = mount.read(&output_name).expect("read output failed");
        // Verify content was uppercased
        assert!(
            content.iter().all(|b| !b.is_ascii_lowercase()),
            "Content should be uppercase"
        );
    }
}

#[test]
fn test_incremental_log_append() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create log file
    mount.write("app.log", b"").expect("create log failed");

    // Simulate multiple log entries
    for i in 1..=5 {
        let current = mount.read("app.log").expect("read log failed");
        let entry = format!("[LOG] Entry {}\n", i);
        let mut new_content = current;
        new_content.extend_from_slice(entry.as_bytes());
        mount.write("app.log", &new_content).expect("append failed");
    }

    let final_log = mount.read("app.log").expect("read final failed");
    let log_str = String::from_utf8_lossy(&final_log);

    assert!(log_str.contains("[LOG] Entry 1"));
    assert!(log_str.contains("[LOG] Entry 5"));
    assert_eq!(log_str.matches("[LOG]").count(), 5);
}

// =============================================================================
// Recovery Workflows
// =============================================================================

#[test]
fn test_transaction_like_pattern() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Simulate a transaction: either all changes succeed or none
    // In practice, this uses a staging directory

    // Original state
    mount.write("account_a.dat", b"balance: 100").expect("write a failed");
    mount.write("account_b.dat", b"balance: 50").expect("write b failed");

    // Create staging area
    mount.mkdir("staging").expect("mkdir staging failed");

    // Stage new values
    mount.write("staging/account_a.dat", b"balance: 80").expect("stage a failed");
    mount.write("staging/account_b.dat", b"balance: 70").expect("stage b failed");

    // "Commit" by moving staged files over originals
    mount.rename("staging/account_a.dat", "account_a.dat").expect("commit a failed");
    mount.rename("staging/account_b.dat", "account_b.dat").expect("commit b failed");

    // Clean up staging
    mount.rmdir("staging").expect("rmdir staging failed");

    // Verify transaction completed
    assert_file_content(&mount, "account_a.dat", b"balance: 80");
    assert_file_content(&mount, "account_b.dat", b"balance: 70");
}

#[test]
fn test_checkpoint_restore() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial data
    mount.mkdir("data").expect("mkdir data failed");
    mount.write("data/file1.txt", b"version 1").expect("write file1 failed");
    mount.write("data/file2.txt", b"version 1").expect("write file2 failed");

    // Create checkpoint (backup)
    mount.copy_dir("data", "checkpoint_1").expect("checkpoint failed");

    // Modify data
    mount.write("data/file1.txt", b"version 2 - modified").expect("modify file1 failed");
    mount.write("data/file3.txt", b"new file").expect("write file3 failed");

    // Verify current state
    assert_file_content(&mount, "data/file1.txt", b"version 2 - modified");
    assert_exists(&mount, "data/file3.txt");

    // Restore from checkpoint
    mount.rmdir_all("data").expect("rmdir data failed");
    mount.copy_dir("checkpoint_1", "data").expect("restore failed");

    // Verify restored state
    assert_file_content(&mount, "data/file1.txt", b"version 1");
    assert_file_content(&mount, "data/file2.txt", b"version 1");
    assert_not_found(&mount, "data/file3.txt");
}

// =============================================================================
// Real-World Application Patterns
// =============================================================================

#[test]
fn test_config_file_update() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial config
    let initial_config = b"setting1=value1\nsetting2=value2\n";
    mount.write("config.ini", initial_config).expect("write config failed");

    // Read, modify, write (common pattern for config updates)
    let config = mount.read("config.ini").expect("read config failed");
    let config_str = String::from_utf8_lossy(&config);
    let new_config = config_str.replace("value2", "new_value");
    mount.write("config.ini", new_config.as_bytes()).expect("update config failed");

    assert_file_content(&mount, "config.ini", b"setting1=value1\nsetting2=new_value\n");
}

#[test]
fn test_download_and_unpack_simulation() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Simulate downloading a file and unpacking it
    let archive_content = multi_chunk_content(2);
    mount.mkdir("downloads").expect("mkdir downloads failed");
    mount.write("downloads/package.bin", &archive_content).expect("write archive failed");

    // "Unpack" to destination
    mount.mkdir("installed").expect("mkdir installed failed");

    // Simulate extracting files from archive
    mount.write("installed/app", b"application binary").expect("write app failed");
    mount.write("installed/config.json", b"{}").expect("write config failed");
    mount.mkdir("installed/data").expect("mkdir data failed");
    mount.write("installed/data/resources.dat", b"resources").expect("write resources failed");

    // Clean up download
    mount.remove("downloads/package.bin").expect("remove archive failed");
    mount.rmdir("downloads").expect("rmdir downloads failed");

    // Verify installed structure
    assert_not_found(&mount, "downloads");
    assert_is_directory(&mount, "installed");
    assert_file_content(&mount, "installed/app", b"application binary");
    assert_is_directory(&mount, "installed/data");
}
