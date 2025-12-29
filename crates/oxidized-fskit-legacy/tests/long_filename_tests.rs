//! Long filename tests for FSKit filesystem.
//!
//! Cryptomator has a 220-character threshold for filenames. Names longer than
//! this are stored in a shortened `.c9s` format with a hash. These tests verify
//! that long filenames are handled correctly at and around this boundary.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests long_filename_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

/// Cryptomator's filename length threshold before switching to .c9s format.
/// Filenames longer than this get shortened to a hash-based name.
const FILENAME_THRESHOLD: usize = 220;

/// Generate a filename of exactly the specified length (including extension).
fn filename_of_length(len: usize) -> String {
    assert!(len >= 4, "Filename must be at least 4 chars for '.txt'");
    let base_len = len - 4; // Reserve space for ".txt"
    let base: String = (0..base_len).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    format!("{}.txt", base)
}

/// Generate a filename with a specific base name repeated to reach length.
fn filename_with_prefix(prefix: &str, total_len: usize) -> String {
    assert!(total_len >= prefix.len() + 4);
    let padding_len = total_len - prefix.len() - 4;
    let padding: String = (0..padding_len).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    format!("{}{}.txt", prefix, padding)
}

// =============================================================================
// Below Threshold (219 chars)
// =============================================================================

#[test]
fn test_filename_below_threshold() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(FILENAME_THRESHOLD - 1);
    assert_eq!(name.len(), 219);

    let content = b"Content for file just below threshold";
    mount.write(&name, content).expect("write failed");

    assert_file_content(&mount, &name, content);
}

#[test]
fn test_filename_at_threshold() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(FILENAME_THRESHOLD);
    assert_eq!(name.len(), 220);

    let content = b"Content for file exactly at threshold";
    mount.write(&name, content).expect("write failed");

    assert_file_content(&mount, &name, content);
}

// =============================================================================
// Above Threshold (221+ chars) - Triggers .c9s Format
// =============================================================================

#[test]
fn test_filename_above_threshold() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(FILENAME_THRESHOLD + 1);
    assert_eq!(name.len(), 221);

    let content = b"Content for file just above threshold (uses .c9s)";
    mount.write(&name, content).expect("write failed");

    assert_file_content(&mount, &name, content);
}

#[test]
fn test_filename_well_above_threshold() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 300 character filename
    let name = filename_of_length(300);
    assert_eq!(name.len(), 300);

    let content = b"Content for file well above threshold";
    mount.write(&name, content).expect("write failed");

    assert_file_content(&mount, &name, content);
}

#[test]
fn test_filename_very_long() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 500 character filename - significantly longer than threshold
    let name = filename_of_length(500);
    assert_eq!(name.len(), 500);

    let content = multi_chunk_content(2);
    mount.write(&name, &content).expect("write failed");

    assert_file_hash(&mount, &name, &sha256(&content));
}

// =============================================================================
// Directory Operations with Long Names
// =============================================================================

#[test]
fn test_long_directory_name() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Directory name above threshold
    let dir_name: String = (0..250).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    assert!(dir_name.len() > FILENAME_THRESHOLD);

    mount.mkdir(&dir_name).expect("mkdir failed");

    assert_is_directory(&mount, &dir_name);

    // Create a file inside the long-named directory
    let file_path = format!("{}/test.txt", dir_name);
    mount.write(&file_path, b"content").expect("write failed");

    assert_file_content(&mount, &file_path, b"content");
}

#[test]
fn test_long_filename_in_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("normal_dir").expect("mkdir failed");

    // Long filename inside normal directory
    let filename = filename_of_length(300);
    let path = format!("normal_dir/{}", filename);

    mount.write(&path, b"content in long-named file").expect("write failed");

    assert_file_content(&mount, &path, b"content in long-named file");
}

#[test]
fn test_long_directory_and_filename() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Both directory and filename above threshold
    let dir_name: String = (0..250).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    let filename = filename_of_length(300);

    mount.mkdir(&dir_name).expect("mkdir failed");

    let path = format!("{}/{}", dir_name, filename);
    mount.write(&path, b"nested long names").expect("write failed");

    assert_file_content(&mount, &path, b"nested long names");
}

// =============================================================================
// Listing and Metadata
// =============================================================================

#[test]
fn test_long_filename_appears_in_listing() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(300);
    mount.write(&name, b"content").expect("write failed");

    let entries = mount.list("/").expect("list failed");

    // The long filename should appear in listing with its original name
    assert!(
        entries.contains(&name),
        "Long filename not found in listing. Entries: {:?}",
        entries
    );
}

#[test]
fn test_long_filename_metadata() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(300);
    let content = b"content for metadata check";
    mount.write(&name, content).expect("write failed");

    let meta = mount.metadata(&name).expect("metadata failed");

    assert!(meta.is_file());
    assert_eq!(meta.len(), content.len() as u64);
}

// =============================================================================
// Move/Copy with Long Names
// =============================================================================

#[test]
fn test_rename_to_long_filename() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let short_name = "short.txt";
    let long_name = filename_of_length(300);

    mount.write(short_name, b"content").expect("write failed");
    mount.rename(short_name, &long_name).expect("rename failed");

    assert_not_found(&mount, short_name);
    assert_file_content(&mount, &long_name, b"content");
}

#[test]
fn test_rename_from_long_filename() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let long_name = filename_of_length(300);
    let short_name = "short.txt";

    mount.write(&long_name, b"content").expect("write failed");
    mount.rename(&long_name, short_name).expect("rename failed");

    assert_not_found(&mount, &long_name);
    assert_file_content(&mount, short_name, b"content");
}

#[test]
fn test_copy_long_filename() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let long_name = filename_of_length(300);
    let copy_name = filename_of_length(250);

    mount.write(&long_name, b"content to copy").expect("write failed");
    mount.copy(&long_name, &copy_name).expect("copy failed");

    assert_file_content(&mount, &long_name, b"content to copy");
    assert_file_content(&mount, &copy_name, b"content to copy");
}

// =============================================================================
// Edge Cases and Unicode
// =============================================================================

#[test]
fn test_long_unicode_filename() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Unicode characters - note that these are multi-byte in UTF-8
    // 中 is 3 bytes in UTF-8, so 100 chars = 300 bytes
    let unicode_base: String = (0..100).map(|_| '中').collect();
    let name = format!("{}.txt", unicode_base);

    // The filename is 100 Chinese characters + ".txt" = 104 characters
    // but 300 + 4 = 304 bytes in UTF-8
    assert!(name.chars().count() > FILENAME_THRESHOLD / 2);

    mount.write(&name, b"unicode long filename content").expect("write failed");

    assert_file_content(&mount, &name, b"unicode long filename content");
}

#[test]
fn test_multiple_long_filenames() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create multiple files with long names
    for i in 0..5 {
        let name = filename_with_prefix(&format!("file_{}_", i), 300);
        let content = format!("Content for file {}", i);
        mount.write(&name, content.as_bytes()).expect("write failed");
    }

    // Verify all exist and have correct content
    for i in 0..5 {
        let name = filename_with_prefix(&format!("file_{}_", i), 300);
        let expected = format!("Content for file {}", i);
        assert_file_content(&mount, &name, expected.as_bytes());
    }
}

#[test]
fn test_long_filename_delete() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(300);
    mount.write(&name, b"to be deleted").expect("write failed");

    assert_exists(&mount, &name);

    mount.remove(&name).expect("delete failed");

    assert_not_found(&mount, &name);
}

#[test]
fn test_long_filename_overwrite() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(300);

    mount.write(&name, b"original content").expect("write 1 failed");
    assert_file_content(&mount, &name, b"original content");

    mount.write(&name, b"new content").expect("write 2 failed");
    assert_file_content(&mount, &name, b"new content");
}

// =============================================================================
// Boundary Testing
// =============================================================================

#[test]
fn test_filenames_around_threshold() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Test filenames at 218, 219, 220, 221, 222 characters
    for len in (FILENAME_THRESHOLD - 2)..=(FILENAME_THRESHOLD + 2) {
        let name = filename_with_prefix(&format!("len{}_", len), len);
        assert_eq!(name.len(), len, "Generated filename has wrong length");

        let content = format!("Content for {} char filename", len);
        mount.write(&name, content.as_bytes()).expect(&format!("write {} chars failed", len));

        assert_file_content(&mount, &name, content.as_bytes());
    }

    // Verify all 5 files exist
    let entries = mount.list("/").expect("list failed");
    assert_eq!(entries.len(), 5, "Expected 5 files, got {:?}", entries);
}

#[test]
fn test_long_filename_with_large_content() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let name = filename_of_length(300);
    let content = multi_chunk_content(5); // 160KB

    mount.write(&name, &content).expect("write failed");

    // Verify integrity via hash
    assert_file_hash(&mount, &name, &sha256(&content));
}
