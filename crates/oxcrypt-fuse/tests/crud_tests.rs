//! CRUD (Create, Read, Update, Delete) tests for FUSE filesystem.
//!
//! Tests basic filesystem operations with focus on Cryptomator's 32KB chunk
//! boundaries. These tests catch off-by-one errors, buffer handling bugs,
//! and encryption/decryption issues at critical file sizes.
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests crud_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Write and Read Roundtrip Tests
// =============================================================================

#[test]
fn test_write_read_small_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"Hello, World!";
    mount.write("small.txt", content).expect("write failed");

    assert_file_content(&mount, "small.txt", content);
}

#[test]
fn test_write_read_empty_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("empty.txt", b"").expect("write failed");

    assert_file_content(&mount, "empty.txt", b"");
    assert_file_size(&mount, "empty.txt", 0);
}

#[test]
fn test_write_read_single_byte() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("single.txt", b"X").expect("write failed");

    assert_file_content(&mount, "single.txt", b"X");
    assert_file_size(&mount, "single.txt", 1);
}

// =============================================================================
// Chunk Boundary Tests (32KB = 32768 bytes)
// =============================================================================

#[test]
fn test_write_read_exactly_one_chunk() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = one_chunk_content();
    assert_eq!(content.len(), CHUNK_SIZE);

    mount.write("one_chunk.bin", &content).expect("write failed");

    assert_file_content(&mount, "one_chunk.bin", &content);
    assert_file_size(&mount, "one_chunk.bin", CHUNK_SIZE as u64);
}

#[test]
fn test_write_read_chunk_minus_one() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = chunk_minus_one();
    assert_eq!(content.len(), CHUNK_SIZE - 1);

    mount.write("chunk_m1.bin", &content).expect("write failed");

    assert_file_content(&mount, "chunk_m1.bin", &content);
    assert_file_size(&mount, "chunk_m1.bin", (CHUNK_SIZE - 1) as u64);
}

#[test]
fn test_write_read_chunk_plus_one() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // This is critical: 32KB + 1 byte requires a second chunk
    let content = chunk_plus_one();
    assert_eq!(content.len(), CHUNK_SIZE + 1);

    mount.write("chunk_p1.bin", &content).expect("write failed");

    assert_file_content(&mount, "chunk_p1.bin", &content);
    assert_file_size(&mount, "chunk_p1.bin", (CHUNK_SIZE + 1) as u64);
}

#[test]
fn test_write_read_multi_chunk() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 3 full chunks = 96KB
    let content = multi_chunk_content(3);
    assert_eq!(content.len(), 3 * CHUNK_SIZE);

    mount.write("multi_chunk.bin", &content).expect("write failed");

    assert_file_content(&mount, "multi_chunk.bin", &content);
    assert_file_size(&mount, "multi_chunk.bin", (3 * CHUNK_SIZE) as u64);
}

#[test]
fn test_write_read_partial_final_chunk() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 2 full chunks + 1000 bytes
    let content = partial_final_chunk(2, 1000);
    let expected_size = 2 * CHUNK_SIZE + 1000;
    assert_eq!(content.len(), expected_size);

    mount.write("partial.bin", &content).expect("write failed");

    assert_file_content(&mount, "partial.bin", &content);
    assert_file_size(&mount, "partial.bin", expected_size as u64);
}

#[test]
fn test_write_read_patterned_chunks() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Each chunk has a distinct byte pattern for easy debugging
    let content = patterned_chunks(4);
    assert_eq!(content.len(), 4 * CHUNK_SIZE);

    mount.write("patterned.bin", &content).expect("write failed");

    let read_content = mount.read("patterned.bin").expect("read failed");
    assert_eq!(read_content.len(), content.len());

    // Verify each chunk starts with the expected byte
    for i in 0..4 {
        let offset = i * CHUNK_SIZE;
        assert_eq!(
            read_content[offset],
            (i % 256) as u8,
            "Chunk {} should start with byte {}",
            i,
            i % 256
        );
    }
}

// =============================================================================
// Overwrite Tests
// =============================================================================

#[test]
fn test_overwrite_same_size() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content1 = b"Original content here";
    let content2 = b"Replaced content xxxx";
    assert_eq!(content1.len(), content2.len());

    mount.write("overwrite.txt", content1).expect("write 1 failed");
    assert_file_content(&mount, "overwrite.txt", content1);

    mount.write("overwrite.txt", content2).expect("write 2 failed");
    assert_file_content(&mount, "overwrite.txt", content2);
}

#[test]
fn test_overwrite_larger() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content1 = b"Short";
    let content2 = b"This is a much longer piece of content";

    mount.write("grow.txt", content1).expect("write 1 failed");
    assert_file_content(&mount, "grow.txt", content1);
    assert_file_size(&mount, "grow.txt", content1.len() as u64);

    mount.write("grow.txt", content2).expect("write 2 failed");
    assert_file_content(&mount, "grow.txt", content2);
    assert_file_size(&mount, "grow.txt", content2.len() as u64);
}

#[test]
fn test_overwrite_smaller() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content1 = b"This is a longer piece of content";
    let content2 = b"Short";

    mount.write("shrink.txt", content1).expect("write 1 failed");
    assert_file_content(&mount, "shrink.txt", content1);

    mount.write("shrink.txt", content2).expect("write 2 failed");
    assert_file_content(&mount, "shrink.txt", content2);
    assert_file_size(&mount, "shrink.txt", content2.len() as u64);
}

#[test]
fn test_overwrite_chunk_boundary_transition() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Start with content below chunk boundary
    let content1 = random_bytes(CHUNK_SIZE - 100);
    mount.write("transition.bin", &content1).expect("write 1 failed");
    assert_file_size(&mount, "transition.bin", (CHUNK_SIZE - 100) as u64);

    // Grow to above chunk boundary (triggers second chunk)
    let content2 = random_bytes(CHUNK_SIZE + 100);
    mount.write("transition.bin", &content2).expect("write 2 failed");
    assert_file_content(&mount, "transition.bin", &content2);
    assert_file_size(&mount, "transition.bin", (CHUNK_SIZE + 100) as u64);

    // Shrink back below chunk boundary
    let content3 = random_bytes(CHUNK_SIZE - 100);
    mount.write("transition.bin", &content3).expect("write 3 failed");
    assert_file_content(&mount, "transition.bin", &content3);
    assert_file_size(&mount, "transition.bin", (CHUNK_SIZE - 100) as u64);
}

// =============================================================================
// Delete Tests
// =============================================================================

#[test]
fn test_delete_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("to_delete.txt", b"content").expect("write failed");
    assert_exists(&mount, "to_delete.txt");

    mount.remove("to_delete.txt").expect("delete failed");
    assert_not_found(&mount, "to_delete.txt");
}

#[test]
fn test_delete_empty_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("empty_dir").expect("mkdir failed");
    assert_is_directory(&mount, "empty_dir");

    mount.rmdir("empty_dir").expect("rmdir failed");
    assert_not_found(&mount, "empty_dir");
}

#[test]
fn test_delete_directory_with_contents() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("dir_with_stuff").expect("mkdir failed");
    mount.write("dir_with_stuff/file.txt", b"content").expect("write failed");

    // rmdir_all should work
    mount.rmdir_all("dir_with_stuff").expect("rmdir_all failed");
    assert_not_found(&mount, "dir_with_stuff");
}

// =============================================================================
// Directory Tests
// =============================================================================

#[test]
fn test_mkdir() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("new_directory").expect("mkdir failed");
    assert_is_directory(&mount, "new_directory");
    assert_dir_empty(&mount, "new_directory");
}

#[test]
fn test_mkdir_nested() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir_all("a/b/c/d").expect("mkdir_all failed");
    assert_is_directory(&mount, "a");
    assert_is_directory(&mount, "a/b");
    assert_is_directory(&mount, "a/b/c");
    assert_is_directory(&mount, "a/b/c/d");
}

#[test]
fn test_file_in_subdirectory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("subdir").expect("mkdir failed");
    mount.write("subdir/file.txt", b"content").expect("write failed");

    assert_file_content(&mount, "subdir/file.txt", b"content");
    assert_dir_contains(&mount, "subdir", &["file.txt"]);
}

// =============================================================================
// Truncate Tests
// =============================================================================

#[test]
fn test_truncate_to_zero() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("truncate.txt", b"some content here").expect("write failed");
    mount.truncate("truncate.txt", 0).expect("truncate failed");

    assert_file_size(&mount, "truncate.txt", 0);
    assert_file_content(&mount, "truncate.txt", b"");
}

#[test]
fn test_truncate_shrink() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"Hello, World!";
    mount.write("truncate.txt", content).expect("write failed");
    mount.truncate("truncate.txt", 5).expect("truncate failed");

    assert_file_size(&mount, "truncate.txt", 5);
    assert_file_content(&mount, "truncate.txt", b"Hello");
}

#[test]
fn test_truncate_extend() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("truncate.txt", b"Hi").expect("write failed");
    mount.truncate("truncate.txt", 10).expect("truncate failed");

    assert_file_size(&mount, "truncate.txt", 10);

    // Extended bytes should be zero
    let content = mount.read("truncate.txt").expect("read failed");
    assert_eq!(&content[0..2], b"Hi");
    assert!(content[2..].iter().all(|&b| b == 0), "Extended bytes should be zero");
}

#[test]
fn test_truncate_across_chunk_boundary() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Start with 2 chunks
    let content = multi_chunk_content(2);
    mount.write("truncate.bin", &content).expect("write failed");
    assert_file_size(&mount, "truncate.bin", (2 * CHUNK_SIZE) as u64);

    // Truncate to 1.5 chunks
    let new_size = CHUNK_SIZE + CHUNK_SIZE / 2;
    mount.truncate("truncate.bin", new_size as u64).expect("truncate failed");
    assert_file_size(&mount, "truncate.bin", new_size as u64);

    // Verify content preserved up to truncation point
    let read_content = mount.read("truncate.bin").expect("read failed");
    assert_eq!(&read_content[..], &content[..new_size]);
}

// =============================================================================
// Large File Tests
// =============================================================================

#[test]
fn test_large_file_10_chunks() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(10); // 320KB
    let expected_hash = sha256(&content);

    mount.write("large.bin", &content).expect("write failed");
    assert_file_hash(&mount, "large.bin", &expected_hash);
}
