//! Append operation tests for FSKit filesystem.
//!
//! Tests file append operations which are important for logging,
//! data collection, and any write pattern that adds to existing files.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests append_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Basic Append Operations
// =============================================================================

#[test]
fn test_append_to_existing_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("log.txt", b"Line 1\n").expect("write failed");
    mount.append("log.txt", b"Line 2\n").expect("append failed");

    assert_file_content(&mount, "log.txt", b"Line 1\nLine 2\n");
}

#[test]
fn test_append_to_empty_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("empty.txt", b"").expect("write failed");
    mount.append("empty.txt", b"First content").expect("append failed");

    assert_file_content(&mount, "empty.txt", b"First content");
}

#[test]
fn test_append_creates_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // File doesn't exist, append should create it
    mount.append("new.txt", b"Created by append").expect("append failed");

    assert_file_content(&mount, "new.txt", b"Created by append");
}

#[test]
fn test_multiple_appends() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("log.txt", b"").expect("write failed");

    for i in 1..=5 {
        let line = format!("Entry {}\n", i);
        mount.append("log.txt", line.as_bytes()).expect("append failed");
    }

    let expected = b"Entry 1\nEntry 2\nEntry 3\nEntry 4\nEntry 5\n";
    assert_file_content(&mount, "log.txt", expected);
}

#[test]
fn test_append_single_byte() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("bytes.bin", b"").expect("write failed");

    for byte in b"HELLO" {
        mount.append("bytes.bin", &[*byte]).expect("append failed");
    }

    assert_file_content(&mount, "bytes.bin", b"HELLO");
}

#[test]
fn test_append_empty() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");
    mount.append("file.txt", b"").expect("append empty failed");

    // File unchanged
    assert_file_content(&mount, "file.txt", b"content");
    assert_file_size(&mount, "file.txt", 7);
}

// =============================================================================
// Append Across Chunk Boundaries
// =============================================================================

#[test]
fn test_append_crossing_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Write content that's 100 bytes short of chunk boundary
    let initial_size = CHUNK_SIZE - 100;
    let initial: Vec<u8> = (0..initial_size).map(|i| (i % 256) as u8).collect();
    mount.write("grow.bin", &initial).expect("write failed");

    // Append 200 bytes, crossing the boundary
    let append_data: Vec<u8> = (0..200).map(|i| ((i + 100) % 256) as u8).collect();
    mount.append("grow.bin", &append_data).expect("append failed");

    // Verify total size
    assert_file_size(&mount, "grow.bin", (initial_size + 200) as u64);

    // Verify content integrity
    let content = mount.read("grow.bin").expect("read failed");
    assert_eq!(&content[..initial_size], &initial[..]);
    assert_eq!(&content[initial_size..], &append_data[..]);
}

#[test]
fn test_append_to_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Write exactly one chunk
    let one_chunk = one_chunk_content();
    mount.write("chunk.bin", &one_chunk).expect("write failed");

    // Append to start second chunk
    let marker = b"SECOND_CHUNK_START";
    mount.append("chunk.bin", marker).expect("append failed");

    // Verify size
    assert_file_size(&mount, "chunk.bin", (CHUNK_SIZE + marker.len()) as u64);

    // Read back and verify boundary
    let last_of_first = mount.read_range("chunk.bin", (CHUNK_SIZE - 10) as u64, 10).expect("read failed");
    assert_eq!(last_of_first, &one_chunk[CHUNK_SIZE - 10..]);

    let start_of_second = mount.read_range("chunk.bin", CHUNK_SIZE as u64, marker.len()).expect("read failed");
    assert_eq!(start_of_second, marker);
}

#[test]
fn test_append_entire_chunk() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let first_chunk = one_chunk_content();
    mount.write("data.bin", &first_chunk).expect("write failed");

    // Append an entire chunk
    let second_chunk: Vec<u8> = (0..CHUNK_SIZE).map(|i| ((i + 128) % 256) as u8).collect();
    mount.append("data.bin", &second_chunk).expect("append failed");

    assert_file_size(&mount, "data.bin", (CHUNK_SIZE * 2) as u64);

    // Verify both chunks
    let content = mount.read("data.bin").expect("read failed");
    assert_eq!(&content[..CHUNK_SIZE], &first_chunk[..]);
    assert_eq!(&content[CHUNK_SIZE..], &second_chunk[..]);
}

#[test]
fn test_grow_file_multiple_chunks() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("growing.bin", b"").expect("write failed");

    // Append chunk by chunk
    for i in 0..5 {
        let chunk: Vec<u8> = (0..CHUNK_SIZE).map(|j| ((i * 50 + j) % 256) as u8).collect();
        mount.append("growing.bin", &chunk).expect(&format!("append chunk {} failed", i));
    }

    assert_file_size(&mount, "growing.bin", (CHUNK_SIZE * 5) as u64);

    // Spot check content
    for i in 0..5 {
        let expected_first_byte = ((i * 50) % 256) as u8;
        let actual = mount.read_range("growing.bin", (i * CHUNK_SIZE) as u64, 1).expect("read failed");
        assert_eq!(actual[0], expected_first_byte, "Chunk {} first byte wrong", i);
    }
}

// =============================================================================
// Append Size Tracking
// =============================================================================

#[test]
fn test_append_updates_size() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("size_test.txt", b"12345").expect("write failed");
    assert_file_size(&mount, "size_test.txt", 5);

    mount.append("size_test.txt", b"67890").expect("append failed");
    assert_file_size(&mount, "size_test.txt", 10);

    mount.append("size_test.txt", b"!").expect("append 2 failed");
    assert_file_size(&mount, "size_test.txt", 11);
}

#[test]
fn test_append_size_chunk_boundaries() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("boundary.bin", b"").expect("write failed");

    // Append to various sizes around chunk boundaries
    let sizes = [
        CHUNK_SIZE - 1,
        1,  // total: CHUNK_SIZE
        1,  // total: CHUNK_SIZE + 1
        CHUNK_SIZE - 2,  // total: 2 * CHUNK_SIZE - 1
        1,  // total: 2 * CHUNK_SIZE
    ];

    let mut total = 0usize;
    for (i, &size) in sizes.iter().enumerate() {
        let data = vec![(i + 1) as u8; size];
        mount.append("boundary.bin", &data).expect("append failed");
        total += size;
        assert_file_size(&mount, "boundary.bin", total as u64);
    }
}

// =============================================================================
// Append and Read Interleaving
// =============================================================================

#[test]
fn test_read_between_appends() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("log.txt", b"[START]\n").expect("write failed");

    for i in 1..=3 {
        // Read current content
        let before = mount.read("log.txt").expect("read failed");
        let before_lines = before.iter().filter(|&&b| b == b'\n').count();

        // Append new line
        let line = format!("[LOG {}]\n", i);
        mount.append("log.txt", line.as_bytes()).expect("append failed");

        // Verify line count increased
        let after = mount.read("log.txt").expect("read failed");
        let after_lines = after.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(after_lines, before_lines + 1);
    }

    let final_content = mount.read("log.txt").expect("read failed");
    let final_str = String::from_utf8_lossy(&final_content);
    assert!(final_str.contains("[START]"));
    assert!(final_str.contains("[LOG 1]"));
    assert!(final_str.contains("[LOG 2]"));
    assert!(final_str.contains("[LOG 3]"));
}

#[test]
fn test_append_after_partial_read() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("data.txt", b"HEADER:").expect("write failed");

    // Read just the header
    let header = mount.read_range("data.txt", 0, 7).expect("read failed");
    assert_eq!(header, b"HEADER:");

    // Append data after partial read
    mount.append("data.txt", b"value").expect("append failed");

    assert_file_content(&mount, "data.txt", b"HEADER:value");
}

// =============================================================================
// Append with Binary Data
// =============================================================================

#[test]
fn test_append_binary_data() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let initial = all_byte_values();
    mount.write("binary.bin", &initial).expect("write failed");

    let append_data = problematic_binary();
    mount.append("binary.bin", &append_data).expect("append failed");

    let content = mount.read("binary.bin").expect("read failed");
    assert_eq!(&content[..256], &initial[..]);
    assert_eq!(&content[256..], &append_data[..]);
}

#[test]
fn test_append_preserves_null_bytes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("nulls.bin", &[0, 0, 0]).expect("write failed");
    mount.append("nulls.bin", &[0, 0, 0]).expect("append failed");

    let content = mount.read("nulls.bin").expect("read failed");
    assert_eq!(content, vec![0u8; 6]);
}

#[test]
fn test_append_hash_integrity() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let part1 = random_bytes(10000);
    let part2 = random_bytes(10000);
    let part3 = random_bytes(10000);

    // Calculate expected hash of combined data
    let mut combined = Vec::new();
    combined.extend_from_slice(&part1);
    combined.extend_from_slice(&part2);
    combined.extend_from_slice(&part3);
    let expected_hash = sha256(&combined);

    // Write and append
    mount.write("hash_test.bin", &part1).expect("write failed");
    mount.append("hash_test.bin", &part2).expect("append 1 failed");
    mount.append("hash_test.bin", &part3).expect("append 2 failed");

    assert_file_hash(&mount, "hash_test.bin", &expected_hash);
}

// =============================================================================
// Append Edge Cases
// =============================================================================

#[test]
fn test_append_to_file_in_directory() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.mkdir("logs").expect("mkdir failed");
    mount.write("logs/app.log", b"[INIT]\n").expect("write failed");

    mount.append("logs/app.log", b"[INFO] Started\n").expect("append failed");

    assert_file_content(&mount, "logs/app.log", b"[INIT]\n[INFO] Started\n");
}

#[test]
fn test_append_unicode_content() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("unicode.txt", "Hello ".as_bytes()).expect("write failed");
    mount.append("unicode.txt", "世界 ".as_bytes()).expect("append 1 failed");
    mount.append("unicode.txt", "🌍".as_bytes()).expect("append 2 failed");

    let content = mount.read("unicode.txt").expect("read failed");
    let text = String::from_utf8(content).expect("invalid utf8");
    assert_eq!(text, "Hello 世界 🌍");
}

#[test]
fn test_append_large_data() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("large.bin", b"").expect("write failed");

    // Append 1MB in chunks
    let chunk = random_bytes(CHUNK_SIZE);
    let chunk_hash = sha256(&chunk);

    for _ in 0..32 {  // 32 * 32KB = 1MB
        mount.append("large.bin", &chunk).expect("append failed");
    }

    assert_file_size(&mount, "large.bin", (CHUNK_SIZE * 32) as u64);

    // Verify each chunk matches
    for i in 0..32 {
        let read_chunk = mount.read_range("large.bin", (i * CHUNK_SIZE) as u64, CHUNK_SIZE).expect("read failed");
        assert_eq!(sha256(&read_chunk), chunk_hash, "Chunk {} corrupted", i);
    }
}

#[test]
fn test_many_small_appends() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("many.txt", b"").expect("write failed");

    // Many tiny appends
    for i in 0..100 {
        let byte = ((i % 26) as u8) + b'a';
        mount.append("many.txt", &[byte]).expect("append failed");
    }

    let content = mount.read("many.txt").expect("read failed");
    assert_eq!(content.len(), 100);

    // Verify pattern
    for (i, &byte) in content.iter().enumerate() {
        let expected = ((i % 26) as u8) + b'a';
        assert_eq!(byte, expected, "Byte {} wrong", i);
    }
}

// =============================================================================
// Append After Other Operations
// =============================================================================

#[test]
fn test_append_after_truncate() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("truncated.txt", b"Original long content").expect("write failed");
    mount.truncate("truncated.txt", 8).expect("truncate failed");

    // Append after truncate
    mount.append("truncated.txt", b" + appended").expect("append failed");

    assert_file_content(&mount, "truncated.txt", b"Original + appended");
}

#[test]
fn test_append_after_write_at() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("modified.txt", b"AAAAAAAAAA").expect("write failed");
    mount.write_at("modified.txt", 5, b"BBBBB").expect("write_at failed");

    // Append
    mount.append("modified.txt", b"CCCCC").expect("append failed");

    assert_file_content(&mount, "modified.txt", b"AAAAABBBBBCCCCC");
}

#[test]
fn test_append_to_renamed_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("old_name.txt", b"Line 1\n").expect("write failed");
    mount.rename("old_name.txt", "new_name.txt").expect("rename failed");

    mount.append("new_name.txt", b"Line 2\n").expect("append failed");

    assert_file_content(&mount, "new_name.txt", b"Line 1\nLine 2\n");
}

#[test]
fn test_append_to_copied_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("original.txt", b"Original\n").expect("write failed");
    mount.copy("original.txt", "copy.txt").expect("copy failed");

    // Append to copy only
    mount.append("copy.txt", b"Copy append\n").expect("append failed");

    // Original unchanged
    assert_file_content(&mount, "original.txt", b"Original\n");
    // Copy has append
    assert_file_content(&mount, "copy.txt", b"Original\nCopy append\n");
}
