//! Large file tests for FSKit filesystem.
//!
//! Tests handling of large files that span many encryption chunks (32KB each).
//! Verifies 64-bit offset support, integrity across many chunks, and
//! performance characteristics of multi-megabyte files.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests large_file_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

/// Cryptomator chunk size (32KB)
const CHUNK_SIZE: usize = 32 * 1024;

/// Generate deterministic content for a given offset.
/// This allows verification without storing the entire file in memory.
fn byte_at_offset(offset: u64) -> u8 {
    // Simple deterministic pattern based on offset
    let mixed = offset
        .wrapping_mul(0x517cc1b727220a95)
        .wrapping_add(0x9e3779b97f4a7c15);
    (mixed >> 56) as u8
}

/// Generate a chunk of deterministic content starting at the given offset.
fn generate_chunk(start_offset: u64, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| byte_at_offset(start_offset + i as u64))
        .collect()
}

/// Verify that content matches expected pattern.
fn verify_content(data: &[u8], start_offset: u64) -> bool {
    data.iter()
        .enumerate()
        .all(|(i, &byte)| byte == byte_at_offset(start_offset + i as u64))
}

// =============================================================================
// Multi-Megabyte Files
// =============================================================================

#[test]
fn test_1mb_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 1024 * 1024; // 1MB = 32 chunks
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("1mb.bin", &content).expect("write failed");

    assert_file_hash(&mount, "1mb.bin", &hash);
}

#[test]
fn test_5mb_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 5 * 1024 * 1024; // 5MB = 160 chunks
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("5mb.bin", &content).expect("write failed");

    assert_file_hash(&mount, "5mb.bin", &hash);
}

#[test]
fn test_10mb_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 10 * 1024 * 1024; // 10MB = 320 chunks
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("10mb.bin", &content).expect("write failed");

    assert_file_hash(&mount, "10mb.bin", &hash);
}

#[test]
fn test_50mb_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 50 * 1024 * 1024; // 50MB = 1600 chunks
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("50mb.bin", &content).expect("write failed");

    assert_file_hash(&mount, "50mb.bin", &hash);
}

// =============================================================================
// Streaming Large File Operations
// =============================================================================

#[test]
fn test_streaming_write_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let total_size = 10 * 1024 * 1024; // 10MB
    let chunk_write_size = 256 * 1024; // Write 256KB at a time

    // Stream write to avoid holding everything in memory
    {
        let path = mount.path("streamed.bin");
        let mut file = File::create(&path).expect("create failed");

        let mut offset = 0u64;
        while (offset as usize) < total_size {
            let remaining = total_size - offset as usize;
            let write_size = remaining.min(chunk_write_size);
            let chunk = generate_chunk(offset, write_size);
            file.write_all(&chunk).expect("write chunk failed");
            offset += write_size as u64;
        }
        file.sync_all().expect("sync failed");
    }

    // Verify size
    let meta = mount.metadata("streamed.bin").expect("metadata failed");
    assert_eq!(meta.len(), total_size as u64);

    // Spot-check content at various offsets
    let checks = [
        (0u64, 1000usize),
        (CHUNK_SIZE as u64 * 10, 1000),
        (CHUNK_SIZE as u64 * 100, 1000),
        (total_size as u64 - 1000, 1000),
    ];

    for (offset, len) in checks {
        let data = mount.read_range("streamed.bin", offset, len).expect("read_range failed");
        assert!(
            verify_content(&data, offset),
            "Content mismatch at offset {}",
            offset
        );
    }
}

#[test]
fn test_streaming_read_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 5 * 1024 * 1024; // 5MB
    let content = generate_chunk(0, size);
    mount.write("to_stream.bin", &content).expect("write failed");

    // Stream read to verify
    let path = mount.path("to_stream.bin");
    let mut file = File::open(&path).expect("open failed");

    let mut offset = 0u64;
    let read_size = 128 * 1024; // 128KB reads
    let mut buffer = vec![0u8; read_size];

    while offset < size as u64 {
        let bytes_read = file.read(&mut buffer).expect("read failed");
        if bytes_read == 0 {
            break;
        }
        assert!(
            verify_content(&buffer[..bytes_read], offset),
            "Content mismatch at offset {}",
            offset
        );
        offset += bytes_read as u64;
    }

    assert_eq!(offset, size as u64);
}

// =============================================================================
// Partial Operations on Large Files
// =============================================================================

#[test]
fn test_read_middle_of_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 10 * 1024 * 1024; // 10MB
    let content = generate_chunk(0, size);
    mount.write("large.bin", &content).expect("write failed");

    // Read from the middle
    let offset = 5 * 1024 * 1024; // 5MB in
    let len = 64 * 1024; // 64KB

    let data = mount.read_range("large.bin", offset as u64, len).expect("read_range failed");
    assert_eq!(data.len(), len);
    assert!(verify_content(&data, offset as u64));
}

#[test]
fn test_write_middle_of_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 5 * 1024 * 1024; // 5MB
    let content = generate_chunk(0, size);
    mount.write("large.bin", &content).expect("write failed");

    // Overwrite middle section
    let offset = 2 * 1024 * 1024; // 2MB in
    let new_data = vec![0xAB; 64 * 1024]; // 64KB of 0xAB

    mount.write_at("large.bin", offset as u64, &new_data).expect("write_at failed");

    // Verify the overwritten section
    let read_back = mount.read_range("large.bin", offset as u64, new_data.len()).expect("read_range failed");
    assert_eq!(read_back, new_data);

    // Verify surrounding data unchanged
    let before = mount.read_range("large.bin", offset as u64 - 1000, 1000).expect("read before failed");
    assert!(verify_content(&before, offset as u64 - 1000));

    let after = mount.read_range("large.bin", offset as u64 + new_data.len() as u64, 1000).expect("read after failed");
    assert!(verify_content(&after, offset as u64 + new_data.len() as u64));
}

#[test]
fn test_read_last_chunk_of_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 3 * 1024 * 1024 + 12345; // Odd size (not chunk-aligned)
    let content = generate_chunk(0, size);
    mount.write("odd_size.bin", &content).expect("write failed");

    // Read the last few KB
    let read_size = 4096;
    let offset = size as u64 - read_size as u64;

    let data = mount.read_range("odd_size.bin", offset, read_size).expect("read_range failed");
    assert_eq!(data.len(), read_size);
    assert!(verify_content(&data, offset));
}

// =============================================================================
// Growing Large Files
// =============================================================================

#[test]
fn test_grow_file_through_appends() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let append_size = 512 * 1024; // 512KB per append
    let num_appends = 10; // Total 5MB

    // Create initial file
    let initial = generate_chunk(0, append_size);
    mount.write("growing.bin", &initial).expect("write failed");

    // Append repeatedly
    for i in 1..num_appends {
        let offset = i * append_size;
        let chunk = generate_chunk(offset as u64, append_size);
        mount.append("growing.bin", &chunk).expect("append failed");
    }

    // Verify final size
    let expected_size = num_appends * append_size;
    let meta = mount.metadata("growing.bin").expect("metadata failed");
    assert_eq!(meta.len(), expected_size as u64);

    // Verify content at various points
    for i in 0..num_appends {
        let offset = i * append_size + 1000;
        let data = mount.read_range("growing.bin", offset as u64, 1000).expect("read failed");
        assert!(
            verify_content(&data, offset as u64),
            "Content mismatch in append section {}",
            i
        );
    }
}

#[test]
fn test_extend_file_with_write_at() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Start with 1MB file
    let initial_size = 1024 * 1024;
    let content = generate_chunk(0, initial_size);
    mount.write("extensible.bin", &content).expect("write failed");

    // Write beyond current EOF to extend
    let extension_offset = 2 * 1024 * 1024; // 2MB (1MB gap)
    let extension_data = vec![0xEE; 64 * 1024]; // 64KB

    mount.write_at("extensible.bin", extension_offset as u64, &extension_data)
        .expect("write_at failed");

    // File should now be larger
    let meta = mount.metadata("extensible.bin").expect("metadata failed");
    assert_eq!(meta.len(), extension_offset as u64 + extension_data.len() as u64);

    // Verify the extended data
    let read_back = mount.read_range("extensible.bin", extension_offset as u64, extension_data.len())
        .expect("read_range failed");
    assert_eq!(read_back, extension_data);
}

// =============================================================================
// Chunk Boundary Stress Tests
// =============================================================================

#[test]
fn test_write_spanning_many_chunks() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Write exactly 100 chunks (3.2MB)
    let num_chunks = 100;
    let size = num_chunks * CHUNK_SIZE;
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("100chunks.bin", &content).expect("write failed");

    assert_file_hash(&mount, "100chunks.bin", &hash);
}

#[test]
fn test_read_crossing_many_chunk_boundaries() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 50 * CHUNK_SIZE; // 50 chunks
    let content = generate_chunk(0, size);
    mount.write("50chunks.bin", &content).expect("write failed");

    // Read that starts mid-chunk and spans 10 chunks
    let start = CHUNK_SIZE / 2; // Start in middle of first chunk
    let len = 10 * CHUNK_SIZE + CHUNK_SIZE / 2; // End in middle of 11th chunk

    let data = mount.read_range("50chunks.bin", start as u64, len).expect("read_range failed");
    assert_eq!(data.len(), len);
    assert!(verify_content(&data, start as u64));
}

#[test]
fn test_write_at_every_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 1MB file filled with zeros
    let size = 32 * CHUNK_SIZE; // 32 chunks = 1MB
    let content = vec![0u8; size];
    mount.write("boundaries.bin", &content).expect("write failed");

    // Write a marker at each chunk boundary
    let marker = [0xFF, 0xFE, 0xFD, 0xFC];
    for chunk_num in 0..32 {
        let offset = chunk_num * CHUNK_SIZE;
        mount.write_at("boundaries.bin", offset as u64, &marker).expect("write_at failed");
    }

    // Verify all markers
    for chunk_num in 0..32 {
        let offset = chunk_num * CHUNK_SIZE;
        let data = mount.read_range("boundaries.bin", offset as u64, 4).expect("read_range failed");
        assert_eq!(data, marker, "Marker missing at chunk {}", chunk_num);
    }
}

// =============================================================================
// 64-bit Offset Support
// =============================================================================

#[test]
fn test_seek_to_large_offset() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file and seek to a large offset to write
    // Note: This creates a sparse file on most filesystems
    let path = mount.path("sparse_large.bin");

    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .expect("create failed");

        // Seek to 100MB offset
        let large_offset = 100 * 1024 * 1024u64;
        file.seek(SeekFrom::Start(large_offset)).expect("seek failed");

        // Write some data
        let data = b"data at large offset";
        file.write_all(data).expect("write failed");
        file.sync_all().expect("sync failed");
    }

    // Verify the file size
    let meta = mount.metadata("sparse_large.bin").expect("metadata failed");
    assert!(meta.len() >= 100 * 1024 * 1024);

    // Read back the data
    let data = mount.read_range("sparse_large.bin", 100 * 1024 * 1024, 20).expect("read failed");
    assert_eq!(data, b"data at large offset");
}

#[test]
fn test_file_size_after_large_seek_write() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let path = mount.path("size_test.bin");

    {
        let mut file = File::create(&path).expect("create failed");

        // Write at offset 50MB
        let offset = 50 * 1024 * 1024u64;
        file.seek(SeekFrom::Start(offset)).expect("seek failed");
        file.write_all(b"test").expect("write failed");
        file.sync_all().expect("sync failed");
    }

    let meta = mount.metadata("size_test.bin").expect("metadata failed");
    assert_eq!(meta.len(), 50 * 1024 * 1024 + 4);
}

// =============================================================================
// Large File Truncation
// =============================================================================

#[test]
fn test_truncate_large_file_smaller() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 5MB file
    let size = 5 * 1024 * 1024;
    let content = generate_chunk(0, size);
    mount.write("to_shrink.bin", &content).expect("write failed");

    // Truncate to 1MB
    let new_size = 1024 * 1024;
    mount.truncate("to_shrink.bin", new_size as u64).expect("truncate failed");

    // Verify new size
    let meta = mount.metadata("to_shrink.bin").expect("metadata failed");
    assert_eq!(meta.len(), new_size as u64);

    // Verify remaining content is intact
    let data = mount.read_range("to_shrink.bin", 0, new_size).expect("read failed");
    assert!(verify_content(&data, 0));
}

#[test]
fn test_truncate_large_file_to_zero() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 10MB file
    let size = 10 * 1024 * 1024;
    let content = generate_chunk(0, size);
    mount.write("to_zero.bin", &content).expect("write failed");

    // Truncate to zero
    mount.truncate("to_zero.bin", 0).expect("truncate failed");

    let meta = mount.metadata("to_zero.bin").expect("metadata failed");
    assert_eq!(meta.len(), 0);
}

#[test]
fn test_truncate_large_file_larger() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 1MB file
    let original_size = 1024 * 1024;
    let content = generate_chunk(0, original_size);
    mount.write("to_grow.bin", &content).expect("write failed");

    // Truncate to 5MB (extends with zeros)
    let new_size = 5 * 1024 * 1024;
    mount.truncate("to_grow.bin", new_size as u64).expect("truncate failed");

    let meta = mount.metadata("to_grow.bin").expect("metadata failed");
    assert_eq!(meta.len(), new_size as u64);

    // Original content should be intact
    let original = mount.read_range("to_grow.bin", 0, original_size).expect("read original failed");
    assert!(verify_content(&original, 0));

    // Extended region should be zeros
    let extended = mount.read_range("to_grow.bin", original_size as u64, 1000).expect("read extended failed");
    assert!(extended.iter().all(|&b| b == 0), "Extended region not zero-filled");
}

// =============================================================================
// Integrity Verification
// =============================================================================

#[test]
fn test_large_file_full_integrity_check() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 20MB file with known content
    let size = 20 * 1024 * 1024;
    let content = generate_chunk(0, size);
    let expected_hash = sha256(&content);

    mount.write("integrity.bin", &content).expect("write failed");

    // Read back and verify hash
    let read_back = mount.read("integrity.bin").expect("read failed");
    let actual_hash = sha256(&read_back);

    assert_eq!(actual_hash, expected_hash, "Data corruption in 20MB file");
}

#[test]
fn test_large_file_chunk_by_chunk_verification() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let num_chunks = 50;
    let size = num_chunks * CHUNK_SIZE;
    let content = generate_chunk(0, size);
    mount.write("chunk_verify.bin", &content).expect("write failed");

    // Verify each chunk individually
    for chunk_num in 0..num_chunks {
        let offset = chunk_num * CHUNK_SIZE;
        let data = mount.read_range("chunk_verify.bin", offset as u64, CHUNK_SIZE).expect("read failed");

        assert_eq!(data.len(), CHUNK_SIZE, "Chunk {} wrong size", chunk_num);
        assert!(
            verify_content(&data, offset as u64),
            "Chunk {} content mismatch",
            chunk_num
        );
    }
}

// =============================================================================
// Multiple Large Files
// =============================================================================

#[test]
fn test_multiple_large_files_concurrently() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let file_size = 2 * 1024 * 1024; // 2MB each
    let num_files = 5;

    // Create multiple large files
    let mut hashes = Vec::new();
    for i in 0..num_files {
        let content = generate_chunk(i as u64 * 1000000, file_size); // Different content each
        let hash = sha256(&content);
        hashes.push(hash);
        mount.write(&format!("large_{}.bin", i), &content).expect("write failed");
    }

    // Verify all files
    for i in 0..num_files {
        let filename = format!("large_{}.bin", i);
        assert_file_hash(&mount, &filename, &hashes[i]);
    }
}

#[test]
fn test_copy_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 5 * 1024 * 1024; // 5MB
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("original_large.bin", &content).expect("write failed");
    mount.copy("original_large.bin", "copy_large.bin").expect("copy failed");

    // Both should have same content
    assert_file_hash(&mount, "original_large.bin", &hash);
    assert_file_hash(&mount, "copy_large.bin", &hash);
}

#[test]
fn test_rename_large_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let size = 5 * 1024 * 1024;
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("before_rename.bin", &content).expect("write failed");
    mount.rename("before_rename.bin", "after_rename.bin").expect("rename failed");

    assert_not_found(&mount, "before_rename.bin");
    assert_file_hash(&mount, "after_rename.bin", &hash);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_large_file_exact_chunk_multiple() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Exactly 64 chunks (no partial final chunk)
    let size = 64 * CHUNK_SIZE;
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("exact_chunks.bin", &content).expect("write failed");

    let meta = mount.metadata("exact_chunks.bin").expect("metadata failed");
    assert_eq!(meta.len(), size as u64);

    assert_file_hash(&mount, "exact_chunks.bin", &hash);
}

#[test]
fn test_large_file_one_byte_over_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 32 chunks + 1 byte
    let size = 32 * CHUNK_SIZE + 1;
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("one_over.bin", &content).expect("write failed");

    assert_file_hash(&mount, "one_over.bin", &hash);
}

#[test]
fn test_large_file_one_byte_under_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 32 chunks - 1 byte
    let size = 32 * CHUNK_SIZE - 1;
    let content = generate_chunk(0, size);
    let hash = sha256(&content);

    mount.write("one_under.bin", &content).expect("write failed");

    assert_file_hash(&mount, "one_under.bin", &hash);
}

#[test]
fn test_overwrite_large_file_completely() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 5MB file
    let size1 = 5 * 1024 * 1024;
    let content1 = generate_chunk(0, size1);
    mount.write("overwrite.bin", &content1).expect("write 1 failed");

    // Completely overwrite with 3MB file (smaller)
    let size2 = 3 * 1024 * 1024;
    let content2 = generate_chunk(999999, size2); // Different pattern
    let hash2 = sha256(&content2);
    mount.write("overwrite.bin", &content2).expect("write 2 failed");

    let meta = mount.metadata("overwrite.bin").expect("metadata failed");
    assert_eq!(meta.len(), size2 as u64);

    assert_file_hash(&mount, "overwrite.bin", &hash2);
}

#[test]
fn test_overwrite_large_file_with_larger() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 2MB file
    let size1 = 2 * 1024 * 1024;
    let content1 = generate_chunk(0, size1);
    mount.write("grow_overwrite.bin", &content1).expect("write 1 failed");

    // Overwrite with 8MB file (larger)
    let size2 = 8 * 1024 * 1024;
    let content2 = generate_chunk(888888, size2);
    let hash2 = sha256(&content2);
    mount.write("grow_overwrite.bin", &content2).expect("write 2 failed");

    let meta = mount.metadata("grow_overwrite.bin").expect("metadata failed");
    assert_eq!(meta.len(), size2 as u64);

    assert_file_hash(&mount, "grow_overwrite.bin", &hash2);
}
