//! Partial I/O tests for FSKit filesystem.
//!
//! Tests seek and partial read/write operations. These are important for
//! applications that don't read/write entire files at once, like databases,
//! media players, and editors.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests partial_io_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Basic Partial Reads
// =============================================================================

#[test]
fn test_read_first_bytes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Hello, World!").expect("write failed");

    let partial = mount.read_range("file.txt", 0, 5).expect("read_range failed");
    assert_eq!(partial, b"Hello");
}

#[test]
fn test_read_middle_bytes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Hello, World!").expect("write failed");

    let partial = mount.read_range("file.txt", 7, 5).expect("read_range failed");
    assert_eq!(partial, b"World");
}

#[test]
fn test_read_last_bytes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Hello, World!").expect("write failed");

    // Read last 6 bytes
    let partial = mount.read_range("file.txt", 7, 6).expect("read_range failed");
    assert_eq!(partial, b"World!");
}

#[test]
fn test_read_single_byte() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"ABCDEFG").expect("write failed");

    for (i, expected) in b"ABCDEFG".iter().enumerate() {
        let byte = mount.read_range("file.txt", i as u64, 1).expect("read_range failed");
        assert_eq!(byte, &[*expected], "Byte at offset {} incorrect", i);
    }
}

#[test]
fn test_read_beyond_eof() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Short").expect("write failed");

    // Request more bytes than available
    let partial = mount.read_range("file.txt", 0, 100).expect("read_range failed");
    assert_eq!(partial, b"Short");
}

#[test]
fn test_read_starting_at_eof() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Content").expect("write failed");

    // Read starting at end of file
    let partial = mount.read_range("file.txt", 7, 10).expect("read_range failed");
    assert!(partial.is_empty(), "Expected empty, got {:?}", partial);
}

#[test]
fn test_read_past_eof() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Content").expect("write failed");

    // Read starting well past end of file
    let partial = mount.read_range("file.txt", 1000, 10).expect("read_range failed");
    assert!(partial.is_empty());
}

// =============================================================================
// Partial Reads Across Chunk Boundaries
// =============================================================================

#[test]
fn test_read_within_first_chunk() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(2);
    mount.write("multi.bin", &content).expect("write failed");

    // Read 1000 bytes from offset 1000 (still in first chunk)
    let partial = mount.read_range("multi.bin", 1000, 1000).expect("read_range failed");
    assert_eq!(partial, &content[1000..2000]);
}

#[test]
fn test_read_spanning_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(2);
    mount.write("multi.bin", &content).expect("write failed");

    // Read across chunk boundary (CHUNK_SIZE = 32768)
    // Start 100 bytes before boundary, read 200 bytes
    let start = CHUNK_SIZE - 100;
    let partial = mount.read_range("multi.bin", start as u64, 200).expect("read_range failed");

    assert_eq!(partial.len(), 200);
    assert_eq!(partial, &content[start..start + 200]);
}

#[test]
fn test_read_starting_at_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(3);
    mount.write("multi.bin", &content).expect("write failed");

    // Read exactly at chunk boundary
    let partial = mount.read_range("multi.bin", CHUNK_SIZE as u64, 100).expect("read_range failed");

    assert_eq!(partial, &content[CHUNK_SIZE..CHUNK_SIZE + 100]);
}

#[test]
fn test_read_entire_second_chunk() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(3);
    mount.write("multi.bin", &content).expect("write failed");

    // Read exactly the second chunk
    let partial = mount.read_range("multi.bin", CHUNK_SIZE as u64, CHUNK_SIZE).expect("read_range failed");

    assert_eq!(partial.len(), CHUNK_SIZE);
    assert_eq!(partial, &content[CHUNK_SIZE..CHUNK_SIZE * 2]);
}

#[test]
fn test_read_spanning_multiple_chunks() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(5);
    mount.write("multi.bin", &content).expect("write failed");

    // Read 3 chunks worth starting mid-first-chunk
    let start = CHUNK_SIZE / 2;
    let len = CHUNK_SIZE * 3;
    let partial = mount.read_range("multi.bin", start as u64, len).expect("read_range failed");

    assert_eq!(partial.len(), len);
    assert_eq!(partial, &content[start..start + len]);
}

// =============================================================================
// Partial Writes
// =============================================================================

#[test]
fn test_write_at_beginning() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"XXXXX World!").expect("write failed");
    mount.write_at("file.txt", 0, b"Hello").expect("write_at failed");

    assert_file_content(&mount, "file.txt", b"Hello World!");
}

#[test]
fn test_write_at_middle() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Hello XXXXX!").expect("write failed");
    mount.write_at("file.txt", 6, b"World").expect("write_at failed");

    assert_file_content(&mount, "file.txt", b"Hello World!");
}

#[test]
fn test_write_at_end() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Hello").expect("write failed");
    mount.write_at("file.txt", 5, b" World!").expect("write_at failed");

    assert_file_content(&mount, "file.txt", b"Hello World!");
}

#[test]
fn test_write_single_byte() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"AAAA").expect("write failed");

    // Replace each byte one at a time
    mount.write_at("file.txt", 0, b"T").expect("write 0 failed");
    mount.write_at("file.txt", 1, b"E").expect("write 1 failed");
    mount.write_at("file.txt", 2, b"S").expect("write 2 failed");
    mount.write_at("file.txt", 3, b"T").expect("write 3 failed");

    assert_file_content(&mount, "file.txt", b"TEST");
}

#[test]
fn test_write_extending_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"Start").expect("write failed");

    // Write beyond current file size
    mount.write_at("file.txt", 10, b"End").expect("write_at failed");

    let content = mount.read("file.txt").expect("read failed");
    assert_eq!(content.len(), 13); // "Start" + 5 zeros + "End"
    assert_eq!(&content[0..5], b"Start");
    assert_eq!(&content[5..10], &[0, 0, 0, 0, 0]); // Gap filled with zeros
    assert_eq!(&content[10..13], b"End");
}

// =============================================================================
// Partial Writes Across Chunk Boundaries
// =============================================================================

#[test]
fn test_write_at_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(2);
    mount.write("multi.bin", &content).expect("write failed");

    // Write at exact chunk boundary
    let marker = b"MARKER";
    mount.write_at("multi.bin", CHUNK_SIZE as u64, marker).expect("write_at failed");

    // Verify marker is at boundary
    let partial = mount.read_range("multi.bin", CHUNK_SIZE as u64, marker.len()).expect("read failed");
    assert_eq!(partial, marker);

    // Verify data before boundary unchanged
    let before = mount.read_range("multi.bin", (CHUNK_SIZE - 10) as u64, 10).expect("read before failed");
    assert_eq!(before, &content[CHUNK_SIZE - 10..CHUNK_SIZE]);
}

#[test]
fn test_write_spanning_chunk_boundary() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = multi_chunk_content(2);
    mount.write("multi.bin", &content).expect("write failed");

    // Write across chunk boundary
    let start = CHUNK_SIZE - 5;
    let marker = b"0123456789"; // 10 bytes spanning boundary
    mount.write_at("multi.bin", start as u64, marker).expect("write_at failed");

    // Read back across boundary
    let partial = mount.read_range("multi.bin", start as u64, 10).expect("read failed");
    assert_eq!(partial, marker);
}

#[test]
fn test_write_entire_chunk_at_offset() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let original = multi_chunk_content(3);
    mount.write("multi.bin", &original).expect("write failed");

    // Replace entire second chunk with a pattern
    let replacement: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 256) as u8).collect();
    mount.write_at("multi.bin", CHUNK_SIZE as u64, &replacement).expect("write_at failed");

    // Verify second chunk is replaced
    let second_chunk = mount.read_range("multi.bin", CHUNK_SIZE as u64, CHUNK_SIZE).expect("read failed");
    assert_eq!(second_chunk, replacement);

    // Verify first and third chunks unchanged
    let first_chunk = mount.read_range("multi.bin", 0, CHUNK_SIZE).expect("read first failed");
    assert_eq!(first_chunk, &original[0..CHUNK_SIZE]);

    let third_chunk = mount.read_range("multi.bin", (CHUNK_SIZE * 2) as u64, CHUNK_SIZE).expect("read third failed");
    assert_eq!(third_chunk, &original[CHUNK_SIZE * 2..CHUNK_SIZE * 3]);
}

// =============================================================================
// Mixed Read/Write Operations
// =============================================================================

#[test]
fn test_read_after_partial_write() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"AAAAAAAAAA").expect("write failed");

    // Partial write in middle
    mount.write_at("file.txt", 3, b"BBB").expect("write_at failed");

    // Read entire file
    assert_file_content(&mount, "file.txt", b"AAABBBAAA");

    // Read just the modified part
    let partial = mount.read_range("file.txt", 3, 3).expect("read_range failed");
    assert_eq!(partial, b"BBB");
}

#[test]
fn test_multiple_partial_writes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create file with zeros
    mount.write("file.txt", &vec![0u8; 20]).expect("write failed");

    // Write at multiple offsets
    mount.write_at("file.txt", 0, b"AA").expect("write 0 failed");
    mount.write_at("file.txt", 5, b"BB").expect("write 5 failed");
    mount.write_at("file.txt", 10, b"CC").expect("write 10 failed");
    mount.write_at("file.txt", 15, b"DD").expect("write 15 failed");

    let content = mount.read("file.txt").expect("read failed");
    assert_eq!(&content[0..2], b"AA");
    assert_eq!(&content[5..7], b"BB");
    assert_eq!(&content[10..12], b"CC");
    assert_eq!(&content[15..17], b"DD");
    // Zeros between
    assert_eq!(&content[2..5], &[0, 0, 0]);
}

#[test]
fn test_interleaved_reads_writes() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"0123456789").expect("write failed");

    // Read-modify-write pattern
    let part1 = mount.read_range("file.txt", 0, 5).expect("read 1 failed");
    mount.write_at("file.txt", 5, &part1).expect("write 1 failed");

    // File should now be "0123401234"
    assert_file_content(&mount, "file.txt", b"0123401234");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_partial_read_empty_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("empty.txt", b"").expect("write failed");

    let partial = mount.read_range("empty.txt", 0, 10).expect("read_range failed");
    assert!(partial.is_empty());
}

#[test]
fn test_partial_write_preserves_size() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"0123456789").expect("write failed");

    // Overwrite in middle, same size
    mount.write_at("file.txt", 3, b"XXX").expect("write_at failed");

    assert_eq!(mount.file_size("file.txt").expect("size failed"), 10);
}

#[test]
fn test_zero_length_read() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");

    let partial = mount.read_range("file.txt", 3, 0).expect("read_range failed");
    assert!(partial.is_empty());
}

#[test]
fn test_zero_length_write() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("file.txt", b"content").expect("write failed");
    mount.write_at("file.txt", 3, b"").expect("write_at failed");

    // File unchanged
    assert_file_content(&mount, "file.txt", b"content");
}

#[test]
fn test_large_offset_small_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("tiny.txt", b"X").expect("write failed");

    // Write at large offset in tiny file
    mount.write_at("tiny.txt", 1000, b"Y").expect("write_at failed");

    let size = mount.file_size("tiny.txt").expect("size failed");
    assert_eq!(size, 1001);

    // Verify sparse content
    let content = mount.read("tiny.txt").expect("read failed");
    assert_eq!(content[0], b'X');
    assert_eq!(content[1000], b'Y');
    // Middle should be zeros
    assert!(content[1..1000].iter().all(|&b| b == 0));
}

// =============================================================================
// Data Integrity
// =============================================================================

#[test]
fn test_partial_io_preserves_hash() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create file with patterned content
    let original = patterned_chunks(3);
    let original_hash = sha256(&original);
    mount.write("data.bin", &original).expect("write failed");

    // Read in pieces and reconstruct
    let mut reconstructed = Vec::new();
    let mut offset = 0;
    while offset < original.len() {
        let chunk_size = 1000.min(original.len() - offset);
        let part = mount.read_range("data.bin", offset as u64, chunk_size).expect("read failed");
        reconstructed.extend_from_slice(&part);
        offset += chunk_size;
    }

    assert_eq!(sha256(&reconstructed), original_hash);
}

#[test]
fn test_partial_write_integrity() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Write file in pieces
    let total_size = CHUNK_SIZE * 3;
    mount.write("data.bin", &vec![0u8; total_size]).expect("initial write failed");

    // Write each chunk with different pattern
    for i in 0..3 {
        let pattern: Vec<u8> = (0..CHUNK_SIZE).map(|j| ((i * 100 + j) % 256) as u8).collect();
        mount.write_at("data.bin", (i * CHUNK_SIZE) as u64, &pattern).expect("write_at failed");
    }

    // Read back and verify each chunk
    for i in 0..3 {
        let expected: Vec<u8> = (0..CHUNK_SIZE).map(|j| ((i * 100 + j) % 256) as u8).collect();
        let actual = mount.read_range("data.bin", (i * CHUNK_SIZE) as u64, CHUNK_SIZE).expect("read failed");
        assert_eq!(actual, expected, "Chunk {} mismatch", i);
    }
}
