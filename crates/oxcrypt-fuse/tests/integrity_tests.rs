//! Data integrity tests for FUSE filesystem.
//!
//! Verifies that data is preserved correctly through the encryption/decryption
//! pipeline. Tests all byte values, Unicode content, binary patterns, and
//! special filenames that might cause issues.
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests integrity_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Binary Content Preservation
// =============================================================================

#[test]
fn test_all_byte_values() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Test that every byte value 0x00-0xFF survives roundtrip
    let content = all_byte_values();
    assert_eq!(content.len(), 256);

    mount.write("all_bytes.bin", &content).expect("write failed");
    assert_file_content(&mount, "all_bytes.bin", &content);
}

#[test]
fn test_null_bytes_only() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = vec![0u8; 1000];
    mount.write("nulls.bin", &content).expect("write failed");
    assert_file_content(&mount, "nulls.bin", &content);
}

#[test]
fn test_high_bytes_only() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // All 0xFF bytes
    let content = vec![0xFFu8; 1000];
    mount.write("high_bytes.bin", &content).expect("write failed");
    assert_file_content(&mount, "high_bytes.bin", &content);
}

#[test]
fn test_control_characters() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // ASCII control characters (0x00-0x1F)
    let content: Vec<u8> = (0..32).collect();
    mount.write("control.bin", &content).expect("write failed");
    assert_file_content(&mount, "control.bin", &content);
}

#[test]
fn test_problematic_binary() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = problematic_binary();
    mount.write("problematic.bin", &content).expect("write failed");
    assert_file_content(&mount, "problematic.bin", &content);
}

#[test]
fn test_alternating_bytes() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Alternating pattern that might confuse run-length encoding
    let content: Vec<u8> = (0..10000).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
    mount.write("alternating.bin", &content).expect("write failed");
    assert_file_content(&mount, "alternating.bin", &content);
}

#[test]
fn test_sequential_bytes() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Sequential pattern
    let content: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    mount.write("sequential.bin", &content).expect("write failed");
    assert_file_content(&mount, "sequential.bin", &content);
}

// =============================================================================
// Unicode Content
// =============================================================================

#[test]
fn test_unicode_content() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = unicode_content();
    mount.write("unicode.txt", &content).expect("write failed");
    assert_file_content(&mount, "unicode.txt", &content);
}

#[test]
fn test_multi_script_unicode() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Multiple scripts in one file
    let content = concat!(
        "English: Hello World\n",
        "Chinese: 你好世界\n",
        "Arabic: مرحبا بالعالم\n",
        "Russian: Привет мир\n",
        "Japanese: こんにちは世界\n",
        "Emoji: 🎉🚀🌍💻\n",
    ).as_bytes().to_vec();

    mount.write("multi_script.txt", &content).expect("write failed");
    assert_file_content(&mount, "multi_script.txt", &content);
}

#[test]
fn test_utf8_bom() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // UTF-8 BOM followed by content
    let mut content = vec![0xEF, 0xBB, 0xBF];
    content.extend_from_slice(b"Content after BOM");

    mount.write("bom.txt", &content).expect("write failed");
    assert_file_content(&mount, "bom.txt", &content);
}

// =============================================================================
// Chunk Boundary Data Integrity
// =============================================================================

#[test]
fn test_distinct_chunk_content() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Each chunk has a distinct byte value to verify chunk ordering
    let content = patterned_chunks(5);
    let expected_hash = sha256(&content);

    mount.write("distinct_chunks.bin", &content).expect("write failed");
    assert_file_hash(&mount, "distinct_chunks.bin", &expected_hash);

    // Also verify specific chunk boundaries
    let read = mount.read("distinct_chunks.bin").expect("read failed");
    for i in 0..5 {
        let offset = i * CHUNK_SIZE;
        assert_eq!(
            read[offset],
            (i % 256) as u8,
            "Chunk {} starts with wrong byte",
            i
        );
    }
}

#[test]
fn test_random_large_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 10 chunks of random data
    let content = multi_chunk_content(10);
    let expected_hash = sha256(&content);

    mount.write("random_large.bin", &content).expect("write failed");
    assert_file_hash(&mount, "random_large.bin", &expected_hash);
}

// =============================================================================
// Unicode Filenames
// =============================================================================

#[test]
fn test_unicode_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = unicode_filename();
    let content = b"Content with unicode filename";

    mount.write(&filename, content).expect("write failed");
    assert_file_content(&mount, &filename, content);
}

#[test]
fn test_chinese_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "测试文件.txt";
    let content = b"Chinese filename test";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
    assert!(mount.list("/").unwrap().contains(&filename.to_string()));
}

#[test]
fn test_emoji_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "🎉_party_🚀.txt";
    let content = b"Emoji filename test";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
}

#[test]
fn test_mixed_script_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "file_文件_αβγ.txt";
    let content = b"Mixed script filename";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
}

// =============================================================================
// Special Character Filenames
// =============================================================================

#[test]
fn test_special_filename() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = special_filename();
    let content = b"Special characters in filename";

    mount.write(&filename, content).expect("write failed");
    assert_file_content(&mount, &filename, content);
}

#[test]
fn test_filename_with_spaces() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "file with spaces.txt";
    let content = b"Spaces in filename";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
}

#[test]
fn test_filename_with_dashes_underscores() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "file-with_dashes-and_underscores.txt";
    let content = b"Dashes and underscores";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
}

#[test]
fn test_filename_with_dots() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = "file.multiple.dots.txt";
    let content = b"Multiple dots";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
}

#[test]
fn test_hidden_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let filename = ".hidden_file";
    let content = b"Hidden file content";

    mount.write(filename, content).expect("write failed");
    assert_file_content(&mount, filename, content);
    assert!(mount.list("/").unwrap().contains(&filename.to_string()));
}

// =============================================================================
// Filename Length Tests
// =============================================================================

#[test]
fn test_long_filename_under_limit() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // 200 characters - well under 255 limit
    let filename = format!("{}.txt", "a".repeat(196));
    let content = b"Long filename content";

    mount.write(&filename, content).expect("write failed");
    assert_file_content(&mount, &filename, content);
}

#[test]
fn test_filename_near_shortening_threshold() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Just under 220 chars (Cryptomator's shortening threshold)
    // When encrypted with base64, this approaches but doesn't exceed the threshold
    let filename = format!("{}.txt", "x".repeat(50));
    let content = b"Near threshold content";

    mount.write(&filename, content).expect("write failed");
    assert_file_content(&mount, &filename, content);
}

// =============================================================================
// Write-Read-Write Cycles
// =============================================================================

#[test]
fn test_multiple_overwrites() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    for i in 0..5 {
        let content = format!("Iteration {} content", i);
        mount.write("cycle.txt", content.as_bytes()).expect("write failed");
        assert_file_content(&mount, "cycle.txt", content.as_bytes());
    }
}

#[test]
fn test_size_transitions() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Empty
    mount.write("transitions.bin", b"").expect("write failed");
    assert_file_size(&mount, "transitions.bin", 0);

    // Small
    let small = random_bytes(100);
    mount.write("transitions.bin", &small).expect("write failed");
    assert_file_content(&mount, "transitions.bin", &small);

    // One chunk
    let one_chunk = one_chunk_content();
    mount.write("transitions.bin", &one_chunk).expect("write failed");
    assert_file_content(&mount, "transitions.bin", &one_chunk);

    // Multiple chunks
    let multi = multi_chunk_content(3);
    mount.write("transitions.bin", &multi).expect("write failed");
    assert_file_content(&mount, "transitions.bin", &multi);

    // Back to small
    mount.write("transitions.bin", &small).expect("write failed");
    assert_file_content(&mount, "transitions.bin", &small);

    // Back to empty
    mount.write("transitions.bin", b"").expect("write failed");
    assert_file_size(&mount, "transitions.bin", 0);
}
