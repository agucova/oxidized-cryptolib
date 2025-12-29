//! Data integrity tests for NFS backend.
//!
//! Tests that data is preserved correctly through encryption/decryption:
//! - Binary content (all byte values)
//! - Unicode content and filenames
//! - Chunk boundary correctness
//! - Large file integrity via hashing
//!
//! Run: `cargo nextest run -p oxidized-nfs --features nfs-tests`

#![cfg(all(unix, feature = "nfs-tests"))]

mod common;

use common::{
    assert_file_content, assert_file_hash, multi_chunk_content, random_bytes, sha256, TestMount,
    CHUNK_SIZE,
};

// ============================================================================
// Binary Content Preservation
// ============================================================================

#[test]
fn test_binary_content_preserved() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content: Vec<u8> = vec![
        0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, // Edge bytes
        0x0A, 0x0D, 0x0A, 0x0D, // CR/LF sequences
        0x1B, 0x5B, 0x30, 0x6D, // ANSI escape sequence
        0xEF, 0xBB, 0xBF, // UTF-8 BOM
        0x00, 0x00, 0x00, 0x00, // Null bytes
    ];

    mount.write("/binary.bin", &content).expect("write failed");
    assert_file_content(&mount, "/binary.bin", &content);
}

#[test]
fn test_all_byte_values() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Content with every possible byte value
    let content: Vec<u8> = (0u8..=255).collect();
    assert_eq!(content.len(), 256);

    mount.write("/all_bytes.bin", &content).expect("write failed");
    assert_file_content(&mount, "/all_bytes.bin", &content);
}

#[test]
fn test_all_byte_values_repeated() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // All byte values repeated for larger file
    let content: Vec<u8> = (0..1000).flat_map(|_| 0u8..=255).collect();
    assert_eq!(content.len(), 256_000);

    let expected_hash = sha256(&content);
    mount.write("/all_bytes_large.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/all_bytes_large.bin", &expected_hash);
}

#[test]
fn test_null_bytes_only() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = vec![0u8; 1000];
    mount.write("/nulls.bin", &content).expect("write failed");
    assert_file_content(&mount, "/nulls.bin", &content);
}

#[test]
fn test_high_bytes_only() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = vec![0xFFu8; 1000];
    mount.write("/high_bytes.bin", &content).expect("write failed");
    assert_file_content(&mount, "/high_bytes.bin", &content);
}

// ============================================================================
// Unicode Content
// ============================================================================

#[test]
fn test_unicode_content_basic() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = "Hello, 世界! Привет мир! 🌍🌎🌏";
    mount.write("/unicode.txt", content.as_bytes()).expect("write failed");
    assert_file_content(&mount, "/unicode.txt", content.as_bytes());
}

#[test]
fn test_unicode_content_extended() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = concat!(
        "Latin: ABCabc\n",
        "Greek: ΑΒΓαβγ\n",
        "Cyrillic: АБВабв\n",
        "Hebrew: אבג\n",
        "Arabic: ابت\n",
        "Chinese: 中文字\n",
        "Japanese: 日本語ひらがなカタカナ\n",
        "Korean: 한국어\n",
        "Emoji: 😀🎉🚀💻🔐\n",
        "Math: ∑∏∫∂√∞\n",
    );

    mount.write("/unicode_extended.txt", content.as_bytes()).expect("write failed");
    assert_file_content(&mount, "/unicode_extended.txt", content.as_bytes());
}

// ============================================================================
// Unicode Filenames
// ============================================================================

#[test]
fn test_unicode_filename_chinese() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"content with chinese filename";
    mount.write("/文件.txt", content).expect("write failed");
    assert_file_content(&mount, "/文件.txt", content);
}

#[test]
fn test_unicode_filename_emoji() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"emoji filename test";
    mount.write("/test_🔐_file.txt", content).expect("write failed");
    assert_file_content(&mount, "/test_🔐_file.txt", content);
}

#[test]
fn test_unicode_filename_mixed_scripts() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"mixed script filename";
    mount.write("/Test_テスト_Тест.txt", content).expect("write failed");
    assert_file_content(&mount, "/Test_テスト_Тест.txt", content);
}

#[test]
fn test_unicode_directory_name() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.mkdir("/文件夹").expect("mkdir failed");
    mount.write("/文件夹/file.txt", b"content").expect("write failed");
    assert_file_content(&mount, "/文件夹/file.txt", b"content");
}

// ============================================================================
// Special Character Filenames
// ============================================================================

#[test]
fn test_filename_with_spaces() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"file with spaces";
    mount.write("/file with spaces.txt", content).expect("write failed");
    assert_file_content(&mount, "/file with spaces.txt", content);
}

#[test]
fn test_filename_special_chars() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let test_cases = [
        "/file-with-dash.txt",
        "/file_with_underscore.txt",
        "/file.multiple.dots.txt",
        "/file (parentheses).txt",
        "/file [brackets].txt",
        "/file 'apostrophe'.txt",
        "/file #hash.txt",
        "/file @at.txt",
        "/file !bang.txt",
        "/file +plus.txt",
        "/file =equals.txt",
        "/file ~tilde.txt",
    ];

    let content = b"special chars test";

    for path in test_cases {
        mount.write(path, content).expect(&format!("write {} failed", path));
        assert_file_content(&mount, path, content);
    }
}

#[test]
fn test_hidden_file() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"hidden file content";
    mount.write("/.hidden", content).expect("write failed");
    assert_file_content(&mount, "/.hidden", content);
}

// ============================================================================
// Chunk Boundary Content Tests
// ============================================================================

#[test]
fn test_chunk_boundary_pattern_data() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Create content with distinct pattern at chunk boundaries
    let mut content = vec![0xAAu8; CHUNK_SIZE];
    content.extend(vec![0xBBu8; CHUNK_SIZE]);
    content.extend(vec![0xCCu8; CHUNK_SIZE]);

    let expected_hash = sha256(&content);
    mount.write("/chunk_pattern.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/chunk_pattern.bin", &expected_hash);
}

#[test]
fn test_chunk_boundary_single_byte_difference() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Content where only the last byte of each chunk differs
    let mut content = vec![0x00u8; CHUNK_SIZE * 3];
    content[CHUNK_SIZE - 1] = 0x01;
    content[CHUNK_SIZE * 2 - 1] = 0x02;
    content[CHUNK_SIZE * 3 - 1] = 0x03;

    let expected_hash = sha256(&content);
    mount.write("/boundary_byte.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/boundary_byte.bin", &expected_hash);
}

#[test]
fn test_partial_final_chunk() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // 2.5 chunks
    let size = CHUNK_SIZE * 2 + CHUNK_SIZE / 2;
    let content = random_bytes(size);

    let expected_hash = sha256(&content);
    mount.write("/partial_chunk.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/partial_chunk.bin", &expected_hash);
}

#[test]
fn test_minimal_final_chunk() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // 2 full chunks + 1 byte
    let size = CHUNK_SIZE * 2 + 1;
    let content = random_bytes(size);

    let expected_hash = sha256(&content);
    mount.write("/minimal_final.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/minimal_final.bin", &expected_hash);
}

// ============================================================================
// Write-Read-Write Cycles
// ============================================================================

#[test]
fn test_write_read_write_cycle() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content1 = random_bytes(10000);
    mount.write("/cycle.bin", &content1).expect("write failed");
    assert_file_content(&mount, "/cycle.bin", &content1);

    let content2 = random_bytes(20000);
    mount.write("/cycle.bin", &content2).expect("overwrite failed");
    assert_file_content(&mount, "/cycle.bin", &content2);

    let content3 = random_bytes(5000);
    mount.write("/cycle.bin", &content3).expect("overwrite failed");
    assert_file_content(&mount, "/cycle.bin", &content3);
}

#[test]
fn test_multiple_overwrite_same_size() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let size = 10000;

    for _ in 0..5 {
        let content = random_bytes(size);
        mount.write("/same_size.bin", &content).expect("write failed");
        assert_file_content(&mount, "/same_size.bin", &content);
    }
}

#[test]
fn test_overwrite_empty_then_content() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    mount.write("/empty_first.bin", &[]).expect("write failed");
    assert_file_content(&mount, "/empty_first.bin", b"");

    let content = b"now has content";
    mount.write("/empty_first.bin", content).expect("write failed");
    assert_file_content(&mount, "/empty_first.bin", content);
}

#[test]
fn test_overwrite_content_then_empty() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content = b"has content initially";
    mount.write("/content_first.bin", content).expect("write failed");
    assert_file_content(&mount, "/content_first.bin", content);

    mount.write("/content_first.bin", &[]).expect("write failed");
    assert_file_content(&mount, "/content_first.bin", b"");
}

// ============================================================================
// Large File Integrity
// ============================================================================

#[test]
fn test_large_file_hash_verification() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // 10 chunks = 320KB
    let content = multi_chunk_content(10);
    let expected_hash = sha256(&content);

    mount.write("/large_verified.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/large_verified.bin", &expected_hash);
}

#[test]
fn test_medium_file_exact_content() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // 3 chunks of recognizable pattern
    let mut content = Vec::with_capacity(CHUNK_SIZE * 3);
    for i in 0..(CHUNK_SIZE * 3) {
        content.push((i % 256) as u8);
    }

    let expected_hash = sha256(&content);
    mount.write("/pattern.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/pattern.bin", &expected_hash);
}

// ============================================================================
// Content Pattern Tests
// ============================================================================

#[test]
fn test_repeating_pattern() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let content: Vec<u8> = pattern.iter().cycle().take(CHUNK_SIZE * 2 + 100).copied().collect();

    let expected_hash = sha256(&content);
    mount.write("/repeating.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/repeating.bin", &expected_hash);
}

#[test]
fn test_alternating_bytes() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    let content: Vec<u8> = (0..CHUNK_SIZE * 2)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
        .collect();

    let expected_hash = sha256(&content);
    mount.write("/alternating.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/alternating.bin", &expected_hash);
}

#[test]
fn test_sequential_numbers() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Sequential 32-bit numbers (catches endianness issues)
    let content: Vec<u8> = (0u32..10000)
        .flat_map(|n| n.to_le_bytes())
        .collect();

    let expected_hash = sha256(&content);
    mount.write("/sequential.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/sequential.bin", &expected_hash);
}

// ============================================================================
// Patterned Chunks (different content per chunk)
// ============================================================================

#[test]
fn test_patterned_chunks() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Each chunk has a different fill byte
    let mut content = Vec::with_capacity(CHUNK_SIZE * 5);
    for chunk_num in 0..5u8 {
        content.extend(vec![chunk_num + 0xA0; CHUNK_SIZE]);
    }

    let expected_hash = sha256(&content);
    mount.write("/patterned.bin", &content).expect("write failed");
    assert_file_hash(&mount, "/patterned.bin", &expected_hash);
}

#[test]
fn test_chunk_identification() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");
    skip_if_not_mounted!(mount);

    // Write chunk number at start of each chunk
    let mut content = Vec::with_capacity(CHUNK_SIZE * 4);
    for chunk_num in 0..4u32 {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        chunk[0..4].copy_from_slice(&chunk_num.to_le_bytes());
        content.extend(chunk);
    }

    mount.write("/chunked_id.bin", &content).expect("write failed");

    let read_content = mount.read("/chunked_id.bin").expect("read failed");
    assert_eq!(read_content.len(), content.len());

    // Verify each chunk starts with correct number
    for chunk_num in 0..4u32 {
        let offset = chunk_num as usize * CHUNK_SIZE;
        let stored_num = u32::from_le_bytes([
            read_content[offset],
            read_content[offset + 1],
            read_content[offset + 2],
            read_content[offset + 3],
        ]);
        assert_eq!(stored_num, chunk_num, "Chunk {} identification failed", chunk_num);
    }
}
