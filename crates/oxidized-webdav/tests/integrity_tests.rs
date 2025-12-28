//! Data integrity tests for WebDAV backend.
//!
//! These tests verify that data is preserved correctly through the
//! encryption/decryption roundtrip, focusing on:
//! - Binary content preservation (all byte values)
//! - Unicode handling (content and filenames)
//! - Chunk boundary correctness
//! - Large file integrity via cryptographic hashing

mod common;

use common::{
    assert_file_content, assert_file_hash, generators::*, sha256, TestServer, CHUNK_SIZE,
};

// ============================================================================
// Binary Content Preservation
// ============================================================================

#[tokio::test]
async fn test_binary_content_preserved() {
    let server = TestServer::with_temp_vault().await;

    // Binary data with various patterns
    let content: Vec<u8> = vec![
        0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, // Edge bytes
        0x0A, 0x0D, 0x0A, 0x0D, // CR/LF sequences
        0x1B, 0x5B, 0x30, 0x6D, // ANSI escape sequence
        0xEF, 0xBB, 0xBF, // UTF-8 BOM
        0x00, 0x00, 0x00, 0x00, // Null bytes
    ];

    server.put_ok("/binary.bin", content.clone()).await;
    assert_file_content(&server, "/binary.bin", &content).await;
}

#[tokio::test]
async fn test_all_byte_values() {
    let server = TestServer::with_temp_vault().await;

    // Content with every possible byte value (0x00 through 0xFF)
    let content: Vec<u8> = (0u8..=255).collect();
    assert_eq!(content.len(), 256);

    server.put_ok("/all_bytes.bin", content.clone()).await;
    assert_file_content(&server, "/all_bytes.bin", &content).await;
}

#[tokio::test]
async fn test_all_byte_values_repeated() {
    let server = TestServer::with_temp_vault().await;

    // All byte values repeated to create larger file
    let content: Vec<u8> = (0..1000).flat_map(|_| 0u8..=255).collect();
    assert_eq!(content.len(), 256_000);

    let expected_hash = sha256(&content);
    server.put_ok("/all_bytes_large.bin", content).await;
    assert_file_hash(&server, "/all_bytes_large.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_null_bytes_only() {
    let server = TestServer::with_temp_vault().await;

    // File of only null bytes (potential edge case for some encodings)
    let content = vec![0u8; 1000];

    server.put_ok("/nulls.bin", content.clone()).await;
    assert_file_content(&server, "/nulls.bin", &content).await;
}

#[tokio::test]
async fn test_high_bytes_only() {
    let server = TestServer::with_temp_vault().await;

    // File of only high bytes (0xFF)
    let content = vec![0xFFu8; 1000];

    server.put_ok("/high_bytes.bin", content.clone()).await;
    assert_file_content(&server, "/high_bytes.bin", &content).await;
}

// ============================================================================
// Unicode Content
// ============================================================================

#[tokio::test]
async fn test_unicode_content_basic() {
    let server = TestServer::with_temp_vault().await;

    let content = "Hello, 世界! Привет мир! 🌍🌎🌏".as_bytes();

    server.put_ok("/unicode.txt", content.to_vec()).await;
    assert_file_content(&server, "/unicode.txt", content).await;
}

#[tokio::test]
async fn test_unicode_content_extended() {
    let server = TestServer::with_temp_vault().await;

    // Various Unicode scripts and symbols
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
        "Arrows: ←→↑↓↔↕\n",
        "Box drawing: ┌┐└┘├┤\n",
    )
    .as_bytes();

    server.put_ok("/unicode_extended.txt", content.to_vec()).await;
    assert_file_content(&server, "/unicode_extended.txt", content).await;
}

#[tokio::test]
async fn test_unicode_content_normalization() {
    let server = TestServer::with_temp_vault().await;

    // Characters that have multiple Unicode representations
    // é as single codepoint vs e + combining acute
    let content = "café naïve résumé".as_bytes();

    server.put_ok("/normalization.txt", content.to_vec()).await;
    assert_file_content(&server, "/normalization.txt", content).await;
}

// ============================================================================
// Unicode Filenames
// ============================================================================

#[tokio::test]
async fn test_unicode_filename_basic() {
    let server = TestServer::with_temp_vault().await;

    let content = b"content with unicode filename";
    server.put_ok("/文件.txt", content.to_vec()).await;

    assert_file_content(&server, "/文件.txt", content).await;
}

#[tokio::test]
async fn test_unicode_filename_emoji() {
    let server = TestServer::with_temp_vault().await;

    let content = b"emoji filename test";
    server.put_ok("/test_🔐_file.txt", content.to_vec()).await;

    assert_file_content(&server, "/test_🔐_file.txt", content).await;
}

#[tokio::test]
async fn test_unicode_filename_mixed_scripts() {
    let server = TestServer::with_temp_vault().await;

    let content = b"mixed script filename";
    server
        .put_ok("/Test_テスト_Тест.txt", content.to_vec())
        .await;

    assert_file_content(&server, "/Test_テスト_Тест.txt", content).await;
}

// ============================================================================
// Special Character Filenames
// ============================================================================

#[tokio::test]
async fn test_filename_with_spaces() {
    let server = TestServer::with_temp_vault().await;

    let content = b"file with spaces in name";
    server
        .put_ok("/file with spaces.txt", content.to_vec())
        .await;

    assert_file_content(&server, "/file with spaces.txt", content).await;
}

#[tokio::test]
async fn test_filename_with_special_chars() {
    let server = TestServer::with_temp_vault().await;

    // Characters that are valid in filenames but often problematic
    let content = b"special chars test";

    // Test various special characters individually
    let test_cases = [
        ("/file-with-dash.txt", "dash"),
        ("/file_with_underscore.txt", "underscore"),
        ("/file.multiple.dots.txt", "dots"),
        ("/file (parentheses).txt", "parentheses"),
        ("/file [brackets].txt", "brackets"),
        ("/file {braces}.txt", "braces"),
        ("/file 'apostrophe'.txt", "apostrophe"),
        ("/file #hash.txt", "hash"),
        ("/file @at.txt", "at"),
        ("/file !bang.txt", "bang"),
        ("/file $dollar.txt", "dollar"),
        ("/file %percent.txt", "percent"),
        ("/file ^caret.txt", "caret"),
        ("/file &ampersand.txt", "ampersand"),
        ("/file +plus.txt", "plus"),
        ("/file =equals.txt", "equals"),
        ("/file ~tilde.txt", "tilde"),
        ("/file `backtick`.txt", "backtick"),
    ];

    for (path, name) in test_cases {
        server.put_ok(path, content.to_vec()).await;
        assert_file_content(&server, path, content).await;
    }
}

#[tokio::test]
async fn test_filename_starting_with_dot() {
    let server = TestServer::with_temp_vault().await;

    let content = b"hidden file content";
    server.put_ok("/.hidden", content.to_vec()).await;

    assert_file_content(&server, "/.hidden", content).await;
}

#[tokio::test]
async fn test_filename_only_dots() {
    let server = TestServer::with_temp_vault().await;

    // Note: . and .. are special, but ... should work
    let content = b"dots only filename";
    server.put_ok("/...", content.to_vec()).await;

    assert_file_content(&server, "/...", content).await;
}

// ============================================================================
// Filename Length Edge Cases
// ============================================================================

#[tokio::test]
async fn test_filename_long_but_valid() {
    let server = TestServer::with_temp_vault().await;

    // 200 characters should be under typical limits
    let name = format!("/{}.txt", "a".repeat(200));
    let content = b"long filename test";

    server.put_ok(&name, content.to_vec()).await;
    assert_file_content(&server, &name, content).await;
}

#[tokio::test]
async fn test_filename_at_cryptomator_threshold() {
    let server = TestServer::with_temp_vault().await;

    // Cryptomator shortens at 220 chars - test near that boundary
    let name = format!("/{}.txt", "x".repeat(215));
    let content = b"threshold filename test";

    server.put_ok(&name, content.to_vec()).await;
    assert_file_content(&server, &name, content).await;
}

#[tokio::test]
async fn test_filename_above_cryptomator_threshold() {
    let server = TestServer::with_temp_vault().await;

    // Above 220 chars - should trigger .c9s shortening
    let name = format!("/{}.txt", "y".repeat(230));
    let content = b"long name test";

    server.put_ok(&name, content.to_vec()).await;
    assert_file_content(&server, &name, content).await;
}

// ============================================================================
// Chunk Boundary Content Tests
// ============================================================================

#[tokio::test]
async fn test_chunk_boundary_pattern_data() {
    let server = TestServer::with_temp_vault().await;

    // Create content with a distinct pattern at chunk boundaries
    // This catches off-by-one errors in chunk handling
    let mut content = vec![0xAAu8; CHUNK_SIZE];
    content.extend(vec![0xBBu8; CHUNK_SIZE]);
    content.extend(vec![0xCCu8; CHUNK_SIZE]);

    let expected_hash = sha256(&content);
    server.put_ok("/chunk_pattern.bin", content).await;
    assert_file_hash(&server, "/chunk_pattern.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_chunk_boundary_single_byte_difference() {
    let server = TestServer::with_temp_vault().await;

    // Content where only the last byte of each chunk differs
    let mut content = vec![0x00u8; CHUNK_SIZE * 3];
    content[CHUNK_SIZE - 1] = 0x01;
    content[CHUNK_SIZE * 2 - 1] = 0x02;
    content[CHUNK_SIZE * 3 - 1] = 0x03;

    let expected_hash = sha256(&content);
    server.put_ok("/boundary_byte.bin", content).await;
    assert_file_hash(&server, "/boundary_byte.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_partial_final_chunk() {
    let server = TestServer::with_temp_vault().await;

    // 2.5 chunks - partial final chunk
    let size = CHUNK_SIZE * 2 + CHUNK_SIZE / 2;
    let content = random_bytes(size);

    let expected_hash = sha256(&content);
    server.put_ok("/partial_chunk.bin", content).await;
    assert_file_hash(&server, "/partial_chunk.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_minimal_final_chunk() {
    let server = TestServer::with_temp_vault().await;

    // 2 full chunks + 1 byte
    let size = CHUNK_SIZE * 2 + 1;
    let content = random_bytes(size);

    let expected_hash = sha256(&content);
    server.put_ok("/minimal_final.bin", content).await;
    assert_file_hash(&server, "/minimal_final.bin", &expected_hash).await;
}

// ============================================================================
// Write-Read-Write Cycles
// ============================================================================

#[tokio::test]
async fn test_write_read_write_cycle() {
    let server = TestServer::with_temp_vault().await;

    // First write
    let content1 = random_bytes(10000);
    server.put_ok("/cycle.bin", content1.clone()).await;
    assert_file_content(&server, "/cycle.bin", &content1).await;

    // Overwrite
    let content2 = random_bytes(20000);
    server.put_ok("/cycle.bin", content2.clone()).await;
    assert_file_content(&server, "/cycle.bin", &content2).await;

    // Overwrite again with smaller
    let content3 = random_bytes(5000);
    server.put_ok("/cycle.bin", content3.clone()).await;
    assert_file_content(&server, "/cycle.bin", &content3).await;
}

#[tokio::test]
async fn test_multiple_overwrite_same_size() {
    let server = TestServer::with_temp_vault().await;

    let size = 10000;

    for i in 0..5 {
        let content = random_bytes(size);
        server.put_ok("/same_size.bin", content.clone()).await;
        assert_file_content(&server, "/same_size.bin", &content).await;
    }
}

#[tokio::test]
async fn test_overwrite_empty_then_content() {
    let server = TestServer::with_temp_vault().await;

    // Start empty
    server.put_ok("/empty_first.bin", Vec::new()).await;
    assert_file_content(&server, "/empty_first.bin", b"").await;

    // Add content
    let content = b"now has content";
    server.put_ok("/empty_first.bin", content.to_vec()).await;
    assert_file_content(&server, "/empty_first.bin", content).await;
}

#[tokio::test]
async fn test_overwrite_content_then_empty() {
    let server = TestServer::with_temp_vault().await;

    // Start with content
    let content = b"has content initially";
    server.put_ok("/content_first.bin", content.to_vec()).await;
    assert_file_content(&server, "/content_first.bin", content).await;

    // Make empty
    server.put_ok("/content_first.bin", Vec::new()).await;
    assert_file_content(&server, "/content_first.bin", b"").await;
}

// ============================================================================
// Large File Integrity
// ============================================================================

#[tokio::test]
async fn test_large_file_hash_verification() {
    let server = TestServer::with_temp_vault().await;

    // 10 chunks = 320KB
    let content = multi_chunk_content(10);
    let expected_hash = sha256(&content);

    server.put_ok("/large_verified.bin", content).await;
    assert_file_hash(&server, "/large_verified.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_medium_file_exact_content() {
    let server = TestServer::with_temp_vault().await;

    // 3 chunks worth of recognizable pattern
    let mut content = Vec::with_capacity(CHUNK_SIZE * 3);
    for i in 0..(CHUNK_SIZE * 3) {
        content.push((i % 256) as u8);
    }

    let expected_hash = sha256(&content);
    server.put_ok("/pattern.bin", content).await;
    assert_file_hash(&server, "/pattern.bin", &expected_hash).await;
}

// ============================================================================
// Content Pattern Tests
// ============================================================================

#[tokio::test]
async fn test_repeating_pattern() {
    let server = TestServer::with_temp_vault().await;

    // Repeating pattern that spans chunks
    let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let content: Vec<u8> = pattern.iter().cycle().take(CHUNK_SIZE * 2 + 100).copied().collect();

    let expected_hash = sha256(&content);
    server.put_ok("/repeating.bin", content).await;
    assert_file_hash(&server, "/repeating.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_alternating_bytes() {
    let server = TestServer::with_temp_vault().await;

    // Alternating 0x00 and 0xFF
    let content: Vec<u8> = (0..CHUNK_SIZE * 2)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
        .collect();

    let expected_hash = sha256(&content);
    server.put_ok("/alternating.bin", content).await;
    assert_file_hash(&server, "/alternating.bin", &expected_hash).await;
}

#[tokio::test]
async fn test_sequential_numbers() {
    let server = TestServer::with_temp_vault().await;

    // Sequential 32-bit numbers (catches endianness issues)
    let content: Vec<u8> = (0u32..10000)
        .flat_map(|n| n.to_le_bytes())
        .collect();

    let expected_hash = sha256(&content);
    server.put_ok("/sequential.bin", content).await;
    assert_file_hash(&server, "/sequential.bin", &expected_hash).await;
}
