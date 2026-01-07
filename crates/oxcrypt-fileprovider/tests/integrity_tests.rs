//! Data integrity tests for File Provider.
//!
//! Tests that verify data is preserved correctly through the encryption/decryption
//! round-trip, including binary data, edge cases, and large files.

#![cfg(all(target_os = "macos", feature = "fileprovider-tests"))]

mod common;

use common::{generate_test_data, random_bytes, sha256, TestMount};

/// Cryptomator chunk size (32KB)
const CHUNK_SIZE: usize = 32 * 1024;

#[test]
fn binary_content_preserved() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("binary");

    // Test various binary patterns
    let patterns: Vec<(&str, Vec<u8>)> = vec![
        ("zeros", vec![0u8; 1024]),
        ("ones", vec![0xFF; 1024]),
        ("alternating", (0..1024).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect()),
        ("random", random_bytes(1024)),
    ];

    for (name, content) in patterns {
        let filename = format!("{name}.bin");
        mount.write_file(&filename, &content).expect("Write failed");

        let read_back = mount.read_file(&filename).expect("Read failed");
        assert_eq!(
            read_back, content,
            "Binary content mismatch for pattern: {name}"
        );
    }
}

#[test]
fn all_byte_values() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("all_bytes");

    // Create content with all 256 possible byte values
    let content: Vec<u8> = (0..=255).collect();

    mount
        .write_file("all_bytes.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("all_bytes.bin").expect("Read failed");
    assert_eq!(read_back.len(), 256, "Should have exactly 256 bytes");

    // Verify each byte value is preserved
    for (i, &byte) in read_back.iter().enumerate() {
        assert_eq!(
            byte, i as u8,
            "Byte value mismatch at position {i}: expected {i}, got {byte}"
        );
    }
}

#[test]
fn unicode_content() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("unicode_content");

    // Various Unicode content including multi-byte characters
    let content = "Hello, World!\n\
        中文测试\n\
        日本語テスト\n\
        한국어 테스트\n\
        Привет мир\n\
        مرحبا بالعالم\n\
        שלום עולם\n\
        Emoji: 🦀🔐📁\n\
        Math: ∑∏∫∂∇\n\
        Symbols: ™©®€£¥\n";

    mount
        .write_file("unicode.txt", content.as_bytes())
        .expect("Write failed");

    let read_back = mount.read_file("unicode.txt").expect("Read failed");
    let read_str = String::from_utf8(read_back).expect("Invalid UTF-8");
    assert_eq!(read_str, content, "Unicode content mismatch");
}

#[test]
fn unicode_filename() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("unicode_name");

    let test_cases = vec![
        ("file_日本語.txt", "Japanese filename"),
        ("file_中文.txt", "Chinese filename"),
        ("file_한국어.txt", "Korean filename"),
        ("file_🦀.txt", "Emoji filename"),
        ("file_café.txt", "Accented filename"),
    ];

    for (filename, description) in test_cases {
        let content = format!("Content for {description}");
        mount
            .write_file(filename, content.as_bytes())
            .expect(&format!("Write failed for {description}"));

        let read_back = mount
            .read_file(filename)
            .expect(&format!("Read failed for {description}"));

        assert_eq!(
            String::from_utf8_lossy(&read_back),
            content,
            "Content mismatch for {description}"
        );
    }
}

#[test]
fn hash_medium_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("hash_medium");

    // 1MB file - large enough to span multiple chunks
    let size = 1024 * 1024;
    let content = generate_test_data(size);
    let original_hash = sha256(&content);

    mount
        .write_file("medium.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("medium.bin").expect("Read failed");
    let read_hash = sha256(&read_back);

    assert_eq!(read_back.len(), size, "Size mismatch");
    assert_eq!(read_hash, original_hash, "SHA-256 hash mismatch");
}

#[test]
fn hash_large_file() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("hash_large");

    // 5MB file - spans many chunks
    let size = 5 * 1024 * 1024;
    let content = generate_test_data(size);
    let original_hash = sha256(&content);

    mount
        .write_file("large.bin", &content)
        .expect("Write failed");

    let read_back = mount.read_file("large.bin").expect("Read failed");
    let read_hash = sha256(&read_back);

    assert_eq!(read_back.len(), size, "Size mismatch");
    assert_eq!(read_hash, original_hash, "SHA-256 hash mismatch for 5MB file");
}

#[test]
fn chunk_boundary_integrity() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("chunk_boundary");

    // Test files that span exact chunk boundaries
    let sizes = vec![
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 2 - 1,
        CHUNK_SIZE * 2,
        CHUNK_SIZE * 2 + 1,
        CHUNK_SIZE * 3,
    ];

    for size in sizes {
        let filename = format!("boundary_{size}.bin");
        let content = generate_test_data(size);
        let original_hash = sha256(&content);

        mount.write_file(&filename, &content).expect("Write failed");

        let read_back = mount.read_file(&filename).expect("Read failed");
        let read_hash = sha256(&read_back);

        assert_eq!(
            read_back.len(),
            size,
            "Size mismatch for {size} byte file"
        );
        assert_eq!(
            read_hash, original_hash,
            "Hash mismatch for {size} byte file"
        );
    }
}

#[test]
fn repeated_read_consistency() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("repeated_read");

    let content = random_bytes(CHUNK_SIZE * 2 + 100);
    let original_hash = sha256(&content);

    mount
        .write_file("repeated.bin", &content)
        .expect("Write failed");

    // Read the file multiple times and verify consistency
    for i in 0..5 {
        let read_back = mount
            .read_file("repeated.bin")
            .expect(&format!("Read {i} failed"));
        let read_hash = sha256(&read_back);
        assert_eq!(
            read_hash, original_hash,
            "Hash mismatch on read iteration {i}"
        );
    }
}

#[test]
fn overwrite_preserves_integrity() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("overwrite_integrity");

    // Write initial content
    let content1 = random_bytes(CHUNK_SIZE + 500);
    mount
        .write_file("overwrite.bin", &content1)
        .expect("Write 1 failed");

    // Overwrite with different size content
    let content2 = random_bytes(CHUNK_SIZE * 2);
    let hash2 = sha256(&content2);
    mount
        .write_file("overwrite.bin", &content2)
        .expect("Write 2 failed");

    let read_back = mount.read_file("overwrite.bin").expect("Read failed");
    let read_hash = sha256(&read_back);

    assert_eq!(read_back.len(), content2.len(), "Size should match new content");
    assert_eq!(read_hash, hash2, "Hash should match new content");
}

#[test]
fn special_characters_in_filename() {
    skip_if_no_fileprovider!();

    let mount = test_mount_or_skip!("special_chars");

    // Note: Avoiding characters that are invalid in HFS+ filenames (: and /)
    let test_cases = vec![
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "file.multiple.dots.txt",
        "UPPERCASE.TXT",
        "MiXeD-CaSe.TxT",
        "file(parentheses).txt",
        "file[brackets].txt",
        "file{braces}.txt",
        "file@at#hash$dollar.txt",
    ];

    for filename in test_cases {
        let content = format!("Content for {filename}");
        mount
            .write_file(filename, content.as_bytes())
            .expect(&format!("Write failed for '{filename}'"));

        let read_back = mount
            .read_file(filename)
            .expect(&format!("Read failed for '{filename}'"));

        assert_eq!(
            String::from_utf8_lossy(&read_back),
            content,
            "Content mismatch for '{filename}'"
        );
    }
}
