//! Tests for error handling paths in file.rs
//!
//! This module focuses on testing error handling, edge cases, and security-critical paths
//! that might not be exercised in happy-path tests.

mod common;

use oxcrypt_core::crypto::keys::MasterKey;
use oxcrypt_core::fs::file::{
    DecryptedFile, FileContext, FileDecryptionError, FileEncryptionError, FileError,
    decrypt_dir_id_backup, decrypt_file, decrypt_file_content, decrypt_file_content_with_context,
    decrypt_file_header, decrypt_file_header_with_context, decrypt_file_with_context,
    encrypt_dir_id_backup, encrypt_file_content, encrypt_file_header,
};
use rand::RngCore;
use std::io;
use std::path::Path;
use tempfile::TempDir;

fn generate_content_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

// =============================================================================
// FileContext Display Tests
// =============================================================================

#[test]
fn test_file_context_display_empty() {
    let context = FileContext::new();
    let display = format!("{context}");
    assert_eq!(display, "(no context)");
}

#[test]
fn test_file_context_display_with_filename() {
    let context = FileContext::new().with_filename("test.txt");
    let display = format!("{context}");
    assert!(display.contains("file 'test.txt'"));
}

#[test]
fn test_file_context_display_with_empty_dir_id() {
    // Empty dir_id (root) should display as <root>
    let context = FileContext::new().with_dir_id("");
    let display = format!("{context}");
    assert!(
        display.contains("<root>"),
        "Expected '<root>', got: {display}"
    );
}

#[test]
fn test_file_context_display_with_short_dir_id() {
    // Short dir_id (8 or fewer chars) should be shown in full
    let context = FileContext::new().with_dir_id("12345678");
    let display = format!("{context}");
    assert!(
        display.contains("12345678"),
        "Expected full dir_id, got: {display}"
    );
}

#[test]
fn test_file_context_display_with_long_dir_id() {
    // Long dir_id (> 8 chars) should be truncated with "..."
    let context = FileContext::new().with_dir_id("123456789abcdef");
    let display = format!("{context}");
    assert!(
        display.contains("12345678..."),
        "Expected truncated dir_id, got: {display}"
    );
}

#[test]
fn test_file_context_display_with_chunk() {
    let context = FileContext::new().with_chunk(5);
    let display = format!("{context}");
    assert!(
        display.contains("chunk 5"),
        "Expected 'chunk 5', got: {display}"
    );
}

#[test]
fn test_file_context_display_with_path() {
    let context = FileContext::new().with_path("/some/encrypted/path");
    let display = format!("{context}");
    assert!(
        display.contains("/some/encrypted/path"),
        "Expected path, got: {display}"
    );
}

#[test]
fn test_file_context_display_combined() {
    let context = FileContext::new()
        .with_filename("secret.txt")
        .with_dir_id("abcdefghij123456")
        .with_chunk(3)
        .with_path("/vault/d/AB/XYZ");

    let display = format!("{context}");

    assert!(
        display.contains("file 'secret.txt'"),
        "Missing filename in: {display}"
    );
    assert!(
        display.contains("abcdefgh..."),
        "Missing truncated dir_id in: {display}"
    );
    assert!(display.contains("chunk 3"), "Missing chunk in: {display}");
    assert!(display.contains("AB/XYZ"), "Missing path in: {display}");
}

// =============================================================================
// Header Decryption Error Tests
// =============================================================================

#[test]
fn test_header_too_short() {
    let master_key = MasterKey::random().unwrap();
    let short_header = vec![0u8; 50]; // Should be 68 bytes

    let result = decrypt_file_header(&short_header, &master_key);

    match result {
        Err(FileDecryptionError::InvalidHeader { reason, .. }) => {
            assert!(reason.contains("expected 68 bytes"));
            assert!(reason.contains("50"));
        }
        other => panic!("Expected InvalidHeader error, got: {other:?}"),
    }
}

#[test]
fn test_header_too_long() {
    let master_key = MasterKey::random().unwrap();
    let long_header = vec![0u8; 100]; // Should be 68 bytes

    let result = decrypt_file_header(&long_header, &master_key);

    match result {
        Err(FileDecryptionError::InvalidHeader { reason, .. }) => {
            assert!(reason.contains("expected 68 bytes"));
            assert!(reason.contains("100"));
        }
        other => panic!("Expected InvalidHeader error, got: {other:?}"),
    }
}

#[test]
fn test_header_wrong_key() {
    let master_key1 = MasterKey::random().unwrap();
    let master_key2 = MasterKey::random().unwrap();
    let content_key = generate_content_key();

    let encrypted_header = encrypt_file_header(&content_key, &master_key1).unwrap();
    let result = decrypt_file_header(&encrypted_header, &master_key2);

    match result {
        Err(FileDecryptionError::HeaderDecryption { .. }) => {
            // Expected - authentication tag mismatch
        }
        other => panic!("Expected HeaderDecryption error, got: {other:?}"),
    }
}

#[test]
fn test_header_decryption_with_context() {
    let master_key = MasterKey::random().unwrap();
    let corrupted_header = vec![0xFF; 68];

    let context = FileContext::new()
        .with_filename("important.txt")
        .with_dir_id("test-dir-id");

    let result = decrypt_file_header_with_context(&corrupted_header, &master_key, &context);

    match result {
        Err(FileDecryptionError::HeaderDecryption { context }) => {
            assert!(context.filename.as_deref() == Some("important.txt"));
            assert!(context.dir_id.as_deref() == Some("test-dir-id"));
        }
        other => panic!("Expected HeaderDecryption error with context, got: {other:?}"),
    }
}

// =============================================================================
// Content Decryption Error Tests
// =============================================================================

#[test]
fn test_incomplete_chunk_error() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();

    // A chunk needs at least 28 bytes (12 nonce + 16 tag minimum)
    let incomplete_chunk = vec![0u8; 20];

    let result = decrypt_file_content(&incomplete_chunk, &content_key, &header_nonce);

    match result {
        Err(FileDecryptionError::IncompleteChunk { actual_size, .. }) => {
            assert_eq!(actual_size, 20);
        }
        other => panic!("Expected IncompleteChunk error, got: {other:?}"),
    }
}

#[test]
fn test_incomplete_chunk_with_context() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();

    let incomplete_chunk = vec![0u8; 15];
    let context = FileContext::new().with_filename("test.bin");

    let result =
        decrypt_file_content_with_context(&incomplete_chunk, &content_key, &header_nonce, &context);

    match result {
        Err(FileDecryptionError::IncompleteChunk {
            context,
            actual_size,
        }) => {
            assert_eq!(actual_size, 15);
            assert!(context.filename.as_deref() == Some("test.bin"));
            // The chunk number should be set to 0 (first chunk)
            assert_eq!(context.chunk_number, Some(0));
        }
        other => panic!("Expected IncompleteChunk error with context, got: {other:?}"),
    }
}

#[test]
fn test_content_tampered_first_chunk() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();
    let content = b"Hello, World! This is test content.";

    let mut encrypted = encrypt_file_content(content, &content_key, &header_nonce).unwrap();

    // Tamper with the first byte after the nonce (in the ciphertext)
    encrypted[12] ^= 0xFF;

    let result = decrypt_file_content(&encrypted, &content_key, &header_nonce);

    match result {
        Err(FileDecryptionError::ContentDecryption { context }) => {
            assert_eq!(context.chunk_number, Some(0));
        }
        other => panic!("Expected ContentDecryption error, got: {other:?}"),
    }
}

#[test]
fn test_content_tampered_second_chunk() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();
    // Create content that spans 2 chunks (>32KB)
    let content = vec![0xAB; 40000];

    let mut encrypted = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();

    // Calculate where the second chunk starts
    // First chunk: 32768 bytes content + 12 nonce + 16 tag = 32796 bytes encrypted
    let second_chunk_start = 32768 + 28;

    // Tamper with the second chunk
    if encrypted.len() > second_chunk_start + 20 {
        encrypted[second_chunk_start + 20] ^= 0xFF;
    }

    let result = decrypt_file_content(&encrypted, &content_key, &header_nonce);

    match result {
        Err(FileDecryptionError::ContentDecryption { context }) => {
            assert_eq!(
                context.chunk_number,
                Some(1),
                "Expected chunk 1, got: {:?}",
                context.chunk_number
            );
        }
        other => panic!("Expected ContentDecryption error for chunk 1, got: {other:?}"),
    }
}

#[test]
fn test_content_wrong_nonce() {
    let content_key = generate_content_key();
    let header_nonce1 = generate_nonce();
    let header_nonce2 = generate_nonce();
    let content = b"Test content";

    let encrypted = encrypt_file_content(content, &content_key, &header_nonce1).unwrap();

    // Try to decrypt with wrong header nonce - should fail because AAD doesn't match
    let result = decrypt_file_content(&encrypted, &content_key, &header_nonce2);

    assert!(result.is_err(), "Should fail with wrong header nonce");
}

// =============================================================================
// decrypt_file() and decrypt_file_with_context() Tests
// =============================================================================

#[test]
fn test_decrypt_file_not_found() {
    let master_key = MasterKey::random().unwrap();
    let non_existent = Path::new("/non/existent/file.c9r");

    let result = decrypt_file(non_existent, &master_key);

    match result {
        Err(FileError::Io { source, context }) => {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(context.encrypted_path.is_some());
        }
        other => panic!("Expected IO error, got: {other:?}"),
    }
}

#[test]
fn test_decrypt_dir_marker_file() {
    let master_key = MasterKey::random().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dir_marker = temp_dir.path().join("dir.c9r");

    // Create a fake dir.c9r file
    std::fs::write(&dir_marker, "fake directory id").unwrap();

    let result = decrypt_file(&dir_marker, &master_key);

    match result {
        Err(FileError::Decryption(FileDecryptionError::InvalidHeader { reason, .. })) => {
            assert!(
                reason.contains("dir.c9r"),
                "Error should mention dir.c9r: {reason}"
            );
        }
        other => panic!("Expected InvalidHeader error about dir.c9r, got: {other:?}"),
    }
}

#[test]
fn test_decrypt_file_too_small() {
    let master_key = MasterKey::random().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let small_file = temp_dir.path().join("small.c9r");

    // Create a file smaller than the minimum header size (68 bytes)
    std::fs::write(&small_file, vec![0u8; 50]).unwrap();

    let result = decrypt_file(&small_file, &master_key);

    match result {
        Err(FileError::Decryption(FileDecryptionError::InvalidHeader { reason, .. })) => {
            assert!(
                reason.contains("too small"),
                "Error should mention size: {reason}"
            );
            assert!(
                reason.contains("50"),
                "Error should mention actual size: {reason}"
            );
        }
        other => panic!("Expected InvalidHeader error about size, got: {other:?}"),
    }
}

#[test]
fn test_decrypt_file_with_context_preserves_context() {
    let master_key = MasterKey::random().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c9r");

    // Create a valid encrypted file
    let content_key = generate_content_key();
    let header = encrypt_file_header(&content_key, &master_key).unwrap();
    let header_nonce: [u8; 12] = header[..12].try_into().unwrap();
    let encrypted_content =
        encrypt_file_content(b"Test content", &content_key, &header_nonce).unwrap();

    let mut file_data = header;
    file_data.extend_from_slice(&encrypted_content);
    std::fs::write(&test_file, file_data).unwrap();

    // Decrypt with context
    let result = decrypt_file_with_context(
        &test_file,
        &master_key,
        Some("my_secret.txt"),
        Some("parent-dir-uuid"),
    );

    // Should succeed
    let decrypted = result.expect("Decryption should succeed");
    assert_eq!(decrypted.content, b"Test content");
}

#[test]
fn test_decrypt_file_with_context_dir_marker() {
    let master_key = MasterKey::random().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dir_marker = temp_dir.path().join("dir.c9r");

    std::fs::write(&dir_marker, "fake").unwrap();

    let result = decrypt_file_with_context(
        &dir_marker,
        &master_key,
        Some("test_dir"),
        Some("parent-id"),
    );

    match result {
        Err(FileError::Decryption(FileDecryptionError::InvalidHeader { reason, context })) => {
            assert!(reason.contains("dir.c9r"));
            // Context should still be set
            assert!(context.filename.as_deref() == Some("test_dir"));
            assert!(context.dir_id.as_deref() == Some("parent-id"));
        }
        other => panic!("Expected InvalidHeader error, got: {other:?}"),
    }
}

// =============================================================================
// Error Conversion Tests
// =============================================================================

#[test]
fn test_io_error_to_file_error() {
    let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let file_error: FileError = io_error.into();

    match file_error {
        FileError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            // Default context should be empty
            assert!(context.filename.is_none());
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

#[test]
fn test_io_error_to_file_decryption_error() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let dec_error: FileDecryptionError = io_error.into();

    match dec_error {
        FileDecryptionError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(context.filename.is_none());
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

#[test]
fn test_io_error_to_file_encryption_error() {
    let io_error = io::Error::new(io::ErrorKind::OutOfMemory, "out of memory");
    let enc_error: FileEncryptionError = io_error.into();

    match enc_error {
        FileEncryptionError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::OutOfMemory);
            assert!(context.filename.is_none());
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

#[test]
fn test_file_error_io_with_context() {
    let io_error = io::Error::new(io::ErrorKind::InvalidData, "bad data");
    let context = FileContext::new().with_filename("bad_file.bin");

    let file_error = FileError::io_with_context(io_error, context);

    match file_error {
        FileError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            assert_eq!(context.filename.as_deref(), Some("bad_file.bin"));
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

#[test]
fn test_file_decryption_error_io_with_context() {
    let io_error = io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe");
    let context = FileContext::new().with_chunk(42);

    let dec_error = FileDecryptionError::io_with_context(io_error, context);

    match dec_error {
        FileDecryptionError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(context.chunk_number, Some(42));
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

#[test]
fn test_file_encryption_error_io_with_context() {
    let io_error = io::Error::new(io::ErrorKind::WriteZero, "write zero");
    let context = FileContext::new().with_path("/some/path");

    let enc_error = FileEncryptionError::io_with_context(io_error, context);

    match enc_error {
        FileEncryptionError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::WriteZero);
            assert!(context.encrypted_path.is_some());
        }
        other => panic!("Expected Io error, got: {other:?}"),
    }
}

// =============================================================================
// Error with_context() Transformation Tests
// =============================================================================

#[test]
fn test_header_decryption_with_context_transformation() {
    let original = FileDecryptionError::HeaderDecryption {
        context: FileContext::new(),
    };

    let new_context = FileContext::new().with_filename("new_file.txt");
    let transformed = original.with_context(new_context);

    match transformed {
        FileDecryptionError::HeaderDecryption { context } => {
            assert_eq!(context.filename.as_deref(), Some("new_file.txt"));
        }
        other => panic!("Expected HeaderDecryption, got: {other:?}"),
    }
}

#[test]
fn test_content_decryption_with_context_transformation() {
    let original = FileDecryptionError::ContentDecryption {
        context: FileContext::new(),
    };

    let new_context = FileContext::new().with_chunk(7);
    let transformed = original.with_context(new_context);

    match transformed {
        FileDecryptionError::ContentDecryption { context } => {
            assert_eq!(context.chunk_number, Some(7));
        }
        other => panic!("Expected ContentDecryption, got: {other:?}"),
    }
}

#[test]
fn test_invalid_header_with_context_transformation() {
    let original = FileDecryptionError::InvalidHeader {
        reason: "test reason".to_string(),
        context: FileContext::new(),
    };

    let new_context = FileContext::new().with_dir_id("new-dir");
    let transformed = original.with_context(new_context);

    match transformed {
        FileDecryptionError::InvalidHeader { reason, context } => {
            assert_eq!(reason, "test reason"); // Reason should be preserved
            assert_eq!(context.dir_id.as_deref(), Some("new-dir"));
        }
        other => panic!("Expected InvalidHeader, got: {other:?}"),
    }
}

#[test]
fn test_incomplete_chunk_with_context_transformation() {
    let original = FileDecryptionError::IncompleteChunk {
        context: FileContext::new(),
        actual_size: 15,
    };

    let new_context = FileContext::new().with_filename("partial.bin");
    let transformed = original.with_context(new_context);

    match transformed {
        FileDecryptionError::IncompleteChunk {
            context,
            actual_size,
        } => {
            assert_eq!(actual_size, 15); // Size should be preserved
            assert_eq!(context.filename.as_deref(), Some("partial.bin"));
        }
        other => panic!("Expected IncompleteChunk, got: {other:?}"),
    }
}

#[test]
fn test_io_error_with_context_transformation() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "not found");
    let original = FileDecryptionError::Io {
        source: io_error,
        context: FileContext::new(),
    };

    let new_context = FileContext::new().with_path("/new/path");
    let transformed = original.with_context(new_context);

    match transformed {
        FileDecryptionError::Io { source, context } => {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(context.encrypted_path.is_some());
        }
        other => panic!("Expected Io, got: {other:?}"),
    }
}

// =============================================================================
// Directory ID Backup Tests
// =============================================================================

#[test]
fn test_dir_id_backup_roundtrip() {
    let master_key = MasterKey::random().unwrap();
    let dir_id = "e9250eb8-078d-4fc0-8835-be92a313360c";

    let encrypted = encrypt_dir_id_backup(dir_id, &master_key).unwrap();
    let decrypted = decrypt_dir_id_backup(&encrypted, &master_key).unwrap();

    assert_eq!(decrypted, dir_id);
}

#[test]
fn test_dir_id_backup_empty_string() {
    // Root directory has empty string as ID
    let master_key = MasterKey::random().unwrap();
    let dir_id = "";

    let encrypted = encrypt_dir_id_backup(dir_id, &master_key).unwrap();
    let decrypted = decrypt_dir_id_backup(&encrypted, &master_key).unwrap();

    assert_eq!(decrypted, dir_id);
}

#[test]
fn test_dir_id_backup_too_small() {
    let master_key = MasterKey::random().unwrap();
    let small_data = vec![0u8; 50]; // Less than 68 bytes

    let result = decrypt_dir_id_backup(&small_data, &master_key);

    match result {
        Err(FileDecryptionError::InvalidHeader { reason, context }) => {
            assert!(reason.contains("dirid.c9r"));
            assert!(reason.contains("too small"));
            assert!(context.filename.as_deref() == Some("dirid.c9r"));
        }
        other => panic!("Expected InvalidHeader error, got: {other:?}"),
    }
}

#[test]
fn test_dir_id_backup_header_only() {
    // A valid header with no content (edge case - shouldn't happen normally)
    let master_key = MasterKey::random().unwrap();
    let content_key = generate_content_key();

    // Create just a header with no content
    let header = encrypt_file_header(&content_key, &master_key).unwrap();
    assert_eq!(header.len(), 68);

    let decrypted = decrypt_dir_id_backup(&header, &master_key).unwrap();

    // Should return empty string when there's no content after the header
    assert_eq!(decrypted, "");
}

#[test]
fn test_dir_id_backup_wrong_key() {
    let master_key1 = MasterKey::random().unwrap();
    let master_key2 = MasterKey::random().unwrap();
    let dir_id = "test-dir-id";

    let encrypted = encrypt_dir_id_backup(dir_id, &master_key1).unwrap();
    let result = decrypt_dir_id_backup(&encrypted, &master_key2);

    match result {
        Err(FileDecryptionError::HeaderDecryption { context }) => {
            assert!(context.filename.as_deref() == Some("dirid.c9r"));
        }
        other => panic!("Expected HeaderDecryption error, got: {other:?}"),
    }
}

#[test]
fn test_dir_id_backup_corrupted() {
    let master_key = MasterKey::random().unwrap();
    let dir_id = "test-dir-id";

    let mut encrypted = encrypt_dir_id_backup(dir_id, &master_key).unwrap();

    // Corrupt the content portion (after header)
    if encrypted.len() > 80 {
        encrypted[80] ^= 0xFF;
    }

    let result = decrypt_dir_id_backup(&encrypted, &master_key);

    assert!(result.is_err(), "Should fail with corrupted content");
}

// =============================================================================
// DecryptedFile Debug Implementation Tests
// =============================================================================

#[test]
fn test_decrypted_file_debug_short_content() {
    let header = oxcrypt_core::fs::file::FileHeader {
        content_key: zeroize::Zeroizing::new([0u8; 32]),
        tag: [0u8; 16],
    };

    let decrypted = DecryptedFile {
        header,
        content: b"Hello, World!".to_vec(),
    };

    let debug_str = format!("{decrypted:?}");

    // Should contain the full content (< 100 bytes)
    assert!(
        debug_str.contains("Hello, World!"),
        "Debug should show content: {debug_str}"
    );
    // Should NOT contain "..." for short content
    assert!(
        !debug_str.ends_with("...\""),
        "Short content should not be truncated: {debug_str}"
    );
    // Content key should be redacted
    assert!(
        debug_str.contains("[REDACTED]"),
        "Content key should be redacted: {debug_str}"
    );
}

#[test]
fn test_decrypted_file_debug_long_content() {
    let header = oxcrypt_core::fs::file::FileHeader {
        content_key: zeroize::Zeroizing::new([0u8; 32]),
        tag: [0x42; 16],
    };

    let content = vec![b'A'; 200]; // 200 bytes, > 100 byte limit
    let decrypted = DecryptedFile { header, content };

    let debug_str = format!("{decrypted:?}");

    // Should contain truncated content with "..."
    assert!(
        debug_str.contains("..."),
        "Long content should be truncated: {debug_str}"
    );
    // Should contain the tag in hex
    assert!(
        debug_str.contains("4242424242"),
        "Should show tag in hex: {debug_str}"
    );
}

#[test]
fn test_decrypted_file_debug_empty_content() {
    let header = oxcrypt_core::fs::file::FileHeader {
        content_key: zeroize::Zeroizing::new([0u8; 32]),
        tag: [0u8; 16],
    };

    let decrypted = DecryptedFile {
        header,
        content: Vec::new(),
    };

    let debug_str = format!("{decrypted:?}");

    // Should handle empty content gracefully
    assert!(
        debug_str.contains("DecryptedFile"),
        "Should be a valid debug output: {debug_str}"
    );
}

#[test]
fn test_decrypted_file_debug_binary_content() {
    let header = oxcrypt_core::fs::file::FileHeader {
        content_key: zeroize::Zeroizing::new([0u8; 32]),
        tag: [0u8; 16],
    };

    // Binary content that's not valid UTF-8
    let content = vec![0xFF, 0xFE, 0x00, 0x01, 0x02];
    let decrypted = DecryptedFile { header, content };

    let debug_str = format!("{decrypted:?}");

    // Should handle binary content with lossy conversion
    assert!(
        debug_str.contains("DecryptedFile"),
        "Should produce valid debug output: {debug_str}"
    );
}

// =============================================================================
// FileHeader Debug Implementation Test
// =============================================================================

#[test]
fn test_file_header_debug_redacts_key() {
    let header = oxcrypt_core::fs::file::FileHeader {
        content_key: zeroize::Zeroizing::new([0x42; 32]),
        tag: [0xAB; 16],
    };

    let debug_str = format!("{header:?}");

    // Content key should be redacted
    assert!(
        debug_str.contains("[REDACTED]"),
        "Content key should be redacted: {debug_str}"
    );
    // Should NOT contain the actual key bytes
    assert!(
        !debug_str.contains("42424242"),
        "Should not expose key bytes: {debug_str}"
    );
    // Tag should be shown in hex
    assert!(
        debug_str.contains("abab") || debug_str.contains("ABAB"),
        "Tag should be shown in hex: {debug_str}"
    );
}

// =============================================================================
// Chunk Boundary Edge Cases
// =============================================================================

#[test]
fn test_content_exactly_one_chunk() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();

    // Exactly 32KB = 32768 bytes (one full chunk)
    let content = vec![0xAB; 32768];

    let encrypted = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
    let decrypted = decrypt_file_content(&encrypted, &content_key, &header_nonce).unwrap();

    assert_eq!(decrypted, content);
}

#[test]
fn test_content_one_byte_over_chunk() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();

    // 32769 bytes = one chunk + 1 byte
    let content = vec![0xCD; 32769];

    let encrypted = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
    let decrypted = decrypt_file_content(&encrypted, &content_key, &header_nonce).unwrap();

    assert_eq!(decrypted, content);
}

#[test]
fn test_content_multiple_exact_chunks() {
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();

    // 3 * 32768 = 98304 bytes (exactly 3 chunks)
    let content = vec![0xEF; 98304];

    let encrypted = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
    let decrypted = decrypt_file_content(&encrypted, &content_key, &header_nonce).unwrap();

    assert_eq!(decrypted, content);
}

// =============================================================================
// Error Display/Message Tests
// =============================================================================

#[test]
fn test_file_error_display() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let context = FileContext::new().with_filename("missing.txt");
    let error = FileError::io_with_context(io_error, context);

    let display = format!("{error}");
    assert!(
        display.contains("IO error"),
        "Should mention IO error: {display}"
    );
    assert!(
        display.contains("missing.txt"),
        "Should mention filename: {display}"
    );
}

#[test]
fn test_file_decryption_error_display() {
    let context = FileContext::new().with_filename("secret.bin").with_chunk(3);

    let error = FileDecryptionError::ContentDecryption { context };
    let display = format!("{error}");

    assert!(
        display.contains("secret.bin"),
        "Should mention filename: {display}"
    );
    assert!(
        display.contains("chunk 3"),
        "Should mention chunk: {display}"
    );
    assert!(
        display.contains("authentication") || display.contains("tampering"),
        "Should mention auth failure: {display}"
    );
}

#[test]
fn test_file_encryption_error_display() {
    let context = FileContext::new().with_filename("output.bin");
    let error = FileEncryptionError::HeaderEncryption {
        reason: "test failure".to_string(),
        context,
    };

    let display = format!("{error}");
    assert!(
        display.contains("output.bin"),
        "Should mention filename: {display}"
    );
    assert!(
        display.contains("test failure"),
        "Should mention reason: {display}"
    );
}
