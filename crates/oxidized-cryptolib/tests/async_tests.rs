//! Integration tests for async vault operations.
//!
//! Tests cover:
//! - Round-trip read/write operations
//! - Sync/async interoperability
//! - Concurrent operations
//! - Edge cases (empty files, large files, unicode filenames)

#![cfg(feature = "async")]

mod common;

use common::vault_builder::VaultBuilder;
use oxidized_cryptolib::vault::{DirId, VaultOperations, VaultOperationsAsync};
use oxidized_cryptolib::vault::config::extract_master_key;
use std::path::PathBuf;

fn test_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault")
}

fn get_test_master_key() -> oxidized_cryptolib::crypto::MasterKey {
    let vault_path = test_vault_path();
    extract_master_key(&vault_path, "123456789").expect("Failed to extract master key")
}

// ==================== Basic Operation Tests ====================

#[tokio::test]
async fn test_async_list_files_root() {
    let vault_path = test_vault_path();
    let master_key = get_test_master_key();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let files = ops.list_files(&DirId::root()).await
        .expect("Failed to list files");

    // The test vault should have some files in root
    assert!(!files.is_empty(), "Expected files in test vault root");
}

#[tokio::test]
async fn test_async_list_directories_root() {
    let vault_path = test_vault_path();
    let master_key = get_test_master_key();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let dirs = ops.list_directories(&DirId::root()).await
        .expect("Failed to list directories");

    // The test vault should have at least one directory
    assert!(!dirs.is_empty(), "Expected directories in test vault root");
}

#[tokio::test]
async fn test_async_from_sync() {
    let vault_path = test_vault_path();
    let master_key = get_test_master_key();

    // Create sync ops first
    let sync_ops = VaultOperations::new(&vault_path, master_key);

    // Create async ops from sync
    let async_ops = VaultOperationsAsync::from_sync(&sync_ops)
        .expect("Failed to create async ops from sync");

    // Should work the same
    let files = async_ops.list_files(&DirId::root()).await
        .expect("Failed to list files");

    assert!(!files.is_empty());
}

// ==================== Round-Trip Tests ====================

#[tokio::test]
async fn test_async_write_read_roundtrip_basic() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let content = b"Hello, async Cryptomator!";

    // Write file
    ops.write_file(&DirId::root(), "greeting.txt", content).await
        .expect("Failed to write file");

    // Read it back
    let decrypted = ops.read_file(&DirId::root(), "greeting.txt").await
        .expect("Failed to read file");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_read_empty_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write empty file
    ops.write_file(&DirId::root(), "empty.txt", b"").await
        .expect("Failed to write empty file");

    // Read it back
    let decrypted = ops.read_file(&DirId::root(), "empty.txt").await
        .expect("Failed to read empty file");

    assert!(decrypted.content.is_empty());
}

#[tokio::test]
async fn test_async_write_read_large_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create content larger than one chunk (32KB = 32768 bytes)
    let content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    ops.write_file(&DirId::root(), "large.bin", &content).await
        .expect("Failed to write large file");

    let decrypted = ops.read_file(&DirId::root(), "large.bin").await
        .expect("Failed to read large file");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_read_binary_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // All possible byte values
    let content: Vec<u8> = (0..=255).collect();

    ops.write_file(&DirId::root(), "binary.bin", &content).await
        .expect("Failed to write binary file");

    let decrypted = ops.read_file(&DirId::root(), "binary.bin").await
        .expect("Failed to read binary file");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_read_unicode_filename() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let content = b"Unicode content";
    let filename = "файл-测试-🔐.txt";

    ops.write_file(&DirId::root(), filename, content).await
        .expect("Failed to write Unicode-named file");

    let decrypted = ops.read_file(&DirId::root(), filename).await
        .expect("Failed to read Unicode-named file");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_read_long_filename() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create filename longer than shortening threshold (220 chars when encrypted)
    let filename = format!("{}.txt", "a".repeat(200));
    let content = b"Long filename content";

    ops.write_file(&DirId::root(), &filename, content).await
        .expect("Failed to write long-named file");

    let decrypted = ops.read_file(&DirId::root(), &filename).await
        .expect("Failed to read long-named file");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_overwrite_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write initial content
    ops.write_file(&DirId::root(), "overwrite.txt", b"Initial content").await
        .expect("Failed to write initial file");

    // Overwrite with new content
    let new_content = b"Updated content!";
    ops.write_file(&DirId::root(), "overwrite.txt", new_content).await
        .expect("Failed to overwrite file");

    // Read back - should be new content
    let decrypted = ops.read_file(&DirId::root(), "overwrite.txt").await
        .expect("Failed to read overwritten file");

    assert_eq!(decrypted.content, new_content);
}

// ==================== safe_write Behavior Tests ====================
// These tests verify the conditional atomic write behavior:
// - New files: direct write (no temp file overhead)
// - Existing files: temp + rename (protects existing data)

#[tokio::test]
async fn test_safe_write_new_file_no_temp_files_left() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write a new file
    ops.write_file(&DirId::root(), "newfile.txt", b"new content").await
        .expect("Failed to write new file");

    // Check that no .tmp files are left in the vault
    let d_dir = vault_path.join("d");
    let temp_files: Vec<_> = walkdir::WalkDir::new(&d_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
        .collect();

    assert!(temp_files.is_empty(), "Temp files should not exist after successful write: {:?}", temp_files);
}

#[tokio::test]
async fn test_safe_write_overwrite_no_temp_files_left() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"original content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Overwrite the existing file
    ops.write_file(&DirId::root(), "existing.txt", b"updated content").await
        .expect("Failed to overwrite file");

    // Check that no .tmp files are left in the vault
    let d_dir = vault_path.join("d");
    let temp_files: Vec<_> = walkdir::WalkDir::new(&d_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
        .collect();

    assert!(temp_files.is_empty(), "Temp files should be cleaned up after overwrite: {:?}", temp_files);

    // Verify content was updated
    let decrypted = ops.read_file(&DirId::root(), "existing.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, b"updated content");
}

#[tokio::test]
async fn test_safe_write_multiple_overwrites() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // First write (new file - direct write)
    ops.write_file(&DirId::root(), "multi.txt", b"version 1").await
        .expect("Failed to write v1");

    // Second write (overwrite - atomic)
    ops.write_file(&DirId::root(), "multi.txt", b"version 2").await
        .expect("Failed to write v2");

    // Third write (overwrite - atomic)
    ops.write_file(&DirId::root(), "multi.txt", b"version 3").await
        .expect("Failed to write v3");

    // Fourth write (overwrite - atomic)
    ops.write_file(&DirId::root(), "multi.txt", b"version 4 - final").await
        .expect("Failed to write v4");

    // Verify final content
    let decrypted = ops.read_file(&DirId::root(), "multi.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, b"version 4 - final");

    // No temp files left
    let d_dir = vault_path.join("d");
    let temp_files: Vec<_> = walkdir::WalkDir::new(&d_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
        .collect();
    assert!(temp_files.is_empty());
}

#[tokio::test]
async fn test_safe_write_overwrite_with_larger_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write small file
    ops.write_file(&DirId::root(), "grow.txt", b"small").await
        .expect("Failed to write small file");

    // Overwrite with much larger content (multi-chunk)
    let large_content: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    ops.write_file(&DirId::root(), "grow.txt", &large_content).await
        .expect("Failed to overwrite with large content");

    let decrypted = ops.read_file(&DirId::root(), "grow.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, large_content);
}

#[tokio::test]
async fn test_safe_write_overwrite_with_smaller_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write large file (multi-chunk)
    let large_content: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    ops.write_file(&DirId::root(), "shrink.txt", &large_content).await
        .expect("Failed to write large file");

    // Overwrite with tiny content
    ops.write_file(&DirId::root(), "shrink.txt", b"tiny").await
        .expect("Failed to overwrite with small content");

    let decrypted = ops.read_file(&DirId::root(), "shrink.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, b"tiny");
}

#[tokio::test]
async fn test_safe_write_overwrite_with_same_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let content = b"identical content";

    // Write file
    ops.write_file(&DirId::root(), "same.txt", content).await
        .expect("Failed to write file");

    // Overwrite with identical content (still uses atomic write path)
    ops.write_file(&DirId::root(), "same.txt", content).await
        .expect("Failed to overwrite with same content");

    let decrypted = ops.read_file(&DirId::root(), "same.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_safe_write_overwrite_empty_to_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write empty file
    ops.write_file(&DirId::root(), "empty_to_full.txt", b"").await
        .expect("Failed to write empty file");

    // Overwrite with actual content
    ops.write_file(&DirId::root(), "empty_to_full.txt", b"now has content").await
        .expect("Failed to overwrite");

    let decrypted = ops.read_file(&DirId::root(), "empty_to_full.txt").await
        .expect("Failed to read");
    assert_eq!(decrypted.content, b"now has content");
}

#[tokio::test]
async fn test_safe_write_overwrite_content_to_empty() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write file with content
    ops.write_file(&DirId::root(), "full_to_empty.txt", b"has content").await
        .expect("Failed to write file");

    // Overwrite with empty content
    ops.write_file(&DirId::root(), "full_to_empty.txt", b"").await
        .expect("Failed to overwrite with empty");

    let decrypted = ops.read_file(&DirId::root(), "full_to_empty.txt").await
        .expect("Failed to read");
    assert!(decrypted.content.is_empty());
}

#[tokio::test]
async fn test_safe_write_long_filename_overwrite() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Long filename that triggers .c9s shortening
    let long_name = format!("{}.txt", "a".repeat(200));

    // Write initial
    ops.write_file(&DirId::root(), &long_name, b"v1").await
        .expect("Failed to write long-named file");

    // Overwrite
    ops.write_file(&DirId::root(), &long_name, b"v2 - updated").await
        .expect("Failed to overwrite long-named file");

    let decrypted = ops.read_file(&DirId::root(), &long_name).await
        .expect("Failed to read");
    assert_eq!(decrypted.content, b"v2 - updated");

    // No temp files in the .c9s directory either
    let d_dir = vault_path.join("d");
    let temp_files: Vec<_> = walkdir::WalkDir::new(&d_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
        .collect();
    assert!(temp_files.is_empty());
}

// ==================== Sync/Async Interop Tests ====================

#[tokio::test]
async fn test_sync_write_async_read() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Write with sync API
    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let content = b"Written by sync, read by async";
    sync_ops.write_file(&DirId::root(), "sync_written.txt", content)
        .expect("Failed to sync write");

    // Read with async API
    let async_ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");
    let decrypted = async_ops.read_file(&DirId::root(), "sync_written.txt").await
        .expect("Failed to async read");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_sync_read() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Write with async API
    let async_ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");
    let content = b"Written by async, read by sync";
    async_ops.write_file(&DirId::root(), "async_written.txt", content).await
        .expect("Failed to async write");

    // Read with sync API
    let sync_ops = VaultOperations::new(&vault_path, master_key);
    let decrypted = sync_ops.read_file(&DirId::root(), "async_written.txt")
        .expect("Failed to sync read");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_sync_async_list_files_consistency() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file1.txt", b"content1")
        .add_file("file2.txt", b"content2")
        .add_file("file3.txt", b"content3")
        .build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let async_ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let sync_files = sync_ops.list_files(&DirId::root())
        .expect("Failed to sync list files");
    let async_files = async_ops.list_files(&DirId::root()).await
        .expect("Failed to async list files");

    // Same number of files
    assert_eq!(sync_files.len(), async_files.len());

    // Same file names (order may differ)
    let mut sync_names: Vec<_> = sync_files.iter().map(|f| &f.name).collect();
    let mut async_names: Vec<_> = async_files.iter().map(|f| &f.name).collect();
    sync_names.sort();
    async_names.sort();
    assert_eq!(sync_names, async_names);
}

// ==================== Concurrent Operation Tests ====================

#[tokio::test]
async fn test_concurrent_reads() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file1.txt", b"content one")
        .add_file("file2.txt", b"content two")
        .add_file("file3.txt", b"content three")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Store DirId to avoid temporary value issues
    let root = DirId::root();

    // Read all files concurrently
    let (r1, r2, r3) = tokio::join!(
        ops.read_file(&root, "file1.txt"),
        ops.read_file(&root, "file2.txt"),
        ops.read_file(&root, "file3.txt")
    );

    assert_eq!(r1.unwrap().content, b"content one");
    assert_eq!(r2.unwrap().content, b"content two");
    assert_eq!(r3.unwrap().content, b"content three");
}

#[tokio::test]
async fn test_concurrent_writes_different_files() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Write different files concurrently
    let (w1, w2, w3) = tokio::join!(
        ops.write_file(&root, "concurrent1.txt", b"data one"),
        ops.write_file(&root, "concurrent2.txt", b"data two"),
        ops.write_file(&root, "concurrent3.txt", b"data three")
    );

    w1.expect("Failed to write file 1");
    w2.expect("Failed to write file 2");
    w3.expect("Failed to write file 3");

    // Verify all files were written correctly
    let files = ops.list_files(&root).await
        .expect("Failed to list files");
    assert_eq!(files.len(), 3);

    // Read back and verify
    let r1 = ops.read_file(&root, "concurrent1.txt").await.unwrap();
    let r2 = ops.read_file(&root, "concurrent2.txt").await.unwrap();
    let r3 = ops.read_file(&root, "concurrent3.txt").await.unwrap();

    assert_eq!(r1.content, b"data one");
    assert_eq!(r2.content, b"data two");
    assert_eq!(r3.content, b"data three");
}

#[tokio::test]
async fn test_concurrent_list_operations() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .add_directory("subdir")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Run list operations concurrently
    let (files, dirs) = tokio::join!(
        ops.list_files(&root),
        ops.list_directories(&root)
    );

    let files = files.expect("Failed to list files");
    let dirs = dirs.expect("Failed to list directories");

    assert!(!files.is_empty());
    assert!(!dirs.is_empty());
}

#[tokio::test]
async fn test_concurrent_read_write_different_files() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"existing content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Concurrently read existing file and write new file
    let (read_result, write_result) = tokio::join!(
        ops.read_file(&root, "existing.txt"),
        ops.write_file(&root, "new.txt", b"new content")
    );

    let read_content = read_result.expect("Failed to read");
    write_result.expect("Failed to write");

    assert_eq!(read_content.content, b"existing content");

    // Verify new file was written
    let new_content = ops.read_file(&root, "new.txt").await.unwrap();
    assert_eq!(new_content.content, b"new content");
}

#[tokio::test]
async fn test_many_sequential_reads() {
    // Note: VaultOperationsAsync is not Send due to MasterKey containing RefCell,
    // so we can't use tokio::spawn. Instead, test many sequential reads which
    // still exercises the async machinery.
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("shared.txt", b"shared content for many readers")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Perform many sequential reads
    for i in 0..20 {
        let content = ops.read_file(&root, "shared.txt").await
            .expect(&format!("Read {} failed", i));
        assert_eq!(content.content, b"shared content for many readers");
    }
}

// ==================== Error Cases ====================

#[tokio::test]
async fn test_async_read_nonexistent_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.read_file(&DirId::root(), "does_not_exist.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_read_from_nonexistent_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let fake_dir = DirId::from_raw("nonexistent-directory-id");
    let result = ops.read_file(&fake_dir, "file.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_list_files_nonexistent_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Note: list_files for a nonexistent directory returns empty list
    // (directory storage path doesn't exist, so no entries are found)
    let fake_dir = DirId::from_raw("nonexistent-directory-id");
    let result = ops.list_files(&fake_dir).await;
    // Either returns an error or an empty list, both are acceptable
    match result {
        Ok(files) => assert!(files.is_empty(), "Expected empty list for nonexistent directory"),
        Err(_) => {} // Error is also acceptable
    }
}

// ==================== Edge Cases ====================

#[tokio::test]
async fn test_async_write_read_exactly_one_chunk() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Exactly 32KB (one chunk boundary)
    let content: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();

    ops.write_file(&DirId::root(), "one_chunk.bin", &content).await
        .expect("Failed to write");

    let decrypted = ops.read_file(&DirId::root(), "one_chunk.bin").await
        .expect("Failed to read");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_write_read_chunk_boundary_plus_one() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // 32KB + 1 byte (crosses chunk boundary)
    let content: Vec<u8> = (0..32769).map(|i| (i % 256) as u8).collect();

    ops.write_file(&DirId::root(), "chunk_plus_one.bin", &content).await
        .expect("Failed to write");

    let decrypted = ops.read_file(&DirId::root(), "chunk_plus_one.bin").await
        .expect("Failed to read");

    assert_eq!(decrypted.content, content);
}

#[tokio::test]
async fn test_async_multiple_files_same_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write multiple files
    for i in 0..10 {
        let filename = format!("file_{}.txt", i);
        let content = format!("Content of file {}", i);
        ops.write_file(&DirId::root(), &filename, content.as_bytes()).await
            .expect(&format!("Failed to write {}", filename));
    }

    // List and verify
    let files = ops.list_files(&DirId::root()).await
        .expect("Failed to list files");
    assert_eq!(files.len(), 10);

    // Read back and verify each
    for i in 0..10 {
        let filename = format!("file_{}.txt", i);
        let expected = format!("Content of file {}", i);
        let decrypted = ops.read_file(&DirId::root(), &filename).await
            .expect(&format!("Failed to read {}", filename));
        assert_eq!(decrypted.content, expected.as_bytes());
    }
}

#[tokio::test]
async fn test_async_special_characters_in_filename() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let special_names = [
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "file.multiple.dots.txt",
        "UPPERCASE.TXT",
        "MixedCase.Txt",
    ];

    for name in special_names {
        let content = format!("Content for {}", name);
        ops.write_file(&DirId::root(), name, content.as_bytes()).await
            .expect(&format!("Failed to write {}", name));

        let decrypted = ops.read_file(&DirId::root(), name).await
            .expect(&format!("Failed to read {}", name));
        assert_eq!(decrypted.content, content.as_bytes());
    }
}

// ==================== Phase 2b: Path-Based API Tests ====================

#[tokio::test]
async fn test_async_resolve_path_root_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("readme.txt", b"Hello from root")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // resolve_path returns (DirId, is_directory)
    let (dir_id, is_directory) = ops.resolve_path("readme.txt").await
        .expect("Failed to resolve path");

    assert_eq!(dir_id.as_str(), "");  // Root dir ID
    assert!(!is_directory);  // It's a file, not a directory
}

#[tokio::test]
async fn test_async_resolve_path_nested_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("docs")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get the docs directory ID
    let dirs = ops.list_directories(&DirId::root()).await
        .expect("Failed to list directories");
    let docs_dir = dirs.iter().find(|d| d.name == "docs").expect("docs dir not found");

    // Write a file in docs
    ops.write_file(&docs_dir.directory_id, "notes.txt", b"nested content").await
        .expect("Failed to write nested file");

    // Resolve the path - returns (DirId, is_directory)
    let (dir_id, is_directory) = ops.resolve_path("docs/notes.txt").await
        .expect("Failed to resolve nested path");

    assert_eq!(dir_id.as_str(), docs_dir.directory_id.as_str());
    assert!(!is_directory);  // It's a file
}

#[tokio::test]
async fn test_async_resolve_path_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("docs")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let docs_dir = dirs.iter().find(|d| d.name == "docs").unwrap();

    // Resolve directory path
    let (dir_id, is_directory) = ops.resolve_path("docs").await
        .expect("Failed to resolve directory path");

    assert_eq!(dir_id.as_str(), docs_dir.directory_id.as_str());
    assert!(is_directory);  // It's a directory
}

#[tokio::test]
async fn test_async_resolve_path_deeply_nested() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("level1")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get level1 dir
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let level1 = dirs.iter().find(|d| d.name == "level1").unwrap();

    // Create level2 inside level1
    let level2_id = ops.create_directory(&level1.directory_id, "level2").await
        .expect("Failed to create level2");

    // Create level3 inside level2
    let level3_id = ops.create_directory(&level2_id, "level3").await
        .expect("Failed to create level3");

    // Write a file in level3
    ops.write_file(&level3_id, "deep.txt", b"deep content").await
        .expect("Failed to write deep file");

    // Resolve the deep path - returns (DirId, is_directory)
    let (dir_id, is_directory) = ops.resolve_path("level1/level2/level3/deep.txt").await
        .expect("Failed to resolve deep path");

    assert_eq!(dir_id.as_str(), level3_id.as_str());
    assert!(!is_directory);  // It's a file
}

#[tokio::test]
async fn test_async_resolve_path_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.resolve_path("nonexistent/path/file.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_read_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("docs")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get docs directory and write a file
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let docs = dirs.iter().find(|d| d.name == "docs").unwrap();
    ops.write_file(&docs.directory_id, "readme.md", b"# Documentation").await.unwrap();

    // Read by path
    let content = ops.read_by_path("docs/readme.md").await
        .expect("Failed to read by path");

    assert_eq!(content.content, b"# Documentation");
}

#[tokio::test]
async fn test_async_read_by_path_root_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("root_file.txt", b"root content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let content = ops.read_by_path("root_file.txt").await
        .expect("Failed to read root file by path");

    assert_eq!(content.content, b"root content");
}

#[tokio::test]
async fn test_async_write_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("output")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write by path
    ops.write_by_path("output/result.txt", b"computed result").await
        .expect("Failed to write by path");

    // Read back to verify
    let content = ops.read_by_path("output/result.txt").await
        .expect("Failed to read back");

    assert_eq!(content.content, b"computed result");
}

#[tokio::test]
async fn test_async_write_by_path_root() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    ops.write_by_path("new_root_file.txt", b"new content").await
        .expect("Failed to write to root by path");

    let content = ops.read_by_path("new_root_file.txt").await
        .expect("Failed to read back");

    assert_eq!(content.content, b"new content");
}

#[tokio::test]
async fn test_async_write_by_path_overwrite() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"original")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    ops.write_by_path("existing.txt", b"updated").await
        .expect("Failed to overwrite by path");

    let content = ops.read_by_path("existing.txt").await
        .expect("Failed to read back");

    assert_eq!(content.content, b"updated");
}

// ==================== Phase 2b: Directory Operation Tests ====================

#[tokio::test]
async fn test_async_create_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create a new directory
    let new_dir_id = ops.create_directory(&DirId::root(), "new_folder").await
        .expect("Failed to create directory");

    // Verify it appears in listing
    let dirs = ops.list_directories(&DirId::root()).await
        .expect("Failed to list directories");

    let found = dirs.iter().find(|d| d.name == "new_folder");
    assert!(found.is_some(), "Created directory should appear in listing");
    assert_eq!(found.unwrap().directory_id.as_str(), new_dir_id.as_str());
}

#[tokio::test]
async fn test_async_create_nested_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("parent")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get parent directory
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let parent = dirs.iter().find(|d| d.name == "parent").unwrap();

    // Create child inside parent
    let child_id = ops.create_directory(&parent.directory_id, "child").await
        .expect("Failed to create child directory");

    // Verify it appears in parent's listing
    let children = ops.list_directories(&parent.directory_id).await
        .expect("Failed to list parent's directories");

    let found = children.iter().find(|d| d.name == "child");
    assert!(found.is_some());
    assert_eq!(found.unwrap().directory_id.as_str(), child_id.as_str());
}

#[tokio::test]
async fn test_async_create_directory_with_unicode_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let unicode_name = "文件夹-📁-папка";
    let dir_id = ops.create_directory(&DirId::root(), unicode_name).await
        .expect("Failed to create unicode directory");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let found = dirs.iter().find(|d| d.name == unicode_name);
    assert!(found.is_some());
    assert_eq!(found.unwrap().directory_id.as_str(), dir_id.as_str());
}

#[tokio::test]
async fn test_async_create_directory_long_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Long name that triggers .c9s shortening
    let long_name = "a".repeat(200);
    let dir_id = ops.create_directory(&DirId::root(), &long_name).await
        .expect("Failed to create long-named directory");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let found = dirs.iter().find(|d| d.name == long_name);
    assert!(found.is_some());
    assert_eq!(found.unwrap().directory_id.as_str(), dir_id.as_str());
}

#[tokio::test]
async fn test_async_delete_directory_empty() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create directory
    ops.create_directory(&DirId::root(), "to_delete").await
        .expect("Failed to create directory");

    // Verify it exists
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    assert!(dirs.iter().any(|d| d.name == "to_delete"));

    // Delete it
    ops.delete_directory(&DirId::root(), "to_delete").await
        .expect("Failed to delete directory");

    // Verify it's gone
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    assert!(!dirs.iter().any(|d| d.name == "to_delete"));
}

#[tokio::test]
async fn test_async_delete_directory_long_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let long_name = "b".repeat(200);

    ops.create_directory(&DirId::root(), &long_name).await
        .expect("Failed to create long-named directory");

    ops.delete_directory(&DirId::root(), &long_name).await
        .expect("Failed to delete long-named directory");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    assert!(!dirs.iter().any(|d| d.name == long_name));
}

// ==================== Phase 2b: File Deletion Tests ====================

#[tokio::test]
async fn test_async_delete_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("to_delete.txt", b"delete me")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Verify file exists
    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(files.iter().any(|f| f.name == "to_delete.txt"));

    // Delete it
    ops.delete_file(&DirId::root(), "to_delete.txt").await
        .expect("Failed to delete file");

    // Verify it's gone
    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!files.iter().any(|f| f.name == "to_delete.txt"));
}

#[tokio::test]
async fn test_async_delete_file_long_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let long_name = format!("{}.txt", "c".repeat(200));

    ops.write_file(&DirId::root(), &long_name, b"content").await
        .expect("Failed to write long-named file");

    ops.delete_file(&DirId::root(), &long_name).await
        .expect("Failed to delete long-named file");

    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!files.iter().any(|f| f.name == long_name));
}

#[tokio::test]
async fn test_async_delete_file_in_subdirectory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("subdir")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get subdir
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let subdir = dirs.iter().find(|d| d.name == "subdir").unwrap();

    // Write and then delete a file
    ops.write_file(&subdir.directory_id, "nested.txt", b"nested content").await.unwrap();
    ops.delete_file(&subdir.directory_id, "nested.txt").await
        .expect("Failed to delete nested file");

    let files = ops.list_files(&subdir.directory_id).await.unwrap();
    assert!(!files.iter().any(|f| f.name == "nested.txt"));
}

#[tokio::test]
async fn test_async_delete_nonexistent_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.delete_file(&DirId::root(), "nonexistent.txt").await;
    assert!(result.is_err());
}

// ==================== Phase 2b: Rename Tests ====================

#[tokio::test]
async fn test_async_rename_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("original.txt", b"content to rename")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    ops.rename_file(&DirId::root(), "original.txt", "renamed.txt").await
        .expect("Failed to rename file");

    // Old name should not exist
    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!files.iter().any(|f| f.name == "original.txt"));
    assert!(files.iter().any(|f| f.name == "renamed.txt"));

    // Content should be preserved
    let content = ops.read_file(&DirId::root(), "renamed.txt").await.unwrap();
    assert_eq!(content.content, b"content to rename");
}

#[tokio::test]
async fn test_async_rename_file_unicode() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"unicode rename test")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let unicode_name = "файл-测试-🔐.txt";
    ops.rename_file(&DirId::root(), "file.txt", unicode_name).await
        .expect("Failed to rename to unicode");

    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(files.iter().any(|f| f.name == unicode_name));

    let content = ops.read_file(&DirId::root(), unicode_name).await.unwrap();
    assert_eq!(content.content, b"unicode rename test");
}

#[tokio::test]
async fn test_async_rename_file_to_long_name() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("short.txt", b"will have long name")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let long_name = format!("{}.txt", "d".repeat(200));
    ops.rename_file(&DirId::root(), "short.txt", &long_name).await
        .expect("Failed to rename to long name");

    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(files.iter().any(|f| f.name == long_name));

    let content = ops.read_file(&DirId::root(), &long_name).await.unwrap();
    assert_eq!(content.content, b"will have long name");
}

#[tokio::test]
async fn test_async_rename_file_from_long_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let long_name = format!("{}.txt", "e".repeat(200));
    ops.write_file(&DirId::root(), &long_name, b"from long name").await.unwrap();

    ops.rename_file(&DirId::root(), &long_name, "short.txt").await
        .expect("Failed to rename from long name");

    let files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!files.iter().any(|f| f.name == long_name));
    assert!(files.iter().any(|f| f.name == "short.txt"));

    let content = ops.read_file(&DirId::root(), "short.txt").await.unwrap();
    assert_eq!(content.content, b"from long name");
}

// ==================== Phase 2b: Move Tests ====================
// Note: move_file keeps the same filename - it only changes the directory

#[tokio::test]
async fn test_async_move_file_to_subdirectory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("moveme.txt", b"content to move")
        .add_directory("destination")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get destination dir
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let dest = dirs.iter().find(|d| d.name == "destination").unwrap();

    // move_file keeps the same filename
    ops.move_file(&DirId::root(), "moveme.txt", &dest.directory_id).await
        .expect("Failed to move file");

    // Should not exist in root
    let root_files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!root_files.iter().any(|f| f.name == "moveme.txt"));

    // Should exist in destination with same name
    let dest_files = ops.list_files(&dest.directory_id).await.unwrap();
    assert!(dest_files.iter().any(|f| f.name == "moveme.txt"));

    // Content preserved
    let content = ops.read_file(&dest.directory_id, "moveme.txt").await.unwrap();
    assert_eq!(content.content, b"content to move");
}

#[tokio::test]
async fn test_async_move_file_to_root() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("source")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get source dir
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let source = dirs.iter().find(|d| d.name == "source").unwrap();

    // Write file in source
    ops.write_file(&source.directory_id, "nested.txt", b"nested content").await.unwrap();

    // Move to root (keeps same filename)
    ops.move_file(&source.directory_id, "nested.txt", &DirId::root()).await
        .expect("Failed to move to root");

    // Should not exist in source
    let source_files = ops.list_files(&source.directory_id).await.unwrap();
    assert!(!source_files.iter().any(|f| f.name == "nested.txt"));

    // Should exist in root with same name
    let root_files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(root_files.iter().any(|f| f.name == "nested.txt"));
}

#[tokio::test]
async fn test_async_move_file_preserves_name() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"same name move")
        .add_directory("target")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let target = dirs.iter().find(|d| d.name == "target").unwrap();

    // Move preserves filename
    ops.move_file(&DirId::root(), "file.txt", &target.directory_id).await
        .expect("Failed to move");

    let root_files = ops.list_files(&DirId::root()).await.unwrap();
    assert!(!root_files.iter().any(|f| f.name == "file.txt"));

    let target_files = ops.list_files(&target.directory_id).await.unwrap();
    assert!(target_files.iter().any(|f| f.name == "file.txt"));

    // Content is still correct
    let content = ops.read_file(&target.directory_id, "file.txt").await.unwrap();
    assert_eq!(content.content, b"same name move");
}

#[tokio::test]
async fn test_async_move_file_with_long_name() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("dest")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Long filename that triggers .c9s shortening
    let long_name = format!("{}.txt", "f".repeat(200));

    ops.write_file(&DirId::root(), &long_name, b"long names").await.unwrap();

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    // Move preserves the long filename
    ops.move_file(&DirId::root(), &long_name, &dest.directory_id).await
        .expect("Failed to move long-named file");

    let dest_files = ops.list_files(&dest.directory_id).await.unwrap();
    assert!(dest_files.iter().any(|f| f.name == long_name));

    let content = ops.read_file(&dest.directory_id, &long_name).await.unwrap();
    assert_eq!(content.content, b"long names");
}

#[tokio::test]
async fn test_async_move_large_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("archive")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create large file (multi-chunk)
    let large_content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    ops.write_file(&DirId::root(), "large.bin", &large_content).await.unwrap();

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let archive = dirs.iter().find(|d| d.name == "archive").unwrap();

    // Move preserves filename
    ops.move_file(&DirId::root(), "large.bin", &archive.directory_id).await
        .expect("Failed to move large file");

    let content = ops.read_file(&archive.directory_id, "large.bin").await.unwrap();
    assert_eq!(content.content, large_content);
}

// ==================== Phase 2b: Combined Operation Tests ====================

#[tokio::test]
async fn test_async_create_write_read_delete_flow() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create directory
    let project_id = ops.create_directory(&DirId::root(), "project").await
        .expect("Failed to create project dir");

    // Write file
    ops.write_file(&project_id, "data.json", b"{\"key\": \"value\"}").await
        .expect("Failed to write data");

    // Read file
    let content = ops.read_file(&project_id, "data.json").await.unwrap();
    assert_eq!(content.content, b"{\"key\": \"value\"}");

    // Delete file
    ops.delete_file(&project_id, "data.json").await
        .expect("Failed to delete file");

    // Delete directory
    ops.delete_directory(&DirId::root(), "project").await
        .expect("Failed to delete directory");

    // Verify both are gone
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    assert!(!dirs.iter().any(|d| d.name == "project"));
}

#[tokio::test]
async fn test_async_path_api_full_workflow() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("workspace")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get workspace dir
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let workspace = dirs.iter().find(|d| d.name == "workspace").unwrap();

    // Create nested structure
    let src_id = ops.create_directory(&workspace.directory_id, "src").await.unwrap();
    ops.write_file(&src_id, "main.rs", b"fn main() {}").await.unwrap();

    // Use path API to read
    let content = ops.read_by_path("workspace/src/main.rs").await
        .expect("Failed to read by path");
    assert_eq!(content.content, b"fn main() {}");

    // Use path API to write
    ops.write_by_path("workspace/src/lib.rs", b"pub mod utils;").await
        .expect("Failed to write by path");

    // Verify both files exist
    let files = ops.list_files(&src_id).await.unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|f| f.name == "main.rs"));
    assert!(files.iter().any(|f| f.name == "lib.rs"));
}

#[tokio::test]
async fn test_async_concurrent_directory_operations() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Create multiple directories concurrently
    let (r1, r2, r3) = tokio::join!(
        ops.create_directory(&root, "dir1"),
        ops.create_directory(&root, "dir2"),
        ops.create_directory(&root, "dir3")
    );

    r1.expect("Failed to create dir1");
    r2.expect("Failed to create dir2");
    r3.expect("Failed to create dir3");

    let dirs = ops.list_directories(&root).await.unwrap();
    assert_eq!(dirs.len(), 3);
}

// ==================== Additional Error Path Tests ====================

#[tokio::test]
async fn test_async_rename_file_same_name() {
    // Test SameSourceAndDestination error for rename_file
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("test.txt", b"content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to rename file to itself - should fail
    let result = ops.rename_file(&DirId::root(), "test.txt", "test.txt").await;
    assert!(result.is_err(), "Renaming file to same name should fail");

    // Check error message contains relevant info
    let err = result.unwrap_err();
    assert!(err.to_string().contains("same") || err.to_string().contains("Same"),
        "Error should mention same source and destination: {}", err);
}

#[tokio::test]
async fn test_async_move_file_same_directory() {
    // Test SameSourceAndDestination error for move_file
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("test.txt", b"content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to move file to same directory - should fail
    let result = ops.move_file(&DirId::root(), "test.txt", &DirId::root()).await;
    assert!(result.is_err(), "Moving file to same directory should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("same") || err.to_string().contains("Same"),
        "Error should mention same source and destination: {}", err);
}

#[tokio::test]
async fn test_async_rename_file_target_exists() {
    // Test FileAlreadyExists error for rename_file
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source.txt", b"source content")
        .add_file("target.txt", b"target content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to rename source.txt to target.txt which already exists
    let result = ops.rename_file(&DirId::root(), "source.txt", "target.txt").await;
    assert!(result.is_err(), "Renaming to existing file should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("exists") || err.to_string().contains("already"),
        "Error should mention file already exists: {}", err);

    // Verify both files still exist with original content
    let source = ops.read_file(&DirId::root(), "source.txt").await.unwrap();
    let target = ops.read_file(&DirId::root(), "target.txt").await.unwrap();
    assert_eq!(source.content, b"source content");
    assert_eq!(target.content, b"target content");
}

#[tokio::test]
async fn test_async_move_file_target_exists() {
    // Test FileAlreadyExists error for move_file
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"source content")
        .add_directory("dest")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get dest dir and write a file with same name there
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    ops.write_file(&dest.directory_id, "file.txt", b"dest content").await.unwrap();

    // Try to move file.txt to dest directory where file.txt already exists
    let result = ops.move_file(&DirId::root(), "file.txt", &dest.directory_id).await;
    assert!(result.is_err(), "Moving to directory with existing file of same name should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("exists") || err.to_string().contains("already"),
        "Error should mention file already exists: {}", err);
}

#[tokio::test]
async fn test_async_delete_directory_not_empty_files() {
    // Test DirectoryNotEmpty error when directory contains files
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("nonempty")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get the nonempty dir and add a file
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let nonempty = dirs.iter().find(|d| d.name == "nonempty").unwrap();

    ops.write_file(&nonempty.directory_id, "file.txt", b"content").await.unwrap();

    // Try to delete the non-empty directory
    let result = ops.delete_directory(&DirId::root(), "nonempty").await;
    assert!(result.is_err(), "Deleting non-empty directory should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("empty") || err.to_string().contains("Empty"),
        "Error should mention directory not empty: {}", err);
}

#[tokio::test]
async fn test_async_delete_directory_not_empty_subdirs() {
    // Test DirectoryNotEmpty error when directory contains subdirectories
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("parent")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Get parent dir and create subdirectory
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let parent = dirs.iter().find(|d| d.name == "parent").unwrap();

    ops.create_directory(&parent.directory_id, "child").await.unwrap();

    // Try to delete the non-empty directory
    let result = ops.delete_directory(&DirId::root(), "parent").await;
    assert!(result.is_err(), "Deleting directory with subdirectories should fail");
}

#[tokio::test]
async fn test_async_delete_nonexistent_directory() {
    // Test DirectoryNotFound error for delete_directory
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.delete_directory(&DirId::root(), "nonexistent").await;
    assert!(result.is_err(), "Deleting nonexistent directory should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found") || err.to_string().contains("NotFound"),
        "Error should mention directory not found: {}", err);
}

#[tokio::test]
async fn test_async_rename_nonexistent_file() {
    // Test FileNotFound error for rename_file
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.rename_file(&DirId::root(), "nonexistent.txt", "newname.txt").await;
    assert!(result.is_err(), "Renaming nonexistent file should fail");

    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found") || err.to_string().contains("NotFound"),
        "Error should mention file not found: {}", err);
}

#[tokio::test]
async fn test_async_move_nonexistent_file() {
    // Test FileNotFound error for move_file
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("dest")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    let result = ops.move_file(&DirId::root(), "nonexistent.txt", &dest.directory_id).await;
    assert!(result.is_err(), "Moving nonexistent file should fail");
}

// ==================== Clone Shared Tests ====================

#[tokio::test]
async fn test_async_clone_shared() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("test.txt", b"shared content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Clone the ops instance
    let ops_clone = ops.clone_shared().expect("Failed to clone shared");

    // Both instances should be able to read the same file
    let content1 = ops.read_file(&DirId::root(), "test.txt").await.unwrap();
    let content2 = ops_clone.read_file(&DirId::root(), "test.txt").await.unwrap();

    assert_eq!(content1.content, content2.content);
    assert_eq!(content1.content, b"shared content");
}

#[tokio::test]
async fn test_async_clone_shared_concurrent_reads() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file1.txt", b"content1")
        .add_file("file2.txt", b"content2")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");
    let ops_clone = ops.clone_shared().expect("Failed to clone shared");

    let root = DirId::root();

    // Read different files concurrently from both instances
    let (r1, r2) = tokio::join!(
        ops.read_file(&root, "file1.txt"),
        ops_clone.read_file(&root, "file2.txt")
    );

    assert_eq!(r1.unwrap().content, b"content1");
    assert_eq!(r2.unwrap().content, b"content2");
}

#[tokio::test]
async fn test_async_clone_shared_write_visibility() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");
    let ops_clone = ops.clone_shared().expect("Failed to clone shared");

    // Write with original
    ops.write_file(&DirId::root(), "new.txt", b"new content").await.unwrap();

    // Read with clone - should see the new file
    let content = ops_clone.read_file(&DirId::root(), "new.txt").await.unwrap();
    assert_eq!(content.content, b"new content");
}

// ==================== Constructor Options Tests ====================

#[tokio::test]
async fn test_async_with_shortening_threshold() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Create with custom shortening threshold
    let ops = VaultOperationsAsync::with_shortening_threshold(&vault_path, &master_key, 100)
        .expect("Failed to create async ops with custom threshold");

    assert_eq!(ops.shortening_threshold(), 100);

    // Write a file with moderately long name (would be shortened at 100 threshold)
    let medium_name = format!("{}.txt", "x".repeat(80));
    ops.write_file(&DirId::root(), &medium_name, b"content").await.unwrap();

    // Should be able to read it back
    let content = ops.read_file(&DirId::root(), &medium_name).await.unwrap();
    assert_eq!(content.content, b"content");
}

#[tokio::test]
async fn test_async_with_options_siv_gcm() {
    use oxidized_cryptolib::vault::config::CipherCombo;

    let (vault_path, master_key) = VaultBuilder::new().build();

    let ops = VaultOperationsAsync::with_options(
        &vault_path,
        &master_key,
        220,
        CipherCombo::SivGcm,
    ).expect("Failed to create async ops with options");

    assert_eq!(ops.cipher_combo(), CipherCombo::SivGcm);
    assert_eq!(ops.shortening_threshold(), 220);

    // Basic operation should work
    ops.write_file(&DirId::root(), "test.txt", b"test").await.unwrap();
    let content = ops.read_file(&DirId::root(), "test.txt").await.unwrap();
    assert_eq!(content.content, b"test");
}

#[tokio::test]
async fn test_async_accessor_methods() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Test accessor methods
    assert_eq!(ops.vault_path(), vault_path);
    assert_eq!(ops.shortening_threshold(), 220); // Default

    // lock_manager and handle_table should return valid references
    let _lock_manager = ops.lock_manager();
    let _handle_table = ops.handle_table();
}

// ==================== Path Resolution Edge Cases ====================

#[tokio::test]
async fn test_async_resolve_empty_path() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Empty path should resolve to root directory
    let (dir_id, is_dir) = ops.resolve_path("").await.expect("Failed to resolve empty path");
    assert_eq!(dir_id.as_str(), "");
    assert!(is_dir);
}

#[tokio::test]
async fn test_async_resolve_path_slash_only() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Single slash should resolve to root
    let (dir_id, is_dir) = ops.resolve_path("/").await.expect("Failed to resolve /");
    assert_eq!(dir_id.as_str(), "");
    assert!(is_dir);
}

#[tokio::test]
async fn test_async_resolve_path_multiple_slashes() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("dir")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Multiple slashes should be handled (empty components filtered)
    let result = ops.resolve_path("//dir//").await;
    assert!(result.is_ok());
    let (_, is_dir) = result.unwrap();
    assert!(is_dir);
}

#[tokio::test]
async fn test_async_resolve_parent_path_empty() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Empty path should return error
    let result = ops.resolve_parent_path("").await;
    assert!(result.is_err(), "Empty path should return error");
}

#[tokio::test]
async fn test_async_resolve_parent_path_not_a_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to resolve path where parent is a file (not a directory)
    let result = ops.resolve_parent_path("file.txt/child.txt").await;
    assert!(result.is_err(), "Should fail when parent is a file");
}

#[tokio::test]
async fn test_async_read_by_path_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.read_by_path("nonexistent/path/file.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_write_by_path_nonexistent_parent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write to path where parent directory doesn't exist
    let result = ops.write_by_path("nonexistent/file.txt", b"content").await;
    assert!(result.is_err(), "Writing to nonexistent parent should fail");
}

// ==================== Streaming Operations Tests ====================

#[tokio::test]
async fn test_async_open_file_streaming() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("stream.txt", b"streaming content here")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let reader = ops.open_file(&DirId::root(), "stream.txt").await
        .expect("Failed to open file for streaming");

    assert_eq!(reader.plaintext_size(), 22); // "streaming content here".len()
}

#[tokio::test]
async fn test_async_open_file_streaming_read_all() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("stream.txt", b"streaming content here")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut reader = ops.open_file(&DirId::root(), "stream.txt").await
        .expect("Failed to open file for streaming");

    // Read entire content
    let content = reader.read_range(0, reader.plaintext_size() as usize).await
        .expect("Failed to read range");

    assert_eq!(content, b"streaming content here");
}

#[tokio::test]
async fn test_async_open_file_streaming_partial_read() {
    let content = b"0123456789ABCDEF";
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("partial.txt", content)
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut reader = ops.open_file(&DirId::root(), "partial.txt").await
        .expect("Failed to open file for streaming");

    // Read partial range
    let partial = reader.read_range(5, 5).await
        .expect("Failed to read partial range");

    assert_eq!(partial, b"56789");
}

#[tokio::test]
async fn test_async_open_file_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.open_file(&DirId::root(), "nonexistent.txt").await;
    assert!(result.is_err(), "Opening nonexistent file should fail");
}

#[tokio::test]
async fn test_async_open_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("docs")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write a file first
    let dirs = ops.list_directories(&DirId::root()).await.unwrap();
    let docs = dirs.iter().find(|d| d.name == "docs").unwrap();
    ops.write_file(&docs.directory_id, "readme.md", b"# Hello").await.unwrap();

    // Open by path
    let reader = ops.open_by_path("docs/readme.md").await
        .expect("Failed to open by path");

    assert_eq!(reader.plaintext_size(), 7); // "# Hello".len()
}

#[tokio::test]
async fn test_async_open_by_path_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.open_by_path("nonexistent/file.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_create_file_streaming() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut writer = ops.create_file(&DirId::root(), "streamed.txt").await
        .expect("Failed to create file for streaming");

    writer.write(b"Hello, ").await.expect("Failed to write chunk 1");
    writer.write(b"World!").await.expect("Failed to write chunk 2");

    writer.finish().await.expect("Failed to finish write");

    // Verify content
    let content = ops.read_file(&DirId::root(), "streamed.txt").await.unwrap();
    assert_eq!(content.content, b"Hello, World!");
}

#[tokio::test]
async fn test_async_create_file_streaming_large() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut writer = ops.create_file(&DirId::root(), "large_stream.bin").await
        .expect("Failed to create file for streaming");

    // Write multiple chunks that span more than one 32KB block
    let chunk: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    for _ in 0..5 {
        writer.write(&chunk).await.expect("Failed to write chunk");
    }

    writer.finish().await.expect("Failed to finish write");

    // Verify content
    let content = ops.read_file(&DirId::root(), "large_stream.bin").await.unwrap();
    assert_eq!(content.content.len(), 50_000);
}

#[tokio::test]
async fn test_async_create_file_streaming_abort() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut writer = ops.create_file(&DirId::root(), "aborted.txt").await
        .expect("Failed to create file for streaming");

    writer.write(b"This will be aborted").await.expect("Failed to write");

    writer.abort().await.expect("Failed to abort write");

    // File should not exist
    let result = ops.read_file(&DirId::root(), "aborted.txt").await;
    assert!(result.is_err(), "Aborted file should not exist");
}

#[tokio::test]
async fn test_async_create_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("output")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let mut writer = ops.create_by_path("output/result.txt").await
        .expect("Failed to create by path");

    writer.write(b"Created by path").await.expect("Failed to write");
    writer.finish().await.expect("Failed to finish");

    // Verify
    let content = ops.read_by_path("output/result.txt").await.unwrap();
    assert_eq!(content.content, b"Created by path");
}

#[tokio::test]
async fn test_async_create_by_path_nonexistent_parent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let result = ops.create_by_path("nonexistent/file.txt").await;
    assert!(result.is_err(), "Creating in nonexistent parent should fail");
}

#[tokio::test]
async fn test_async_create_file_long_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let long_name = format!("{}.txt", "z".repeat(200));

    let mut writer = ops.create_file(&DirId::root(), &long_name).await
        .expect("Failed to create file with long name");

    writer.write(b"Long name content").await.expect("Failed to write");
    writer.finish().await.expect("Failed to finish");

    // Verify
    let content = ops.read_file(&DirId::root(), &long_name).await.unwrap();
    assert_eq!(content.content, b"Long name content");
}

// ==================== Large File Streaming Tests ====================

#[tokio::test]
async fn test_async_streaming_multi_chunk_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create a file larger than 2 chunks (64KB+)
    let large_content: Vec<u8> = (0..70_000).map(|i| (i % 256) as u8).collect();
    ops.write_file(&DirId::root(), "multi_chunk.bin", &large_content).await.unwrap();

    // Open and read using streaming
    let mut reader = ops.open_file(&DirId::root(), "multi_chunk.bin").await
        .expect("Failed to open multi-chunk file");

    assert_eq!(reader.plaintext_size(), 70_000);

    // Read from different positions
    let start = reader.read_range(0, 100).await.unwrap();
    assert_eq!(start.len(), 100);

    // Read spanning chunk boundary (around 32KB)
    let middle = reader.read_range(32_000, 1_000).await.unwrap();
    assert_eq!(middle.len(), 1_000);

    // Read near end
    let end = reader.read_range(69_900, 100).await.unwrap();
    assert_eq!(end.len(), 100);
}

#[tokio::test]
async fn test_async_streaming_empty_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("empty_stream.txt", b"")
        .build();

    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let reader = ops.open_file(&DirId::root(), "empty_stream.txt").await
        .expect("Failed to open empty file");

    assert_eq!(reader.plaintext_size(), 0);
}

// ==================== Concurrent Operation Edge Cases ====================

#[tokio::test]
async fn test_async_concurrent_write_same_file() {
    // This tests that locking prevents corruption when writing same file concurrently
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Write the same file concurrently from two operations
    // Due to locking, one should complete before the other
    let (r1, r2) = tokio::join!(
        ops.write_file(&root, "concurrent.txt", b"first"),
        ops.write_file(&root, "concurrent.txt", b"second")
    );

    // Both should succeed (writes are serialized)
    r1.expect("First write failed");
    r2.expect("Second write failed");

    // File should have one of the contents
    let content = ops.read_file(&root, "concurrent.txt").await.unwrap();
    assert!(
        content.content == b"first" || content.content == b"second",
        "Content should be from one of the writes"
    );
}

#[tokio::test]
async fn test_async_concurrent_create_and_delete() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let root = DirId::root();

    // Create a file
    ops.write_file(&root, "temp.txt", b"temporary").await.unwrap();

    // Try concurrent delete and read
    let (delete_result, read_result) = tokio::join!(
        ops.delete_file(&root, "temp.txt"),
        ops.read_file(&root, "temp.txt")
    );

    // Delete should succeed, read might succeed or fail depending on order
    delete_result.expect("Delete should succeed");
    // read_result may or may not be an error - that's fine
    let _ = read_result;
}

// ==================== Error Context Tests ====================

#[tokio::test]
async fn test_async_error_contains_context() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to read nonexistent file
    let err = ops.read_file(&DirId::root(), "context_test.txt").await
        .expect_err("Should fail");

    let err_string = err.to_string();
    assert!(err_string.contains("context_test.txt"),
        "Error should contain filename: {}", err_string);
}

#[tokio::test]
async fn test_async_error_delete_dir_contains_context() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    let err = ops.delete_directory(&DirId::root(), "nonexistent_dir").await
        .expect_err("Should fail");

    let err_string = err.to_string();
    assert!(err_string.contains("nonexistent_dir") || err_string.contains("not found"),
        "Error should contain directory name or 'not found': {}", err_string);
}

// ==================== Optimized Lookup Tests ====================

#[tokio::test]
async fn test_find_file_existing() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Write a file first
    let content = b"find me!";
    ops.write_file(&DirId::root(), "findable.txt", content).await
        .expect("Failed to write file");

    // Find it using the optimized lookup
    let found = ops.find_file(&DirId::root(), "findable.txt").await
        .expect("Failed to find file");

    assert!(found.is_some(), "File should be found");
    let info = found.unwrap();
    assert_eq!(info.name, "findable.txt");
    assert!(!info.is_shortened);
}

#[tokio::test]
async fn test_find_file_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to find a file that doesn't exist
    let found = ops.find_file(&DirId::root(), "ghost.txt").await
        .expect("find_file should not error for missing files");

    assert!(found.is_none(), "Non-existent file should return None");
}

#[tokio::test]
async fn test_find_file_shortened_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    // Use a low threshold to force shortening
    let ops = VaultOperationsAsync::with_shortening_threshold(&vault_path, &master_key, 50)
        .expect("Failed to create async ops");

    // Create a file with a very long name that will be shortened (> 50 chars base64 encoded)
    let long_name = "this_is_a_very_long_filename_that_will_definitely_exceed_the_threshold.txt";
    let content = b"shortened content";
    ops.write_file(&DirId::root(), long_name, content).await
        .expect("Failed to write file with long name");

    // Find it using the optimized lookup
    let found = ops.find_file(&DirId::root(), long_name).await
        .expect("Failed to find shortened file");

    assert!(found.is_some(), "Shortened file should be found");
    let info = found.unwrap();
    assert_eq!(info.name, long_name);
    assert!(info.is_shortened, "File should be marked as shortened");
}

#[tokio::test]
async fn test_find_directory_existing() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create a directory first
    let dir_id = ops.create_directory(&DirId::root(), "findable_dir").await
        .expect("Failed to create directory");

    // Find it using the optimized lookup
    let found = ops.find_directory(&DirId::root(), "findable_dir").await
        .expect("Failed to find directory");

    assert!(found.is_some(), "Directory should be found");
    let info = found.unwrap();
    assert_eq!(info.name, "findable_dir");
    assert_eq!(info.directory_id, dir_id);
}

#[tokio::test]
async fn test_find_directory_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Try to find a directory that doesn't exist
    let found = ops.find_directory(&DirId::root(), "ghost_dir").await
        .expect("find_directory should not error for missing directories");

    assert!(found.is_none(), "Non-existent directory should return None");
}

#[tokio::test]
async fn test_find_directory_shortened_name() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    // Use a low threshold to force shortening
    let ops = VaultOperationsAsync::with_shortening_threshold(&vault_path, &master_key, 50)
        .expect("Failed to create async ops");

    // Create a directory with a very long name that will be shortened (> 50 chars base64 encoded)
    let long_name = "this_is_a_very_long_directory_name_that_will_definitely_exceed_the_threshold";
    let dir_id = ops.create_directory(&DirId::root(), long_name).await
        .expect("Failed to create directory with long name");

    // Find it using the optimized lookup
    let found = ops.find_directory(&DirId::root(), long_name).await
        .expect("Failed to find shortened directory");

    assert!(found.is_some(), "Shortened directory should be found");
    let info = found.unwrap();
    assert_eq!(info.name, long_name);
    assert_eq!(info.directory_id, dir_id);
}

#[tokio::test]
async fn test_find_file_vs_list_files_consistency() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create several files
    for i in 0..5 {
        let name = format!("consistency_test_{}.txt", i);
        ops.write_file(&DirId::root(), &name, b"test").await
            .expect("Failed to write file");
    }

    // Get all files via list_files
    let all_files = ops.list_files(&DirId::root()).await
        .expect("Failed to list files");

    // Verify each file can be found individually
    for file in &all_files {
        let found = ops.find_file(&DirId::root(), &file.name).await
            .expect("find_file should succeed");
        assert!(found.is_some(), "File {} should be found", file.name);
        let found_info = found.unwrap();
        assert_eq!(found_info.name, file.name);
        assert_eq!(found_info.encrypted_path, file.encrypted_path);
    }
}

#[tokio::test]
async fn test_list_entries_combined() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create some files and directories
    ops.write_file(&DirId::root(), "entry_file1.txt", b"content1").await
        .expect("Failed to write file 1");
    ops.write_file(&DirId::root(), "entry_file2.txt", b"content2").await
        .expect("Failed to write file 2");
    ops.create_directory(&DirId::root(), "entry_dir1").await
        .expect("Failed to create directory 1");
    ops.create_directory(&DirId::root(), "entry_dir2").await
        .expect("Failed to create directory 2");

    // Get combined entries
    let (files, dirs) = ops.list_entries(&DirId::root()).await
        .expect("Failed to list entries");

    // Verify we got both files and directories
    let file_names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    let dir_names: Vec<_> = dirs.iter().map(|d| d.name.as_str()).collect();

    assert!(file_names.contains(&"entry_file1.txt"), "Should contain entry_file1.txt");
    assert!(file_names.contains(&"entry_file2.txt"), "Should contain entry_file2.txt");
    assert!(dir_names.contains(&"entry_dir1"), "Should contain entry_dir1");
    assert!(dir_names.contains(&"entry_dir2"), "Should contain entry_dir2");
}

#[tokio::test]
async fn test_list_entries_consistency_with_separate_calls() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create mixed content
    ops.write_file(&DirId::root(), "combo_file.txt", b"data").await
        .expect("Failed to write file");
    ops.create_directory(&DirId::root(), "combo_dir").await
        .expect("Failed to create directory");

    // Get entries via list_entries
    let (combined_files, combined_dirs) = ops.list_entries(&DirId::root()).await
        .expect("Failed to list entries");

    // Get entries via separate calls
    let separate_files = ops.list_files(&DirId::root()).await
        .expect("Failed to list files");
    let separate_dirs = ops.list_directories(&DirId::root()).await
        .expect("Failed to list directories");

    // Results should be consistent
    assert_eq!(combined_files.len(), separate_files.len(),
        "File counts should match between list_entries and list_files");
    assert_eq!(combined_dirs.len(), separate_dirs.len(),
        "Directory counts should match between list_entries and list_directories");
}

#[tokio::test]
async fn test_find_file_performance_vs_list() {
    use std::time::Instant;

    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create async ops");

    // Create many files
    for i in 0..20 {
        let name = format!("perf_test_{:03}.txt", i);
        ops.write_file(&DirId::root(), &name, b"x").await
            .expect("Failed to write file");
    }

    // Time find_file for a specific file
    let target = "perf_test_015.txt";
    let start = Instant::now();
    for _ in 0..10 {
        let _ = ops.find_file(&DirId::root(), target).await;
    }
    let find_duration = start.elapsed();

    // Time list_files + search
    let start = Instant::now();
    for _ in 0..10 {
        let files = ops.list_files(&DirId::root()).await.unwrap();
        let _ = files.iter().find(|f| f.name == target);
    }
    let list_duration = start.elapsed();

    // find_file should be faster (or at least not significantly slower)
    // We allow some variance since both are fast operations
    println!("find_file: {:?}, list_files: {:?}", find_duration, list_duration);
    // Note: We don't assert strict timing as it can vary, but we log for visibility
}
