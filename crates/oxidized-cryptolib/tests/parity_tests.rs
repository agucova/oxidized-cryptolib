//! Parity tests comparing sync and async vault operations.
//!
//! These tests ensure that `VaultOperations` (sync) and `VaultOperationsAsync`
//! produce identical results for the same operations. This is critical after
//! the refactoring to share `VaultCore` between implementations.

#![cfg(feature = "async")]

mod common;

use common::vault_builder::VaultBuilder;
use oxidized_cryptolib::vault::{DirId, VaultOperations, VaultOperationsAsync};
use std::sync::Arc;

// ==================== List Operations Parity ====================

#[tokio::test]
async fn test_parity_list_files() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Create sync ops and add some files
    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.write_file(&DirId::root(), "file1.txt", b"content1").unwrap();
    sync_ops.write_file(&DirId::root(), "file2.txt", b"content2").unwrap();
    sync_ops.write_file(&DirId::root(), "file3.txt", b"content3").unwrap();

    // Create async ops from same vault
    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // List files with both
    let sync_files = sync_ops.list_files(&DirId::root()).unwrap();
    let async_files = async_ops.list_files(&DirId::root()).await.unwrap();

    // Compare results
    assert_eq!(sync_files.len(), async_files.len(), "File count mismatch");

    let mut sync_names: Vec<_> = sync_files.iter().map(|f| &f.name).collect();
    let mut async_names: Vec<_> = async_files.iter().map(|f| &f.name).collect();
    sync_names.sort();
    async_names.sort();

    assert_eq!(sync_names, async_names, "File names mismatch");
}

#[tokio::test]
async fn test_parity_list_directories() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.create_directory(&DirId::root(), "dir1").unwrap();
    sync_ops.create_directory(&DirId::root(), "dir2").unwrap();
    sync_ops.create_directory(&DirId::root(), "dir3").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    let sync_dirs = sync_ops.list_directories(&DirId::root()).unwrap();
    let async_dirs = async_ops.list_directories(&DirId::root()).await.unwrap();

    assert_eq!(sync_dirs.len(), async_dirs.len(), "Directory count mismatch");

    let mut sync_names: Vec<_> = sync_dirs.iter().map(|d| &d.name).collect();
    let mut async_names: Vec<_> = async_dirs.iter().map(|d| &d.name).collect();
    sync_names.sort();
    async_names.sort();

    assert_eq!(sync_names, async_names, "Directory names mismatch");
}

// ==================== Read/Write Parity ====================

#[tokio::test]
async fn test_parity_read_write_roundtrip() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let content = b"Test content for parity check";

    // Write with sync
    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.write_file(&DirId::root(), "parity.txt", content).unwrap();

    // Read with async
    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key.try_clone().unwrap()));
    let async_read = async_ops.read_file(&DirId::root(), "parity.txt").await.unwrap();

    assert_eq!(async_read.content, content, "Async read of sync-written file failed");

    // Write with async
    let async_content = b"Async written content";
    async_ops.write_file(&DirId::root(), "async_file.txt", async_content).await.unwrap();

    // Read with sync
    let sync_read = sync_ops.read_file(&DirId::root(), "async_file.txt").unwrap();

    assert_eq!(sync_read.content, async_content, "Sync read of async-written file failed");
}

#[tokio::test]
async fn test_parity_large_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Large file spanning multiple chunks (32KB each)
    let content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.write_file(&DirId::root(), "large.bin", &content).unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));
    let async_read = async_ops.read_file(&DirId::root(), "large.bin").await.unwrap();

    assert_eq!(async_read.content, content, "Large file parity failed");
}

// ==================== Directory Operations Parity ====================

#[tokio::test]
async fn test_parity_create_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let sync_dir_id = sync_ops.create_directory(&DirId::root(), "sync_created").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Async should be able to see the sync-created directory
    let dirs = async_ops.list_directories(&DirId::root()).await.unwrap();
    let found = dirs.iter().find(|d| d.name == "sync_created");

    assert!(found.is_some(), "Async couldn't find sync-created directory");
    assert_eq!(found.unwrap().directory_id, sync_dir_id, "Directory ID mismatch");
}

#[tokio::test]
async fn test_parity_nested_structure() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());

    // Create nested structure with sync
    let docs_id = sync_ops.create_directory(&DirId::root(), "docs").unwrap();
    let src_id = sync_ops.create_directory(&DirId::root(), "src").unwrap();
    sync_ops.write_file(&docs_id, "readme.md", b"# Docs").unwrap();
    sync_ops.write_file(&src_id, "main.rs", b"fn main() {}").unwrap();

    // Verify with async
    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    let root_dirs = async_ops.list_directories(&DirId::root()).await.unwrap();
    assert_eq!(root_dirs.len(), 2);

    let docs_files = async_ops.list_files(&docs_id).await.unwrap();
    assert_eq!(docs_files.len(), 1);
    assert_eq!(docs_files[0].name, "readme.md");

    let src_files = async_ops.list_files(&src_id).await.unwrap();
    assert_eq!(src_files.len(), 1);
    assert_eq!(src_files[0].name, "main.rs");
}

// ==================== find_file / find_directory Parity ====================

#[tokio::test]
async fn test_parity_find_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.write_file(&DirId::root(), "findme.txt", b"found!").unwrap();
    sync_ops.write_file(&DirId::root(), "other.txt", b"not this").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Both should find the same file
    let sync_found = sync_ops.find_file(&DirId::root(), "findme.txt").unwrap();
    let async_found = async_ops.find_file(&DirId::root(), "findme.txt").await.unwrap();

    assert!(sync_found.is_some(), "Sync find_file failed");
    assert!(async_found.is_some(), "Async find_file failed");

    assert_eq!(sync_found.unwrap().name, async_found.unwrap().name);
}

#[tokio::test]
async fn test_parity_find_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let created_id = sync_ops.create_directory(&DirId::root(), "findable").unwrap();
    sync_ops.create_directory(&DirId::root(), "other_dir").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    let sync_found = sync_ops.find_directory(&DirId::root(), "findable").unwrap();
    let async_found = async_ops.find_directory(&DirId::root(), "findable").await.unwrap();

    assert!(sync_found.is_some(), "Sync find_directory failed");
    assert!(async_found.is_some(), "Async find_directory failed");

    assert_eq!(sync_found.as_ref().unwrap().directory_id, created_id);
    assert_eq!(async_found.as_ref().unwrap().directory_id, created_id);
    assert_eq!(sync_found.unwrap().name, async_found.unwrap().name);
}

#[tokio::test]
async fn test_parity_find_file_shortened() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Create a filename long enough to exceed 220 char encrypted name threshold
    // ~160 chars plaintext → ~250+ chars encrypted after base64url encoding
    let long_filename = format!("{}.txt", "x".repeat(160));

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops
        .write_file(&DirId::root(), &long_filename, b"shortened file content")
        .unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Both should find the file via .c9s format
    let sync_found = sync_ops.find_file(&DirId::root(), &long_filename).unwrap();
    let async_found = async_ops
        .find_file(&DirId::root(), &long_filename)
        .await
        .unwrap();

    assert!(sync_found.is_some(), "Sync find_file failed for shortened name");
    assert!(
        async_found.is_some(),
        "Async find_file failed for shortened name"
    );

    let sync_info = sync_found.unwrap();
    let async_info = async_found.unwrap();

    assert_eq!(sync_info.name, async_info.name, "File names don't match");
    assert_eq!(sync_info.name, long_filename, "Decrypted name incorrect");
    assert!(sync_info.is_shortened, "Sync should report shortened");
    assert!(async_info.is_shortened, "Async should report shortened");
    assert_eq!(
        sync_info.encrypted_size, async_info.encrypted_size,
        "Encrypted sizes don't match"
    );
}

#[tokio::test]
async fn test_parity_find_directory_shortened() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    // Create a directory name long enough to exceed 220 char encrypted name threshold
    let long_dirname = "d".repeat(160);

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let created_id = sync_ops
        .create_directory(&DirId::root(), &long_dirname)
        .unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Both should find the directory via .c9s format
    let sync_found = sync_ops
        .find_directory(&DirId::root(), &long_dirname)
        .unwrap();
    let async_found = async_ops
        .find_directory(&DirId::root(), &long_dirname)
        .await
        .unwrap();

    assert!(
        sync_found.is_some(),
        "Sync find_directory failed for shortened name"
    );
    assert!(
        async_found.is_some(),
        "Async find_directory failed for shortened name"
    );

    let sync_info = sync_found.unwrap();
    let async_info = async_found.unwrap();

    assert_eq!(
        sync_info.name, async_info.name,
        "Directory names don't match"
    );
    assert_eq!(sync_info.name, long_dirname, "Decrypted name incorrect");
    assert_eq!(
        sync_info.directory_id, created_id,
        "Sync directory ID mismatch"
    );
    assert_eq!(
        async_info.directory_id, created_id,
        "Async directory ID mismatch"
    );
    assert_eq!(
        sync_info.directory_id, async_info.directory_id,
        "Directory IDs don't match between sync and async"
    );
}

// ==================== Symlink Parity ====================

#[tokio::test]
async fn test_parity_symlink_operations() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    sync_ops.create_symlink(&DirId::root(), "link.txt", "/target/path").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Both should read the same target
    let sync_target = sync_ops.read_symlink(&DirId::root(), "link.txt").unwrap();
    let async_target = async_ops.read_symlink(&DirId::root(), "link.txt").await.unwrap();

    assert_eq!(sync_target, "/target/path");
    assert_eq!(async_target, "/target/path");
    assert_eq!(sync_target, async_target);
}

// ==================== Path Resolution Parity ====================

#[tokio::test]
async fn test_parity_resolve_path() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let docs_id = sync_ops.create_directory(&DirId::root(), "docs").unwrap();
    let sub_id = sync_ops.create_directory(&docs_id, "sub").unwrap();
    sync_ops.write_file(&sub_id, "file.txt", b"deep").unwrap();

    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // Resolve same paths
    let sync_result = sync_ops.resolve_path("docs/sub");
    let async_result = async_ops.resolve_path("docs/sub").await;

    assert!(sync_result.is_ok());
    assert!(async_result.is_ok());

    let (sync_id, sync_is_dir) = sync_result.unwrap();
    let (async_id, async_is_dir) = async_result.unwrap();

    assert_eq!(sync_id, async_id, "Resolved directory IDs don't match");
    assert_eq!(sync_is_dir, async_is_dir, "is_directory flags don't match");
    assert!(sync_is_dir, "Should be a directory");
}

// ==================== VaultCore Accessor Parity ====================

#[tokio::test]
async fn test_parity_vault_core_accessors() {
    let (vault_path, master_key) = VaultBuilder::new().build();

    let sync_ops = VaultOperations::new(&vault_path, master_key.try_clone().unwrap());
    let async_ops = VaultOperationsAsync::new(&vault_path, Arc::new(master_key));

    // These should be identical since they both delegate to VaultCore
    assert_eq!(sync_ops.vault_path(), async_ops.vault_path());
    assert_eq!(sync_ops.cipher_combo(), async_ops.cipher_combo());
    assert_eq!(sync_ops.shortening_threshold(), async_ops.shortening_threshold());
}
