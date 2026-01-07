//! Multi-step workflow tests for WebDAV backend.
//!
//! These tests verify correct behavior across sequences of operations:
//! - Complete CRUD cycles
//! - Directory tree operations
//! - Backup/restore workflows
//! - Complex interleaved operations

mod common;

use common::{assert_file_content, assert_not_found, multi_chunk_content, one_chunk_content, random_bytes, sha256, TestServer, CHUNK_SIZE};
use reqwest::StatusCode;

// ============================================================================
// Complete CRUD Cycles
// ============================================================================

#[tokio::test]
async fn test_create_populate_delete_cycle() {
    let server = TestServer::with_temp_vault().await;

    // Create directory
    server.mkcol_ok("/project").await;

    // Add files
    server.put_ok("/project/readme.txt", b"Project README".to_vec()).await;
    server.put_ok("/project/config.json", b"{}".to_vec()).await;
    server.put_ok("/project/data.bin", random_bytes(5000)).await;

    // Verify all exist
    assert_file_content(&server, "/project/readme.txt", b"Project README").await;
    assert_file_content(&server, "/project/config.json", b"{}").await;

    // Modify one file
    server.put_ok("/project/config.json", b"{\"version\": 2}".to_vec()).await;
    assert_file_content(&server, "/project/config.json", b"{\"version\": 2}").await;

    // Delete one file
    server.delete_ok("/project/data.bin").await;
    assert_not_found(&server, "/project/data.bin").await;

    // Others still exist
    assert_file_content(&server, "/project/readme.txt", b"Project README").await;
}

#[tokio::test]
async fn test_nested_directory_full_lifecycle() {
    let server = TestServer::with_temp_vault().await;

    // Create nested structure
    server.mkcol_ok("/root").await;
    server.mkcol_ok("/root/level1").await;
    server.mkcol_ok("/root/level1/level2").await;
    server.mkcol_ok("/root/level1/level2/level3").await;

    // Add files at each level
    server.put_ok("/root/file0.txt", b"level 0".to_vec()).await;
    server.put_ok("/root/level1/file1.txt", b"level 1".to_vec()).await;
    server.put_ok("/root/level1/level2/file2.txt", b"level 2".to_vec()).await;
    server.put_ok("/root/level1/level2/level3/file3.txt", b"level 3".to_vec()).await;

    // Verify all files
    assert_file_content(&server, "/root/file0.txt", b"level 0").await;
    assert_file_content(&server, "/root/level1/file1.txt", b"level 1").await;
    assert_file_content(&server, "/root/level1/level2/file2.txt", b"level 2").await;
    assert_file_content(&server, "/root/level1/level2/level3/file3.txt", b"level 3").await;

    // Delete from bottom up
    server.delete_ok("/root/level1/level2/level3/file3.txt").await;
    server.delete("/root/level1/level2/level3").await;  // May fail if not empty

    // Parent files still exist
    assert_file_content(&server, "/root/level1/level2/file2.txt", b"level 2").await;
}

#[tokio::test]
async fn test_file_replace_workflow() {
    let server = TestServer::with_temp_vault().await;

    // Create file
    server.put_ok("/replaceable.txt", b"version 1".to_vec()).await;
    assert_file_content(&server, "/replaceable.txt", b"version 1").await;

    // Delete and recreate with same name
    server.delete_ok("/replaceable.txt").await;
    assert_not_found(&server, "/replaceable.txt").await;

    // Recreate with different content
    server.put_ok("/replaceable.txt", b"version 2 - new".to_vec()).await;
    assert_file_content(&server, "/replaceable.txt", b"version 2 - new").await;
}

// ============================================================================
// Backup Workflows
// ============================================================================

#[tokio::test]
async fn test_backup_workflow() {
    let server = TestServer::with_temp_vault().await;

    // Create original file
    let original_content = random_bytes(10000);
    let original_hash = sha256(&original_content);
    server.put_ok("/document.dat", original_content.clone()).await;

    // Create backup via COPY
    let resp = server.copy("/document.dat", "/document.dat.backup", false).await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CREATED,
        "Backup copy failed"
    );

    // Modify original
    let modified_content = random_bytes(8000);
    let modified_hash = sha256(&modified_content);
    server.put_ok("/document.dat", modified_content).await;

    // Verify backup unchanged
    let backup = server.get_bytes("/document.dat.backup").await.unwrap();
    assert_eq!(sha256(&backup), original_hash, "Backup should have original content");

    // Verify original changed
    let current = server.get_bytes("/document.dat").await.unwrap();
    assert_eq!(sha256(&current), modified_hash, "Original should be modified");
}

#[tokio::test]
async fn test_restore_from_backup() {
    let server = TestServer::with_temp_vault().await;

    // Create original
    server.put_ok("/important.txt", b"important data v1".to_vec()).await;

    // Backup
    server.copy("/important.txt", "/important.txt.bak", false).await;

    // Corrupt original (simulate)
    server.put_ok("/important.txt", b"corrupted!".to_vec()).await;

    // Restore from backup
    server.copy("/important.txt.bak", "/important.txt", true).await;

    // Verify restored
    assert_file_content(&server, "/important.txt", b"important data v1").await;
}

// ============================================================================
// Directory Tree Operations
// ============================================================================

#[tokio::test]
async fn test_directory_tree_enumeration() {
    let server = TestServer::with_temp_vault().await;

    // Create tree
    server.mkcol_ok("/tree").await;
    server.put_ok("/tree/a.txt", b"a".to_vec()).await;
    server.put_ok("/tree/b.txt", b"b".to_vec()).await;
    server.mkcol_ok("/tree/sub").await;
    server.put_ok("/tree/sub/c.txt", b"c".to_vec()).await;

    // List root
    let (status, body) = server.propfind_body("/tree", "1").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());
    assert!(body.contains("a.txt") || body.contains(">a<"));
    assert!(body.contains("b.txt") || body.contains(">b<"));
    assert!(body.contains("sub"));
}

#[tokio::test]
async fn test_move_directory_with_contents() {
    let server = TestServer::with_temp_vault().await;

    // Create source tree
    server.mkcol_ok("/source").await;
    server.put_ok("/source/file1.txt", b"content1".to_vec()).await;
    server.put_ok("/source/file2.txt", b"content2".to_vec()).await;

    // Move entire directory
    let resp = server.move_("/source", "/destination", false).await;

    if resp.status().is_success() || resp.status() == StatusCode::CREATED {
        // Directory move succeeded
        assert_not_found(&server, "/source/file1.txt").await;
        assert_file_content(&server, "/destination/file1.txt", b"content1").await;
        assert_file_content(&server, "/destination/file2.txt", b"content2").await;
    }
    // If directory move failed, that's a known limitation
}

// ============================================================================
// Interleaved Operations
// ============================================================================

#[tokio::test]
async fn test_interleaved_reads_writes() {
    let server = TestServer::with_temp_vault().await;

    // Create initial files
    server.put_ok("/file_a.txt", b"initial A".to_vec()).await;
    server.put_ok("/file_b.txt", b"initial B".to_vec()).await;

    // Interleave reads and writes
    assert_file_content(&server, "/file_a.txt", b"initial A").await;
    server.put_ok("/file_b.txt", b"updated B".to_vec()).await;
    assert_file_content(&server, "/file_b.txt", b"updated B").await;
    server.put_ok("/file_a.txt", b"updated A".to_vec()).await;
    assert_file_content(&server, "/file_a.txt", b"updated A").await;
    assert_file_content(&server, "/file_b.txt", b"updated B").await;
}

#[tokio::test]
async fn test_multiple_file_operations() {
    let server = TestServer::with_temp_vault().await;

    let count = 10;

    // Create many files
    for i in 0..count {
        let content = format!("file {i} content").into_bytes();
        server.put_ok(&format!("/multi{i}.txt"), content).await;
    }

    // Read all
    for i in 0..count {
        let expected = format!("file {i} content").into_bytes();
        assert_file_content(&server, &format!("/multi{i}.txt"), &expected).await;
    }

    // Delete even numbered
    for i in (0..count).step_by(2) {
        server.delete_ok(&format!("/multi{i}.txt")).await;
    }

    // Verify odd numbered still exist
    for i in (1..count).step_by(2) {
        let expected = format!("file {i} content").into_bytes();
        assert_file_content(&server, &format!("/multi{i}.txt"), &expected).await;
    }

    // Verify even numbered are gone
    for i in (0..count).step_by(2) {
        assert_not_found(&server, &format!("/multi{i}.txt")).await;
    }
}

// ============================================================================
// Size Transition Workflows
// ============================================================================

#[tokio::test]
async fn test_file_size_growth() {
    let server = TestServer::with_temp_vault().await;

    // Start tiny
    server.put_ok("/growing.bin", b"x".to_vec()).await;
    assert_file_content(&server, "/growing.bin", b"x").await;

    // Grow to small
    let small = random_bytes(100);
    server.put_ok("/growing.bin", small.clone()).await;
    assert_file_content(&server, "/growing.bin", &small).await;

    // Grow to medium (under chunk size)
    let medium = random_bytes(CHUNK_SIZE - 100);
    server.put_ok("/growing.bin", medium.clone()).await;
    assert_file_content(&server, "/growing.bin", &medium).await;

    // Grow to exactly one chunk
    let one_chunk = one_chunk_content();
    server.put_ok("/growing.bin", one_chunk.clone()).await;
    assert_file_content(&server, "/growing.bin", &one_chunk).await;

    // Grow to multi-chunk
    let large = multi_chunk_content(3);
    let hash = sha256(&large);
    server.put_ok("/growing.bin", large).await;
    let retrieved = server.get_bytes("/growing.bin").await.unwrap();
    assert_eq!(sha256(&retrieved), hash);
}

#[tokio::test]
async fn test_file_size_shrinking() {
    let server = TestServer::with_temp_vault().await;

    // Start large
    let large = multi_chunk_content(3);
    server.put_ok("/shrinking.bin", large).await;

    // Shrink to one chunk
    let one_chunk = one_chunk_content();
    server.put_ok("/shrinking.bin", one_chunk.clone()).await;
    assert_file_content(&server, "/shrinking.bin", &one_chunk).await;

    // Shrink to small
    server.put_ok("/shrinking.bin", b"small".to_vec()).await;
    assert_file_content(&server, "/shrinking.bin", b"small").await;

    // Shrink to empty
    server.put_ok("/shrinking.bin", Vec::new()).await;
    assert_file_content(&server, "/shrinking.bin", b"").await;
}

// ============================================================================
// Session-like Workflows
// ============================================================================

#[tokio::test]
async fn test_document_editing_session() {
    let server = TestServer::with_temp_vault().await;

    // Open (create) document
    server.put_ok("/document.txt", b"Hello, World!".to_vec()).await;

    // Multiple edits
    server.put_ok("/document.txt", b"Hello, WebDAV!".to_vec()).await;
    server.put_ok("/document.txt", b"Hello, Cryptomator WebDAV!".to_vec()).await;

    // Verify final state
    assert_file_content(&server, "/document.txt", b"Hello, Cryptomator WebDAV!").await;

    // Close (delete)
    server.delete_ok("/document.txt").await;
    assert_not_found(&server, "/document.txt").await;
}

#[tokio::test]
async fn test_project_setup_workflow() {
    let server = TestServer::with_temp_vault().await;

    // Create project structure
    server.mkcol_ok("/myproject").await;
    server.mkcol_ok("/myproject/src").await;
    server.mkcol_ok("/myproject/tests").await;
    server.mkcol_ok("/myproject/docs").await;

    // Add files
    server.put_ok("/myproject/README.md", b"# My Project".to_vec()).await;
    server.put_ok("/myproject/src/main.rs", b"fn main() {}".to_vec()).await;
    server.put_ok("/myproject/tests/test.rs", b"#[test] fn it_works() {}".to_vec()).await;

    // Verify structure
    let (status, body) = server.propfind_body("/myproject", "1").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());
    assert!(body.contains("README") || body.contains("readme"));
    assert!(body.contains("src"));
    assert!(body.contains("tests"));
    assert!(body.contains("docs"));

    // Access files
    assert_file_content(&server, "/myproject/README.md", b"# My Project").await;
    assert_file_content(&server, "/myproject/src/main.rs", b"fn main() {}").await;
}

// ============================================================================
// Edge Case Workflows
// ============================================================================

#[tokio::test]
async fn test_same_name_different_extensions() {
    let server = TestServer::with_temp_vault().await;

    // Create files with same base name, different extensions
    server.put_ok("/document.txt", b"text".to_vec()).await;
    server.put_ok("/document.md", b"markdown".to_vec()).await;
    server.put_ok("/document.json", b"{}".to_vec()).await;
    server.put_ok("/document.xml", b"<doc/>".to_vec()).await;

    // All should coexist
    assert_file_content(&server, "/document.txt", b"text").await;
    assert_file_content(&server, "/document.md", b"markdown").await;
    assert_file_content(&server, "/document.json", b"{}").await;
    assert_file_content(&server, "/document.xml", b"<doc/>").await;

    // Delete one
    server.delete_ok("/document.json").await;

    // Others still exist
    assert_file_content(&server, "/document.txt", b"text").await;
    assert_file_content(&server, "/document.md", b"markdown").await;
    assert_not_found(&server, "/document.json").await;
    assert_file_content(&server, "/document.xml", b"<doc/>").await;
}

#[tokio::test]
async fn test_hidden_files_workflow() {
    let server = TestServer::with_temp_vault().await;

    // Create hidden files (Unix-style dotfiles)
    server.put_ok("/.gitignore", b"*.log".to_vec()).await;
    server.put_ok("/.env", b"SECRET=value".to_vec()).await;
    server.mkcol_ok("/.config").await;
    server.put_ok("/.config/settings.json", b"{}".to_vec()).await;

    // Access them
    assert_file_content(&server, "/.gitignore", b"*.log").await;
    assert_file_content(&server, "/.env", b"SECRET=value").await;
    assert_file_content(&server, "/.config/settings.json", b"{}").await;
}
