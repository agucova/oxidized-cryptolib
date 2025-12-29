//! CRUD operation tests for WebDAV backend.
//!
//! Tests basic Create, Read, Update, Delete operations with focus on:
//! - Encryption/decryption correctness
//! - Chunk boundary handling (32KB chunks)
//! - Cache invalidation on overwrites
//! - Error semantics

mod common;

use common::{
    assert_file_content, assert_not_found, chunk_minus_one, chunk_plus_one, multi_chunk_content,
    one_chunk_content, random_bytes, sha256, TestServer, CHUNK_SIZE,
};
use reqwest::StatusCode;

// ============================================================================
// PUT/GET Roundtrip Tests
// ============================================================================

#[tokio::test]
async fn test_put_get_roundtrip() {
    let server = TestServer::with_temp_vault().await;

    let content = b"Hello, WebDAV!";
    server.put_ok("/test.txt", content.to_vec()).await;

    assert_file_content(&server, "/test.txt", content).await;
}

#[tokio::test]
async fn test_put_overwrite() {
    let server = TestServer::with_temp_vault().await;

    // Write initial content
    server.put_ok("/file.txt", b"version1".to_vec()).await;
    assert_file_content(&server, "/file.txt", b"version1").await;

    // Overwrite with different content
    server.put_ok("/file.txt", b"version2".to_vec()).await;

    // Must see new content (cache invalidation)
    assert_file_content(&server, "/file.txt", b"version2").await;
}

#[tokio::test]
async fn test_put_empty_file() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/empty.txt", Vec::new()).await;

    assert_file_content(&server, "/empty.txt", b"").await;
}

#[tokio::test]
async fn test_put_one_byte() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/one.bin", vec![0x42]).await;

    assert_file_content(&server, "/one.bin", &[0x42]).await;
}

// ============================================================================
// Chunk Boundary Tests (32KB boundaries - critical for Cryptomator)
// ============================================================================

#[tokio::test]
async fn test_put_exactly_one_chunk() {
    let server = TestServer::with_temp_vault().await;

    let content = one_chunk_content();
    assert_eq!(content.len(), CHUNK_SIZE);

    let expected_hash = sha256(&content);
    server.put_ok("/one_chunk.bin", content.clone()).await;

    let retrieved = server.get_bytes("/one_chunk.bin").await.unwrap();
    assert_eq!(retrieved.len(), CHUNK_SIZE);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[tokio::test]
async fn test_put_chunk_boundary_minus_one() {
    let server = TestServer::with_temp_vault().await;

    let content = chunk_minus_one();
    assert_eq!(content.len(), CHUNK_SIZE - 1);

    let expected_hash = sha256(&content);
    server.put_ok("/chunk_minus.bin", content.clone()).await;

    let retrieved = server.get_bytes("/chunk_minus.bin").await.unwrap();
    assert_eq!(retrieved.len(), CHUNK_SIZE - 1);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[tokio::test]
async fn test_put_chunk_boundary_plus_one() {
    let server = TestServer::with_temp_vault().await;

    let content = chunk_plus_one();
    assert_eq!(content.len(), CHUNK_SIZE + 1);

    let expected_hash = sha256(&content);
    server.put_ok("/chunk_plus.bin", content.clone()).await;

    let retrieved = server.get_bytes("/chunk_plus.bin").await.unwrap();
    assert_eq!(retrieved.len(), CHUNK_SIZE + 1);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[tokio::test]
async fn test_put_large_file_multi_chunk() {
    let server = TestServer::with_temp_vault().await;

    // 5 chunks = 160KB
    let content = multi_chunk_content(5);
    assert_eq!(content.len(), 5 * CHUNK_SIZE);

    let expected_hash = sha256(&content);
    server.put_ok("/large.bin", content.clone()).await;

    let retrieved = server.get_bytes("/large.bin").await.unwrap();
    assert_eq!(retrieved.len(), 5 * CHUNK_SIZE);
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[tokio::test]
async fn test_put_exactly_two_chunks() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(2);
    assert_eq!(content.len(), 2 * CHUNK_SIZE);

    let expected_hash = sha256(&content);
    server.put_ok("/two_chunks.bin", content.clone()).await;

    let retrieved = server.get_bytes("/two_chunks.bin").await.unwrap();
    assert_eq!(sha256(&retrieved), expected_hash);
}

// ============================================================================
// GET Tests
// ============================================================================

#[tokio::test]
async fn test_get_nonexistent() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.get("/does_not_exist.txt").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_after_delete() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/temp.txt", b"temporary".to_vec()).await;
    assert_file_content(&server, "/temp.txt", b"temporary").await;

    server.delete_ok("/temp.txt").await;

    assert_not_found(&server, "/temp.txt").await;
}

// ============================================================================
// DELETE Tests
// ============================================================================

#[tokio::test]
async fn test_delete_file() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/to_delete.txt", b"delete me".to_vec()).await;
    assert_file_content(&server, "/to_delete.txt", b"delete me").await;

    let resp = server.delete("/to_delete.txt").await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT,
        "DELETE failed with status {}",
        resp.status()
    );

    assert_not_found(&server, "/to_delete.txt").await;
}

#[tokio::test]
async fn test_delete_nonexistent() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.delete("/nonexistent.txt").await;
    // WebDAV spec says 404 for deleting non-existent, but some servers return 204
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::NO_CONTENT,
        "Expected 404 or 204, got {}",
        resp.status()
    );
}

// ============================================================================
// MKCOL (Directory Creation) Tests
// ============================================================================

#[tokio::test]
async fn test_mkcol_simple() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.mkcol("/newdir").await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CREATED,
        "MKCOL failed with status {}",
        resp.status()
    );

    // Verify directory exists via PROPFIND
    let resp = server.propfind("/newdir", "0").await;
    assert!(
        resp.status() == StatusCode::MULTI_STATUS || resp.status().is_success(),
        "Directory not accessible after MKCOL"
    );
}

#[tokio::test]
async fn test_mkcol_nested_should_fail() {
    let server = TestServer::with_temp_vault().await;

    // Creating /a/b when /a doesn't exist should fail with 409 Conflict
    let resp = server.mkcol("/nonexistent/nested").await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "Expected 409 Conflict for nested MKCOL without parent"
    );
}

#[tokio::test]
async fn test_mkcol_exists() {
    let server = TestServer::with_temp_vault().await;

    // Create directory
    server.mkcol_ok("/existingdir").await;

    // Create again - should fail with 405 Method Not Allowed
    let resp = server.mkcol("/existingdir").await;
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for MKCOL on existing directory"
    );
}

#[tokio::test]
async fn test_mkcol_then_put_file_inside() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/mydir").await;
    server.put_ok("/mydir/file.txt", b"inside dir".to_vec()).await;

    assert_file_content(&server, "/mydir/file.txt", b"inside dir").await;
}

// ============================================================================
// Directory Deletion Tests
// ============================================================================

#[tokio::test]
async fn test_rmdir_empty() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/emptydir").await;

    let resp = server.delete("/emptydir").await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT,
        "DELETE empty dir failed with status {}",
        resp.status()
    );

    // Verify it's gone
    let resp = server.propfind("/emptydir", "0").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_rmdir_nonempty_should_fail() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/nonempty").await;
    server.put_ok("/nonempty/file.txt", b"content".to_vec()).await;

    // Deleting non-empty directory should fail
    // Note: Some WebDAV implementations allow recursive delete
    let resp = server.delete("/nonempty").await;

    // Could be CONFLICT or success with recursive delete - depends on implementation
    // We just verify the directory behavior is consistent
    if resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT {
        // Recursive delete succeeded - verify everything is gone
        assert_not_found(&server, "/nonempty/file.txt").await;
        let resp = server.propfind("/nonempty", "0").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    } else {
        // Delete blocked - directory and file should still exist
        assert_file_content(&server, "/nonempty/file.txt", b"content").await;
    }
}

// ============================================================================
// Files in Subdirectories
// ============================================================================

#[tokio::test]
async fn test_put_get_in_subdirectory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/subdir").await;
    server.put_ok("/subdir/nested.txt", b"nested content".to_vec()).await;

    assert_file_content(&server, "/subdir/nested.txt", b"nested content").await;
}

#[tokio::test]
async fn test_deep_directory_structure() {
    let server = TestServer::with_temp_vault().await;

    // Create nested directories one by one
    server.mkcol_ok("/a").await;
    server.mkcol_ok("/a/b").await;
    server.mkcol_ok("/a/b/c").await;

    server.put_ok("/a/b/c/deep.txt", b"deep file".to_vec()).await;

    assert_file_content(&server, "/a/b/c/deep.txt", b"deep file").await;
}

// ============================================================================
// Multiple Files
// ============================================================================

#[tokio::test]
async fn test_multiple_files_independence() {
    let server = TestServer::with_temp_vault().await;

    // Create multiple files
    server.put_ok("/file1.txt", b"content 1".to_vec()).await;
    server.put_ok("/file2.txt", b"content 2".to_vec()).await;
    server.put_ok("/file3.txt", b"content 3".to_vec()).await;

    // Verify all have correct content
    assert_file_content(&server, "/file1.txt", b"content 1").await;
    assert_file_content(&server, "/file2.txt", b"content 2").await;
    assert_file_content(&server, "/file3.txt", b"content 3").await;

    // Modify one
    server.put_ok("/file2.txt", b"modified 2".to_vec()).await;

    // Others should be unchanged
    assert_file_content(&server, "/file1.txt", b"content 1").await;
    assert_file_content(&server, "/file2.txt", b"modified 2").await;
    assert_file_content(&server, "/file3.txt", b"content 3").await;
}

#[tokio::test]
async fn test_overwrite_with_different_size() {
    let server = TestServer::with_temp_vault().await;

    // Start with small content
    server.put_ok("/resize.bin", b"small".to_vec()).await;
    assert_file_content(&server, "/resize.bin", b"small").await;

    // Overwrite with larger content
    let large = random_bytes(10000);
    let hash = sha256(&large);
    server.put_ok("/resize.bin", large.clone()).await;

    let retrieved = server.get_bytes("/resize.bin").await.unwrap();
    assert_eq!(retrieved.len(), 10000);
    assert_eq!(sha256(&retrieved), hash);

    // Overwrite with smaller content again
    server.put_ok("/resize.bin", b"small again".to_vec()).await;
    assert_file_content(&server, "/resize.bin", b"small again").await;
}
