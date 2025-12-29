//! Move and Copy operation tests for WebDAV backend.
//!
//! Tests file and directory move/copy operations:
//! - Same-directory renames
//! - Cross-directory moves
//! - Overwrite behavior
//! - Content integrity after move/copy
//! - Cache invalidation

mod common;

use common::{assert_file_content, assert_not_found, multi_chunk_content, sha256, TestServer, CHUNK_SIZE};
use reqwest::StatusCode;

// ============================================================================
// File Move (Rename) Tests
// ============================================================================

#[tokio::test]
async fn test_move_file_same_dir() {
    let server = TestServer::with_temp_vault().await;

    let content = b"content to move";
    server.put_ok("/original.txt", content.to_vec()).await;

    let resp = server.move_("/original.txt", "/renamed.txt", false).await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CREATED,
        "MOVE failed with status {}",
        resp.status()
    );

    // Verify old path is gone
    assert_not_found(&server, "/original.txt").await;

    // Verify content at new path
    assert_file_content(&server, "/renamed.txt", content).await;
}

#[tokio::test]
async fn test_move_file_different_dir() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/source_dir").await;
    server.mkcol_ok("/dest_dir").await;

    // Verify dest_dir exists via PROPFIND
    let resp = server.propfind("/dest_dir", "0").await;
    eprintln!("DEBUG: dest_dir PROPFIND status: {}", resp.status());

    let content = b"content to move across dirs";
    server.put_ok("/source_dir/file.txt", content.to_vec()).await;

    let resp = server.move_("/source_dir/file.txt", "/dest_dir/file.txt", false).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    eprintln!("DEBUG: MOVE response status: {}, body: {}", status, body);
    assert!(
        status.is_success() || status == StatusCode::CREATED,
        "Cross-dir MOVE failed with status {}: {}",
        status,
        body
    );

    assert_not_found(&server, "/source_dir/file.txt").await;
    assert_file_content(&server, "/dest_dir/file.txt", content).await;
}

#[tokio::test]
async fn test_move_file_and_rename() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/from").await;
    server.mkcol_ok("/to").await;

    let content = b"move and rename content";
    server.put_ok("/from/oldname.txt", content.to_vec()).await;

    let resp = server.move_("/from/oldname.txt", "/to/newname.txt", false).await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CREATED,
        "Move+rename failed"
    );

    assert_not_found(&server, "/from/oldname.txt").await;
    assert_file_content(&server, "/to/newname.txt", content).await;
}

#[tokio::test]
async fn test_move_file_overwrite_true() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/source.txt", b"source content".to_vec()).await;
    server.put_ok("/dest.txt", b"original dest".to_vec()).await;

    let resp = server.move_("/source.txt", "/dest.txt", true).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    eprintln!("DEBUG: MOVE status={}, body={}", status, body);
    assert!(
        status.is_success() || status == StatusCode::NO_CONTENT,
        "MOVE with overwrite=true failed with status {}: {}",
        status,
        body
    );

    assert_not_found(&server, "/source.txt").await;
    assert_file_content(&server, "/dest.txt", b"source content").await;
}

#[tokio::test]
async fn test_move_large_file() {
    let server = TestServer::with_temp_vault().await;

    // Multi-chunk file
    let content = multi_chunk_content(3);
    let expected_hash = sha256(&content);

    server.put_ok("/large_source.bin", content).await;

    let resp = server.move_("/large_source.bin", "/large_dest.bin", false).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::CREATED);

    assert_not_found(&server, "/large_source.bin").await;

    let retrieved = server.get_bytes("/large_dest.bin").await.unwrap();
    assert_eq!(sha256(&retrieved), expected_hash);
}

#[tokio::test]
async fn test_move_then_read_old_path() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/before.txt", b"content".to_vec()).await;
    server.move_("/before.txt", "/after.txt", false).await;

    // Old path must return 404
    let resp = server.get("/before.txt").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Old path should return 404 after move"
    );
}

#[tokio::test]
async fn test_move_preserves_binary_content() {
    let server = TestServer::with_temp_vault().await;

    // All byte values
    let content: Vec<u8> = (0u8..=255).collect();

    server.put_ok("/binary_source.bin", content.clone()).await;
    server.move_("/binary_source.bin", "/binary_dest.bin", false).await;

    assert_file_content(&server, "/binary_dest.bin", &content).await;
}

// ============================================================================
// Directory Move Tests
// ============================================================================

#[tokio::test]
async fn test_move_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/olddir").await;
    server.put_ok("/olddir/file.txt", b"inside".to_vec()).await;

    let resp = server.move_("/olddir", "/newdir", false).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    eprintln!("DEBUG: Directory MOVE status: {}, body: {}", status, body);
    assert!(
        status.is_success() || status == StatusCode::CREATED,
        "Directory MOVE failed with {}: {}",
        status,
        body
    );

    // Check old path is gone
    let resp = server.propfind("/olddir", "0").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Check new path has the file
    assert_file_content(&server, "/newdir/file.txt", b"inside").await;
}

#[tokio::test]
async fn test_move_nested_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/parent").await;
    server.mkcol_ok("/parent/child").await;
    server.put_ok("/parent/child/deep.txt", b"deep content".to_vec()).await;

    let resp = server.move_("/parent", "/moved_parent", false).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::CREATED);

    // Verify entire tree moved
    assert_file_content(&server, "/moved_parent/child/deep.txt", b"deep content").await;
}

// ============================================================================
// File Copy Tests
// ============================================================================

#[tokio::test]
async fn test_copy_file() {
    let server = TestServer::with_temp_vault().await;

    let content = b"content to copy";
    server.put_ok("/original.txt", content.to_vec()).await;

    let resp = server.copy("/original.txt", "/copied.txt", false).await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CREATED,
        "COPY failed with status {}",
        resp.status()
    );

    // Both should exist
    assert_file_content(&server, "/original.txt", content).await;
    assert_file_content(&server, "/copied.txt", content).await;
}

#[tokio::test]
async fn test_copy_file_large() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(4);
    let expected_hash = sha256(&content);

    server.put_ok("/large.bin", content).await;

    let resp = server.copy("/large.bin", "/large_copy.bin", false).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::CREATED);

    // Verify both exist with correct content
    let orig = server.get_bytes("/large.bin").await.unwrap();
    let copy = server.get_bytes("/large_copy.bin").await.unwrap();

    assert_eq!(sha256(&orig), expected_hash);
    assert_eq!(sha256(&copy), expected_hash);
}

#[tokio::test]
async fn test_copy_file_overwrite() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/source.txt", b"source content".to_vec()).await;
    server.put_ok("/dest.txt", b"original dest".to_vec()).await;

    let resp = server.copy("/source.txt", "/dest.txt", true).await;
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT,
        "COPY with overwrite=true failed"
    );

    // Both should exist, dest has source content
    assert_file_content(&server, "/source.txt", b"source content").await;
    assert_file_content(&server, "/dest.txt", b"source content").await;
}

#[tokio::test]
async fn test_copy_then_modify_original() {
    let server = TestServer::with_temp_vault().await;

    let original_content = b"original content";
    server.put_ok("/original.txt", original_content.to_vec()).await;

    server.copy("/original.txt", "/copy.txt", false).await;

    // Modify original
    server.put_ok("/original.txt", b"modified original".to_vec()).await;

    // Copy should still have original content (independence)
    assert_file_content(&server, "/copy.txt", original_content).await;
    assert_file_content(&server, "/original.txt", b"modified original").await;
}

#[tokio::test]
async fn test_copy_then_modify_copy() {
    let server = TestServer::with_temp_vault().await;

    let original_content = b"original content";
    server.put_ok("/original.txt", original_content.to_vec()).await;

    server.copy("/original.txt", "/copy.txt", false).await;

    // Modify copy
    server.put_ok("/copy.txt", b"modified copy".to_vec()).await;

    // Original should be unchanged
    assert_file_content(&server, "/original.txt", original_content).await;
    assert_file_content(&server, "/copy.txt", b"modified copy").await;
}

#[tokio::test]
async fn test_copy_to_different_dir() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/dir1").await;
    server.mkcol_ok("/dir2").await;

    let content = b"cross-directory copy";
    server.put_ok("/dir1/file.txt", content.to_vec()).await;

    let resp = server.copy("/dir1/file.txt", "/dir2/file.txt", false).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::CREATED);

    assert_file_content(&server, "/dir1/file.txt", content).await;
    assert_file_content(&server, "/dir2/file.txt", content).await;
}

// ============================================================================
// Directory Copy Tests (if supported)
// ============================================================================

#[tokio::test]
async fn test_copy_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/original_dir").await;
    server.put_ok("/original_dir/file.txt", b"file content".to_vec()).await;

    let resp = server.copy("/original_dir", "/copied_dir", false).await;

    if resp.status().is_success() || resp.status() == StatusCode::CREATED {
        // Directory copy is supported - verify contents
        assert_file_content(&server, "/original_dir/file.txt", b"file content").await;
        assert_file_content(&server, "/copied_dir/file.txt", b"file content").await;
    } else {
        // Directory copy not supported (403 or 501)
        assert!(
            resp.status() == StatusCode::FORBIDDEN
                || resp.status() == StatusCode::NOT_IMPLEMENTED
                || resp.status() == StatusCode::METHOD_NOT_ALLOWED,
            "Unexpected status for directory COPY: {}",
            resp.status()
        );
    }
}

// ============================================================================
// Rename Chain Tests
// ============================================================================

#[tokio::test]
async fn test_rename_chain() {
    let server = TestServer::with_temp_vault().await;

    let content = b"chain test content";
    server.put_ok("/a.txt", content.to_vec()).await;

    // A → B → C → D
    server.move_("/a.txt", "/b.txt", false).await;
    server.move_("/b.txt", "/c.txt", false).await;
    server.move_("/c.txt", "/d.txt", false).await;

    // Only D should exist
    assert_not_found(&server, "/a.txt").await;
    assert_not_found(&server, "/b.txt").await;
    assert_not_found(&server, "/c.txt").await;
    assert_file_content(&server, "/d.txt", content).await;
}

#[tokio::test]
async fn test_copy_chain() {
    let server = TestServer::with_temp_vault().await;

    let content = b"copy chain content";
    server.put_ok("/start.txt", content.to_vec()).await;

    // Create chain of copies
    server.copy("/start.txt", "/copy1.txt", false).await;
    server.copy("/copy1.txt", "/copy2.txt", false).await;
    server.copy("/copy2.txt", "/copy3.txt", false).await;

    // All should exist with same content
    assert_file_content(&server, "/start.txt", content).await;
    assert_file_content(&server, "/copy1.txt", content).await;
    assert_file_content(&server, "/copy2.txt", content).await;
    assert_file_content(&server, "/copy3.txt", content).await;
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_move_to_self() {
    let server = TestServer::with_temp_vault().await;

    let content = b"self move test";
    server.put_ok("/selfmove.txt", content.to_vec()).await;

    // Move to same path
    let resp = server.move_("/selfmove.txt", "/selfmove.txt", true).await;

    // Should either succeed as no-op or return an error
    // Content should be unchanged
    if resp.status().is_success() {
        assert_file_content(&server, "/selfmove.txt", content).await;
    }
}

#[tokio::test]
async fn test_copy_to_self() {
    let server = TestServer::with_temp_vault().await;

    let content = b"self copy test";
    server.put_ok("/selfcopy.txt", content.to_vec()).await;

    let resp = server.copy("/selfcopy.txt", "/selfcopy.txt", true).await;

    // Should either succeed as no-op or return an error
    if resp.status().is_success() {
        assert_file_content(&server, "/selfcopy.txt", content).await;
    }
}

#[tokio::test]
async fn test_move_unicode_filename() {
    let server = TestServer::with_temp_vault().await;

    let content = b"unicode filename move";
    server.put_ok("/文件.txt", content.to_vec()).await;

    let resp = server.move_("/文件.txt", "/档案.txt", false).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    eprintln!("DEBUG: Unicode MOVE status: {}, body: {}", status, body);
    assert!(
        status.is_success() || status == StatusCode::CREATED,
        "Unicode MOVE failed with status {}: {}",
        status,
        body
    );

    assert_not_found(&server, "/文件.txt").await;
    assert_file_content(&server, "/档案.txt", content).await;
}

#[tokio::test]
async fn test_copy_unicode_filename() {
    let server = TestServer::with_temp_vault().await;

    let content = b"unicode filename copy";
    server.put_ok("/原文.txt", content.to_vec()).await;

    let resp = server.copy("/原文.txt", "/复制.txt", false).await;
    assert!(resp.status().is_success() || resp.status() == StatusCode::CREATED);

    assert_file_content(&server, "/原文.txt", content).await;
    assert_file_content(&server, "/复制.txt", content).await;
}

#[tokio::test]
async fn test_move_preserves_chunk_boundaries() {
    let server = TestServer::with_temp_vault().await;

    // Exactly at chunk boundary
    let content = multi_chunk_content(2);
    let expected_hash = sha256(&content);

    server.put_ok("/boundary.bin", content).await;
    server.move_("/boundary.bin", "/moved_boundary.bin", false).await;

    let retrieved = server.get_bytes("/moved_boundary.bin").await.unwrap();
    assert_eq!(sha256(&retrieved), expected_hash);
    assert_eq!(retrieved.len(), 2 * CHUNK_SIZE);
}
