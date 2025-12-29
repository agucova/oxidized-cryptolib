//! PROPFIND and metadata tests for WebDAV backend.
//!
//! Tests directory listing, file metadata, and property retrieval:
//! - PROPFIND with depth 0 and 1
//! - File size accuracy
//! - Metadata refresh after writes
//! - Directory listing consistency

mod common;

use common::{multi_chunk_content, one_chunk_content, TestServer, CHUNK_SIZE};
use reqwest::StatusCode;

// ============================================================================
// Basic PROPFIND Tests
// ============================================================================

#[tokio::test]
async fn test_propfind_root_depth_0() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.propfind("/", "0").await;
    assert!(
        resp.status() == StatusCode::MULTI_STATUS || resp.status().is_success(),
        "PROPFIND / depth=0 failed with status {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_propfind_root_depth_1() {
    let server = TestServer::with_temp_vault().await;

    // Create some content
    server.put_ok("/file1.txt", b"content1".to_vec()).await;
    server.mkcol_ok("/subdir").await;

    let (status, body) = server.propfind_body("/", "1").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND / depth=1 failed with status {}",
        status
    );

    // Verify response contains our entries
    assert!(
        body.contains("file1.txt") || body.contains("file1"),
        "PROPFIND should list file1.txt"
    );
    assert!(
        body.contains("subdir"),
        "PROPFIND should list subdir"
    );
}

#[tokio::test]
async fn test_propfind_file() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/myfile.txt", b"file content".to_vec()).await;

    let (status, body) = server.propfind_body("/myfile.txt", "0").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND on file failed"
    );

    // Should be identified as a file (not collection)
    // Check that it doesn't have <D:collection/> in resourcetype
    assert!(
        !body.contains("<D:collection/>") && !body.contains("<D:collection />"),
        "File should not be marked as collection"
    );
}

#[tokio::test]
async fn test_propfind_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/mydir").await;

    let (status, body) = server.propfind_body("/mydir", "0").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND on directory failed"
    );

    // Should be identified as a collection
    assert!(
        body.contains("<D:collection/>") || body.contains("<D:collection />") || body.contains(":collection"),
        "Directory should be marked as collection"
    );
}

// ============================================================================
// File Size Accuracy Tests
// ============================================================================

#[tokio::test]
async fn test_propfind_size_small_file() {
    let server = TestServer::with_temp_vault().await;

    let content = b"small content";
    server.put_ok("/small.txt", content.to_vec()).await;

    let (status, body) = server.propfind_body("/small.txt", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // Check content-length in response
    let expected_size = content.len().to_string();
    assert!(
        body.contains(&expected_size) || body.contains("getcontentlength"),
        "PROPFIND should include file size"
    );
}

#[tokio::test]
async fn test_propfind_size_chunk_boundary() {
    let server = TestServer::with_temp_vault().await;

    let content = one_chunk_content();
    server.put_ok("/one_chunk.bin", content.clone()).await;

    let (status, body) = server.propfind_body("/one_chunk.bin", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // Size should be exactly CHUNK_SIZE
    let expected_size = CHUNK_SIZE.to_string();
    assert!(
        body.contains(&expected_size),
        "PROPFIND should show size {} for one chunk file, body: {}",
        expected_size,
        body
    );
}

#[tokio::test]
async fn test_propfind_size_multi_chunk() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(3);
    let expected_len = content.len();
    server.put_ok("/multi.bin", content).await;

    let (status, body) = server.propfind_body("/multi.bin", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // Size should be 3 * CHUNK_SIZE
    let expected_size = expected_len.to_string();
    assert!(
        body.contains(&expected_size),
        "PROPFIND should show size {} for multi-chunk file",
        expected_size
    );
}

// ============================================================================
// Metadata After Operations
// ============================================================================

#[tokio::test]
async fn test_propfind_after_put() {
    let server = TestServer::with_temp_vault().await;

    // Initial write
    server.put_ok("/changing.txt", b"initial".to_vec()).await;

    // Verify content was written correctly
    let content1 = server.get_bytes("/changing.txt").await.expect("Should get content");
    eprintln!("DEBUG: First GET returned {} bytes: {:?}", content1.len(), String::from_utf8_lossy(&content1));
    assert_eq!(content1.as_ref(), b"initial", "Content should be 'initial'");

    let (status1, body1) = server.propfind_body("/changing.txt", "0").await;
    assert!(status1 == StatusCode::MULTI_STATUS || status1.is_success());
    assert!(body1.contains("7"), "Initial size should be 7, body: {}", body1);

    // Overwrite with larger
    server.put_ok("/changing.txt", b"larger content here".to_vec()).await;

    // Verify content was overwritten correctly
    let content2 = server.get_bytes("/changing.txt").await.expect("Should get content");
    eprintln!("DEBUG: Second GET returned {} bytes: {:?}", content2.len(), String::from_utf8_lossy(&content2));
    assert_eq!(content2.as_ref(), b"larger content here", "Content should be updated");

    let (status2, body2) = server.propfind_body("/changing.txt", "0").await;
    assert!(status2 == StatusCode::MULTI_STATUS || status2.is_success());
    assert!(
        body2.contains("19"),
        "Updated size should be 19, body: {}",
        body2
    );
}

#[tokio::test]
async fn test_propfind_after_delete() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/todelete.txt", b"content".to_vec()).await;

    // Verify it exists
    let resp = server.propfind("/todelete.txt", "0").await;
    assert!(resp.status() == StatusCode::MULTI_STATUS || resp.status().is_success());

    // Delete it
    server.delete_ok("/todelete.txt").await;

    // Should now return 404
    let resp = server.propfind("/todelete.txt", "0").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PROPFIND after delete should return 404"
    );
}

#[tokio::test]
async fn test_propfind_list_after_create() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/listtest").await;

    // Check it's empty
    let (status1, _body1) = server.propfind_body("/listtest", "1").await;
    assert!(status1 == StatusCode::MULTI_STATUS || status1.is_success());

    // Add a file
    server.put_ok("/listtest/newfile.txt", b"new".to_vec()).await;

    // Check it appears in listing
    let (status2, body2) = server.propfind_body("/listtest", "1").await;
    assert!(status2 == StatusCode::MULTI_STATUS || status2.is_success());
    assert!(
        body2.contains("newfile.txt") || body2.contains("newfile"),
        "New file should appear in listing"
    );
}

#[tokio::test]
async fn test_propfind_list_after_delete() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/deletelist").await;
    server.put_ok("/deletelist/file.txt", b"content".to_vec()).await;

    // Verify file is in listing
    let (_, body1) = server.propfind_body("/deletelist", "1").await;
    assert!(body1.contains("file.txt") || body1.contains("file"));

    // Delete the file
    server.delete_ok("/deletelist/file.txt").await;

    // Verify file is no longer in listing
    let (_, body2) = server.propfind_body("/deletelist", "1").await;
    assert!(
        !body2.contains("file.txt"),
        "Deleted file should not appear in listing"
    );
}

// ============================================================================
// Directory Listing Tests
// ============================================================================

#[tokio::test]
async fn test_propfind_multiple_entries() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/multi").await;
    server.put_ok("/multi/a.txt", b"a".to_vec()).await;
    server.put_ok("/multi/b.txt", b"b".to_vec()).await;
    server.put_ok("/multi/c.txt", b"c".to_vec()).await;
    server.mkcol_ok("/multi/subdir").await;

    let (status, body) = server.propfind_body("/multi", "1").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // All entries should be listed
    assert!(body.contains("a.txt") || body.contains(">a<"));
    assert!(body.contains("b.txt") || body.contains(">b<"));
    assert!(body.contains("c.txt") || body.contains(">c<"));
    assert!(body.contains("subdir"));
}

#[tokio::test]
async fn test_propfind_empty_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/emptydir").await;

    let (status, body) = server.propfind_body("/emptydir", "1").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // Should contain the directory itself but no children
    // The response element count should be minimal
    let response_count = body.matches("<D:response>").count()
        + body.matches("<response>").count();
    assert!(
        response_count <= 2,
        "Empty directory should have minimal responses (got {})",
        response_count
    );
}

#[tokio::test]
async fn test_propfind_nested_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/outer").await;
    server.mkcol_ok("/outer/inner").await;
    server.put_ok("/outer/inner/deep.txt", b"deep".to_vec()).await;

    // Depth 1 on /outer should show /outer/inner but not /outer/inner/deep.txt
    let (status, body) = server.propfind_body("/outer", "1").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    assert!(body.contains("inner"), "Should list inner directory");
    // deep.txt should NOT appear with depth=1
    assert!(
        !body.contains("deep.txt"),
        "Depth 1 should not show nested files"
    );
}

// ============================================================================
// Special Cases
// ============================================================================

#[tokio::test]
async fn test_propfind_unicode_filename() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/テスト.txt", b"content".to_vec()).await;

    let (status, body) = server.propfind_body("/テスト.txt", "0").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND on unicode filename failed"
    );

    // Should be accessible
    assert!(body.contains("テスト") || body.contains("%E3%83"), "Response should contain filename");
}

#[tokio::test]
async fn test_propfind_with_spaces() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file with spaces.txt", b"content".to_vec()).await;

    let (status, _body) = server.propfind_body("/file with spaces.txt", "0").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND on filename with spaces failed"
    );
}

#[tokio::test]
async fn test_propfind_root_empty_vault() {
    let server = TestServer::with_temp_vault().await;

    // Fresh vault - PROPFIND root with depth 1
    let (status, body) = server.propfind_body("/", "1").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND on empty vault root failed"
    );

    // Should contain at least the root itself
    assert!(
        body.contains("<D:response>") || body.contains("<response>"),
        "Response should contain at least root entry"
    );
}

// ============================================================================
// Resource Type Identification
// ============================================================================

#[tokio::test]
async fn test_propfind_resourcetype_file() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/regularfile.txt", b"content".to_vec()).await;

    let (status, body) = server.propfind_body("/regularfile.txt", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // File should have empty resourcetype or no collection marker
    assert!(
        body.contains("<D:resourcetype/>")
            || body.contains("<D:resourcetype />")
            || body.contains("<resourcetype/>")
            || !body.contains("collection"),
        "File should have empty resourcetype (no collection)"
    );
}

#[tokio::test]
async fn test_propfind_resourcetype_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/collectiondir").await;

    let (status, body) = server.propfind_body("/collectiondir", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // Directory should be marked as collection
    assert!(
        body.contains("collection"),
        "Directory should be marked as collection in resourcetype"
    );
}
