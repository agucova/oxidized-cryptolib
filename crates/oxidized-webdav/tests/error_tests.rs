//! Error handling tests for WebDAV backend.
//!
//! These tests verify correct HTTP status codes and error semantics:
//! - 404 Not Found for missing resources
//! - 409 Conflict for missing parent directories
//! - 405 Method Not Allowed for invalid operations
//! - Security: path traversal prevention

mod common;

use common::TestServer;
use reqwest::StatusCode;

// ============================================================================
// 404 Not Found Tests
// ============================================================================

#[tokio::test]
async fn test_get_nonexistent_returns_404() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.get("/does_not_exist.txt").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET on nonexistent file should return 404"
    );
}

#[tokio::test]
async fn test_get_nonexistent_deep_path() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.get("/a/b/c/d/e/f/missing.txt").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET on deep nonexistent path should return 404"
    );
}

#[tokio::test]
async fn test_delete_nonexistent_file() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.delete("/nonexistent.txt").await;
    // WebDAV spec allows either 404 or 204 for deleting non-existent
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::NO_CONTENT,
        "DELETE on nonexistent should return 404 or 204, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_propfind_nonexistent() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.propfind("/nonexistent_dir", "0").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PROPFIND on nonexistent should return 404"
    );
}

// ============================================================================
// 409 Conflict Tests (Missing Parent)
// ============================================================================

#[tokio::test]
async fn test_mkcol_no_parent_returns_409() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.mkcol("/nonexistent_parent/newdir").await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "MKCOL with missing parent should return 409"
    );
}

#[tokio::test]
async fn test_mkcol_deep_no_parent_returns_409() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.mkcol("/a/b/c/d/e").await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "MKCOL on deep path with missing parents should return 409"
    );
}

#[tokio::test]
async fn test_put_no_parent_behavior() {
    let server = TestServer::with_temp_vault().await;

    // PUT to a path where parent doesn't exist
    // WebDAV behavior varies - some servers auto-create parents, others return 409
    let resp = server.put("/missing_parent/file.txt", b"content".to_vec()).await;

    // We accept either 409 (strict) or 2xx (auto-create parent)
    let status = resp.status();
    assert!(
        status == StatusCode::CONFLICT || status.is_success(),
        "PUT with missing parent should return 409 or succeed, got {}",
        status
    );
}

// ============================================================================
// 405 Method Not Allowed Tests
// ============================================================================

#[tokio::test]
async fn test_mkcol_on_existing_dir_returns_405() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/existingdir").await;

    let resp = server.mkcol("/existingdir").await;
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "MKCOL on existing directory should return 405"
    );
}

#[tokio::test]
async fn test_mkcol_on_existing_file_returns_405() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/existingfile.txt", b"content".to_vec()).await;

    let resp = server.mkcol("/existingfile.txt").await;
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "MKCOL on existing file should return 405"
    );
}

#[tokio::test]
async fn test_put_to_directory_fails() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/mydir").await;

    // Attempting to PUT content to a directory path
    let resp = server.put("/mydir", b"content".to_vec()).await;

    // Should fail - can't write to a directory
    assert!(
        !resp.status().is_success() || resp.status() == StatusCode::METHOD_NOT_ALLOWED,
        "PUT to directory should fail or return 405, got {}",
        resp.status()
    );
}

// ============================================================================
// Move/Copy Error Tests
// ============================================================================

#[tokio::test]
async fn test_move_nonexistent_source_returns_404() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.move_("/nonexistent.txt", "/destination.txt", false).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "MOVE of nonexistent source should return 404"
    );
}

#[tokio::test]
async fn test_copy_nonexistent_source_returns_404() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.copy("/nonexistent.txt", "/destination.txt", false).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "COPY of nonexistent source should return 404"
    );
}

#[tokio::test]
async fn test_move_no_overwrite_existing_destination() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/source.txt", b"source".to_vec()).await;
    server.put_ok("/destination.txt", b"dest".to_vec()).await;

    // Move with overwrite=false when destination exists
    let resp = server.move_("/source.txt", "/destination.txt", false).await;

    // Should fail with 412 Precondition Failed
    assert_eq!(
        resp.status(),
        StatusCode::PRECONDITION_FAILED,
        "MOVE with Overwrite: F and existing dest should return 412, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_copy_no_overwrite_existing_destination() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/source.txt", b"source".to_vec()).await;
    server.put_ok("/destination.txt", b"dest".to_vec()).await;

    let resp = server.copy("/source.txt", "/destination.txt", false).await;

    assert_eq!(
        resp.status(),
        StatusCode::PRECONDITION_FAILED,
        "COPY with Overwrite: F and existing dest should return 412, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_move_to_nonexistent_parent() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/source.txt", b"content".to_vec()).await;

    let resp = server.move_("/source.txt", "/missing_parent/dest.txt", true).await;

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "MOVE to path with missing parent should return 409"
    );
}

// ============================================================================
// Directory Deletion Error Tests
// ============================================================================

#[tokio::test]
async fn test_delete_nonempty_dir_behavior() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/nonempty").await;
    server.put_ok("/nonempty/file.txt", b"content".to_vec()).await;

    let resp = server.delete("/nonempty").await;

    // WebDAV allows either:
    // - 403/409/conflict if recursive delete not supported
    // - 204 if recursive delete succeeds
    let status = resp.status();
    assert!(
        status == StatusCode::FORBIDDEN
            || status == StatusCode::CONFLICT
            || status == StatusCode::NO_CONTENT
            || status.is_success(),
        "DELETE on non-empty dir should return 403/409 or succeed recursively, got {}",
        status
    );
}

// ============================================================================
// Security: Path Traversal Prevention
// ============================================================================

#[tokio::test]
async fn test_path_traversal_parent_dir() {
    let server = TestServer::with_temp_vault().await;

    // Attempt to escape vault via ../
    let resp = server.get("/../../../etc/passwd").await;

    // Should either return 404 (path normalized or blocked) or 400 (bad request)
    let status = resp.status();
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "Path traversal attempt should be blocked, got {}",
        status
    );
}

#[tokio::test]
async fn test_path_traversal_encoded() {
    let server = TestServer::with_temp_vault().await;

    // URL-encoded path traversal
    let resp = server.get("/..%2F..%2F..%2Fetc%2Fpasswd").await;

    let status = resp.status();
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "Encoded path traversal should be blocked, got {}",
        status
    );
}

#[tokio::test]
async fn test_path_traversal_put() {
    let server = TestServer::with_temp_vault().await;

    let resp = server.put("/../../../tmp/malicious", b"evil".to_vec()).await;

    let status = resp.status();
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::CONFLICT,
        "PUT with path traversal should be blocked, got {}",
        status
    );
}

#[tokio::test]
async fn test_path_with_null_byte() {
    let server = TestServer::with_temp_vault().await;

    // Null byte injection attempt
    let resp = server.get("/file%00.txt").await;

    // Should be blocked or return not found
    let status = resp.status();
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "Null byte in path should be blocked, got {}",
        status
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_get_root_as_file() {
    let server = TestServer::with_temp_vault().await;

    // GET on root should not return file content (it's a directory)
    let resp = server.get("/").await;

    // Should either redirect to PROPFIND or return some kind of listing/error
    // Definitely shouldn't be 200 with file content
    let status = resp.status();
    assert!(
        status != StatusCode::PARTIAL_CONTENT,
        "GET / should not return partial content like a file"
    );
}

#[tokio::test]
async fn test_empty_path() {
    let server = TestServer::with_temp_vault().await;

    // Empty path behavior
    let resp = server.get("").await;
    // Should handle gracefully (redirect to / or return root listing)
    // Just verifying no crash/panic
    let _ = resp.status();
}

#[tokio::test]
async fn test_double_slash_in_path() {
    let server = TestServer::with_temp_vault().await;

    // Double slashes should be normalized
    server.put_ok("/test.txt", b"content".to_vec()).await;

    let resp = server.get("//test.txt").await;
    // Should work (normalized) or fail gracefully
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "Double slash should be normalized or return 404, got {}",
        status
    );
}

#[tokio::test]
async fn test_very_deep_path() {
    let server = TestServer::with_temp_vault().await;

    // Very deep nesting
    let deep_path = format!("/{}", "a/".repeat(50));

    let resp = server.get(&deep_path).await;
    // Should handle without panic
    let status = resp.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "Very deep path should return 404 or 400, got {}",
        status
    );
}

#[tokio::test]
async fn test_special_webdav_paths() {
    let server = TestServer::with_temp_vault().await;

    // Paths that might have special meaning in WebDAV
    for path in &[
        "/.DAV/",
        "/_vti_bin/",
        "/DAV:",
        "/\\",
    ] {
        let resp = server.get(path).await;
        // Should not panic, return some status
        let _ = resp.status();
    }
}

// ============================================================================
// Content-Length and Transfer Issues
// ============================================================================

#[tokio::test]
async fn test_put_zero_content_length() {
    let server = TestServer::with_temp_vault().await;

    // PUT with empty body and Content-Length: 0
    let resp = server.put("/zero_length.txt", Vec::new()).await;

    // Should create empty file or handle gracefully
    let status = resp.status();
    assert!(
        status.is_success() || status == StatusCode::CREATED,
        "PUT with zero content-length should succeed, got {}",
        status
    );
}
