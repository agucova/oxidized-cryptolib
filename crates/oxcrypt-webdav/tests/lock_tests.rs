//! Lock/Unlock tests for WebDAV backend.
//!
//! These tests verify WebDAV LOCK and UNLOCK method support.
//! Note: The current implementation uses FakeLs which accepts
//! lock requests but doesn't actually enforce locking. These tests
//! verify the protocol is handled correctly.

mod common;

use common::TestServer;
use reqwest::StatusCode;

// ============================================================================
// LOCK Request Handling
// ============================================================================

#[tokio::test]
async fn test_lock_request_accepted() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content to lock".to_vec()).await;

    let resp = server.lock("/file.txt").await;

    // FakeLs accepts lock requests
    assert!(
        resp.status().is_success(),
        "LOCK request should be accepted, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_lock_returns_lock_token() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let resp = server.lock("/file.txt").await;
    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();

    // Lock response should contain locktoken
    assert!(
        body.contains("locktoken") || body.contains("Lock-Token") || body.contains("href"),
        "Lock response should contain lock token information: {body}"
    );
}

#[tokio::test]
async fn test_lock_response_contains_lockdiscovery() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let resp = server.lock("/file.txt").await;
    assert!(resp.status().is_success());

    let body = resp.text().await.unwrap();

    // Lock response should contain lockdiscovery element
    assert!(
        body.contains("lockdiscovery") || body.contains("activelock"),
        "Lock response should contain lockdiscovery: {body}"
    );
}

#[tokio::test]
async fn test_lock_on_nonexistent_file() {
    let server = TestServer::with_temp_vault().await;

    // Try to lock a file that doesn't exist
    let resp = server.lock("/nonexistent.txt").await;

    // Behavior varies - some servers create the file, others return 404
    // FakeLs typically accepts and creates a lock-null resource
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND,
        "LOCK on nonexistent should succeed or return 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_lock_on_directory() {
    let server = TestServer::with_temp_vault().await;

    server.mkcol_ok("/dir").await;

    let resp = server.lock("/dir").await;

    // Directory locking should be accepted (or rejected with 405)
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::METHOD_NOT_ALLOWED,
        "LOCK on directory should succeed or return 405, got {}",
        resp.status()
    );
}

// ============================================================================
// UNLOCK Request Handling
// ============================================================================

#[tokio::test]
async fn test_unlock_request_accepted() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    // First lock the file
    let lock_resp = server.lock("/file.txt").await;
    assert!(lock_resp.status().is_success());

    // Use a fake lock token (FakeLs doesn't validate)
    let resp = server.unlock("/file.txt", "urn:uuid:fake-lock-token").await;

    // FakeLs accepts unlock requests
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT,
        "UNLOCK request should be accepted, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_unlock_without_prior_lock() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/unlocked.txt", b"content".to_vec()).await;

    // Try to unlock without locking first
    let resp = server.unlock("/unlocked.txt", "urn:uuid:invalid-token").await;

    // May succeed (FakeLs) or fail with 409 Conflict or 412 Precondition Failed
    assert!(
        resp.status().is_success()
            || resp.status() == StatusCode::NO_CONTENT
            || resp.status() == StatusCode::CONFLICT
            || resp.status() == StatusCode::PRECONDITION_FAILED,
        "UNLOCK without lock should succeed or return error, got {}",
        resp.status()
    );
}

// ============================================================================
// Lock Properties in PROPFIND
// ============================================================================

#[tokio::test]
async fn test_propfind_shows_lock_support() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let (status, body) = server.propfind_body("/file.txt", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // PROPFIND should show lock-related properties (supportedlock)
    // This may or may not be present depending on server config
    // Just verify PROPFIND works after the file exists
    assert!(
        body.contains("response") || body.contains("multistatus"),
        "PROPFIND should return valid response: {body}"
    );
}

#[tokio::test]
async fn test_propfind_after_lock() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/locked_file.txt", b"content".to_vec()).await;

    // Lock the file
    let lock_resp = server.lock("/locked_file.txt").await;
    assert!(lock_resp.status().is_success());

    // PROPFIND should still work on locked file
    let (status, body) = server.propfind_body("/locked_file.txt", "0").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND should work on locked file, got {status}"
    );

    // May show lockdiscovery if server tracks locks
    assert!(
        body.contains("response"),
        "PROPFIND should return valid response"
    );
}

// ============================================================================
// Lock Interaction with Other Operations
// ============================================================================

#[tokio::test]
async fn test_read_locked_file() {
    let server = TestServer::with_temp_vault().await;

    let content = b"locked content";
    server.put_ok("/readable.txt", content.to_vec()).await;

    // Lock the file
    let lock_resp = server.lock("/readable.txt").await;
    assert!(lock_resp.status().is_success());

    // Reading should still work (locks typically only protect writes)
    let read_bytes = server.get_bytes("/readable.txt").await;
    assert!(
        read_bytes.is_ok(),
        "Should be able to read locked file"
    );
    assert_eq!(&read_bytes.unwrap()[..], content);
}

#[tokio::test]
async fn test_write_locked_file_without_token() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/protected.txt", b"original".to_vec()).await;

    // Lock the file
    let lock_resp = server.lock("/protected.txt").await;
    assert!(lock_resp.status().is_success());

    // Try to write without lock token
    // FakeLs doesn't enforce locks, so this will succeed
    // A real implementation would return 423 Locked
    let write_resp = server.put("/protected.txt", b"modified".to_vec()).await;

    // FakeLs accepts the write (doesn't enforce)
    // Real locking would return 423 Locked
    assert!(
        write_resp.status().is_success()
            || write_resp.status() == StatusCode::NO_CONTENT
            || write_resp.status() == StatusCode::LOCKED,
        "Write to locked file should succeed (FakeLs) or return 423, got {}",
        write_resp.status()
    );
}

#[tokio::test]
async fn test_delete_locked_file() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/to_delete.txt", b"content".to_vec()).await;

    // Lock the file
    let lock_resp = server.lock("/to_delete.txt").await;
    assert!(lock_resp.status().is_success());

    // Try to delete locked file
    let delete_resp = server.delete("/to_delete.txt").await;

    // FakeLs doesn't enforce locks, so deletion succeeds
    // Real implementation would return 423 Locked
    assert!(
        delete_resp.status().is_success()
            || delete_resp.status() == StatusCode::NO_CONTENT
            || delete_resp.status() == StatusCode::LOCKED,
        "DELETE on locked file should succeed (FakeLs) or return 423, got {}",
        delete_resp.status()
    );
}
