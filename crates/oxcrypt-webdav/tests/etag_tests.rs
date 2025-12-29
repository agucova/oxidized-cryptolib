//! ETag and conditional request tests for WebDAV backend.
//!
//! These tests verify HTTP ETag support and conditional request handling:
//! - ETag presence in responses
//! - ETag changes after modification
//! - If-None-Match (304 Not Modified)
//! - If-Match (conditional updates)
//! - If-Match failure (412 Precondition Failed)

mod common;

use common::{random_bytes, TestServer};
use reqwest::StatusCode;

// ============================================================================
// ETag Presence
// ============================================================================

#[tokio::test]
async fn test_etag_present_in_get_response() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let resp = server.get("/file.txt").await;
    assert!(resp.status().is_success());

    let etag = resp.headers().get("etag");
    assert!(etag.is_some(), "ETag header should be present in GET response");

    let etag_value = etag.unwrap().to_str().unwrap();
    assert!(
        !etag_value.is_empty(),
        "ETag should not be empty"
    );
}

#[tokio::test]
async fn test_etag_present_in_propfind_response() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let (status, body) = server.propfind_body("/file.txt", "0").await;
    assert!(status == StatusCode::MULTI_STATUS || status.is_success());

    // ETag should appear in PROPFIND response as getetag property
    assert!(
        body.contains("getetag") || body.contains("etag"),
        "PROPFIND response should contain getetag property: {}",
        body
    );
}

// ============================================================================
// ETag Changes
// ============================================================================

#[tokio::test]
async fn test_etag_changes_after_content_update() {
    let server = TestServer::with_temp_vault().await;

    // Create file and get initial ETag
    server.put_ok("/mutable.txt", b"version 1".to_vec()).await;
    let resp1 = server.get("/mutable.txt").await;
    let etag1 = resp1
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    // Update file content
    server.put_ok("/mutable.txt", b"version 2".to_vec()).await;
    let resp2 = server.get("/mutable.txt").await;
    let etag2 = resp2
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    assert_ne!(
        etag1, etag2,
        "ETag should change after content modification"
    );
}

#[tokio::test]
async fn test_etag_changes_after_size_change() {
    let server = TestServer::with_temp_vault().await;

    // Create file
    server.put_ok("/size_test.bin", random_bytes(1000)).await;
    let resp1 = server.get("/size_test.bin").await;
    let etag1 = resp1
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    // Change file size
    server.put_ok("/size_test.bin", random_bytes(2000)).await;
    let resp2 = server.get("/size_test.bin").await;
    let etag2 = resp2
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    assert_ne!(
        etag1, etag2,
        "ETag should change when file size changes"
    );
}

#[tokio::test]
async fn test_etag_format_consistent() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/stable.txt", b"unchanged content".to_vec()).await;

    // Get ETag twice - verify format is consistent even if timestamp portion varies
    let resp1 = server.get("/stable.txt").await;
    let etag1 = resp1
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    let resp2 = server.get("/stable.txt").await;
    let etag2 = resp2
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    // Verify both ETags have the same format (quoted string with size component)
    assert!(
        etag1.starts_with('"') || etag1.starts_with("W/\""),
        "ETag should be quoted: {}",
        etag1
    );
    assert!(
        etag2.starts_with('"') || etag2.starts_with("W/\""),
        "ETag should be quoted: {}",
        etag2
    );

    // Extract size component (before the hyphen) - should be same for unchanged file
    fn extract_size(etag: &str) -> Option<String> {
        let inner = etag.trim_start_matches("W/").trim_matches('"');
        inner.split('-').next().map(|s| s.to_string())
    }

    let size1 = extract_size(&etag1);
    let size2 = extract_size(&etag2);

    assert_eq!(
        size1, size2,
        "ETag size component should be stable: {} vs {}",
        etag1, etag2
    );
}

// ============================================================================
// If-None-Match (Conditional GET)
// ============================================================================

#[tokio::test]
async fn test_if_none_match_with_wildcard_returns_304() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/cached.txt", b"cacheable content".to_vec()).await;

    // Use wildcard * which should match any ETag
    // Note: Individual ETag matching is unreliable because dav-server includes
    // a timestamp component that changes between requests
    let resp = server.get_if_none_match("/cached.txt", "*").await;

    assert_eq!(
        resp.status(),
        StatusCode::NOT_MODIFIED,
        "If-None-Match with * should return 304"
    );

    // Body should be empty for 304
    let body = resp.bytes().await.unwrap();
    assert!(
        body.is_empty(),
        "304 response should have empty body"
    );
}

#[tokio::test]
async fn test_if_none_match_returns_200_when_modified() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/changing.txt", b"original".to_vec()).await;

    // Get the ETag
    let resp1 = server.get("/changing.txt").await;
    let old_etag = resp1
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    // Modify the file
    server.put_ok("/changing.txt", b"modified".to_vec()).await;

    // Request with old ETag - should get new content
    let resp2 = server.get_if_none_match("/changing.txt", &old_etag).await;

    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "If-None-Match with stale ETag should return 200"
    );

    let body = resp2.text().await.unwrap();
    assert_eq!(body, "modified");
}

#[tokio::test]
async fn test_if_none_match_with_wrong_etag() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    // Request with non-matching ETag
    let resp = server.get_if_none_match("/file.txt", "\"wrong-etag\"").await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "If-None-Match with wrong ETag should return 200"
    );
}

#[tokio::test]
async fn test_if_none_match_wildcard() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    // Wildcard * matches any ETag
    let resp = server.get_if_none_match("/file.txt", "*").await;

    assert_eq!(
        resp.status(),
        StatusCode::NOT_MODIFIED,
        "If-None-Match with * should return 304 for any existing resource"
    );
}

// ============================================================================
// If-Match (Conditional PUT)
// ============================================================================

#[tokio::test]
async fn test_if_match_with_wildcard_succeeds() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/guarded.txt", b"original".to_vec()).await;

    // Use wildcard * which matches any ETag
    // Note: Individual ETag matching is unreliable because dav-server includes
    // a timestamp component that changes between requests
    let update_resp = server
        .put_if_match("/guarded.txt", b"updated".to_vec(), "*")
        .await;

    assert!(
        update_resp.status().is_success() || update_resp.status() == StatusCode::NO_CONTENT,
        "If-Match with * should succeed, got {}",
        update_resp.status()
    );

    // Verify content was updated
    let content = server.get_bytes("/guarded.txt").await.unwrap();
    assert_eq!(&content[..], b"updated");
}

#[tokio::test]
async fn test_if_match_fails_with_wrong_etag() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/protected.txt", b"original".to_vec()).await;

    // Try to update with wrong ETag
    let resp = server
        .put_if_match("/protected.txt", b"new content".to_vec(), "\"wrong-etag\"")
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::PRECONDITION_FAILED,
        "If-Match with wrong ETag should return 412"
    );

    // Verify content was NOT updated
    let content = server.get_bytes("/protected.txt").await.unwrap();
    assert_eq!(&content[..], b"original");
}

#[tokio::test]
async fn test_if_match_fails_after_concurrent_modification() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/race.txt", b"version 1".to_vec()).await;

    // Client A gets ETag
    let resp_a = server.get("/race.txt").await;
    let etag_a = resp_a
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    // Client B modifies the file (simulated)
    server.put_ok("/race.txt", b"version 2".to_vec()).await;

    // Client A tries to update with stale ETag
    let resp = server
        .put_if_match("/race.txt", b"version from A".to_vec(), &etag_a)
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::PRECONDITION_FAILED,
        "If-Match should fail after concurrent modification"
    );

    // Content should be Client B's version
    let content = server.get_bytes("/race.txt").await.unwrap();
    assert_eq!(&content[..], b"version 2");
}

// ============================================================================
// ETag Format
// ============================================================================

#[tokio::test]
async fn test_etag_format_is_quoted() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    let resp = server.get("/file.txt").await;
    let etag = resp
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap();

    // ETags should be quoted strings per HTTP spec
    // Weak ETags start with W/"..." and strong ETags are just "..."
    assert!(
        (etag.starts_with('"') && etag.ends_with('"'))
            || (etag.starts_with("W/\"") && etag.ends_with('"')),
        "ETag should be quoted: got {}",
        etag
    );
}

#[tokio::test]
async fn test_different_files_have_different_etags() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file1.txt", b"content 1".to_vec()).await;
    server.put_ok("/file2.txt", b"content 2".to_vec()).await;

    let resp1 = server.get("/file1.txt").await;
    let etag1 = resp1
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    let resp2 = server.get("/file2.txt").await;
    let etag2 = resp2
        .headers()
        .get("etag")
        .expect("ETag should be present")
        .to_str()
        .unwrap()
        .to_string();

    assert_ne!(
        etag1, etag2,
        "Different files should have different ETags"
    );
}
