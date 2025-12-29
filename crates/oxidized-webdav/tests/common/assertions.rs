//! Custom assertions for WebDAV integration tests.

use crate::common::TestServer;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

/// Assert that a file exists and has the expected content.
pub async fn assert_file_content(server: &TestServer, path: &str, expected: &[u8]) {
    let result = server.get_bytes(path).await;
    match result {
        Ok(actual) => {
            assert_eq!(
                actual.as_ref(),
                expected,
                "File content mismatch at {}: expected {} bytes, got {} bytes",
                path,
                expected.len(),
                actual.len()
            );
        }
        Err((status, body)) => {
            panic!(
                "Failed to read file {}: status={}, body={}",
                path, status, body
            );
        }
    }
}

/// Assert that a file exists and its SHA-256 hash matches.
///
/// More efficient than comparing full content for large files.
pub async fn assert_file_hash(server: &TestServer, path: &str, expected_hash: &[u8; 32]) {
    let result = server.get_bytes(path).await;
    match result {
        Ok(actual) => {
            let actual_hash = sha256(&actual);
            assert_eq!(
                &actual_hash, expected_hash,
                "File hash mismatch at {}: expected {:x?}, got {:x?}",
                path, expected_hash, actual_hash
            );
        }
        Err((status, body)) => {
            panic!(
                "Failed to read file {}: status={}, body={}",
                path, status, body
            );
        }
    }
}

/// Assert that a path returns 404 Not Found.
pub async fn assert_not_found(server: &TestServer, path: &str) {
    let resp = server.get(path).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Expected 404 for {}, got {}",
        path,
        resp.status()
    );
}

/// Assert that a response has a specific status code.
pub fn assert_status(actual: StatusCode, expected: StatusCode, context: &str) {
    assert_eq!(
        actual, expected,
        "{}: expected status {}, got {}",
        context, expected, actual
    );
}

/// Assert that a directory contains exactly the expected entries.
///
/// Parses a PROPFIND depth=1 response and checks for entry hrefs.
pub async fn assert_dir_entries(server: &TestServer, path: &str, expected: &[&str]) {
    let (status, body) = server.propfind_body(path, "1").await;
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "PROPFIND {} failed with status {}: {}",
        path,
        status,
        body
    );

    // Parse the XML response to extract hrefs
    let entries = extract_hrefs_from_propfind(&body, path);

    let expected_set: std::collections::HashSet<String> = expected.iter().map(|s| s.to_string()).collect();
    let mut actual_set: std::collections::HashSet<String> = entries.into_iter().collect();

    // Remove the directory itself from actual (PROPFIND includes it)
    let normalized_path = path.trim_end_matches('/');
    actual_set.remove(normalized_path);
    actual_set.remove(&format!("{}/", normalized_path));

    // Compare
    let missing: Vec<_> = expected_set.difference(&actual_set).collect();
    let extra: Vec<_> = actual_set.difference(&expected_set).collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "Directory {} entries mismatch:\n  missing: {:?}\n  extra: {:?}\n  expected: {:?}\n  actual: {:?}",
        path,
        missing,
        extra,
        expected,
        actual_set
    );
}

/// Assert that a directory exists (PROPFIND returns success).
pub async fn assert_dir_exists(server: &TestServer, path: &str) {
    let resp = server.propfind(path, "0").await;
    let status = resp.status();
    assert!(
        status == StatusCode::MULTI_STATUS || status.is_success(),
        "Expected directory {} to exist, but got status {}",
        path,
        status
    );
}

/// Calculate SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Extract href values from a PROPFIND XML response.
///
/// This is a simple parser - doesn't handle all XML edge cases but works for testing.
fn extract_hrefs_from_propfind(xml: &str, _base_path: &str) -> Vec<String> {
    let mut hrefs = Vec::new();

    // Simple regex-free parsing: look for <D:href> or <href> tags
    for line in xml.lines() {
        if let Some(start) = line.find("<D:href>").or_else(|| line.find("<href>")) {
            let tag_end = line[start..].find('>').unwrap() + 1;
            let content_start = start + tag_end;
            if let Some(end) = line[content_start..].find('<') {
                let href = &line[content_start..content_start + end];
                // Decode URL encoding
                let decoded = urlencoding_decode(href);
                hrefs.push(decoded);
            }
        }
    }

    hrefs
}

/// Simple URL decoding (handles %XX escapes).
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello world");
        // Known hash for "hello world"
        let expected: [u8; 32] = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
            0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
            0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_urlencoding_decode() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("foo%2Fbar"), "foo/bar");
        assert_eq!(urlencoding_decode("normal"), "normal");
    }
}
