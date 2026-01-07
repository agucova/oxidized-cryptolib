//! Range request tests for WebDAV backend.
//!
//! These tests verify HTTP Range header support for partial content retrieval:
//! - First N bytes
//! - Middle of file (including chunk boundaries)
//! - Last N bytes (suffix range)
//! - Multi-chunk spanning ranges
//! - Invalid/unsatisfiable ranges

mod common;

use common::{multi_chunk_content, random_bytes, TestServer, CHUNK_SIZE};
use reqwest::StatusCode;

// ============================================================================
// Basic Range Requests
// ============================================================================

#[tokio::test]
async fn test_range_first_n_bytes() {
    let server = TestServer::with_temp_vault().await;

    // Create a file larger than one chunk
    let content = multi_chunk_content(3); // 96KB (3 * 32KB chunks)
    server.put_ok("/large.bin", content.clone()).await;

    // Request first 1000 bytes
    let resp = server.get_range("/large.bin", "bytes=0-999").await;

    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "Expected 206 Partial Content"
    );

    // Check Content-Range header
    let content_range = resp
        .headers()
        .get("content-range")
        .expect("Missing Content-Range header")
        .to_str()
        .unwrap();
    assert!(
        content_range.starts_with("bytes 0-999/"),
        "Content-Range should indicate bytes 0-999"
    );

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 1000);
    assert_eq!(&bytes[..], &content[0..1000]);
}

#[tokio::test]
async fn test_range_middle_of_file() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(3);
    server.put_ok("/large.bin", content.clone()).await;

    // Request bytes from the middle
    let start = 10000;
    let end = 20000;
    let range = format!("bytes={}-{}", start, end - 1);
    let resp = server.get_range("/large.bin", &range).await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), end - start);
    assert_eq!(&bytes[..], &content[start..end]);
}

#[tokio::test]
async fn test_range_last_n_bytes() {
    let server = TestServer::with_temp_vault().await;

    let content = random_bytes(50000);
    server.put_ok("/file.bin", content.clone()).await;

    // Request last 500 bytes using suffix range
    let resp = server.get_range("/file.bin", "bytes=-500").await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 500);
    assert_eq!(&bytes[..], &content[content.len() - 500..]);
}

#[tokio::test]
async fn test_range_from_offset_to_end() {
    let server = TestServer::with_temp_vault().await;

    let content = random_bytes(10000);
    server.put_ok("/file.bin", content.clone()).await;

    // Request from offset 8000 to end (open-ended range)
    let resp = server.get_range("/file.bin", "bytes=8000-").await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 2000);
    assert_eq!(&bytes[..], &content[8000..]);
}

// ============================================================================
// Chunk Boundary Range Requests
// ============================================================================

#[tokio::test]
async fn test_range_spanning_chunk_boundary() {
    let server = TestServer::with_temp_vault().await;

    // Create content spanning multiple chunks
    let content = multi_chunk_content(3);
    server.put_ok("/multi_chunk.bin", content.clone()).await;

    // Request bytes spanning the first chunk boundary (CHUNK_SIZE = 32768)
    let start = CHUNK_SIZE - 1000;
    let end = CHUNK_SIZE + 1000;
    let range = format!("bytes={}-{}", start, end - 1);
    let resp = server.get_range("/multi_chunk.bin", &range).await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 2000);
    assert_eq!(&bytes[..], &content[start..end]);
}

#[tokio::test]
async fn test_range_spanning_multiple_chunks() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(4); // 4 chunks = 128KB
    server.put_ok("/big.bin", content.clone()).await;

    // Request range spanning chunks 1, 2, and part of 3
    let start = CHUNK_SIZE / 2; // Middle of chunk 0
    let end = CHUNK_SIZE * 3 - 1000; // Near end of chunk 2
    let range = format!("bytes={}-{}", start, end - 1);
    let resp = server.get_range("/big.bin", &range).await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), end - start);
    assert_eq!(&bytes[..], &content[start..end]);
}

#[tokio::test]
async fn test_range_exact_chunk() {
    let server = TestServer::with_temp_vault().await;

    let content = multi_chunk_content(3);
    server.put_ok("/chunked.bin", content.clone()).await;

    // Request exactly the second chunk
    let start = CHUNK_SIZE;
    let end = CHUNK_SIZE * 2;
    let range = format!("bytes={}-{}", start, end - 1);
    let resp = server.get_range("/chunked.bin", &range).await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), CHUNK_SIZE);
    assert_eq!(&bytes[..], &content[start..end]);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_range_single_byte() {
    let server = TestServer::with_temp_vault().await;

    let content = b"Hello, World!";
    server.put_ok("/hello.txt", content.to_vec()).await;

    // Request single byte
    let resp = server.get_range("/hello.txt", "bytes=7-7").await;

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 1);
    assert_eq!(bytes[0], b'W');
}

#[tokio::test]
async fn test_range_entire_file() {
    let server = TestServer::with_temp_vault().await;

    let content = random_bytes(5000);
    server.put_ok("/file.bin", content.clone()).await;

    // Request entire file via range
    let range = format!("bytes=0-{}", content.len() - 1);
    let resp = server.get_range("/file.bin", &range).await;

    // Could be 200 or 206 depending on server implementation
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::PARTIAL_CONTENT,
        "Expected 200 or 206, got {}",
        resp.status()
    );

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), content.len());
    assert_eq!(&bytes[..], &content[..]);
}

#[tokio::test]
async fn test_range_empty_file() {
    let server = TestServer::with_temp_vault().await;

    // Create empty file
    server.put_ok("/empty.bin", Vec::new()).await;

    // Any range on empty file should fail
    let resp = server.get_range("/empty.bin", "bytes=0-0").await;

    assert_eq!(
        resp.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "Range on empty file should return 416"
    );
}

// ============================================================================
// Invalid Range Requests
// ============================================================================

#[tokio::test]
async fn test_range_beyond_eof() {
    let server = TestServer::with_temp_vault().await;

    let content = random_bytes(1000);
    server.put_ok("/small.bin", content.clone()).await;

    // Request range starting beyond file size
    let resp = server.get_range("/small.bin", "bytes=5000-5999").await;

    assert_eq!(
        resp.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "Range beyond EOF should return 416"
    );
}

#[tokio::test]
async fn test_range_invalid_format() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"content".to_vec()).await;

    // Invalid range format - server may ignore and return full content
    let resp = server.get_range("/file.txt", "bytes=invalid").await;

    // Most servers ignore invalid ranges and return 200 with full content
    // Some may return 400 Bad Request
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST,
        "Invalid range should return 200 (ignored) or 400, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_range_reversed() {
    let server = TestServer::with_temp_vault().await;

    server.put_ok("/file.txt", b"Hello World".to_vec()).await;

    // Reversed range (start > end)
    let resp = server.get_range("/file.txt", "bytes=10-5").await;

    // Reversed ranges are typically ignored or return 416
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::RANGE_NOT_SATISFIABLE
            || resp.status() == StatusCode::BAD_REQUEST,
        "Reversed range should return 200 (ignored), 416, or 400, got {}",
        resp.status()
    );
}

// ============================================================================
// Content Verification
// ============================================================================

#[tokio::test]
async fn test_range_content_integrity() {
    let server = TestServer::with_temp_vault().await;

    // Create file with recognizable pattern
    let mut content = Vec::with_capacity(CHUNK_SIZE * 2);
    for i in 0..(CHUNK_SIZE * 2) {
        content.push((i % 256) as u8);
    }
    server.put_ok("/pattern.bin", content.clone()).await;

    // Test multiple ranges and verify content
    let test_ranges = [
        (0, 100),
        (100, 200),
        (CHUNK_SIZE - 50, CHUNK_SIZE + 50),
        (CHUNK_SIZE, CHUNK_SIZE + 100),
        (CHUNK_SIZE * 2 - 100, CHUNK_SIZE * 2),
    ];

    for (start, end) in test_ranges {
        let range = format!("bytes={}-{}", start, end - 1);
        let bytes = server.get_range_bytes("/pattern.bin", &range).await;

        match bytes {
            Ok(data) => {
                assert_eq!(
                    data.len(),
                    end - start,
                    "Range {start}-{end} returned wrong length"
                );
                assert_eq!(
                    &data[..],
                    &content[start..end],
                    "Range {start}-{end} content mismatch"
                );
            }
            Err((status, _)) => {
                panic!("Range {start}-{end} failed with status {status}");
            }
        }
    }
}
