//! Concurrency tests for WebDAV backend.
//!
//! These tests verify thread safety and correct behavior under parallel operations:
//! - Concurrent reads of the same file
//! - Concurrent writes to different files
//! - Rapid create/delete cycles
//! - Cache consistency under concurrent access

mod common;

use common::{generators::*, sha256, SharedTestClient, TestServer, CHUNK_SIZE};
use reqwest::StatusCode;
use tokio::task::JoinSet;

// ============================================================================
// Concurrent Read Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_reads_same_file() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Create file with known content
    let content = multi_chunk_content(3); // ~96KB
    let expected_hash = sha256(&content);
    server.put_ok("/shared.bin", content).await;

    // Spawn concurrent readers
    let mut handles = JoinSet::new();
    for i in 0..10 {
        let client = client.clone();
        let expected = expected_hash;
        handles.spawn(async move {
            let result = client.get_bytes("/shared.bin").await;
            match result {
                Ok(data) => {
                    let hash = sha256(&data);
                    assert_eq!(
                        hash, expected,
                        "Reader {} got corrupted data",
                        i
                    );
                    Ok(())
                }
                Err((status, body)) => Err(format!(
                    "Reader {} failed: {} - {}",
                    i, status, body
                )),
            }
        });
    }

    // All readers must succeed
    while let Some(result) = handles.join_next().await {
        let inner = result.expect("Task panicked");
        inner.expect("Reader failed");
    }
}

#[tokio::test]
async fn test_concurrent_reads_different_files() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Create multiple files
    let contents: Vec<Vec<u8>> = (0..5)
        .map(|i| random_bytes(1000 + i * 100))
        .collect();
    let hashes: Vec<[u8; 32]> = contents.iter().map(|c| sha256(c)).collect();

    for (i, content) in contents.iter().enumerate() {
        server.put_ok(&format!("/file{}.bin", i), content.clone()).await;
    }

    // Concurrent reads of different files
    let mut handles = JoinSet::new();
    for i in 0..5 {
        let client = client.clone();
        let expected = hashes[i];
        handles.spawn(async move {
            let path = format!("/file{}.bin", i);
            let result = client.get_bytes(&path).await;
            match result {
                Ok(data) => {
                    let hash = sha256(&data);
                    assert_eq!(hash, expected, "File {} corrupted", i);
                    Ok(())
                }
                Err((status, body)) => Err(format!("Read {} failed: {} - {}", i, status, body)),
            }
        });
    }

    while let Some(result) = handles.join_next().await {
        let inner = result.expect("Task panicked");
        inner.expect("Read failed");
    }
}

// ============================================================================
// Concurrent Write Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_writes_different_files() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    let contents: Vec<Vec<u8>> = (0..5)
        .map(|i| random_bytes(5000 + i * 1000))
        .collect();
    let hashes: Vec<[u8; 32]> = contents.iter().map(|c| sha256(c)).collect();

    // Concurrent writes to different files
    let mut handles = JoinSet::new();
    for (i, content) in contents.into_iter().enumerate() {
        let client = client.clone();
        handles.spawn(async move {
            let path = format!("/write{}.bin", i);
            let result = client.put(&path, content).await;
            match result {
                Ok(status) => {
                    if status.is_success() || status == StatusCode::CREATED {
                        Ok(i)
                    } else {
                        Err(format!("Write {} failed with status {}", i, status))
                    }
                }
                Err(e) => Err(format!("Write {} error: {}", i, e)),
            }
        });
    }

    // All writes must succeed
    while let Some(result) = handles.join_next().await {
        let inner = result.expect("Task panicked");
        inner.expect("Write failed");
    }

    // Verify all files exist with correct content
    for (i, expected_hash) in hashes.into_iter().enumerate() {
        let path = format!("/write{}.bin", i);
        let data = server.get_bytes(&path).await.expect("Should exist");
        assert_eq!(sha256(&data), expected_hash, "File {} has wrong content", i);
    }
}

#[tokio::test]
async fn test_concurrent_write_same_file_last_wins() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Multiple writers to the same file
    let mut handles = JoinSet::new();
    for i in 0..5 {
        let client = client.clone();
        let content = format!("writer_{}_content", i).into_bytes();
        handles.spawn(async move {
            let _ = client.put("/contested.txt", content).await;
        });
    }

    // Wait for all writes
    while let Some(result) = handles.join_next().await {
        result.expect("Task panicked");
    }

    // File should exist with one of the written contents
    let data = server.get_bytes("/contested.txt").await.expect("Should exist");
    let content = String::from_utf8_lossy(&data);
    assert!(
        content.starts_with("writer_") && content.ends_with("_content"),
        "File should have valid content from one writer: {}",
        content
    );
}

// ============================================================================
// Create/Delete Race Conditions
// ============================================================================

#[tokio::test]
async fn test_rapid_create_delete_cycle() {
    let server = TestServer::with_temp_vault().await;

    // Rapid create-delete cycles
    for iteration in 0..10 {
        let path = format!("/cycle{}.txt", iteration);
        let content = format!("content_{}", iteration).into_bytes();

        // Create
        server.put_ok(&path, content.clone()).await;

        // Verify exists
        let read_result = server.get_bytes(&path).await;
        assert!(
            read_result.is_ok(),
            "Read after create failed on iteration {}",
            iteration
        );

        // Delete
        server.delete_ok(&path).await;

        // Verify gone
        let resp = server.get(&path).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "File should be gone after delete on iteration {}",
            iteration
        );
    }
}

#[tokio::test]
async fn test_concurrent_create_delete_same_file() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Concurrent create and delete of the same file
    let mut handles = JoinSet::new();

    for _ in 0..3 {
        let client = client.clone();
        handles.spawn(async move {
            let _ = client.put("/concurrent.txt", b"create".to_vec()).await;
        });
    }

    for _ in 0..3 {
        let client = client.clone();
        handles.spawn(async move {
            let _ = client.delete("/concurrent.txt").await;
        });
    }

    // Wait for all operations
    while let Some(result) = handles.join_next().await {
        result.expect("Task panicked");
    }

    // File may or may not exist - but server shouldn't crash
    let _resp = server.get("/concurrent.txt").await;
}

// ============================================================================
// Directory Operation Races
// ============================================================================

#[tokio::test]
async fn test_concurrent_mkcol_same_path() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    let mut handles = JoinSet::new();

    // Multiple concurrent MKCOL on same path
    for _ in 0..5 {
        let client = client.clone();
        handles.spawn(async move {
            client.mkcol("/racedir").await
        });
    }

    let mut success_count = 0;

    while let Some(result) = handles.join_next().await {
        if let Ok(Ok(resp)) = result {
            if resp.status().is_success() || resp.status() == StatusCode::CREATED {
                success_count += 1;
            }
        }
    }

    // At least one should succeed
    assert!(
        success_count >= 1,
        "At least one MKCOL should succeed"
    );

    // Directory should exist
    let resp = server.propfind("/racedir", "0").await;
    assert!(
        resp.status() == StatusCode::MULTI_STATUS || resp.status().is_success(),
        "Directory should exist after race"
    );
}

#[tokio::test]
async fn test_concurrent_file_in_new_dir() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Create directory first
    server.mkcol_ok("/newdir").await;

    let mut handles = JoinSet::new();

    // Concurrent file creations in the new directory
    for i in 0..5 {
        let client = client.clone();
        let content = format!("file_{}", i).into_bytes();
        handles.spawn(async move {
            let path = format!("/newdir/file{}.txt", i);
            client.put(&path, content).await
        });
    }

    while let Some(result) = handles.join_next().await {
        if let Ok(Ok(status)) = result {
            assert!(
                status.is_success() || status == StatusCode::CREATED,
                "File creation should succeed"
            );
        }
    }

    // All files should exist
    for i in 0..5 {
        let path = format!("/newdir/file{}.txt", i);
        let resp = server.get(&path).await;
        assert!(
            resp.status().is_success(),
            "File {} should exist",
            i
        );
    }
}

// ============================================================================
// Cache Consistency Tests
// ============================================================================

#[tokio::test]
async fn test_read_after_parallel_write() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    // Initial content
    server.put_ok("/cache_test.txt", b"initial".to_vec()).await;

    // Parallel: one writer, multiple readers
    let mut handles = JoinSet::new();

    // Writer
    let writer_client = client.clone();
    handles.spawn(async move {
        // Small delay to let readers start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let _ = writer_client.put("/cache_test.txt", b"updated".to_vec()).await;
    });

    // Readers
    for _ in 0..3 {
        let reader_client = client.clone();
        handles.spawn(async move {
            for _ in 0..5 {
                let _ = reader_client.get("/cache_test.txt").await;
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            }
        });
    }

    while let Some(result) = handles.join_next().await {
        result.expect("Task panicked");
    }

    // Final read should see updated content
    let final_data = server.get_bytes("/cache_test.txt").await.expect("Should exist");
    assert_eq!(
        final_data.as_ref(),
        b"updated",
        "Final content should be the updated version"
    );
}

#[tokio::test]
async fn test_propfind_during_writes() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    server.mkcol_ok("/listing_test").await;

    let mut handles = JoinSet::new();

    // Writers adding files
    for i in 0..5 {
        let writer_client = client.clone();
        handles.spawn(async move {
            let path = format!("/listing_test/file{}.txt", i);
            let _ = writer_client.put(&path, format!("content{}", i).into_bytes()).await;
        });
    }

    // Concurrent PROPFIND
    for _ in 0..3 {
        let lister_client = client.clone();
        handles.spawn(async move {
            for _ in 0..5 {
                let _ = lister_client.propfind("/listing_test", "1").await;
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            }
        });
    }

    while let Some(result) = handles.join_next().await {
        result.expect("Task panicked");
    }

    // All files should exist
    for i in 0..5 {
        let path = format!("/listing_test/file{}.txt", i);
        let resp = server.get(&path).await;
        assert!(resp.status().is_success(), "File {} should exist after concurrent ops", i);
    }
}

// ============================================================================
// Large File Concurrent Access
// ============================================================================

#[tokio::test]
async fn test_parallel_large_uploads() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    let contents: Vec<Vec<u8>> = (0..3)
        .map(|_| multi_chunk_content(2)) // ~64KB each
        .collect();
    let hashes: Vec<[u8; 32]> = contents.iter().map(|c| sha256(c)).collect();

    let mut handles = JoinSet::new();

    for (i, content) in contents.into_iter().enumerate() {
        let upload_client = client.clone();
        handles.spawn(async move {
            let path = format!("/large{}.bin", i);
            upload_client.put(&path, content).await
        });
    }

    while let Some(result) = handles.join_next().await {
        if let Ok(Ok(status)) = result {
            assert!(
                status.is_success() || status == StatusCode::CREATED,
                "Large upload should succeed"
            );
        }
    }

    // Verify content integrity
    for (i, expected_hash) in hashes.into_iter().enumerate() {
        let path = format!("/large{}.bin", i);
        let data = server.get_bytes(&path).await.expect("Should exist");
        assert_eq!(sha256(&data), expected_hash, "Large file {} corrupted", i);
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_many_small_files() {
    let server = TestServer::with_temp_vault().await;
    let client = server.shared_client();

    let file_count = 20;
    let mut handles = JoinSet::new();

    // Create many small files concurrently
    for i in 0..file_count {
        let upload_client = client.clone();
        let content = format!("small_file_{}", i).into_bytes();
        handles.spawn(async move {
            let path = format!("/small{}.txt", i);
            upload_client.put(&path, content).await
        });
    }

    while let Some(result) = handles.join_next().await {
        result.expect("Task panicked");
    }

    // Verify all exist
    for i in 0..file_count {
        let path = format!("/small{}.txt", i);
        let resp = server.get(&path).await;
        assert!(
            resp.status().is_success(),
            "Small file {} should exist",
            i
        );
    }
}
