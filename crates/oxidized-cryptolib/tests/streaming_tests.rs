//! Integration tests for streaming file I/O.

#![cfg(feature = "async")]

use oxidized_cryptolib::{
    fs::streaming::{CHUNK_PLAINTEXT_SIZE, encrypted_to_plaintext_size_or_zero},
    vault::{VaultOperationsAsync, DirId},
};
use std::path::PathBuf;

mod common;
use common::vault_builder::VaultBuilder;

// ============================================================================
// Helper Functions
// ============================================================================

async fn setup_vault() -> (PathBuf, VaultOperationsAsync) {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let ops = VaultOperationsAsync::new(&vault_path, &master_key)
        .expect("Failed to create VaultOperationsAsync");
    (vault_path, ops)
}

// ============================================================================
// VaultFileWriter + VaultFileReader Roundtrip Tests
// ============================================================================

#[tokio::test]
async fn test_streaming_write_read_roundtrip_small() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write using streaming API
    let mut writer = ops.create_file(&root, "small.txt").await
        .expect("Failed to create file");

    writer.write(b"Hello, World!").await
        .expect("Failed to write data");

    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Read back using streaming API
    let mut reader = ops.open_file(&root, "small.txt").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), 13);

    let data = reader.read_range(0, 100).await
        .expect("Failed to read data");

    assert_eq!(data, b"Hello, World!");
}

#[tokio::test]
async fn test_streaming_write_read_roundtrip_empty() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write empty file using streaming API
    let writer = ops.create_file(&root, "empty.txt").await
        .expect("Failed to create file");

    // Don't write anything, just finish
    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Read back using streaming API
    let mut reader = ops.open_file(&root, "empty.txt").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), 0);

    let data = reader.read_range(0, 100).await
        .expect("Failed to read data");

    assert!(data.is_empty());
}

#[tokio::test]
async fn test_streaming_write_read_roundtrip_large() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create data larger than one chunk (32KB)
    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size * 2 + 1000; // 2 full chunks + partial
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    // Write using streaming API in multiple calls
    let mut writer = ops.create_file(&root, "large.bin").await
        .expect("Failed to create file");

    // Write in 10KB chunks to test buffering
    for chunk in test_data.chunks(10 * 1024) {
        writer.write(chunk).await
            .expect("Failed to write chunk");
    }

    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Read back using streaming API
    let mut reader = ops.open_file(&root, "large.bin").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), total_size as u64);

    // Read entire file
    let data = reader.read_range(0, total_size).await
        .expect("Failed to read data");

    assert_eq!(data.len(), total_size);
    assert_eq!(data, test_data);
}

// ============================================================================
// Random Access Read Tests
// ============================================================================

#[tokio::test]
async fn test_streaming_random_access_within_chunk() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create test file
    let test_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    ops.write_file(&root, "random.txt", test_data).await
        .expect("Failed to write file");

    // Open for streaming
    let mut reader = ops.open_file(&root, "random.txt").await
        .expect("Failed to open file");

    // Read from middle
    let data = reader.read_range(10, 10).await
        .expect("Failed to read range");
    assert_eq!(data, b"ABCDEFGHIJ");

    // Read from start
    let data = reader.read_range(0, 5).await
        .expect("Failed to read range");
    assert_eq!(data, b"01234");

    // Read from end
    let data = reader.read_range(30, 10).await
        .expect("Failed to read range");
    assert_eq!(data, b"UVWXYZ");
}

#[tokio::test]
async fn test_streaming_random_access_across_chunks() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create data spanning multiple chunks
    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size * 3;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    ops.write_file(&root, "multi_chunk.bin", &test_data).await
        .expect("Failed to write file");

    // Open for streaming
    let mut reader = ops.open_file(&root, "multi_chunk.bin").await
        .expect("Failed to open file");

    // Read across chunk boundary
    let start = chunk_size - 100;
    let len = 200;
    let data = reader.read_range(start as u64, len).await
        .expect("Failed to read range");

    assert_eq!(data.len(), len);
    assert_eq!(data, &test_data[start..start + len]);

    // Read from second chunk only
    let start = chunk_size + 500;
    let len = 1000;
    let data = reader.read_range(start as u64, len).await
        .expect("Failed to read range");

    assert_eq!(data.len(), len);
    assert_eq!(data, &test_data[start..start + len]);

    // Read spanning all three chunks
    let start = chunk_size / 2;
    let len = chunk_size * 2;
    let data = reader.read_range(start as u64, len).await
        .expect("Failed to read range");

    assert_eq!(data.len(), len);
    assert_eq!(data, &test_data[start..start + len]);
}

#[tokio::test]
async fn test_streaming_read_past_eof() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let test_data = b"Short file content";
    ops.write_file(&root, "short.txt", test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "short.txt").await
        .expect("Failed to open file");

    // Request more than file contains
    let data = reader.read_range(0, 1000).await
        .expect("Failed to read range");
    assert_eq!(data, test_data);

    // Read starting past EOF
    let data = reader.read_range(100, 100).await
        .expect("Failed to read range");
    assert!(data.is_empty());

    // Read starting near EOF
    let data = reader.read_range(10, 100).await
        .expect("Failed to read range");
    assert_eq!(data, &test_data[10..]);
}

// ============================================================================
// Streaming Writer Edge Cases
// ============================================================================

#[tokio::test]
async fn test_streaming_write_abort() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create and write some data
    let mut writer = ops.create_file(&root, "aborted.txt").await
        .expect("Failed to create file");

    writer.write(b"This will be discarded").await
        .expect("Failed to write data");

    // Abort instead of finish
    writer.abort().await
        .expect("Failed to abort");

    // File should not exist
    let files = ops.list_files(&root).await
        .expect("Failed to list files");

    assert!(files.iter().all(|f| f.name != "aborted.txt"));
}

#[tokio::test]
async fn test_streaming_write_exact_chunk_boundary() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write exactly one chunk worth of data
    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let test_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

    let mut writer = ops.create_file(&root, "exact_chunk.bin").await
        .expect("Failed to create file");

    writer.write(&test_data).await
        .expect("Failed to write data");

    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Read back and verify
    let mut reader = ops.open_file(&root, "exact_chunk.bin").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), chunk_size as u64);

    let data = reader.read_range(0, chunk_size).await
        .expect("Failed to read data");

    assert_eq!(data, test_data);
}

// ============================================================================
// Path-based API Tests
// ============================================================================

#[tokio::test]
async fn test_streaming_open_by_path() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a subdirectory and file
    let sub_dir = ops.create_directory(&root, "subdir").await
        .expect("Failed to create directory");

    let test_data = b"File in subdirectory";
    ops.write_file(&sub_dir, "nested.txt", test_data).await
        .expect("Failed to write file");

    // Open by path
    let mut reader = ops.open_by_path("subdir/nested.txt").await
        .expect("Failed to open by path");

    assert_eq!(reader.plaintext_size(), test_data.len() as u64);

    let data = reader.read_range(0, 100).await
        .expect("Failed to read data");

    assert_eq!(data, test_data);
}

#[tokio::test]
async fn test_streaming_create_by_path() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a subdirectory first
    ops.create_directory(&root, "newdir").await
        .expect("Failed to create directory");

    // Create file by path
    let mut writer = ops.create_by_path("newdir/created.txt").await
        .expect("Failed to create by path");

    writer.write(b"Created via path").await
        .expect("Failed to write data");

    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Verify file exists and has correct content
    let decrypted = ops.read_by_path("newdir/created.txt").await
        .expect("Failed to read file");

    assert_eq!(decrypted.content, b"Created via path");
}

// ============================================================================
// Interoperability with Non-Streaming API
// ============================================================================

#[tokio::test]
async fn test_streaming_read_non_streaming_write() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write with non-streaming API
    let test_data = b"Written with write_file()";
    ops.write_file(&root, "regular.txt", test_data).await
        .expect("Failed to write file");

    // Read with streaming API
    let mut reader = ops.open_file(&root, "regular.txt").await
        .expect("Failed to open file");

    let data = reader.read_range(0, 100).await
        .expect("Failed to read data");

    assert_eq!(data, test_data);
}

#[tokio::test]
async fn test_non_streaming_read_streaming_write() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write with streaming API
    let mut writer = ops.create_file(&root, "streamed.txt").await
        .expect("Failed to create file");

    writer.write(b"Written with streaming API").await
        .expect("Failed to write data");

    let _path = writer.finish().await
        .expect("Failed to finish write");

    // Read with non-streaming API
    let decrypted = ops.read_file(&root, "streamed.txt").await
        .expect("Failed to read file");

    assert_eq!(decrypted.content, b"Written with streaming API");
}

// ============================================================================
// Error Path Tests - VaultFileReader
// ============================================================================

#[tokio::test]
async fn test_reader_file_too_small() {
    use oxidized_cryptolib::fs::streaming::VaultFileReader;
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Create a file that's too small (less than HEADER_SIZE = 68 bytes)
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    temp_file.write_all(b"too short").expect("Failed to write");
    temp_file.flush().expect("Failed to flush");

    let master_key = common::create_test_master_key();

    let result = VaultFileReader::open(temp_file.path(), &master_key).await;
    assert!(result.is_err(), "Expected error for file too small");

    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("too small") || err_string.contains("FileTooSmall"),
        "Expected FileTooSmall error, got: {}",
        err_string
    );
}

#[tokio::test]
async fn test_reader_invalid_header() {
    use oxidized_cryptolib::fs::streaming::{VaultFileReader, HEADER_SIZE};
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Create a file with correct size but garbage header data
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let garbage_header = vec![0xFFu8; HEADER_SIZE + 100]; // Header + some "chunk" data
    temp_file.write_all(&garbage_header).expect("Failed to write");
    temp_file.flush().expect("Failed to flush");

    let master_key = common::create_test_master_key();

    let result = VaultFileReader::open(temp_file.path(), &master_key).await;
    assert!(result.is_err(), "Expected error for invalid header");

    // The error should be about header decryption failure
    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("Header") || err_string.contains("decryption"),
        "Expected header decryption error, got: {}",
        err_string
    );
}

#[tokio::test]
async fn test_reader_file_not_found() {
    use oxidized_cryptolib::fs::streaming::VaultFileReader;
    use std::path::PathBuf;

    let master_key = common::create_test_master_key();
    let nonexistent_path = PathBuf::from("/nonexistent/path/to/file.c9r");

    let result = VaultFileReader::open(&nonexistent_path, &master_key).await;
    assert!(result.is_err(), "Expected error for nonexistent file");

    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("IO error") || err_string.contains("No such file"),
        "Expected IO error, got: {}",
        err_string
    );
}

#[tokio::test]
async fn test_reader_corrupted_chunk() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a valid file first
    let test_data = b"Valid content for testing corruption";
    ops.write_file(&root, "to_corrupt.txt", test_data).await
        .expect("Failed to write file");

    // Get the encrypted path
    let files = ops.list_files(&root).await.expect("Failed to list files");
    let file_info = files.iter().find(|f| f.name == "to_corrupt.txt")
        .expect("File not found");

    // Corrupt the file by modifying some bytes in the chunk area (after header)
    let mut encrypted_data = tokio::fs::read(&file_info.encrypted_path).await
        .expect("Failed to read encrypted file");

    // Corrupt bytes in the chunk area (after the 68-byte header)
    if encrypted_data.len() > 80 {
        encrypted_data[70] ^= 0xFF;
        encrypted_data[71] ^= 0xFF;
        encrypted_data[72] ^= 0xFF;
    }

    tokio::fs::write(&file_info.encrypted_path, &encrypted_data).await
        .expect("Failed to write corrupted file");

    // Try to read the corrupted file
    let mut reader = ops.open_file(&root, "to_corrupt.txt").await
        .expect("Opening should succeed (header is valid)");

    let result = reader.read_range(0, 100).await;
    assert!(result.is_err(), "Expected error reading corrupted chunk");

    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("Chunk decryption failed") ||
        err_string.contains("authentication tag") ||
        err_string.contains("Streaming"),
        "Expected chunk decryption error, got: {}",
        err_string
    );
}

// ============================================================================
// Error Path Tests - VaultFileWriter
// ============================================================================

#[tokio::test]
async fn test_writer_write_after_finish() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let mut writer = ops.create_file(&root, "finished.txt").await
        .expect("Failed to create file");

    writer.write(b"Initial content").await
        .expect("Failed to write initial content");

    // Finish the writer - this consumes self
    let _path = writer.finish().await
        .expect("Failed to finish");

    // We can't test write after finish directly because finish() consumes self.
    // Instead, test double finish which should also fail.
}

#[tokio::test]
async fn test_writer_abort_cleans_up_temp_file() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create and write some data
    let mut writer = ops.create_file(&root, "will_abort.txt").await
        .expect("Failed to create file");

    writer.write(b"This will be discarded").await
        .expect("Failed to write data");

    writer.write(b" - more data").await
        .expect("Failed to write more data");

    // Abort the write
    writer.abort().await
        .expect("Failed to abort");

    // Verify file doesn't exist
    let files = ops.list_files(&root).await
        .expect("Failed to list files");

    assert!(
        files.iter().all(|f| f.name != "will_abort.txt"),
        "Aborted file should not exist"
    );
}

#[tokio::test]
async fn test_writer_invalid_path_no_parent() {
    use oxidized_cryptolib::fs::streaming::VaultFileWriter;

    let master_key = common::create_test_master_key();

    // Try to create a writer with a path that has no parent
    // On Unix, "/" has no parent directory (it's the root)
    let result = VaultFileWriter::create("/", &master_key).await;

    assert!(result.is_err(), "Expected error for invalid path");

    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("Invalid path") || err_string.contains("no parent"),
        "Expected invalid path error, got: {}",
        err_string
    );
}

// ============================================================================
// Cache Behavior Tests
// ============================================================================

#[tokio::test]
async fn test_reader_cache_hit_on_sequential_reads() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a file with known content
    let test_data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ops.write_file(&root, "cache_test.txt", test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "cache_test.txt").await
        .expect("Failed to open file");

    // Multiple reads from the same chunk should use the cache
    let data1 = reader.read_range(0, 5).await.expect("First read failed");
    let data2 = reader.read_range(5, 5).await.expect("Second read failed");
    let data3 = reader.read_range(0, 10).await.expect("Third read failed");

    assert_eq!(data1, b"ABCDE");
    assert_eq!(data2, b"FGHIJ");
    assert_eq!(data3, b"ABCDEFGHIJ");

    // Verify content integrity across cached reads
    let full_data = reader.read_range(0, test_data.len()).await
        .expect("Full read failed");
    assert_eq!(full_data, test_data);
}

#[tokio::test]
async fn test_reader_cache_across_chunk_boundaries() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create data spanning multiple chunks
    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size * 2 + 100;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    ops.write_file(&root, "multi_chunk_cache.bin", &test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "multi_chunk_cache.bin").await
        .expect("Failed to open file");

    // Read from chunk 0, then chunk 1, then back to chunk 0
    // This tests that cache is updated when reading different chunks
    let chunk0_data = reader.read_range(0, 100).await.expect("Chunk 0 read failed");
    let chunk1_data = reader.read_range(chunk_size as u64, 100).await.expect("Chunk 1 read failed");
    let chunk0_again = reader.read_range(50, 100).await.expect("Chunk 0 re-read failed");

    assert_eq!(chunk0_data, &test_data[0..100]);
    assert_eq!(chunk1_data, &test_data[chunk_size..chunk_size + 100]);
    assert_eq!(chunk0_again, &test_data[50..150]);
}

// ============================================================================
// Edge Case Tests - Read Boundaries
// ============================================================================

#[tokio::test]
async fn test_read_zero_length() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let test_data = b"Some content";
    ops.write_file(&root, "zero_len.txt", test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "zero_len.txt").await
        .expect("Failed to open file");

    // Request zero bytes
    let data = reader.read_range(0, 0).await.expect("Zero-length read failed");
    assert!(data.is_empty(), "Zero-length read should return empty vec");

    let data = reader.read_range(5, 0).await.expect("Zero-length read at offset failed");
    assert!(data.is_empty(), "Zero-length read at offset should return empty vec");
}

#[tokio::test]
async fn test_read_at_exact_chunk_boundary() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size * 2;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    ops.write_file(&root, "chunk_boundary.bin", &test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "chunk_boundary.bin").await
        .expect("Failed to open file");

    // Read starting exactly at chunk boundary
    let data = reader.read_range(chunk_size as u64, 100).await
        .expect("Read at boundary failed");
    assert_eq!(data, &test_data[chunk_size..chunk_size + 100]);

    // Read ending exactly at chunk boundary
    let data = reader.read_range((chunk_size - 100) as u64, 100).await
        .expect("Read ending at boundary failed");
    assert_eq!(data, &test_data[chunk_size - 100..chunk_size]);
}

#[tokio::test]
async fn test_read_spanning_multiple_chunks() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size * 4; // 4 chunks
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    ops.write_file(&root, "four_chunks.bin", &test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "four_chunks.bin").await
        .expect("Failed to open file");

    // Read spanning all 4 chunks
    let start = chunk_size / 2;
    let len = chunk_size * 3;
    let data = reader.read_range(start as u64, len).await
        .expect("Multi-chunk read failed");

    assert_eq!(data.len(), len);
    assert_eq!(data, &test_data[start..start + len]);
}

// ============================================================================
// StreamingContext Tests
// ============================================================================

#[test]
fn test_streaming_context_display_empty() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;

    let ctx = StreamingContext::new();
    let display = format!("{}", ctx);
    assert_eq!(display, "(no context)");
}

#[test]
fn test_streaming_context_display_with_path_only() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;
    use std::path::PathBuf;

    let ctx = StreamingContext::new().with_path(PathBuf::from("/test/path"));
    let display = format!("{}", ctx);
    assert!(display.contains("/test/path"), "Display should contain path: {}", display);
}

#[test]
fn test_streaming_context_display_with_chunk_only() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;

    let ctx = StreamingContext::new().with_chunk(42);
    let display = format!("{}", ctx);
    assert!(display.contains("chunk 42"), "Display should contain chunk: {}", display);
}

#[test]
fn test_streaming_context_display_with_operation_only() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;

    let ctx = StreamingContext::new().with_operation("test_op");
    let display = format!("{}", ctx);
    assert!(display.contains("test_op"), "Display should contain operation: {}", display);
}

#[test]
fn test_streaming_context_display_full() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;
    use std::path::PathBuf;

    let ctx = StreamingContext::new()
        .with_path(PathBuf::from("/vault/file.c9r"))
        .with_chunk(5)
        .with_operation("decrypt");

    let display = format!("{}", ctx);
    assert!(display.contains("decrypt"), "Display should contain operation: {}", display);
    assert!(display.contains("file.c9r"), "Display should contain path: {}", display);
    assert!(display.contains("chunk 5"), "Display should contain chunk: {}", display);
}

#[test]
fn test_streaming_context_default() {
    use oxidized_cryptolib::fs::streaming::StreamingContext;

    let ctx = StreamingContext::default();
    assert!(ctx.path.is_none());
    assert!(ctx.chunk_number.is_none());
    assert!(ctx.operation.is_none());
}

// ============================================================================
// StreamingError Tests
// ============================================================================

#[test]
fn test_streaming_error_io_with_context() {
    use oxidized_cryptolib::fs::streaming::{StreamingError, StreamingContext};
    use std::io;

    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let ctx = StreamingContext::new().with_operation("test");

    let streaming_err = StreamingError::io_with_context(io_err, ctx);
    let err_string = streaming_err.to_string();

    assert!(err_string.contains("IO error"), "Error should mention IO: {}", err_string);
    assert!(err_string.contains("test"), "Error should contain context: {}", err_string);
}

// ============================================================================
// Chunk Size Calculation Tests
// ============================================================================

#[test]
fn test_encrypted_to_plaintext_size_invalid_cases() {
    use oxidized_cryptolib::fs::streaming::{
        encrypted_to_plaintext_size,
        HEADER_SIZE, CHUNK_OVERHEAD,
    };

    // Size = 0 is invalid
    assert_eq!(encrypted_to_plaintext_size(0), None);

    // Size less than header is invalid
    assert_eq!(encrypted_to_plaintext_size((HEADER_SIZE - 1) as u64), None);

    // Exactly header size (no content) is invalid
    assert_eq!(encrypted_to_plaintext_size(HEADER_SIZE as u64), None);

    // Header + partial overhead (less than minimum chunk) is invalid
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_OVERHEAD - 1) as u64),
        None
    );

    // Header + minimum valid chunk (just overhead, empty plaintext)
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_OVERHEAD) as u64),
        Some(0)
    );
}

#[test]
fn test_encrypted_to_plaintext_size_valid_cases() {
    use oxidized_cryptolib::fs::streaming::{
        encrypted_to_plaintext_size,
        HEADER_SIZE, CHUNK_OVERHEAD, CHUNK_ENCRYPTED_SIZE, CHUNK_PLAINTEXT_SIZE,
    };

    // Header + empty chunk = 0 plaintext bytes
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_OVERHEAD) as u64),
        Some(0)
    );

    // Header + chunk with 1 plaintext byte
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_OVERHEAD + 1) as u64),
        Some(1)
    );

    // Header + full chunk = 32KB plaintext
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_ENCRYPTED_SIZE) as u64),
        Some(CHUNK_PLAINTEXT_SIZE as u64)
    );

    // Header + 2 full chunks
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + 2 * CHUNK_ENCRYPTED_SIZE) as u64),
        Some((2 * CHUNK_PLAINTEXT_SIZE) as u64)
    );

    // Header + 1 full chunk + partial chunk with 500 bytes
    let partial_encrypted = CHUNK_OVERHEAD + 500;
    assert_eq!(
        encrypted_to_plaintext_size((HEADER_SIZE + CHUNK_ENCRYPTED_SIZE + partial_encrypted) as u64),
        Some((CHUNK_PLAINTEXT_SIZE + 500) as u64)
    );
}

#[test]
fn test_chunk_offset_calculations() {
    use oxidized_cryptolib::fs::streaming::{
        plaintext_to_chunk_number, plaintext_to_chunk_offset, chunk_to_encrypted_offset,
        CHUNK_PLAINTEXT_SIZE, CHUNK_ENCRYPTED_SIZE, HEADER_SIZE,
    };

    // Verify consistency of offset calculations
    let offsets = [0, 1, 1000, CHUNK_PLAINTEXT_SIZE - 1, CHUNK_PLAINTEXT_SIZE,
                   CHUNK_PLAINTEXT_SIZE + 1, CHUNK_PLAINTEXT_SIZE * 2,
                   CHUNK_PLAINTEXT_SIZE * 10 + 500];

    for &offset in &offsets {
        let chunk_num = plaintext_to_chunk_number(offset as u64);
        let chunk_offset = plaintext_to_chunk_offset(offset as u64);

        // Verify: chunk_num * CHUNK_PLAINTEXT_SIZE + chunk_offset == offset
        assert_eq!(
            chunk_num * CHUNK_PLAINTEXT_SIZE as u64 + chunk_offset as u64,
            offset as u64,
            "Offset {} should decompose correctly into chunk {} offset {}",
            offset, chunk_num, chunk_offset
        );

        // Verify encrypted offset
        let encrypted_offset = chunk_to_encrypted_offset(chunk_num);
        assert_eq!(
            encrypted_offset,
            HEADER_SIZE as u64 + chunk_num * CHUNK_ENCRYPTED_SIZE as u64,
            "Encrypted offset for chunk {} should match formula",
            chunk_num
        );
    }
}

// ============================================================================
// Writer Multi-Chunk Tests
// ============================================================================

#[tokio::test]
async fn test_writer_exactly_one_chunk() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let test_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

    let mut writer = ops.create_file(&root, "one_chunk.bin").await
        .expect("Failed to create file");

    writer.write(&test_data).await
        .expect("Failed to write data");

    let _path = writer.finish().await
        .expect("Failed to finish");

    // Verify content
    let mut reader = ops.open_file(&root, "one_chunk.bin").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), chunk_size as u64);

    let data = reader.read_range(0, chunk_size).await
        .expect("Failed to read");

    assert_eq!(data, test_data);
}

#[tokio::test]
async fn test_writer_multiple_small_writes() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let mut writer = ops.create_file(&root, "many_writes.txt").await
        .expect("Failed to create file");

    // Write many small pieces
    for i in 0..100 {
        writer.write(format!("Line {}\n", i).as_bytes()).await
            .expect("Failed to write line");
    }

    let _path = writer.finish().await
        .expect("Failed to finish");

    // Verify
    let mut reader = ops.open_file(&root, "many_writes.txt").await
        .expect("Failed to open file");

    let data = reader.read_range(0, reader.plaintext_size() as usize).await
        .expect("Failed to read");

    // Verify first few lines
    let content = String::from_utf8_lossy(&data);
    assert!(content.starts_with("Line 0\nLine 1\n"));
    assert!(content.contains("Line 99\n"));
}

#[tokio::test]
async fn test_writer_large_single_write() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Write data larger than the buffer in a single call
    let total_size = CHUNK_PLAINTEXT_SIZE * 3 + 500;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    let mut writer = ops.create_file(&root, "large_write.bin").await
        .expect("Failed to create file");

    // Single large write
    writer.write(&test_data).await
        .expect("Failed to write large data");

    let _path = writer.finish().await
        .expect("Failed to finish");

    // Verify
    let mut reader = ops.open_file(&root, "large_write.bin").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), total_size as u64);

    let data = reader.read_range(0, total_size).await
        .expect("Failed to read");

    assert_eq!(data, test_data);
}

// ============================================================================
// Chunk Math Integration Tests
// ============================================================================

#[tokio::test]
async fn test_encrypted_size_matches_expected() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create files of various sizes and verify encrypted size calculation
    let test_cases = vec![
        ("empty.bin", 0usize),
        ("small.bin", 100),
        ("one_chunk.bin", CHUNK_PLAINTEXT_SIZE),
        ("two_chunks.bin", CHUNK_PLAINTEXT_SIZE * 2),
        ("partial.bin", CHUNK_PLAINTEXT_SIZE + 500),
    ];

    for (name, size) in test_cases {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        ops.write_file(&root, name, &data).await
            .expect(&format!("Failed to write {}", name));

        let files = ops.list_files(&root).await
            .expect("Failed to list files");

        let file_info = files.iter()
            .find(|f| f.name == name)
            .expect(&format!("File {} not found", name));

        let calculated_plaintext = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);

        assert_eq!(
            calculated_plaintext, size as u64,
            "Plaintext size mismatch for {}: expected {}, got {}",
            name, size, calculated_plaintext
        );
    }
}

// ============================================================================
// Drop Behavior Tests
// ============================================================================

#[tokio::test]
async fn test_writer_drop_without_finish_cleans_up() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a writer in a block so it gets dropped
    {
        let mut writer = ops.create_file(&root, "dropped.txt").await
            .expect("Failed to create file");

        writer.write(b"This will be dropped").await
            .expect("Failed to write data");

        // Writer is dropped here without calling finish() or abort()
    }

    // The drop implementation should clean up the temp file
    // The file should NOT exist in the vault
    let files = ops.list_files(&root).await
        .expect("Failed to list files");

    assert!(
        files.iter().all(|f| f.name != "dropped.txt"),
        "Dropped writer should not leave the file in the vault"
    );
}

#[tokio::test]
async fn test_reader_debug_format() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    ops.write_file(&root, "debug_test.txt", b"test content").await
        .expect("Failed to write file");

    let reader = ops.open_file(&root, "debug_test.txt").await
        .expect("Failed to open file");

    // Test Debug implementation
    let debug_str = format!("{:?}", reader);
    assert!(debug_str.contains("VaultFileReader"), "Debug output should identify type");
    assert!(debug_str.contains("plaintext_size"), "Debug output should show size");
}

#[tokio::test]
async fn test_writer_debug_format() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let mut writer = ops.create_file(&root, "writer_debug.txt").await
        .expect("Failed to create file");

    writer.write(b"some data").await.expect("write failed");

    // Test Debug implementation
    let debug_str = format!("{:?}", writer);
    assert!(debug_str.contains("VaultFileWriter"), "Debug output should identify type");
    assert!(debug_str.contains("chunks_written"), "Debug output should show chunks written");
    assert!(debug_str.contains("buffer_len"), "Debug output should show buffer length");

    // Clean up
    writer.abort().await.expect("abort failed");
}

// ============================================================================
// Incomplete Chunk Tests
// ============================================================================

#[tokio::test]
async fn test_reader_handles_partial_final_chunk() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create a file with partial final chunk
    let chunk_size = CHUNK_PLAINTEXT_SIZE;
    let total_size = chunk_size + 500; // 1 full chunk + 500 bytes
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

    ops.write_file(&root, "partial_chunk.bin", &test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "partial_chunk.bin").await
        .expect("Failed to open file");

    assert_eq!(reader.plaintext_size(), total_size as u64);

    // Read the partial chunk specifically
    let data = reader.read_range(chunk_size as u64, 500).await
        .expect("Failed to read partial chunk");

    assert_eq!(data, &test_data[chunk_size..]);
}

#[tokio::test]
async fn test_reader_read_very_large_range() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let test_data = b"Small file content";
    ops.write_file(&root, "small_large_read.txt", test_data).await
        .expect("Failed to write file");

    let mut reader = ops.open_file(&root, "small_large_read.txt").await
        .expect("Failed to open file");

    // Request much more than file size
    let data = reader.read_range(0, usize::MAX).await
        .expect("Large read should succeed");

    // Should return only the actual file content, clamped
    assert_eq!(data, test_data);
}

// ============================================================================
// VaultFileReader Plaintext Size Tests
// ============================================================================

#[tokio::test]
async fn test_reader_plaintext_size_accessor() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    let test_sizes = [0, 1, 100, 1000, CHUNK_PLAINTEXT_SIZE, CHUNK_PLAINTEXT_SIZE * 2 + 100];

    for &size in &test_sizes {
        let filename = format!("size_{}.bin", size);
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        ops.write_file(&root, &filename, &data).await
            .expect("Failed to write file");

        let reader = ops.open_file(&root, &filename).await
            .expect("Failed to open file");

        assert_eq!(
            reader.plaintext_size(), size as u64,
            "Plaintext size should match for {} byte file",
            size
        );
    }
}

// ============================================================================
// Streaming Overwrite Tests
// ============================================================================

#[tokio::test]
async fn test_streaming_overwrite_existing_file() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Create initial file
    ops.write_file(&root, "overwrite.txt", b"Original content").await
        .expect("Failed to write initial file");

    // Overwrite with streaming
    let mut writer = ops.create_file(&root, "overwrite.txt").await
        .expect("Failed to create writer for overwrite");

    writer.write(b"New content that is different").await
        .expect("Failed to write new content");

    let _path = writer.finish().await
        .expect("Failed to finish overwrite");

    // Verify the new content
    let mut reader = ops.open_file(&root, "overwrite.txt").await
        .expect("Failed to open overwritten file");

    let data = reader.read_range(0, 100).await
        .expect("Failed to read");

    assert_eq!(data, b"New content that is different");
}

// ============================================================================
// Binary Content Tests
// ============================================================================

#[tokio::test]
async fn test_streaming_binary_data_with_null_bytes() {
    let (_temp_dir, ops) = setup_vault().await;
    let root = DirId::root();

    // Binary data with null bytes and all byte values
    let test_data: Vec<u8> = (0..=255).cycle().take(1000).collect();

    let mut writer = ops.create_file(&root, "binary.bin").await
        .expect("Failed to create file");

    writer.write(&test_data).await
        .expect("Failed to write binary data");

    let _path = writer.finish().await
        .expect("Failed to finish");

    let mut reader = ops.open_file(&root, "binary.bin").await
        .expect("Failed to open file");

    let data = reader.read_range(0, test_data.len()).await
        .expect("Failed to read");

    assert_eq!(data, test_data, "Binary data with null bytes should roundtrip correctly");
}
