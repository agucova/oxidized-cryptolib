# Integration Testing Guide

This document captures the testing philosophy and architecture for mount backend integration tests. Use it as a reference when implementing test suites for FUSE, FSKit, WebDAV, or future backends.

## Testing Philosophy

### Principle 1: Every test should catch a real bug class

No "smoke tests" that just check something runs. Each test targets specific failure modes:

```rust
// BAD: Just checks it doesn't crash
#[test]
fn test_read_file() {
    let content = fs.read("/file.txt");
    assert!(content.is_ok());
}

// GOOD: Verifies actual behavior
#[test]
fn test_read_preserves_binary_content() {
    let original: Vec<u8> = (0u8..=255).collect();
    fs.write("/file.bin", &original);
    let retrieved = fs.read("/file.bin").unwrap();
    assert_eq!(retrieved, original, "Binary content corrupted in roundtrip");
}
```

### Principle 2: Validate data integrity, not just success codes

- Always verify content matches expected values
- Use cryptographic hashes for large file verification
- Test the full encrypt → mount backend → decrypt roundtrip

```rust
// Verify large file integrity with hash
let content = random_bytes(5 * 1024 * 1024);  // 5MB
let expected_hash = sha256(&content);
fs.write("/large.bin", &content);
let retrieved = fs.read("/large.bin").unwrap();
assert_eq!(sha256(&retrieved), expected_hash);
```

### Principle 3: Test combinations, not just individual operations

Operations often fail in sequences. Cache invalidation bugs only appear in multi-step scenarios:

```rust
// Test sequence that catches cache bugs
fs.write("/file.txt", b"version1");
assert_eq!(fs.read("/file.txt"), b"version1");
fs.write("/file.txt", b"version2");  // Overwrite
assert_eq!(fs.read("/file.txt"), b"version2");  // Must see new content
```

### Principle 4: Automate everything

- No external tool dependencies (avoid pjdfstest, fsx requiring manual setup)
- Tests run with just `cargo test`
- Self-contained test fixtures

## Test Categories

Every mount backend should have tests in these categories:

### 1. Basic CRUD Operations

| Test | What it catches |
|------|-----------------|
| `put_get_roundtrip` | Basic encryption/decryption |
| `put_overwrite` | Overwrite semantics, cache invalidation |
| `put_empty_file` | Zero-length file handling |
| `put_exactly_one_chunk` | 32KB boundary (exactly one chunk) |
| `put_chunk_boundary_minus_one` | 32KB - 1 byte (chunk boundary) |
| `put_chunk_boundary_plus_one` | 32KB + 1 byte (two chunks) |
| `put_large_file` | Multi-chunk (5+ chunks) |
| `delete_file` | File deletion |
| `mkdir_simple` | Directory creation |
| `rmdir_empty` | Delete empty directory |
| `rmdir_nonempty` | Delete non-empty dir (should fail) |

**Why chunk boundaries matter**: Cryptomator uses 32KB chunks with AES-GCM. Bugs often appear at:
- Exactly 32KB (one full chunk)
- 32KB - 1 (partial chunk)
- 32KB + 1 (chunk boundary crossing)

### 2. Move/Copy Operations

| Test | What it catches |
|------|-----------------|
| `move_file_same_dir` | Rename within directory |
| `move_file_different_dir` | Move across directories |
| `move_file_overwrite` | Move with overwrite=true |
| `move_directory` | Directory rename |
| `copy_file` | File duplication |
| `move_then_read_old_path` | Verify old path returns error |
| `copy_then_modify_original` | Copy independence verification |

**Bug classes**: Path mapping after move, directory ID tracking, cache invalidation.

### 3. Metadata Operations

| Test | What it catches |
|------|-----------------|
| `list_root` | Root directory listing |
| `list_subdirectory` | Nested directory listing |
| `file_size_accuracy` | Size matches actual content |
| `metadata_after_write` | Metadata refresh after modification |
| `metadata_after_delete` | Removed entries not in listing |

### 4. Concurrent Operations

| Test | What it catches |
|------|-----------------|
| `concurrent_reads_same_file` | No corruption under parallel reads |
| `concurrent_writes_different_files` | Parallel writes don't interfere |
| `concurrent_write_same_file` | Proper conflict handling |
| `rapid_create_delete_cycle` | Fast create/delete race conditions |
| `cache_invalidation_race` | Read stale after parallel write |

**Implementation pattern**:
```rust
#[tokio::test]
async fn test_concurrent_reads() {
    let content = random_bytes(100_000);
    fs.write("/file.bin", &content).await;

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let fs = fs.clone();
            let expected = content.clone();
            tokio::spawn(async move {
                let actual = fs.read("/file.bin").await.unwrap();
                assert_eq!(actual, expected);
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}
```

### 5. Error Handling

| Test | What it catches |
|------|-----------------|
| `read_nonexistent` | Proper error for missing files |
| `mkdir_no_parent` | Error when parent missing |
| `mkdir_over_file` | Can't mkdir over existing file |
| `write_to_directory` | Can't write to directory path |
| `delete_nonempty_dir` | Error for non-empty directory |
| `path_traversal_attempt` | Security: `../` handling |

### 6. Data Integrity

| Test | What it catches |
|------|-----------------|
| `binary_content_preserved` | No encoding corruption |
| `all_byte_values` | All 256 byte values (0x00-0xFF) |
| `unicode_content` | UTF-8 content preservation |
| `unicode_filename` | Unicode filenames work |
| `special_char_filename` | Spaces, quotes, etc. in names |
| `chunk_boundary_content` | Data spanning chunk boundaries |
| `hash_large_file` | SHA-256 verification for big files |

### 7. Multi-Step Workflows

| Test | What it catches |
|------|-----------------|
| `create_populate_delete_cycle` | Full CRUD sequence |
| `nested_directory_operations` | Deep mkdir/rmdir |
| `file_replace_workflow` | Delete + create same name |
| `rename_chain` | A→B→C→D rename sequence |
| `directory_tree_operations` | Create tree, enumerate, delete |

## Test Infrastructure Pattern

### Test Harness

Each backend should have a test harness that:
1. Sets up a temporary vault
2. Starts the mount backend
3. Provides convenience methods for operations
4. Cleans up on drop

```rust
pub struct TestMount {
    // Backend-specific handle (FUSE session, WebDAV server, etc.)
    handle: BackendHandle,
    // Cleanup on drop
    _temp_dir: TempDir,
}

impl TestMount {
    /// Create mount with fresh temporary vault
    pub async fn with_temp_vault() -> Self;

    /// Create mount with shared test_vault (read-only tests)
    pub async fn with_test_vault() -> Self;

    // Convenience methods adapted per backend
    pub async fn read(&self, path: &str) -> Result<Vec<u8>>;
    pub async fn write(&self, path: &str, content: &[u8]) -> Result<()>;
    pub async fn delete(&self, path: &str) -> Result<()>;
    pub async fn mkdir(&self, path: &str) -> Result<()>;
    pub async fn list(&self, path: &str) -> Result<Vec<String>>;
    pub async fn rename(&self, from: &str, to: &str) -> Result<()>;
    pub async fn copy(&self, from: &str, to: &str) -> Result<()>;
}
```

### Assertion Utilities

```rust
/// Verify file content matches expected
pub async fn assert_content(mount: &TestMount, path: &str, expected: &[u8]);

/// Verify directory contains exactly these entries
pub async fn assert_entries(mount: &TestMount, path: &str, expected: &[&str]);

/// Verify path does not exist
pub async fn assert_not_found(mount: &TestMount, path: &str);
```

### Test Data Generators

```rust
/// Generate random bytes
pub fn random_bytes(size: usize) -> Vec<u8>;

/// Generate content spanning N encryption chunks (32KB each)
pub fn multi_chunk_content(chunks: usize) -> Vec<u8>;

/// Generate filename with special characters
pub fn special_filename() -> String;

/// Generate deep nested path
pub fn deep_path(depth: usize) -> String;
```

## Backend-Specific Considerations

### FUSE
- Use `fuser` crate's test utilities
- Mount in foreground for tests
- Signal handling for cleanup
- Test with both sync and async operations

### FSKit (macOS 15.4+)
- Requires FSKitBridge.app running
- XPC communication adds latency
- Test item ID stability across operations

### WebDAV
- HTTP client (reqwest) for operations
- Test WebDAV-specific methods (PROPFIND, MKCOL, MOVE, COPY)
- Verify HTTP status codes match WebDAV spec
- Test Range requests for partial reads

## File Structure

```
crates/oxcrypt-{backend}/
├── tests/
│   ├── common/
│   │   ├── mod.rs           # Re-exports
│   │   ├── harness.rs       # TestMount implementation
│   │   ├── assertions.rs    # Custom assertions
│   │   └── generators.rs    # Test data generators
│   │
│   ├── crud_tests.rs        # Basic CRUD operations
│   ├── move_copy_tests.rs   # Move/copy operations
│   ├── metadata_tests.rs    # Listing and metadata
│   ├── concurrency_tests.rs # Parallel operations
│   ├── error_tests.rs       # Error handling
│   ├── integrity_tests.rs   # Data integrity
│   └── workflow_tests.rs    # Multi-step sequences
```

## Success Criteria

- All tests run with `cargo test -p oxcrypt-{backend}`
- No external tool dependencies
- Tests complete in < 60 seconds
- All filesystem operations exercised
- Chunk boundary edge cases covered
- Concurrency bugs detectable
- No flaky tests (deterministic)

## Porting Tests Between Backends

When implementing a new backend:

1. Copy the test structure from an existing backend
2. Implement `TestMount` for the new backend
3. Adapt operation methods to backend's interface
4. Run tests - most should pass if backend is correct
5. Add backend-specific tests (e.g., WebDAV HTTP codes)

The test logic remains the same; only the harness changes.
