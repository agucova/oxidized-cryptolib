# oxidized-cryptolib Implementation Scratchpad

## Priority Tiers

### Tier 1: Core Operations (High Impact, Low Risk) ✅ COMPLETE
- [x] **Rename/move operations** - `rename_file()`, `move_file()`, `rename_directory()`, `move_and_rename_file()`
- [x] **Recursive delete** - `delete_directory_recursive()`

### Tier 2: API Hardening (Medium Impact) ✅ COMPLETE
- [x] **O_EXCL semantics** - `write_file_exclusive()` that fails if file exists
- [x] **Path type safety** - `VaultPath` newtype for virtual paths, `DirId` for directory IDs
- [x] **Error context** - Comprehensive error types with path/filename context

### Tier 3: Performance & Usability ✅ COMPLETE (Phase 3: Streaming I/O)
- [x] **File handles** - `VaultFileReader` and `VaultFileWriter` for streaming operations
- [x] **Streaming I/O** - Async streaming read/write with random access support
- [x] **Metadata access** - File size calculation via `encrypted_to_plaintext_size()`

### Tier 4: Concurrency & Caching ✅ COMPLETE (Phase 4: Concurrent Access)
- [x] **Thread safety** - `VaultLockManager` with per-directory and per-file RwLocks
- [x] **Handle table** - `VaultHandleTable` for FUSE file handle management
- [x] **Async API** - `VaultOperationsAsync` with full async/await support
- [x] **Deadlock prevention** - Ordered locking strategy for multi-resource operations

### Tier 5: Protocol Completeness ✅ COMPLETE
- [x] **Symlink support** - Read/write `symlink.c9r` files via `create_symlink()`, `read_symlink()`
- [x] **Copy optimization** - Direct encrypted content copy in `move_file()` without re-encryption
- [x] **Integrity checking** - AES-GCM tag verification on all chunks

---

## Phase 3: Streaming I/O Implementation ✅ COMPLETE

### Components Created

| File | Purpose |
|------|---------|
| `src/fs/streaming.rs` | `VaultFileReader` and `VaultFileWriter` types |
| `tests/streaming_tests.rs` | Integration tests for streaming API |

### VaultFileReader Features
- Random access reads via `read_range(offset, length)`
- Automatic chunk caching for efficient access patterns
- Cross-chunk reads handled transparently
- EOF handling with partial reads

### VaultFileWriter Features
- Sequential streaming writes via `write(data)`
- Automatic chunk boundary handling
- Safe abort via `abort()` method
- Finalization via `finish()` that returns encrypted path

### API Integration
```rust
// Streaming read
let mut reader = ops.open_file(&dir_id, "file.txt").await?;
let data = reader.read_range(0, 1024).await?;

// Streaming write
let mut writer = ops.create_file(&dir_id, "new.txt").await?;
writer.write(b"Hello, World!").await?;
writer.finish().await?;

// Path-based streaming
let mut reader = ops.open_file_by_path("dir/file.txt").await?;
let mut writer = ops.create_file_by_path("dir/new.txt").await?;
```

---

## Phase 4: Concurrent Access Implementation ✅ COMPLETE

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    VaultOperationsAsync                      │
│  (holds Arc<VaultLockManager>, coordinates all operations)   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     VaultLockManager                         │
│  ┌──────────────────────┐  ┌──────────────────────────────┐ │
│  │   directory_locks    │  │       file_locks             │ │
│  │  DashMap<DirId,      │  │  DashMap<(DirId, String),    │ │
│  │    Arc<RwLock<()>>>  │  │    Arc<RwLock<()>>>          │ │
│  └──────────────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     VaultHandleTable                         │
│  (For FUSE: maps u64 handles to open files/writers)         │
│  DashMap<u64, OpenHandle>                                    │
└─────────────────────────────────────────────────────────────┘
```

### Components Created

| File | Purpose | Lines |
|------|---------|-------|
| `src/vault/locks.rs` | `VaultLockManager` with ordered locking | ~410 |
| `src/vault/handles.rs` | `VaultHandleTable` for FUSE handles | ~230 |
| `tests/concurrency_tests.rs` | 17 concurrency tests | ~500 |

### Locking Strategy

| Operation | Lock Type |
|-----------|-----------|
| `list_files`, `list_directories` | Directory read |
| `read_file`, `open_file` | File read |
| `write_file`, `create_file` | File write |
| `delete_file` | Directory write + File write |
| `create_directory`, `delete_directory` | Directory write (ordered if multiple) |
| `rename_file` | Directory write + File writes (ordered by name) |
| `move_file` | Both directory writes (ordered by DirId) + File write |

### Deadlock Prevention Rules
1. **Consistent directory ordering**: Lock directories in lexicographic order of `DirId`
2. **Directory before file**: Always acquire directory lock before file lock
3. **No lock upgrades**: Never upgrade read to write lock
4. **No recursive locking**: tokio::sync::RwLock is not reentrant
5. **Ordered file locking**: Lock multiple files in lexicographic filename order

### Key Implementation Details
- Uses `DashMap` for lock-free reads on existing entries
- Uses `tokio::sync::RwLock` for async-compatible locks
- Uses `OwnedRwLockReadGuard`/`OwnedRwLockWriteGuard` for holding locks across await points
- Internal unlocked methods (`list_files_unlocked`, `list_directories_unlocked`) prevent reentrant deadlocks

---

## Security Hardening ✅ COMPLETE

### High Priority (Security Critical) ✅ COMPLETE

- [x] **1. Constant-time comparison for integrity checks**
  - Location: `src/crypto/key_wrap.rs`
  - Fix: Using `subtle::ConstantTimeEq` for IV comparison
  - Verified via dudect timing analysis

- [x] **2. Memory-protected keys via `memsafe` crate**
  - Location: `src/crypto/keys.rs`
  - Features: mlock, mprotect, automatic zeroization on drop
  - Prevents keys from being swapped to disk

- [x] **3. Zeroize all key material**
  - `FileHeader.content_key` wrapped in `Zeroizing<[u8; 32]>`
  - `unwrap_key` returns `Zeroizing<Vec<u8>>`
  - Debug impls show `[REDACTED]` instead of key bytes

### Medium Priority (Robustness) ✅ COMPLETE

- [x] **4. Private `MasterKey` fields**
  - Enforces use of scoped access methods
  - Constructor: `MasterKey::new(aes_key, mac_key)`

- [x] **5. Fuzzing targets**
  - Location: `fuzz/` directory with `cargo-fuzz` targets
  - Targets: `fuzz_file_header`, `fuzz_filename`, `fuzz_keywrap`, `fuzz_symlink`
  - Continuous fuzzing infrastructure

- [x] **6. Wycheproof test vectors**
  - Location: `tests/wycheproof_tests.rs`
  - Coverage: AES-GCM, AES Key Wrap, HMAC edge cases
  - Industry-standard cryptographic test suite

### Lower Priority (Polish) ✅ COMPLETE

- [x] **7. Threat model documentation**
  - Location: `SECURITY.md`
  - Contents: Security goals, in/out-of-scope threats, accepted risks

- [x] **8. mlock for key pages**
  - Implemented via `memsafe` crate
  - Automatic on supported platforms (Linux, macOS)

- [x] **9. Timing leak detection**
  - Location: `benches/timing_leaks.rs`
  - Method: dudect statistical analysis
  - Tests: key unwrap, HMAC, AES-GCM decryption, filename decryption

---

## Test Coverage Summary

| Test Suite | Count | Feature |
|------------|-------|---------|
| Unit tests (lib) | ~150 | default |
| Integration tests | ~110 | default |
| Async tests | ~70 | async |
| Streaming tests | ~20 | async |
| Concurrency tests | 17 | async |
| Wycheproof tests | 6 | default |
| Property-based tests | ~20 | default |
| **Total** | **~395** | |

Run tests:
```bash
# All tests with async
cargo nextest run --features async

# Without async (277 tests)
cargo nextest run

# Timing leak detection
cargo bench --bench timing_leaks
```

---

## Dependencies Added

```toml
# Constant-time comparisons
subtle = "2"

# Memory protection
memsafe = "0.1"

# Async runtime
tokio = { version = "1", features = ["fs", "io-util", "sync", "rt-multi-thread"] }

# Concurrent data structures
dashmap = "6"

# Fuzzing (dev)
arbitrary = { version = "1", features = ["derive"] }

# Timing analysis (dev)
dudect-bencher = "0.4"
```

---

## Files Reference

### Core Crypto
| File | Purpose |
|------|---------|
| `src/crypto/keys.rs` | `MasterKey` with memory protection |
| `src/crypto/key_wrap.rs` | RFC 3394 AES Key Wrap |

### Vault Operations
| File | Purpose |
|------|---------|
| `src/vault/operations.rs` | Sync `VaultOperations` API |
| `src/vault/operations_async.rs` | Async `VaultOperationsAsync` API |
| `src/vault/locks.rs` | `VaultLockManager` for concurrency |
| `src/vault/handles.rs` | `VaultHandleTable` for FUSE |
| `src/vault/path.rs` | `DirId` and `VaultPath` types |

### Filesystem
| File | Purpose |
|------|---------|
| `src/fs/file.rs` | File encryption/decryption |
| `src/fs/streaming.rs` | `VaultFileReader`/`VaultFileWriter` |
| `src/fs/name.rs` | Filename encryption (AES-SIV) |
| `src/fs/symlink.rs` | Symlink handling |
| `src/fs/directory.rs` | Directory traversal |

---

## Next Steps (Phase 5: FUSE Implementation)

The concurrent access infrastructure is ready for FUSE integration:

```rust
// Example FUSE integration pattern
fn open(&mut self, ino: u64, flags: i32) -> Result<u64> {
    let reader = self.ops.open_file(&dir_id, &filename).await?;
    let handle = self.ops.handle_table().insert(OpenHandle::Reader(reader));
    Ok(handle)
}

fn read(&mut self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>> {
    let mut handle = self.ops.handle_table().get_mut(fh)?;
    if let OpenHandle::Reader(ref mut reader) = *handle {
        reader.read_range(offset as u64, size as usize).await
    } else {
        Err(EBADF)
    }
}

fn release(&mut self, fh: u64) -> Result<()> {
    self.ops.handle_table().remove(fh);
    Ok(())
}
```

Key components ready:
- [x] `VaultHandleTable` for file handle management
- [x] `VaultLockManager` for concurrent access control
- [x] `VaultFileReader` for random-access reads
- [x] `VaultFileWriter` for streaming writes
- [ ] FUSE filesystem implementation (using `fuser` crate)
