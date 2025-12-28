# Roadmap: oxidized-cryptolib → Production FUSE Filesystem

## Goal
Transform oxidized-cryptolib into a feature-complete, ergonomic library for building a high-performance Cryptomator client with FUSE filesystem support.

**Target:** FUSE mount (macOS/Linux) with full Cryptomator compatibility using Tokio async runtime.

---

## Phase 1: Protocol Completeness ✅ COMPLETE

**Priority:** HIGHEST | **Dependency:** None

All other features depend on full Cryptomator Format 8 compatibility.

### 1.1 Symlink Support
**Files:** `src/fs/symlink.rs`, `src/vault/operations.rs`, `src/fs/directory.rs`

- [x] Add `read_symlink()` to decrypt `symlink.c9r` content
- [x] Add `create_symlink(dir_id, name, target)`
- [x] Update `DirectoryEntry` enum with `Symlink { name, target }` variant
- [x] Handle symlinks in `list_files()` and directory traversal
- [x] Support long symlink names (`.c9s` format)

### 1.2 Unicode NFC Normalization
**File:** `src/fs/name.rs`

```rust
use unicode_normalization::UnicodeNormalization;
let normalized: String = name.nfc().collect();
```

- [x] Apply in `encrypt_filename()` - normalize before encryption
- [x] Apply in path resolution throughout `VaultOperations`

### 1.3 Backup dirid.c9r Files
**File:** `src/vault/operations.rs`

- [x] Write `dirid.c9r` (encrypted parent ID) when creating directories
- [x] Add `recover_directory_id()` for vault repair scenarios (`recover_parent_dir_id()`, `recover_directory_tree()`)

---

## Phase 2: Async Migration ✅ COMPLETE

**Priority:** HIGH | **Dependency:** Phase 1

### 2.1 Dual API Strategy ✅
Separate struct approach for clean async/sync separation:

```rust
// Sync (existing, unchanged)
pub struct VaultOperations { ... }

// Async (new, behind feature flag)
#[cfg(feature = "async")]
pub struct VaultOperationsAsync { ... }
```

**Rationale:** MasterKey uses RefCell (not Send/Sync), so a separate struct with cloned key is cleaner than `_async` method variants.

### 2.2 Tokio Integration ✅
**File:** `crates/oxidized-cryptolib/Cargo.toml`

```toml
[features]
default = []
async = ["dep:tokio"]

[dependencies]
tokio = { version = "1", features = ["fs", "io-util", "sync"], optional = true }
```

### 2.3 Operations Made Async (Phase 2a - HIGH Priority) ✅
| Operation | Status | Notes |
|-----------|--------|-------|
| `list_files()` | ✅ Done | Async directory iteration |
| `list_directories()` | ✅ Done | Async directory iteration |
| `read_file()` | ✅ Done | Uses `tokio::fs::read()` |
| `write_file()` | ✅ Done | Uses `atomic_write()` with tokio::fs |
| Crypto ops | N/A | Keep sync (CPU-bound) |

### 2.4 Remaining Operations (Phase 2b) ✅ COMPLETE
| Operation | Priority | Status |
|-----------|----------|--------|
| `resolve_path()` | Medium | ✅ Done |
| `read_by_path()` | Medium | ✅ Done |
| `write_by_path()` | Medium | ✅ Done |
| `delete_file()` | Low | ✅ Done |
| `delete_directory()` | Low | ✅ Done |
| `create_directory()` | Low | ✅ Done |
| `rename_file()` | Low | ✅ Done |
| `move_file()` | Low | ✅ Done |

---

## Phase 3: Streaming API ✅ COMPLETE

**Priority:** HIGH | **Dependency:** Phase 2

Essential for FUSE where files are read/written in chunks.

### 3.1 Streaming Reader ✅
**File:** `src/fs/streaming.rs`

```rust
pub struct VaultFileReader {
    pub async fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
    pub fn plaintext_size(&self) -> u64;
}
```

- [x] Random access reads via `read_range(offset, length)`
- [x] Automatic chunk caching for efficient access patterns
- [x] Cross-chunk reads handled transparently
- [x] EOF handling with partial reads

### 3.2 Random Access (Seek) ✅
- [x] Calculate chunk number from plaintext offset
- [x] Seek to encrypted chunk position
- [x] Decrypt only needed chunks
- [x] Cache current chunk for sequential reads

### 3.3 Streaming Writer ✅
```rust
pub struct VaultFileWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<usize>;
    pub async fn finish(self) -> Result<PathBuf>;
    pub async fn abort(self) -> Result<()>;
}
```

- [x] Sequential streaming writes
- [x] Automatic chunk boundary handling
- [x] Safe abort with temp file cleanup
- [x] Finalization returns encrypted path

### 3.4 Memory Efficiency ✅
- [x] Buffer one chunk at a time
- [x] Zeroize key material on drop
- [x] Efficient chunk caching

---

## Phase 4: Concurrent Access ✅ COMPLETE

**Priority:** MEDIUM | **Dependency:** Phase 2

### 4.1 Locking Strategy ✅
**File:** `src/vault/locks.rs`

```rust
pub struct VaultLockManager {
    directory_locks: DashMap<DirId, Arc<RwLock<()>>>,
    file_locks: DashMap<(DirId, String), Arc<RwLock<()>>>,
}
```

- [x] Multiple readers allowed (RwLock)
- [x] Single writer with exclusive access
- [x] Directory writes lock parent
- [x] Move operations lock source + destination with ordered locking

### 4.2 Handle Table ✅
**File:** `src/vault/handles.rs`

```rust
pub struct VaultHandleTable {
    handles: DashMap<u64, OpenHandle>,
    next_id: AtomicU64,
}
```

- [x] FUSE-compatible file handle management
- [x] Atomic handle ID generation
- [x] Thread-safe insert/get/remove

### 4.3 Deadlock Prevention ✅
- [x] Consistent directory ordering (lexicographic by DirId)
- [x] Directory before file locking
- [x] No lock upgrades (read → write)
- [x] Ordered file locking (lexicographic by filename)
- [x] Internal unlocked methods prevent reentrant deadlocks

---

## Phase 5: FUSE Integration Layer

**Priority:** MEDIUM | **Dependency:** Phases 3, 4

### 5.1 Core Abstractions
**File:** `src/fuse/mod.rs` (new module)

```rust
pub struct InodeTable {
    path_to_inode: HashMap<VaultPath, u64>,
    inode_to_entry: HashMap<u64, InodeEntry>,
}

pub struct FileHandleTable {
    handles: DashMap<u64, FileHandle>,
}

pub struct AttrCache {
    entries: DashMap<u64, CachedAttr>,
    ttl: Duration,
}
```

### 5.2 FUSE → Vault Mapping

| FUSE Op | Vault Operation |
|---------|-----------------|
| `lookup` | `resolve_path` + inode creation |
| `read` | `VaultFileReader::read_range` |
| `write` | `VaultFileWriter::write` |
| `readdir` | `list_files` + `list_directories` |
| `create` | `write_file` |
| `mkdir` | `create_directory` |
| `unlink` | `delete_file` |
| `rmdir` | `delete_directory` |
| `rename` | `move_and_rename_file` |
| `readlink` | `read_symlink` |
| `symlink` | `create_symlink` |

### 5.3 Dependencies
```toml
[target.'cfg(unix)'.dependencies]
fuser = "0.14"
```

---

## Phase 6: Ergonomics & Polish (90% Complete)

**Priority:** LOW | **Dependency:** None (parallel)

### 6.1 Path-Based High-Level API ✅
```rust
vault_ops.read_by_path("docs/readme.txt")?;
vault_ops.write_by_path("docs/new.txt", content)?;
vault_ops.delete_by_path("docs/old.txt")?;
```

### 6.2 Structured Error Context ✅
Implemented via `NameContext`, `FileContext`, `SymlinkContext`, `VaultOpContext` structs:
```rust
#[error("[INTEGRITY VIOLATION] Failed to decrypt {context}: authentication failed")]
DecryptionFailed { context: NameContext }
```

### 6.3 Tracing Integration ✅
25+ functions instrumented with `#[instrument]`:
```rust
#[instrument(level = "debug", skip(self), fields(dir_id = %dir_id.as_str()))]
pub fn read_file(...) { ... }
```

### 6.4 CLI Tool ✅
**Crate:** `crates/oxidized-cli`

Full-featured CLI with commands:
- `init` - Create new vault
- `info` - Show vault details
- `ls` / `tree` - List files
- `cat` / `write` - Read/write files
- `mkdir` / `rm` / `mv` / `cp` - File operations
- `touch` - Create empty files

### 6.5 Documentation
- [ ] Comprehensive rustdoc
- [ ] `examples/mount_vault.rs`
- [ ] `examples/explore_vault.rs`
- [ ] ARCHITECTURE.md

---

## Dependency Graph

```
Phase 1 (Protocol) ✅ ──→ Phase 2 (Async) ✅ ──→ Phase 3 (Streaming) ✅ ──┬─→ Phase 5 (FUSE) ⏳
                               │                                          │
                               └─→ Phase 4 (Concurrent) ✅ ───────────────┘

Phase 6 (Polish) ──→ 90% complete, runs in parallel
```

---

## Critical Files

| File | Status | Changes |
|------|--------|---------|
| `src/fs/symlink.rs` | ✅ Done | Symlink read/write |
| `src/fs/name.rs` | ✅ Done | NFC normalization added |
| `src/vault/operations.rs` | ✅ Done | Symlink ops, path-based API, recovery functions |
| `src/fs/file_async.rs` | ✅ Done | Async file decrypt/encrypt |
| `src/vault/operations_async.rs` | ✅ Done | VaultOperationsAsync struct (all operations) |
| `Cargo.toml` | ✅ Done | Tokio feature flag added |
| `src/fs/streaming.rs` | ✅ Done | VaultFileReader, VaultFileWriter |
| `src/vault/locks.rs` | ✅ Done | VaultLockManager with deadlock prevention |
| `src/vault/handles.rs` | ✅ Done | VaultHandleTable for FUSE handles |
| `src/fuse/mod.rs` | Pending | FUSE integration layer |
