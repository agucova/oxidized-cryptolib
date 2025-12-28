# Roadmap: oxidized-cryptolib → Production FUSE Filesystem

## Goal
Transform oxidized-cryptolib into a feature-complete, ergonomic library for building a high-performance Cryptomator client with FUSE filesystem support.

**Target:** FUSE mount (macOS/Linux) with full Cryptomator compatibility using Tokio async runtime.

---

## Phase 1: Protocol Completeness ⬅️ CURRENT

**Priority:** HIGHEST | **Dependency:** None

All other features depend on full Cryptomator Format 8 compatibility.

### 1.1 Symlink Support
**Files:** `src/fs/symlink.rs` (new), `src/vault/operations.rs`, `src/fs/directory.rs`

- [ ] Add `read_symlink()` to decrypt `symlink.c9r` content
- [ ] Add `create_symlink(dir_id, name, target)`
- [ ] Update `DirectoryEntry` enum with `Symlink { name, target }` variant
- [ ] Handle symlinks in `list_files()` and directory traversal
- [ ] Support long symlink names (`.c9s` format)

### 1.2 Unicode NFC Normalization
**File:** `src/fs/name.rs`

```rust
use unicode_normalization::UnicodeNormalization;
let normalized: String = name.nfc().collect();
```

- [ ] Apply in `encrypt_filename()` - normalize before encryption
- [ ] Apply in path resolution throughout `VaultOperations`

### 1.3 Backup dirid.c9r Files
**File:** `src/vault/operations.rs`

- [ ] Write `dirid.c9r` (encrypted parent ID) when creating directories
- [ ] Add `recover_directory_id()` for vault repair scenarios

---

## Phase 2: Async Migration

**Priority:** HIGH | **Dependency:** Phase 1

### 2.1 Dual API Strategy
Maintain sync API, add async variants:

```rust
// Sync (existing)
pub fn read_file(&self, ...) -> Result<DecryptedFile>

// Async (new)
pub async fn read_file_async(&self, ...) -> Result<DecryptedFile>
```

### 2.2 Tokio Integration
**File:** `Cargo.toml`

```toml
[dependencies]
tokio = { version = "1", features = ["fs", "io-util", "rt-multi-thread"], optional = true }

[features]
default = []
async = ["tokio"]
```

### 2.3 Operations to Make Async
| Operation | Priority | Reason |
|-----------|----------|--------|
| `read_file` | High | Large file I/O |
| `write_file` | High | Large file I/O |
| `list_files` | Medium | Directory iteration |
| `resolve_path` | Medium | Multiple dir reads |
| Crypto ops | N/A | Keep sync (CPU-bound) |

---

## Phase 3: Streaming API

**Priority:** HIGH | **Dependency:** Phase 2

Essential for FUSE where files are read/written in chunks.

### 3.1 Streaming Reader
**File:** `src/fs/streaming.rs` (new)

```rust
pub struct VaultFileReader {
    // Decrypts on-demand, supports random access
    pub async fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
    pub fn plaintext_size(&self) -> u64;
}
```

### 3.2 Random Access (Seek)
Cryptomator's 32KB independent chunks enable efficient seeking:
- Calculate chunk number from plaintext offset
- Seek to encrypted chunk position
- Decrypt only needed chunks

### 3.3 Streaming Writer
```rust
pub struct VaultFileWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<usize>;
    pub async fn finish(self, dest: &Path) -> Result<()>;
}
```

### 3.4 Memory Efficiency
- Buffer max 2 chunks (current + read-ahead)
- Zeroize key material and decrypted data
- Use `Cow<[u8]>` for zero-copy where possible

---

## Phase 4: Concurrent Access

**Priority:** MEDIUM | **Dependency:** Phase 2

### 4.1 Locking Strategy
**File:** `src/vault/locks.rs` (new)

```rust
pub struct VaultLockManager {
    file_locks: DashMap<VaultPath, Arc<RwLock<()>>>,
    directory_locks: DashMap<DirId, Arc<RwLock<()>>>,
}
```

- Multiple readers allowed
- Single writer with exclusive access
- Directory writes lock parent
- Move operations lock source + destination

### 4.2 Consistency Model
Start with optimistic concurrency (let FUSE handle ENOENT), add snapshot isolation if needed.

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

## Phase 6: Ergonomics & Polish

**Priority:** LOW | **Dependency:** None (parallel)

### 6.1 Path-Based High-Level API
```rust
vault_ops.read_by_path("docs/readme.txt")?;
vault_ops.write_by_path("docs/new.txt", content)?;
vault_ops.delete_by_path("docs/old.txt")?;
```

### 6.2 Structured Error Context
```rust
#[error("Failed to read '{filename}' in {dir_id}: {source}")]
FileRead { filename: String, dir_id: DirId, source: FileError }
```

### 6.3 Tracing Integration
```rust
#[instrument(skip(self, master_key))]
pub fn read_file(...) { ... }
```

### 6.4 Documentation
- Comprehensive rustdoc
- `examples/mount_vault.rs`
- `examples/explore_vault.rs`
- ARCHITECTURE.md

---

## Dependency Graph

```
Phase 1 (Protocol) ──→ Phase 2 (Async) ──→ Phase 3 (Streaming) ──┬─→ Phase 5 (FUSE)
                            │                                     │
                            └─→ Phase 4 (Concurrent) ─────────────┘

Phase 6 (Polish) ──→ runs in parallel with all phases
```

---

## Critical Files

| File | Changes |
|------|---------|
| `src/fs/symlink.rs` | **NEW** - Symlink read/write |
| `src/fs/streaming.rs` | **NEW** - Streaming reader/writer |
| `src/fs/name.rs` | Add NFC normalization |
| `src/vault/operations.rs` | Async variants, symlink ops, path-based API |
| `src/vault/locks.rs` | **NEW** - Concurrent access |
| `src/fuse/mod.rs` | **NEW** - FUSE integration layer |
| `Cargo.toml` | Add tokio, fuser, features |
