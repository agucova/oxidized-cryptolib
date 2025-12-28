# oxidized-cryptolib Implementation Scratchpad

## Priority Tiers

### Tier 1: Core Operations (High Impact, Low Risk) ✅ COMPLETE
- [x] **Rename/move operations** - `rename_file()`, `move_file()`, `rename_directory()`, `move_and_rename_file()`
- [x] **Recursive delete** - `delete_directory_recursive()`

### Tier 2: API Hardening (Medium Impact)
- [ ] **O_EXCL semantics** - `write_file_exclusive()` that fails if file exists
- [ ] **Path type safety** - `VaultPath` newtype to prevent path/dir_id confusion
- [ ] **Error context** - Add path/filename context to error variants

### Tier 3: Performance & Usability
- [ ] **File handles** - `OpenFile` struct for multiple read/write operations
- [ ] **Streaming I/O** - `Read`/`Write` trait implementations for large files
- [ ] **Metadata access** - File size, timestamps without full decryption

### Tier 4: Concurrency & Caching
- [ ] **Thread safety audit** - Document/enforce `Send + Sync` bounds
- [ ] **Directory cache** - LRU cache for directory listings
- [ ] **Async API** - `async fn` variants for FUSE/network backends

### Tier 5: Protocol Completeness
- [ ] **Symlink support** - Read/write `symlink.c9r` files
- [ ] **Copy optimization** - Server-side copy without decrypt/re-encrypt
- [ ] **Integrity checking** - Verify all chunks, detect corruption

---

## Tier 1 Implementation Plan

### 1. Rename/Move Operations

#### 1.1 `rename_file(dir_id, old_name, new_name) -> Result<(), VaultWriteError>`

**Semantics**: Rename a file within the same directory.

**Implementation**:
1. Find the existing encrypted file path via `list_files()` lookup
2. Encrypt the new filename with same `dir_id` as context
3. Handle long filename transitions:
   - Short → Short: Simple rename of `.c9r` file
   - Short → Long: Create `.c9s` directory, move content, write `name.c9s`
   - Long → Short: Read from `.c9s`, write as `.c9r`, delete `.c9s` directory
   - Long → Long: Update `name.c9s` content only
4. Atomic operation: Create new first, then delete old (crash-safe)

**Edge cases**:
- Target name already exists → Return error (no silent overwrite)
- Source doesn't exist → `NotFound` error

#### 1.2 `move_file(src_dir_id, filename, dest_dir_id) -> Result<(), VaultWriteError>`

**Semantics**: Move a file to a different directory (re-encryption required).

**Implementation**:
1. Read and decrypt the file content from source
2. Write (encrypt) to destination with new directory context
3. Delete the source file
4. This is NOT atomic - document the failure modes

**Why re-encryption is required**:
- Filename encryption uses `dir_id` as associated data in AES-SIV
- Moving to different directory requires re-encrypting the filename
- File content doesn't need re-encryption (uses content key, not dir_id)

**Optimization opportunity**:
- Only re-encrypt filename, copy encrypted content blob directly
- Saves decrypt/encrypt cycle for file body

#### 1.3 `rename_directory(parent_dir_id, old_name, new_name) -> Result<(), VaultWriteError>`

**Semantics**: Rename a directory (does NOT change its internal `dir_id`).

**Implementation**:
1. Find existing directory entry in parent
2. Encrypt new name with `parent_dir_id`
3. Rename/recreate the `.c9r` directory with new encrypted name
4. The `dir.c9r` file inside keeps the same directory ID
5. All children remain valid (they reference the dir_id, not the name)

**Key insight**: Directory rename is simpler than file move because the `dir_id` doesn't change - only the encrypted name in the parent changes.

---

### 2. Recursive Delete

#### 2.1 `delete_directory_recursive(parent_dir_id, dir_name) -> Result<DeleteStats, VaultWriteError>`

**Semantics**: Delete a directory and all its contents.

**Return type**:
```rust
pub struct DeleteStats {
    pub files_deleted: usize,
    pub directories_deleted: usize,
}
```

**Implementation**:
1. Resolve the directory to get its `dir_id`
2. Recursively list all contents (depth-first)
3. Delete all files in the directory
4. Recursively delete all subdirectories
5. Delete the now-empty directory itself
6. Clean up the storage path under `/d/XX/YYYY.../`

**Traversal order**: Post-order (children before parents) to ensure directories are empty before deletion.

**Error handling options**:
- **Fail-fast**: Stop on first error, leave partial state
- **Best-effort**: Continue on errors, collect failures, return summary
- Recommend: Fail-fast for simplicity, document behavior

---

## Implementation Order

1. `rename_file()` - Most isolated, good starting point
2. `rename_directory()` - Similar pattern, simpler than move
3. `delete_directory_recursive()` - Builds on existing `delete_*` functions
4. `move_file()` - Most complex, benefits from rename patterns

---

## Test Cases Needed

### Rename Tests
- Rename file with short name to short name
- Rename file with short name to long name (>220 chars)
- Rename file with long name to short name
- Rename to existing name (should fail)
- Rename non-existent file (should fail)
- Rename directory
- Rename directory with children (verify children still accessible)

### Move Tests
- Move file between directories
- Move file to same directory (edge case, should work)
- Move to non-existent directory (should fail)
- Move non-existent file (should fail)

### Recursive Delete Tests
- Delete empty directory
- Delete directory with files only
- Delete directory with subdirectories
- Delete deeply nested structure
- Verify storage paths cleaned up

---

## Security Hardening (vs `ring` Best Practices)

Based on comprehensive code review comparing against top cryptographic libraries.

### High Priority (Security Critical) ✅ COMPLETE

- [x] **1. Add constant-time comparison for integrity checks**
  - Location: `src/crypto/key_wrap.rs:165-166`
  - Fix applied: Using `subtle::ConstantTimeEq` for IV comparison
  - Prevents timing oracle attacks on integrity verification

- [x] **2. Wrap `FileHeader.content_key` in `Zeroizing`**
  - Location: `src/fs/file.rs:53-55`
  - Fix applied: `pub content_key: Zeroizing<[u8; 32]>`
  - Also fixed: Debug impl now shows `[REDACTED]` instead of hex-encoded key
  - Ensures content keys are zeroed on drop, prevents accidental logging

- [x] **3. Zeroize unwrapped key material in `unwrap_key`**
  - Location: `src/crypto/key_wrap.rs:125, 178-179`
  - Fix applied: Returns `Zeroizing<Vec<u8>>` instead of `Vec<u8>`
  - Plaintext key material now automatically zeroed when dropped

### Medium Priority (Robustness)

- [x] **4. Make `MasterKey` fields private** ✅ COMPLETE
  - Location: `src/crypto/keys.rs:28-31`
  - Fix applied: Removed `pub` from fields, added `MasterKey::new(aes_key, mac_key)` constructor
  - Updated callers: `vault/master_key.rs`, test helpers in `fs/directory.rs`, `fs/name.rs`
  - Rationale: Enforces use of scoped access methods for better security

- [ ] **5. Add fuzzing targets**
  - Create: `fuzz/` directory with `cargo-fuzz` targets
  - Priority targets:
    - `fuzz_file_header_decrypt` - malformed headers
    - `fuzz_key_unwrap` - malformed ciphertext
    - `fuzz_filename_decrypt` - malformed Base64/ciphertext
  - Rationale: Catches edge cases property tests miss

- [ ] **6. Integrate Wycheproof AEAD test vectors**
  - Location: New test file `tests/wycheproof_tests.rs`
  - Source: https://github.com/google/wycheproof
  - Focus: AES-GCM edge cases (invalid tags, nonce reuse detection, etc.)
  - Rationale: Industry-standard cryptographic test suite

### Lower Priority (Polish)

- [x] **7. Document threat model** ✅ COMPLETE
  - Created: `SECURITY.md`
  - Contents: Security goals, in/out-of-scope threats, accepted risks, dependency trust model
  - Timing attacks in scope (verified via dudect)
  - mlock noted as planned mitigation

- [ ] **8. Consider `mlock` for key pages**
  - Scope: Optional feature flag `#[cfg(feature = "mlock")]`
  - Implementation: Use `region` or `memsec` crate
  - Platforms: Linux, macOS (Windows has different API)
  - Rationale: Prevents keys from being swapped to disk
  - Trade-off: Adds platform-specific code, may fail on some systems

- [ ] **9. Add timing regression tests**
  - Location: `benches/` or separate CI job
  - Method: Statistical comparison of decrypt times for valid vs invalid data
  - Rationale: Catches accidentally introduced timing leaks
  - Note: Flaky by nature, needs careful threshold tuning

---

## Code Locations Reference

| Issue | File | Line(s) |
|-------|------|---------|
| Non-constant-time comparison | `src/crypto/key_wrap.rs` | 163 |
| Unprotected content key | `src/fs/file.rs` | 46-48 |
| Unzeroed return value | `src/crypto/key_wrap.rs` | 170 |
| Public MasterKey fields | `src/crypto/keys.rs` | 24-27 |
| MasterKey construction | `src/vault/master_key.rs` | 136-139 |

---

## Dependencies to Add

```toml
# For constant-time comparisons (issue #1) ✅ ADDED
subtle = "2"

# For fuzzing (issue #5)
[dev-dependencies]
arbitrary = { version = "1", features = ["derive"] }

# Optional mlock support (issue #8)
[target.'cfg(unix)'.dependencies]
region = { version = "3", optional = true }
```
