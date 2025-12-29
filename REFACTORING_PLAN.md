# Vault Operations Refactoring Plan

## Problem

- `operations.rs` (2,935 lines) and `operations_async.rs` (2,756 lines) have 60-70% code duplication
- 40+ methods implemented twice with nearly identical logic
- Async has optimizations (`find_file`, `find_directory`) that sync lacks
- Bug fixes must be manually ported between files
- No shared abstractions exist

## Approach: Shared Core + Thin Wrappers

After evaluating alternatives (maybe-async, full generics, code generation), the recommended approach is:

1. **VaultCore<K>** - Generic struct holding common state, parametric over key type
2. **Shared helpers** - Pure functions extracted to dedicated module
3. **Thin wrappers** - Sync/async implementations delegate to core, handle I/O
4. **Macros** - Generate boilerplate for `*_by_path()` convenience methods

This preserves the legitimate architectural differences (async has locking, streaming, handles) while eliminating duplicated logic.

## New Module Structure

```
crates/oxcrypt-core/src/vault/
├── operations/
│   ├── mod.rs           # Exports
│   ├── core.rs          # VaultCore<K> - shared logic
│   ├── helpers.rs       # Pure functions (path calc, builders)
│   ├── sync.rs          # VaultOperations wrapper
│   └── async_.rs        # VaultOperationsAsync wrapper
└── macros.rs            # Path wrapper macros
```

## Implementation Milestones

### Milestone 1: Foundation (files to create)
- [ ] Create `operations/` directory
- [ ] Create `operations/helpers.rs` - extract pure functions:
  - `calculate_storage_path()`
  - `parse_path_components()`
  - `build_file_info()`, `build_directory_info()`, `build_symlink_info()`
  - `needs_shortening()`
- [ ] Create `operations/core.rs` with `VaultCore<K>`:
  ```rust
  pub struct VaultCore<K> {
      vault_path: PathBuf,
      master_key: K,
      cipher_combo: CipherCombo,
      shortening_threshold: usize,
  }

  impl<K: AsRef<MasterKey>> VaultCore<K> {
      pub fn encrypt_filename(&self, ...) { ... }
      pub fn decrypt_filename(&self, ...) { ... }
      pub fn calculate_directory_storage_path(&self, ...) { ... }
  }
  ```
- [ ] Create `operations/mod.rs` with re-exports
- [ ] Verify all existing tests pass

### Milestone 2: Sync Refactor
- [ ] Move `operations.rs` to `operations/sync.rs`
- [ ] Refactor `VaultOperations` to contain `VaultCore<MasterKey>`
- [ ] Delegate pure methods to core
- [ ] Add `find_file()` and `find_directory()` (port from async)
- [ ] Update `resolve_path()` to use optimized lookups
- [ ] Run sync tests

### Milestone 3: Async Refactor
- [ ] Move `operations_async.rs` to `operations/async_.rs`
- [ ] Refactor `VaultOperationsAsync` to contain `VaultCore<Arc<MasterKey>>`
- [ ] Keep locking, streaming, handles unchanged
- [ ] Delegate pure methods to core
- [ ] Run async tests

### Milestone 4: Macro Cleanup
- [ ] Create `macros.rs` with `impl_path_wrappers_sync!` and `impl_path_wrappers_async!`
- [ ] Replace ~15 duplicated `*_by_path()` methods with macro invocations
- [ ] Verify path-based tests pass

### Milestone 5: Parity Tests
- [ ] Add comparison tests running same ops on sync/async
- [ ] Add tests for new sync `find_file()`, `find_directory()`
- [ ] Update module documentation

## Files to Modify

| File | Action |
|------|--------|
| `src/vault/operations.rs` | Move to `operations/sync.rs`, refactor |
| `src/vault/operations_async.rs` | Move to `operations/async_.rs`, refactor |
| `src/vault/mod.rs` | Update imports for new structure |
| `src/vault/operations/mod.rs` | Create - re-exports |
| `src/vault/operations/core.rs` | Create - VaultCore<K> |
| `src/vault/operations/helpers.rs` | Create - pure functions |
| `src/vault/macros.rs` | Create - path wrapper macros |
| `tests/async_tests.rs` | Add parity tests |
| `tests/write_operations_tests.rs` | Add find_file/find_directory tests |

## API Changes

**Preserved (no breaking changes):**
- All existing public methods and signatures
- Error types and variants

**Added to sync:**
- `find_file(dir_id, filename)` - optimized single-file lookup
- `find_directory(dir_id, dirname)` - optimized single-directory lookup

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Regression in sync/async behavior | Existing 200+ tests catch issues |
| Arc/owned MasterKey confusion | VaultCore<K> enforces at compile time |
| Breaking downstream crates | All public APIs preserved |
| spawn_blocking changes | Keep async I/O patterns intact |

## Estimated Effort

- Milestone 1: 1-2 days
- Milestone 2: 2-3 days
- Milestone 3: 2-3 days
- Milestone 4: 1 day
- Milestone 5: 1 day
- **Total: 7-10 days**
