# Phase 3 Optimization Plan: Async Task Overhead & Arena Allocations

## Context

**Current Status:**
- ✅ Phase 1: mimalloc v3 allocator (+18% cold start, +10% backup/sync)
- ✅ Phase 2: Arc LRU cache + WriteBuffer geometric growth (-27% working set, -16% backup/sync)
  - Fixed critical WriteBuffer bug (43-64GB memory leak)
  - Reverted Moka cache (TinyLFU overhead) → kept DashMap

**Profiling Results (PROFILING_ANALYSIS.md):**
- **27% CPU in async task overhead** (polling + scheduling)
- 10% CPU in synchronization primitives
- 15% CPU in FUSE operations
- <2% CPU in cache operations

## Phase 3 Goals

Target: **15-25% performance improvement** on concurrent workloads by reducing:
1. Allocations in hot paths (per-operation arena allocator)
2. Async task spawning overhead (inline hot paths)
3. Temporary buffer allocations (reuse via arena)

## Optimizations

### 3.1: Per-Operation Bumpalo Arena (High Priority)

**Problem:**
Each FUSE operation allocates many temporary buffers:
- Encrypted filename strings during path resolution
- Intermediate crypto buffers during encryption/decryption
- Path component slicing and concatenation
- Error context strings and formatting

**Solution:**
Use `bumpalo::Bump` arena allocator for operation-scoped allocations:

```rust
use bumpalo::Bump;

pub struct OperationContext<'arena> {
    arena: &'arena Bump,
    // ... other context fields
}

impl<'arena> OperationContext<'arena> {
    pub fn alloc_str(&self, s: &str) -> &'arena str {
        self.arena.alloc_str(s)
    }

    pub fn alloc_path(&self, path: &Path) -> &'arena Path {
        // Allocate path in arena instead of heap
    }
}
```

**Implementation:**
1. Add `bumpalo` dependency to `oxcrypt-core`
2. Thread `Bump` arena through FUSE operation call chain
3. Replace heap allocations with arena allocations in:
   - `encrypt_filename()` / `decrypt_filename()` - intermediate strings
   - Path resolution in `resolve_path()` - component slicing
   - Error context building - avoid format! allocations
4. Arena is dropped when FUSE operation completes

**Expected Gain:** 8-12% (eliminate ~50% of temporary allocations)

**Complexity:** Medium (requires threading arena through function signatures)

### 3.2: Reduce Async Task Spawning (Medium Priority)

**Problem:**
Every FUSE operation spawns a tokio task:
```rust
fn read(...) -> Result<Vec<u8>> {
    runtime.block_on(async {
        tokio::spawn(async {  // ← Extra task spawn overhead
            vault.read_file(path).await
        }).await
    })
}
```

**Solution:**
Inline hot paths to avoid task spawning for simple operations:

```rust
fn getattr(...) -> Result<FileAttr> {
    // Direct call - no task spawn for metadata ops
    runtime.block_on(vault.get_file_attr(path))
}
```

**Operations to inline:**
- `getattr()` - stat operations (30% of all ops)
- `lookup()` - path resolution
- `readdir()` - directory listing (uses cache)

**Keep async for:**
- `read()` / `write()` - actual file I/O
- `create()` / `mkdir()` - vault mutations

**Expected Gain:** 6-10% (eliminate task spawn overhead for 30-40% of operations)

**Complexity:** Low-Medium (requires careful async/sync boundary management)

### 3.3: Reuse Crypto Buffers (Low Priority)

**Problem:**
Each encryption/decryption allocates fresh 32KB chunk buffers.

**Solution:**
Thread-local buffer pool using `thread_local!` macro:

```rust
thread_local! {
    static CHUNK_BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}

fn get_chunk_buffer() -> Vec<u8> {
    CHUNK_BUFFER_POOL.with(|pool| {
        pool.borrow_mut().pop()
            .unwrap_or_else(|| Vec::with_capacity(CHUNK_SIZE))
    })
}

fn return_chunk_buffer(mut buf: Vec<u8>) {
    buf.clear();
    CHUNK_BUFFER_POOL.with(|pool| {
        if pool.borrow().len() < MAX_POOLED {
            pool.borrow_mut().push(buf);
        }
    });
}
```

**Expected Gain:** 2-4% (reduce allocations in crypto hot path)

**Complexity:** Low (isolated to streaming.rs)

## Implementation Order

1. **Phase 3.1**: Per-operation bumpalo arena (highest impact)
2. **Phase 3.2**: Inline metadata operations (good impact/effort ratio)
3. **Phase 3.3**: Thread-local buffer pool (polish optimization)

## Benchmark Suite

After each phase:
```bash
OXCRYPT_FAST_KDF=1 FORCE_COLOR=1 timeout 600 \
  ./target/release/oxbench test_vault fuse \
  --password 123456789 \
  --suite workloads \
  --iterations 5 2>&1 | tee benchmarks/phase3-X.txt
```

Focus metrics:
- **Concurrent Access** (main target - async task overhead)
- **IDE Simulation** (many small operations - arena benefits)
- **Working Set** (mixed operations - inlining benefits)

## Success Criteria

- Concurrent Access: -15% or better
- IDE Simulation: -10% or better
- No regressions on other workloads
- Memory usage stable (arena cleanup verified)

## Risk Mitigation

**Arena lifetime safety:**
- Use Rust's lifetime system to prevent use-after-free
- Arena is owned by operation context, dropped at operation end
- References can't escape operation scope

**Async boundary issues:**
- Carefully audit which operations need async (I/O) vs sync (metadata)
- Keep comprehensive test coverage
- Monitor for deadlocks or blocking issues

## Rollback Plan

If Phase 3.X causes regressions or bugs:
1. Revert specific optimization (git/jj)
2. Keep successful optimizations
3. Document findings in PHASE3_ANALYSIS.md

## Files to Modify

**Phase 3.1 (Arena):**
- `crates/oxcrypt-core/Cargo.toml` - add bumpalo dependency
- `crates/oxcrypt-core/src/fs/name.rs` - arena-based name encryption
- `crates/oxcrypt-core/src/vault/operations_async.rs` - thread arena through ops
- `crates/oxcrypt-fuse/src/filesystem.rs` - create arena per FUSE operation

**Phase 3.2 (Inlining):**
- `crates/oxcrypt-fuse/src/filesystem.rs` - inline getattr/lookup/readdir

**Phase 3.3 (Buffer pool):**
- `crates/oxcrypt-core/src/fs/streaming.rs` - thread-local chunk buffers

## References

- Profiling data: `PROFILING_ANALYSIS.md`
- Bumpalo docs: https://docs.rs/bumpalo/
- Tokio performance guide: https://tokio.rs/tokio/topics/performance
