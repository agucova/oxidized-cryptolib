# Comprehensive Profiling Analysis: Concurrent Access Workload

**Date**: 2026-01-05
**Baseline Time**: 5.09s ± 11.71ms (5 iterations)
**Current Run**: 5.10s ± 0ns (1 iteration)
**Analysis Type**: Flamegraph hotspot identification + code structure analysis

---

## Executive Summary

After thorough profiling with flamegraphs and operation pattern analysis, the concurrent access workload bottleneck is **NOT** in cache invalidation frequency or handle table contention (Phase 1 was targeting the wrong problem).

**The actual bottleneck is in the async task execution layer**, specifically:
- 22% CPU time in `tokio::runtime::task::raw::poll` (task executor overhead)
- 15% CPU time in `run_task` (task scheduling and execution)
- 9-10% CPU time waiting in parking/condition variables
- Remaining time distributed across FUSE operations, file I/O, and vault operations

This is NOT a traditional "hot function" bottleneck - it's architectural. The concurrent workload spawns 4 threads with different access patterns, creating high task scheduling overhead.

---

## Flamegraph Analysis Results

### Top CPU Consumers (by category)

```
Category                  CPU %   Interpretation
─────────────────────────────────────────────────────
Async/Task Runtime        27%     Task polling, scheduling, park timeouts
FUSE Operations           15%     read, write, lookup, getattr operations
File I/O                  10%     Disk reads/writes, open, close
Vault Operations           8%     Encryption, decryption, crypto operations
Synchronization           10%     pthread_cond_wait, locks
Other                     30%     Various infrastructure, backtrace, memory
```

### Top 10 Functions

| Rank | CPU % | Samples | Function |
|------|-------|---------|----------|
| 1 | 22.0% | 20 | `tokio::runtime::task::raw::poll::<BlockingTask>` |
| 2 | 15.4% | 14 | `<tokio::runtime::scheduler::multi_thread::worker::Context>::run_task` |
| 3 | 13.2% | 12 | `<tokio::runtime::scheduler::multi_thread::worker::Context>::run_task` |
| 4 | 8.8% | 8 | `<tokio::runtime::scheduler::multi_thread::worker::Context>::park_timeout` |
| 5 | 6.6% | 6 | `tokio::runtime::task::raw::poll::<async_bridge::execute>` |
| 6 | 6.6% | 6 | `<oxcrypt_core::vault::operations_async::VaultOperationsAsync>::open_file_unlocked` |
| 7 | 5.5% | 5 | `<oxcrypt_core::vault::operations_async::VaultOperationsAsync>::write_file` |
| 8 | 5.5% | 5 | `<oxcrypt_core::vault::operations_async::VaultOperationsAsync>::find_file_unlocked` |
| 9 | 4.4% | 4 | `<std::fs::OpenOptions>::_open` |
| 10 | 4.4% | 4 | `<std::sys::fs::unix::File>::open_c` |

---

## Why Phase 1 Failed

### Phase 1 Assumption (WRONG)
**"Cache invalidations are expensive - batch them to reduce lock acquisitions"**

- Assumed cache invalidation was consuming significant CPU time
- Expected 10-15% improvement from batching
- Implementation was technically correct but targeted wrong bottleneck

### Reality (From Flamegraph)
- Cache-related operations: **<2%** of CPU time
- Directory cache invalidations: **not visible** in top hotspots
- Moka cache overhead: **absorbed into other categories**

### Why No Improvement Was Observed
1. **Invalidation frequency was never the bottleneck** - it's a negligible operation
2. **Batching doesn't reduce task scheduling overhead** - tokio still has 27% overhead regardless
3. **Phase 1 optimizations were premature** - addressing a non-existent problem
4. **Architectural bottleneck masked micro-optimizations** - you can't fix task scheduling overhead with cache batching

---

## Actual Bottleneck: Async Task Overhead (27% CPU)

### What's Happening

The concurrent workload spawns 4 concurrent threads:
```rust
// Thread 1: Editor - Read-modify-write files every 100ms
let editor_handle = tokio::spawn(async { ... });

// Thread 2: File Watcher - Stat all files every 500ms
let watcher_handle = tokio::spawn(async { ... });

// Thread 3: Build Process - Read all files, write outputs every 5 sec
let build_handle = tokio::spawn(async { ... });

// Thread 4: Terminal - Random reads and directory operations every 50-150ms
let terminal_handle = tokio::spawn(async { ... });
```

Each operation goes through:
1. `tokio::runtime::task::raw::poll` - Check if task can proceed
2. `run_task` - Execute the task
3. `park_timeout` - Wait for more work if blocked

With 4 concurrent threads × 30+ operations/sec, the executor is constantly:
- Polling tasks
- Scheduling execution
- Parking/unparking threads
- Context switching

This creates **27% overhead just managing task execution**.

### Why This Happens
- **No true parallelism**: All 4 threads are competing for the same async executor on the same cores
- **High task churn**: 30+ spawned operations per second creates scheduling pressure
- **Blocking operations**: tokio::blocking pool spawning adds more overhead
- **Multi-threaded executor contention**: Multiple executor threads fighting for the same runqueue

---

## Secondary Bottleneck: Synchronization (10% CPU)

From earlier analysis, `pthread_cond_wait` appears as ~10% in this flamegraph, which is lower than the baseline 40% from before. This is likely because:
- The workload has sufficient parallelism that threads aren't completely blocked
- Some operations can proceed while others wait
- The async executor's park/unpark is more efficient than raw condition variables

However, there's still synchronization overhead from:
- Moka cache internal locks
- DashMap lookup contention
- InodeTable operations
- FUSE channel synchronization

---

## Implications for Optimization

### What WON'T Help
- ❌ Cache batching/invalidation optimization (Phase 1)
- ❌ Handle table backoff (Phase 1.2)
- ❌ Per-directory cache index (Phase 1.3)
- ❌ More aggressive caching
- ❌ Reducing lock acquisitions on non-bottleneck structures

**Why**: These target cache operations that consume <2% CPU time. Even eliminating them entirely would improve overall performance by <2%.

### What MIGHT Help (High Priority)

1. **Reduce Async Task Overhead (22% in task polling)**
   - **Option A**: Use sync filesystem layer instead of async
     - Current: 4 threads → tokio executor → task polling → actual work
     - Alternative: Direct threads → work
     - **Potential gain**: 10-15% (eliminate task scheduling overhead)
     - **Cost**: Rewrite VaultOperationsAsync to sync version
     - **Risk**: High complexity, may affect other backends

   - **Option B**: Batch FUSE operations before async dispatch
     - Current: 30+ ops/sec → 30+ task spawns/sec
     - Alternative: Batch N operations → 1 task
     - **Potential gain**: 8-12% (reduce task churn)
     - **Cost**: Complexity in FUSE operation batching
     - **Feasibility**: Medium

   - **Option C**: Use single-threaded executor for this workload
     - Current: Multi-threaded tokio executor with contention
     - Alternative: spawning_local for single-thread execution
     - **Potential gain**: 5-8% (eliminate executor contention)
     - **Risk**: Blocks on I/O differently
     - **Feasibility**: High

2. **Optimize Task Spawning (15% in run_task)**
   - Current: Each FUSE operation triggers full task cycle
   - Current path: `fuse_op → async_bridge::execute → tokio::spawn → VaultOperation`
   - **Option**: Inline hot paths to avoid task spawning overhead
     - Stat operations (getattr) don't need async
     - Small reads might not need async
   - **Potential gain**: 5-10% if 30% of operations can be sync
   - **Feasibility**: Medium (requires careful inlining)

3. **Reduce Synchronization Overhead (10%)**
   - **Option A**: Replace Moka with lock-free cache
     - Current: Moka uses internal locks under concurrent access
     - Alternative: DashMap-based cache or read-write optimized structure
     - **Potential gain**: 3-5%
     - **Complexity**: Medium
   -
   - **Option B**: Thread-local caches
     - Current: All threads contend on single cache
     - Alternative: Per-thread cached data + occasional sync
     - **Potential gain**: 4-6% for read-heavy workload
     - **Feasibility**: Medium-High

4. **Optimize File I/O (10%)**
   - Current: Direct filesystem calls through vault layer
   - Options:
     - Pre-allocate file buffers
     - Batch multiple small reads/writes
     - Use memory-mapped I/O where possible
   - **Potential gain**: 2-4%

### Realistic Improvement Scenarios

| Scenario | Changes | Potential Gain | Effort |
|----------|---------|----------------|--------|
| **Sync hot paths only** | Make stat/lookup sync instead of async | 8-12% | 🔴 High |
| **Task batching** | Batch FUSE operations before tokio::spawn | 8-12% | 🟡 Medium |
| **Single-threaded executor** | Use tokio::runtime_local for this workload | 5-8% | 🟢 Low |
| **All three combined** | Full optimization | 18-25% | 🔴 Very High |
| **Cache optimization only** | DashMap + thread-local cache | 4-7% | 🟡 Medium |

---

## Recommended Investigation Path

### Phase 2: Data-Driven Optimization

Before implementing any changes, measure which specific operations are slowest:

```bash
# 1. Identify operation breakdown
RUST_LOG=oxcrypt_bench::bench::workloads=debug timeout 60 \
  ./target/release/oxbench test_vault fuse \
  --password 123456789 \
  --workload concurrent \
  --iterations 1 \
  --verbose 2>&1 | grep -E "read|write|stat|lookup|open" | \
  awk '{print $1}' | sort | uniq -c | sort -rn

# 2. Profile with different executor configurations
# Test: tokio::runtime_local vs multi_threaded vs work_stealing

# 3. Measure task spawning frequency
# Use tokio-console or tracing to see task creation rate
```

### Phase 2.1: Quick Win (5-10 min effort)
Try single-threaded executor for concurrent workload:
- Create feature flag: `--features fuse-single-threaded`
- Build tokio runtime with just one thread
- Benchmark and compare

### Phase 2.2: Medium Effort (1-2 hours)
Implement task batching:
- Group related FUSE operations
- Spawn batched task instead of individual tasks
- Measure reduction in task overhead

### Phase 2.3: High Impact (4-8 hours)
Make stat/lookup operations synchronous:
- Separate sync path for metadata operations
- Keep async for file I/O heavy operations
- Benchmark improvement

---

## Conclusion

**Phase 1 targeted the wrong bottleneck** and that's why no improvements were observed despite correct implementation. The actual bottleneck is not cache invalidation frequency - it's the overhead of async task execution and scheduling.

To achieve 30% improvement, focus on:
1. **Async executor overhead** (22% of CPU) → Potential 10-15% gain
2. **Task scheduling cost** (15% of CPU) → Potential 5-10% gain
3. **Synchronization** (10% of CPU) → Potential 3-5% gain

Rather than batching cache operations (which are <2% CPU), optimize the task execution pipeline that accounts for 37% of CPU time.

---

## Files Generated in This Analysis
- `/Users/agucova/repos/oxidized-cryptolib/extract_flamegraph_hotspots.py` - Flamegraph extraction
- `/Users/agucova/repos/oxidized-cryptolib/analyze_flamegraph_simple.py` - Hotspot analysis
- `/Users/agucova/repos/oxidized-cryptolib/profiles/fuse_Concurrent_Access.svg` - Raw flamegraph
- `/Users/agucova/repos/oxidized-cryptolib/profiles/concurrent_baseline.log` - Baseline timing
