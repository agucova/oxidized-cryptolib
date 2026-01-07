# oxcrypt-fuse Concurrency & I/O Scheduling Spec (Linux + macOS)

**Status:** Ready for implementation  
**Audience:** Engineers implementing the `oxcrypt-fuse` backend + shared abstractions in `oxcrypt-common` (as appropriate).  
**Primary objective:** Robustness and correctness under pathological underlying filesystem latency (e.g., Drive for Desktop, network drives) **without** starving the daemon, deadlocking the mount, or exhausting resources.

---

## 0) Context & Problem

oxcrypt-fuse implements a FUSE filesystem (via `fuser`) whose underlying storage is an arbitrary POSIX filesystem chosen by the user:
- Local disk (fast, low variance)
- Network drives (slow, variable)
- macOS Drive for Desktop / file provider backed paths (can cause *minute-long*, kernel-blocking syscalls)

The current architecture bridges synchronous `fuser::Filesystem` callbacks to async work via `tokio::runtime::Handle::block_on()` and uses `tokio::fs` (which internally consumes Tokio’s blocking executor).

### Confirmed capability
- `Reply*` types (e.g., `ReplyData`) are `Send + Sync`
- Writing replies to `/dev/fuse` from multiple threads is thread-safe

Therefore, FUSE callbacks can **enqueue work and return immediately**, and replies can be issued later by scheduler/executor threads.

### Critical observation (current code)
- Only `read()` currently uses `block_on()` (with the streaming Reader handle) and is the primary starvation trigger.
- Many write operations currently complete quickly because they only update an in-memory `WriteBuffer`.

This spec defines a **long-term architecture** that:
- fixes `read()` immediately by removing `block_on` and isolating blocking syscalls, and
- prevents future regressions when other operations eventually touch slow underlying I/O or barriers (`fsync*`, `flush`, structural ops).

---

## 1) Goals & Non-goals

### Goals
1. **Mount liveness under worst-case stalls**
   - The daemon must keep making progress even if some underlying syscalls block for 60+ seconds.
2. **Bounded resource usage**
   - Hard caps on:
     - number of in-flight kernel-blocking syscalls,
     - pending request queue sizes,
     - buffered bytes (esp. writes),
     - cache memory.
3. **Prioritized responsiveness**
   - Metadata and small foreground reads remain responsive under storms.
   - Writes do not starve indefinitely under read storms (and vice versa).
4. **Correctness**
   - Never reply twice to a FUSE request.
   - FUSE callbacks never wait for long operations.
   - Ordering constraints for writes and barrier ops are respected.
5. **Performance**
   - Competitive on local disk.
   - Minimizes syscall count via coalescing where possible.
   - Avoids unnecessary copies (use `bytes`).

### Non-goals
- Cancelling a kernel-stuck syscall (generally impossible).
- Integrating platform-specific cloud APIs (must remain filesystem-agnostic).
- Perfect UX under overload for every client (we will pick conservative, test-backed error strategies).

---

## 2) Design Principles (Hard Requirements)

1. **No underlying filesystem syscalls on Tokio’s blocking pool.**
   - Do not use `tokio::fs` on performance-/liveness-critical paths.
   - Do not use `spawn_blocking` for underlying filesystem syscalls.

2. **FUSE callbacks must be non-blocking.**
   - No `block_on`, no waiting on semaphores, no long locks, no IO.
   - Callbacks do: validate + classify + admission control + enqueue (or fail-fast).

3. **Bounded admission is the only backpressure.**
   - If we cannot accept work quickly, we *immediately* reply with an error (usually retryable).

4. **Deadlines for all enqueued work.**
   - Every request has a deadline and is replied to (success or error) by that deadline.
   - Timeouts do not cancel kernel syscalls, but they must prevent “stuck forever”.

5. **Avoid priority inversion and global locks.**
   - “Fast-path” synchronous operations must not contend on locks held by slow paths.
   - Prefer sharded structures (`DashMap`) and fine-grained `parking_lot` locks.

---

## 3) Operation Inventory & Classification

Your implemented operations (plus ENOTSUP set) drive the scheduler’s lane design.

### 3.1 Data modification
- `write()` — writes to file (currently uses in-memory `WriteBuffer`)
- `copy_file_range()` — server-side copy between files
- `fallocate()` — preallocate/resize file

### 3.2 File/directory creation
- `create()` — atomically create and open
- `mkdir()`
- `symlink()`

### 3.3 File/directory deletion
- `unlink()`
- `rmdir()`

### 3.4 Move/rename
- `rename()`

### 3.5 Metadata modification
- `setattr()` — includes truncate, mtime/atime

### 3.6 Read operations
- `read()`, `readdir()`, `readdirplus()`, `readlink()`, `getattr()`, `access()`, `statfs()`, `lseek()`

### 3.7 Lifecycle/control
- `init()`, `destroy()`, `lookup()`, `forget()`, `batch_forget()`,
  `open()`, `release()`, `opendir()`, `releasedir()`,
  `flush()`, `fsync()`, `fsyncdir()`

### 3.8 Not supported (ENOTSUP)
- `link()`, `mknod()`,
  `getxattr()`, `setxattr()`, `listxattr()`, `removexattr()`

---

## 4) “Fast-path” vs “Hazardous” Ops (Key Concept)

Because many operations currently “finish quickly”, we explicitly separate:

### 4.1 Fast-path ops (may remain synchronous **iff proven non-blocking**)
These may continue to execute within the `fuser` callback thread, provided they:
- do not perform underlying filesystem syscalls,
- do not wait on long operations,
- do not take locks that could be held by slow paths.

Examples (subject to proof in your codebase):
- `forget()`, `batch_forget()` (cache bookkeeping)
- `lseek()` (pure handle bookkeeping)
- `access()` (if implemented as pure permission check / cached metadata)
- `write()` (only if it *only* updates in-memory `WriteBuffer` and is O(1)/bounded)
- handle-table bookkeeping in `open/release/opendir/releasedir` (if no I/O)

**Rule:** If an op can *ever* hit underlying I/O or wait on a barrier, it must be reclassified as Hazardous.

### 4.2 Hazardous ops (must go through Scheduler + bounded executor)
Ops that either:
- perform underlying filesystem syscalls, or
- may block on correctness barriers (`flush`, `fsync*`, commit), or
- are structurally complex (rename/unlink/truncate), or
- are likely to become slow across different underlying FS implementations.

At minimum, treat as Hazardous:
- `read()` (critical)
- `readdir()`, `readdirplus()`, `readlink()`, `getattr()`, `lookup()`, `statfs()` (depending on implementation)
- `create()`, `mkdir()`, `symlink()`
- `unlink()`, `rmdir()`
- `rename()`
- `setattr()` (truncate/size changes especially)
- `fallocate()`
- `copy_file_range()`
- **barriers:** `flush()`, `fsync()`, `fsyncdir()`, and often `release()` (if it triggers commit/close semantics)

---

## 5) Architecture Overview

### Components
1. **FUSE Frontend (`oxcrypt-fuse`)**
   - Implements `fuser::Filesystem`.
   - Performs: validation, classification (lane + hazard), admission control (`try_enqueue`), return.
   - Replies immediately only when rejecting admission (fail-fast).

2. **Scheduler (`oxcrypt-fuse::scheduler`)**
   - Owns bounded lane queues, deadlines, fairness, per-file ordering, single-flight for reads.
   - Dispatches filesystem syscalls to the **FS Syscall Executor**.
   - Dispatches CPU work (crypto) to a CPU pool (Rayon) or to Tokio non-blocking tasks.
   - Issues FUSE replies using stored `Reply*` handles from any thread.

3. **FS Syscall Executor (dedicated bounded I/O executor)**
   - Fixed number of OS threads (`io_threads`).
   - Bounded submission queue (reject-fast).
   - Executes blocking syscalls only (no Tokio usage).
   - Returns results to Scheduler via oneshot.

4. **Crypto / Transform Pipeline**
   - Decrypt/auth/assemble; no blocking syscalls.
   - Prefer Rayon for predictable CPU throughput.

5. **Cache & Single-flight**
   - In-memory cache of decrypted chunks/spans using `bytes::Bytes`.
   - Single-flight map for in-flight reads to dedup identical work.

### Where to place primitives
- `oxcrypt-fuse`: scheduler logic and FUSE semantics
- `oxcrypt-common`: reusable bounded executor, admission helpers, (optional) generic lane queue abstractions

---

## 6) Scheduler: Lanes, Admission, Fairness

### 6.1 Lane model (operation classes)
We schedule by lane (categorical priority), not by a single global priority queue:

- **L0 — Control / lifecycle**
  - internal scheduler bookkeeping, shutdown coordination

- **L1 — Metadata foreground**
  - `lookup`, `getattr`, `access`, `statfs`, `readlink`, `readdir`, `readdirplus`

- **L2 — Read foreground**
  - `read` (small reads, interactive patterns)

- **L3 — Write foreground + structural ops**
  - `create`, `mkdir`, `symlink`
  - `unlink`, `rmdir`, `rename`
  - `setattr` (truncate), `fallocate`, `copy_file_range`
  - `write` if/when it becomes non-trivial or touches underlying FS

- **L4 — Bulk/background**
  - large sequential reads, read-ahead/prefetch, background revalidation

- **Barrier mechanism (cross-cutting)**
  - `flush`, `fsync`, `fsyncdir`, and possibly `release`
  - Implemented as “barrier ops” that wait for per-handle/per-file state

### 6.2 Bounded admission (non-blocking)
For every Hazardous request:
- compute lane and deadline (`now + lane_deadline`)
- attempt `try_send` into the lane queue
- if it fails: reply immediately with error (default `EAGAIN`, configurable)

**No waiting in callback.** If full, fail-fast.

### 6.3 Fairness & reserved capacity
The dispatch policy must guarantee:
- L1 (metadata) always progresses under storms
- writes (L3) are not starved by reads (L2)

Recommended policy:
- Always dispatch L1 when non-empty and under L1 in-flight budget
- Otherwise choose between L2 and L3 using weighted round-robin
- Only dispatch L4 if L1–L3 are below thresholds

Additionally reserve syscall executor capacity:
- ≥1 slot for L1 (metadata)
- ≥1–2 slots for L3 (writes/structural), configurable

---

## 7) Read Path Design

### 7.1 Remove `block_on` from `read()`
`read()` must:
- validate handle
- classify lane (L2/L4)
- enqueue a `ReadRequest { reply, offset, size, deadline, key }`
- return immediately

### 7.2 Read key and coalescing
Define a read key aligned to crypto chunking:
- Minimal: `(file_handle_id, chunk_idx)`
- Preferred (for syscall coalescing): span-based key `(file_handle_id, span_start, span_len)`

### 7.3 Single-flight
Use `DashMap<ReadKey, InFlightRead>`:
- first request starts underlying fetch
- others attach as waiters
- completion fulfills all waiters and fills cache

### 7.4 Cache
Cache decrypted bytes using `bytes::Bytes` for cheap slicing:
- bounded by total bytes
- eviction: LRU acceptable

### 7.5 Underlying IO strategy
- Use `pread` / `read_at` (avoid shared seek cursor)
- Coalesce multi-chunk reads into spans where possible to reduce syscall count

---

## 8) Write & Structural Ops Design

Even if `write()` is currently “fast buffer only”, the architecture must support correctness barriers and slow underlying FS.

### 8.1 Per-file ordering
For any op that mutates file contents/structure on disk:
- maintain `DashMap<FileKey, FileState>` with:
  - write/structural op queue
  - `in_flight` flag
  - last error to propagate to barriers
- dispatch at most one structural/mutating op per `FileKey` at a time (baseline correctness)

### 8.2 Buffered write budget
If/when writes buffer bytes:
- enforce global + per-file buffered byte budgets
- admission checks are non-blocking (try-acquire)
- on overflow: reply `EAGAIN`

### 8.3 Barrier ops (`flush/fsync/fsyncdir/release`)
Treat as barriers:
- must observe completion/failure of prior mutating ops for that handle/file
- reply success only when barrier semantics satisfied
- obey deadlines; on timeout, reply error and mark cancelled

### 8.4 Composite transactions
Ops like `rename`, `unlink`, `truncate (setattr size)`, `copy_file_range`, `fallocate` may be multi-step:
- execute as explicit sequences using the syscall executor for each blocking step
- propagate errors deterministically
- ensure no double replies

---

## 9) Deadlines, Timeouts, Cancellation

### 9.1 Deadline model
Each enqueued request:
- has `request_id`, `deadline`, and cancellation state
- cancellation prevents late completion from replying

### 9.2 Deadline data structure
Use a dedicated deadline min-heap using stdlib:
- `BinaryHeap<(Reverse(deadline), request_id, generation)>`
- discard stale entries using a generation counter per request

### 9.3 Timeout behavior
On deadline:
- if request still pending: send error reply (e.g., `ETIMEDOUT` or `EAGAIN` per policy)
- mark cancelled so late completion cannot reply
- optionally still cache results (policy-controlled)

---

## 10) FS Syscall Executor (Dedicated Bounded I/O)

### 10.1 Purpose
Contain minute-long kernel stalls to a fixed number of threads; prevent starvation elsewhere.

### 10.2 Requirements
- fixed-size threadpool (`io_threads`)
- bounded submission queue (reject-fast)
- no Tokio usage in worker threads
- results returned via oneshot

### 10.3 Recommended implementation
- `crossbeam_channel::bounded<Job>(capacity)` submission
- worker threads:
  - recv job
  - execute blocking syscall (`pread`, `stat`, `readdir`, etc.)
  - send result via oneshot

### 10.4 Syscall API
- Prefer `pread` via `libc` for reads
- Avoid shared seek cursors
- Avoid open/close churn where possible (stable fds per handle)

---

## 11) Rust / Crate Decisions

### Use existing deps
- `crossbeam-channel` — bounded queues
- `parking_lot` — fine-grained locks
- `dashmap` — in-flight reads, per-file state
- `lru` — cache (or reuse existing cache abstractions carefully)
- `tracing` — instrumentation

### Add
- `bytes` — represent cached decrypted data as `Bytes` for slicing + sharing

### Avoid in hot path
- `tokio::fs`
- `tokio::spawn_blocking` for underlying filesystem syscalls

---

## 12) Observability (tracing)

Instrument:
- admission decisions: accepted/rejected, lane, queue depth
- in-flight counts per lane and per executor
- syscall latency histograms
- cache hit/miss and single-flight dedup ratio
- timeout counts and error codes
- span size effectiveness (bytes per syscall)
- buffered write bytes usage and rejections

Every request carries a stable `request_id` for end-to-end tracing.

---

## 13) Configuration Knobs (defaults + override)

Initial conservative defaults:
- `io_threads`: 16
- `executor_queue_capacity`: 1024 jobs
- per-lane queue capacities:
  - L1: 1024, L2: 2048, L3: 1024, L4: 512
- deadlines (tune below mount-death thresholds):
  - L1: 2s, L2: 10s, L3: 10s, L4: 10s
- cache size: bounded by bytes (e.g., 512 MiB configurable)
- span read size: 512 KiB–2 MiB configurable
- buffered write budgets: (if applicable) 256 MiB global, 32 MiB per file

---

## 14) Implementation Milestones

1. **Fix read path**
   - Remove `block_on()` from `read()`.
   - Implement scheduler enqueue + async reply for reads.
   - Replace `tokio::fs` in the read hot path with syscall executor + `pread`.

2. **Introduce FS Syscall Executor**
   - Fixed threads + bounded queue.
   - Route underlying syscalls needed by reads and metadata through it.

3. **Add scheduler deadlines + timeouts**
   - Deadline heap, cancellation, guaranteed reply.

4. **Add read cache + single-flight**
   - `bytes::Bytes` cache, `DashMap` in-flight dedup.

5. **Expand hazardous ops coverage**
   - Move structural ops (`rename`, `unlink`, `setattr(truncate)`, etc.) through scheduler/executor as needed.

6. **Add write/barrier correctness**
   - Per-file ordering, barrier ops semantics, buffered write budgets (if/when writes hit disk).

7. **Stress tests + metrics**
   - Induce blocking in executor to simulate cloud stalls.
   - Validate liveness and boundedness.

---

## 15) Testing Plan

### Unit tests
- single-flight: exactly one underlying fetch, N waiters, exactly one reply each
- timeout: reply exactly once, late completion never replies
- per-file serialization: ordering enforced, barriers observe prior writes

### Property tests
- randomized interleavings; enforce invariants:
  - no double reply
  - bounded counters don’t under/overflow
  - admission rejects when full

### Integration/stress tests
- instrumented blocking injection in syscall executor
- concurrent storms of reads + metadata + structural ops
- verify:
  - L1 remains responsive
  - no unbounded growth
  - daemon stays alive and continues responding

---

## 16) Open Decisions (ADR-style)

1. Overload error codes:
   - default `EAGAIN`, adjust per-client behavior if needed

2. Read-your-writes semantics:
   - baseline committed view only; evaluate overlay later

3. Durability semantics:
   - define what `fsync*` means in vault format and how to map to underlying FS

4. Interrupt handling:
   - if surfaced via `fuser` later, integrate; otherwise rely on deadlines + robustness

---

## Summary

This design replaces “sync callback blocks on async runtime” with:
- enqueue-only FUSE callbacks for Hazardous ops,
- a scheduler enforcing bounded admission, deadlines, fairness, and ordering,
- a dedicated bounded syscall executor containing kernel stalls,
- cache + single-flight + syscall coalescing for performance.

It fixes the current `read()` starvation issue and prevents future regressions as more ops inevitably become slow or barrier-sensitive on cloud-backed filesystems.
