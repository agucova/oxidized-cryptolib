# FUSE Backend Async Runtime Starvation on Cloud Storage

## Problem Summary

OxCrypt is a Cryptomator client written in Rust. Our FUSE backend under macOS hangs after 20-80 seconds when reading a directory with many large video files stored on Google Drive. While the folder is initially read fine and the throughput stays high, the system then appears to experience complete tokio async runtime starvation where all workers become idle while waiting for blocking I/O operations to complete on slow cloud storage.

## Symptoms

### User-Observed Behavior
- Initial performance is excellent (20-40 seconds of fast reads, thumbnails load, good throughput)
- Complete system hang after initial period
- Finder becomes unresponsive
- Mount point stops responding to any operations
- Desktop app `/usr/bin/open` commands fail with exit code 256

### Log Evidence
```
20:05:19 ERROR oxcrypt_fuse::filesystem: Read failed error=IO error during read_chunk,
  at "/Users/.../GoogleDrive-.../My Drive/0 Vaults/Large Videos/d/US/GCEY5I64CAUAKTKACDHTWK6Y3DIHMF/tHKxeLvqB5IRmSFR4wlXIQINrOKHURgF4NmaFamh3oZAjk-TVSBDj0XfqCPRhhLmD9oDo2VVjp7uKuh7V_zv.c9r",
  chunk 29568: Operation timed out (os error 60)

20:06:59 ERROR fuser::reply: Failed to send FUSE reply: Socket is not connected (os error 57)
20:06:59 ERROR oxcrypt_desktop::components::vault_detail: Failed to open /Users/.../Large Videos:
  Launcher "/usr/bin/open" "/Users/.../Large Videos" failed with ExitStatus(unix_wait_status(256))
```

**Key observation**: 100-second gap between first error (20:05:19) and subsequent errors (20:06:59), indicating long blocking operations.

### Performance Metrics at Hang
- **Throughput**: ~0 bytes/sec
- **Open locks**: 0 files, 1 directory
- **Cache hit rate**: 94% (excellent)
- **Reported errors**: 675
- **Filesystem state**: Appears healthy but completely unresponsive

### Tokio Console Evidence

**Before hang (Screenshot 1):**
- 31 tasks total: 29 running, 2 idle
- Tasks in "blocking" state at `scheduler::multi_thread::worker::Launch::launch`
- Location: `<cargo>/tokio-1.48.0/src/runtime/scheduler/multi_thread/worker.rs:457:13`
- All tasks blocked in tokio runtime scheduler's worker launch code

**During hang (Screenshots 2-3):**
- Task states: All showing `11m20s` total time, `11m20s` busy, `0ns` scheduled
- **Critical**: `Current workers: 0` (all async workers idle/parked)
- Woken: 0 times
- All poll times at 0.00ns (no progress being made)
- Tasks stuck at same location: `fn-tokio::runtime::scheduler::multi_thread::worker::Launch::launch`

## Root Cause Analysis

### Architecture Overview

#### Layer 1: FUSE Kernel Module (macFUSE)
macFUSE provides a kernel extension that intercepts filesystem operations. When a process (like Finder) reads from our mountpoint, the kernel creates a worker thread (from a pool of 16-32 threads) and calls into userspace via `/dev/fuse`.

**Key constraint**: FUSE worker threads are **synchronous**—they block waiting for our response. If we don't reply quickly, the kernel may timeout and kill the connection.

#### Layer 2: fuser Crate (Rust FUSE Bindings)
The `fuser` crate provides a Rust trait we implement:

```rust
pub trait Filesystem {
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        reply.error(ENOSYS);
    }
    // ... other operations
}
```

**Key constraint**: These methods are called from FUSE worker threads. They are **synchronous** (no `async`). We must call `reply.data()` or `reply.error()` before returning, or the FUSE thread blocks forever.

#### Layer 3: Our Implementation (CryptomatorFS)
We have async vault operations (`VaultOperationsAsync`) but need to bridge to fuser's sync API:

**From `crates/oxcrypt-fuse/src/filesystem.rs:1354-1408`:**
```rust
fn read(
    &mut self,
    _req: &Request<'_>,
    ino: u64,
    fh: u64,
    offset: i64,
    size: u32,
    _flags: i32,
    _lock_owner: Option<u64>,
    reply: ReplyData,
) {
    trace!(inode = ino, fh = fh, offset = offset, size = size, "read");

    let Some(mut handle) = self.handle_table.get_mut(&fh) else {
        reply.error(libc::EBADF);
        return;
    };

    match &mut *handle {
        FuseHandle::Reader(reader) => {
            self.vault_stats.start_read();
            let start = Instant::now();

            // THIS IS THE CRITICAL LINE:
            // We block the FUSE worker thread waiting for async I/O
            match self
                .handle
                .block_on(reader.read_range(                    // ← Blocks FUSE thread
                    u64::try_from(offset).unwrap_or(0),
                    usize::try_from(size).unwrap_or(0)
                ))
            {
                Ok(data) => {
                    let elapsed = start.elapsed();
                    self.vault_stats.record_read(data.len() as u64);
                    reply.data(&data);
                }
                Err(e) => {
                    error!(error = %e, "Read failed");
                    reply.error(libc::EIO);
                }
            }
        }
        // ... other handle types
    }
}
```

**The bridging mechanism**: `self.handle` is a `tokio::runtime::Handle`. Calling `handle.block_on()` from a non-tokio thread:
1. Submits the future to the tokio runtime
2. **Blocks the current thread** (FUSE worker) until the future completes
3. Returns the result

#### Layer 4: Async Vault Operations
**From `crates/oxcrypt-core/src/fs/streaming.rs:651-714`:**
```rust
async fn read_chunk(&mut self, chunk_num: u64) -> Result<Arc<Zeroizing<Vec<u8>>>, StreamingError> {
    // Check LRU cache - Arc::clone is 8 bytes instead of 32KB data clone
    if let Some(data) = self.chunk_cache.get(&chunk_num) {
        trace!(chunk = chunk_num, "Cache hit");
        return Ok(Arc::clone(data));  // ← Fast path, no I/O
    }

    trace!(chunk = chunk_num, "Cache miss, reading from disk");

    // Seek to chunk position
    let encrypted_offset = chunk_to_encrypted_offset_for_cipher(chunk_num, self.cipher_combo);
    self.file
        .seek(SeekFrom::Start(encrypted_offset))
        .await                                    // ← tokio::fs async seek
        .map_err(|e| StreamingError::io_with_context(e, context.clone()))?;

    // Read encrypted chunk
    let mut encrypted_chunk = vec![0u8; chunk_encrypted_size];
    let bytes_read = self.file.read(&mut encrypted_chunk).await.map_err(|e| {  // ← THIS LINE
        StreamingError::io_with_context(e, context.clone())
    })?;

    // ... decryption happens here (CPU-bound, fast)

    Ok(decrypted)
}
```

**The hidden layer**: `self.file` is a `tokio::fs::File`. When we call `.read().await`, tokio internally does:

```rust
// Simplified view of tokio::fs::File::read() internals
pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    // Dispatch to blocking threadpool because file I/O isn't truly async on most OS
    tokio::task::spawn_blocking(move || {
        // This runs on a blocking thread from the pool (max 512 by default)
        std::fs::File::read(...)  // ← Actual syscall that blocks on Google Drive
    }).await
}
```

#### Layer 5: The Blocking Threadpool
Tokio maintains a **separate threadpool** for blocking operations:
- **Purpose**: Execute synchronous I/O without blocking async workers
- **Default size**: 512 threads maximum
- **Thread lifecycle**: Threads are created on-demand, kept alive for reuse
- **Invisible**: Does NOT show up in tokio-console's "workers" count

When all 512 threads are doing 60-second Google Drive reads, new `.read()` calls **queue up waiting** for a free thread.

#### Layer 6: Google Drive Virtual Filesystem
At the bottom, our `std::fs::File::read()` syscall hits Google Drive's FUSE filesystem:
- If file is locally cached: returns quickly (milliseconds)
- If file needs remote fetch: **blocks in kernel space** for 60+ seconds
- No async I/O hints—appears as synchronous I/O to our process

### Complete Architecture Flow
```
Finder.app reads file
    ↓
macOS VFS layer
    ↓
macFUSE kernel module
    ↓
/dev/fuse device
    ↓
FUSE worker thread (1 of 16-32)                    ← Synchronous, blocks
    ↓
fuser crate: Filesystem::read()                    ← Synchronous trait method
    ↓
CryptomatorFS::read()                              ← Our implementation
    ↓
handle.block_on(reader.read_range(...))            ← Blocks FUSE thread, waits for tokio
    ↓
[Tokio Runtime Scheduler]
    ↓
VaultFileReader::read_chunk()                      ← Async function
    ↓
tokio::fs::File::read()                            ← Appears async...
    ↓
tokio::spawn_blocking(|| std::fs::read(...))       ← ...but internally uses blocking pool
    ↓
Blocking threadpool thread (1 of max 512)          ← Synchronous OS thread
    ↓
read() syscall
    ↓
macOS VFS layer (again)
    ↓
Google Drive FUSE kernel module
    ↓
Google Drive sync daemon
    ↓
Network fetch (60+ seconds)                        ← This is where we're stuck
```

### The Three Thread Pools

This architecture involves **three separate thread pools**:

1. **FUSE worker threads** (16-32, from kernel):
   - Owned by macFUSE kernel module
   - Synchronous, block waiting for our reply
   - Shown in Activity Monitor as "oxmount" threads

2. **Tokio async workers** (default: num_cpus ≈ 10-12):
   - Execute async tasks at `.await` points
   - Visible in tokio-console as "workers"
   - **Shown as "Current workers: 0" when all parked**

3. **Tokio blocking threadpool** (default: max 512):
   - Execute `spawn_blocking()` calls
   - Used internally by `tokio::fs`
   - **NOT visible in tokio-console**
   - This is the saturated pool causing starvation

### The Starvation Cascade

1. **Initial phase (0-30s)**: Fast performance
   - Finder requests thumbnails for many video files simultaneously
   - First ~30 files hit cache or are locally available on Google Drive
   - System appears responsive

2. **Saturation begins (30-40s)**:
   - More files are requested (30+ concurrent reads)
   - Google Drive doesn't have these cached locally
   - Each file triggers 60+ second network fetch
   - Blocking threadpool begins to saturate

3. **Complete starvation (40s+)**:
   - All 512 blocking threads doing slow Google Drive I/O
   - New FUSE reads arrive → create async tasks → call `spawn_blocking()`
   - **No blocking threads available** → async tasks wait
   - Async workers have nothing to do → park themselves
   - **Result: "Current workers: 0"** in tokio-console

4. **Deadlock-like state**:
   - All blocking threads: waiting on Google Drive (60s each)
   - All async workers: parked (nothing to do)
   - All FUSE callbacks: blocked in `block_on()` waiting for async tasks
   - Even cached reads can't proceed (no workers to schedule them)

### Key Insight: The "0 Workers" Paradox

The tokio-console screenshot showing **"Current workers: 0"** is the smoking gun. This doesn't mean we have zero threads—it means:

- **Tokio async workers** (the "workers" in tokio-console): All parked/idle, nothing to do
- **Tokio blocking threadpool** (invisible in console): All 512 threads saturated doing slow Google Drive I/O
- **Result**: Async tasks waiting for blocking threads → async workers park → "0 workers"

See "The Three Thread Pools" section above for the complete architecture.

### Why This Affects Even Cached Reads

Once the blocking threadpool is saturated:
1. New read requests create async tasks
2. Even cached chunk reads need a worker to execute the cache lookup
3. Workers are parked → cache lookups can't run
4. System appears completely frozen

### Why Google Drive Specifically

Google Drive's virtual filesystem (Google Drive File Stream / Drive for Desktop):
- Does **synchronous network I/O** when files aren't locally cached
- 60+ second timeouts for remote fetches (evidence: error timestamps)
- No async I/O hints to the OS
- Standard filesystem operations block in kernel space

This is fundamentally incompatible with `tokio::fs`'s design assumptions:
- `tokio::fs` optimized for local disk (millisecond latencies)
- Blocking threadpool sized for fast I/O (512 threads)
- No backpressure mechanism for slow storage

## References

- Tokio blocking threadpool documentation: https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html#method.max_blocking_threads
- Issue discussion in project: `docs/ASYNC_STARVATION_ISSUE.md`
- Related code:
  - `crates/oxcrypt-fuse/src/filesystem.rs:1354-1408` (read implementation)
  - `crates/oxcrypt-core/src/fs/streaming.rs:651-714` (read_chunk implementation)
  - `crates/oxcrypt-fuse/src/filesystem.rs:173-189` (runtime creation)
