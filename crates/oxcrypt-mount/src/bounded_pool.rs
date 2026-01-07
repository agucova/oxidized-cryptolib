//! Bounded thread pool for timeout-wrapped filesystem operations.
//!
//! When filesystem operations timeout (e.g., due to ghost FUSE mounts), the spawned
//! thread may be stuck in kernel D-state (uninterruptible sleep) forever. This module
//! provides a thread pool that tracks these "leaked" threads and refuses new operations
//! once a threshold is reached, preventing unbounded resource consumption.
//!
//! # Thread Leak Problem
//!
//! The pattern `spawn thread + channel + recv_timeout` is used throughout the codebase
//! to avoid blocking on ghost mounts. However, when the timeout expires, the spawned
//! thread is still blocked in a kernel syscall and cannot be killed. These threads
//! accumulate until process exit.
//!
//! # Solution
//!
//! This module tracks the number of potentially-leaked threads and rejects new
//! operations once a threshold is reached. This provides:
//!
//! 1. **Bounded resource usage** - At most `MAX_LEAKED_THREADS` threads can leak
//! 2. **Early failure** - Operations fail fast instead of spawning more threads
//! 3. **Observability** - The blocked count can be monitored for diagnostics
//!
//! # Example
//!
//! ```ignore
//! use oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL;
//! use std::time::Duration;
//!
//! let result = BOUNDED_FS_POOL.run_with_timeout(Duration::from_secs(2), || {
//!     std::fs::metadata("/some/path")
//! });
//! ```

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Maximum threads that can be leaked before we start rejecting operations.
///
/// This is a balance between:
/// - Too low: Legitimate operations may be rejected
/// - Too high: Too many leaked threads consume resources
///
/// 32 threads is enough to handle multiple ghost mount encounters while
/// still providing protection against runaway resource consumption.
pub const MAX_LEAKED_THREADS: usize = 32;

/// Counter of currently-blocked threads (potential leaks).
///
/// This counter is incremented when a thread is spawned and decremented when
/// it completes successfully. If a timeout occurs, the counter stays elevated
/// because the thread is still running (blocked in kernel).
static BLOCKED_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A thread pool that tracks and limits leaked threads from timeout operations.
///
/// When operations time out, the spawned thread may be stuck in D-state
/// on a ghost mount. This pool tracks those "leaked" threads and refuses
/// new operations once a threshold is reached, preventing unbounded resource
/// consumption.
#[derive(Debug, Clone)]
pub struct BoundedFsPool {
    max_leaked: usize,
}

impl Default for BoundedFsPool {
    fn default() -> Self {
        Self {
            max_leaked: MAX_LEAKED_THREADS,
        }
    }
}

impl BoundedFsPool {
    /// Create a new pool with a custom max leaked thread limit.
    pub fn new(max_leaked: usize) -> Self {
        Self { max_leaked }
    }

    /// Run an operation with timeout, tracking potential thread leaks.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for the operation
    /// * `op` - The operation to run (typically a blocking filesystem call)
    ///
    /// # Returns
    ///
    /// - `Ok(T)` if the operation completed within the timeout
    /// - `Err(TimedOut)` if the operation timed out (thread may be leaked)
    /// - `Err(ResourceBusy)` if too many threads are already blocked
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. Multiple threads can call it concurrently.
    pub fn run_with_timeout<T, F>(&self, timeout: Duration, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        // Check if we've exceeded the leak threshold
        let current_blocked = BLOCKED_THREAD_COUNT.load(Ordering::Acquire);
        if current_blocked >= self.max_leaked {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "Too many blocked filesystem threads ({}/{}). \
                    Possible ghost mounts detected. Please check your mounts \
                    and consider rebooting to clear stale mounts.",
                    current_blocked, self.max_leaked
                ),
            ));
        }

        let (tx, rx) = mpsc::channel();

        // Increment blocked count before spawning
        // The thread will decrement it when it completes
        BLOCKED_THREAD_COUNT.fetch_add(1, Ordering::AcqRel);

        std::thread::spawn(move || {
            let result = op();
            // Decrement count - this thread completed successfully
            BLOCKED_THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Thread is blocked - count stays elevated (leak tracked)
                // Note: we don't decrement here because the thread is still running
                tracing::warn!(
                    blocked_threads = BLOCKED_THREAD_COUNT.load(Ordering::Acquire),
                    max_allowed = self.max_leaked,
                    "Filesystem operation timed out. Thread may be blocked on ghost mount."
                );
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Filesystem operation timed out - path may be on a stale mount",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Thread panicked or was dropped - decrement count
                BLOCKED_THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
                Err(io::Error::other(
                    "Filesystem operation thread terminated unexpectedly",
                ))
            }
        }
    }

    /// Get the current count of blocked/leaked threads.
    ///
    /// This can be used for monitoring and diagnostics.
    pub fn blocked_count(&self) -> usize {
        BLOCKED_THREAD_COUNT.load(Ordering::Acquire)
    }

    /// Get the maximum allowed blocked threads for this pool.
    pub fn max_allowed(&self) -> usize {
        self.max_leaked
    }

    /// Check if the pool is healthy (no blocked threads).
    pub fn is_healthy(&self) -> bool {
        self.blocked_count() == 0
    }

    /// Check if the pool is degraded (some blocked threads but under threshold).
    pub fn is_degraded(&self) -> bool {
        let count = self.blocked_count();
        count > 0 && count < self.max_leaked
    }

    /// Check if the pool is exhausted (at or above threshold).
    pub fn is_exhausted(&self) -> bool {
        self.blocked_count() >= self.max_leaked
    }
}

/// Global bounded filesystem pool instance.
///
/// Use this for all timeout-wrapped filesystem operations to ensure
/// consistent leak tracking across the application.
///
/// # Example
///
/// ```ignore
/// use oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL;
/// use std::time::Duration;
///
/// let accessible = BOUNDED_FS_POOL
///     .run_with_timeout(Duration::from_millis(500), || {
///         std::fs::metadata("/some/path").map(|_| true)
///     })
///     .unwrap_or(false);
/// ```
pub static BOUNDED_FS_POOL: std::sync::LazyLock<BoundedFsPool> =
    std::sync::LazyLock::new(BoundedFsPool::default);

/// Diagnostic information about blocked threads.
#[derive(Debug, Clone)]
pub struct BlockedThreadDiagnostics {
    /// Current number of blocked/leaked threads
    pub blocked_count: usize,
    /// Maximum allowed before rejection
    pub max_allowed: usize,
    /// Health status: "healthy", "degraded", or "exhausted"
    pub status: &'static str,
}

/// Get diagnostic information about potentially-blocked threads.
///
/// This is useful for health checks and monitoring.
pub fn get_blocked_thread_diagnostics() -> BlockedThreadDiagnostics {
    let blocked_count = BLOCKED_THREAD_COUNT.load(Ordering::Acquire);
    let status = if blocked_count == 0 {
        "healthy"
    } else if blocked_count < MAX_LEAKED_THREADS {
        "degraded"
    } else {
        "exhausted"
    };

    BlockedThreadDiagnostics {
        blocked_count,
        max_allowed: MAX_LEAKED_THREADS,
        status,
    }
}

/// Reset the blocked thread counter.
///
/// # Safety
///
/// Only call this after confirming all ghost mounts have been cleared
/// (e.g., after a reboot or successful force-unmount of all stale mounts).
///
/// Calling this while threads are actually blocked will cause the counter
/// to become inaccurate.
pub fn reset_blocked_count() {
    BLOCKED_THREAD_COUNT.store(0, Ordering::Release);
    tracing::info!("Blocked thread counter reset");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_successful_operation() {
        let pool = BoundedFsPool::new(10);
        let result = pool.run_with_timeout(Duration::from_secs(1), || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_failed_operation() {
        let pool = BoundedFsPool::new(10);
        let result: io::Result<i32> = pool.run_with_timeout(Duration::from_secs(1), || {
            Err(io::Error::new(io::ErrorKind::NotFound, "not found"))
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_timeout() {
        let pool = BoundedFsPool::new(10);
        let result: io::Result<i32> = pool.run_with_timeout(Duration::from_millis(10), || {
            std::thread::sleep(Duration::from_secs(10));
            Ok(42)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_pool_status() {
        let pool = BoundedFsPool::new(10);
        assert!(pool.is_healthy());
        assert!(!pool.is_degraded());
        assert!(!pool.is_exhausted());
    }

    #[test]
    fn test_diagnostics() {
        let diag = get_blocked_thread_diagnostics();
        assert_eq!(diag.max_allowed, MAX_LEAKED_THREADS);
        // Note: blocked_count depends on other tests, so we just check it doesn't panic
    }
}
