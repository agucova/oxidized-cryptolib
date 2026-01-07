//! Per-file ordering for structural operations.
//!
//! Ensures that structural operations (writes, truncate, etc.) on the same file
//! are serialized to maintain correctness. Barrier operations (flush, fsync)
//! wait for all pending operations on a file to complete.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::oneshot;

use super::request::RequestId;

/// State for a single file's pending operations.
#[derive(Debug)]
pub struct FileState {
    /// Queue of pending structural operations waiting to be dispatched.
    pending: Mutex<VecDeque<PendingOp>>,
    /// Whether a structural operation is currently in-flight for this file.
    in_flight: AtomicBool,
    /// Last error from a structural operation (propagated to barriers).
    last_error: Mutex<Option<i32>>,
    /// Number of operations waiting on barriers.
    barrier_waiters: AtomicU64,
}

/// A pending structural operation.
#[derive(Debug)]
pub struct PendingOp {
    /// Request ID for tracking.
    pub request_id: RequestId,
    /// Channel to signal when the op can proceed.
    pub ready_tx: oneshot::Sender<()>,
}

impl Default for FileState {
    fn default() -> Self {
        Self::new()
    }
}

impl FileState {
    /// Create a new file state.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            in_flight: AtomicBool::new(false),
            last_error: Mutex::new(None),
            barrier_waiters: AtomicU64::new(0),
        }
    }

    /// Check if there's an operation in-flight.
    pub fn has_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Check if there are pending operations.
    pub fn has_pending(&self) -> bool {
        !self.pending.lock().is_empty()
    }

    /// Get the number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Get the last error (if any).
    pub fn last_error(&self) -> Option<i32> {
        *self.last_error.lock()
    }

    /// Set the last error.
    pub fn set_last_error(&self, errno: i32) {
        *self.last_error.lock() = Some(errno);
    }

    /// Clear the last error.
    pub fn clear_last_error(&self) {
        *self.last_error.lock() = None;
    }

    /// Try to claim the in-flight slot.
    ///
    /// Returns `true` if successfully claimed, `false` if already in-flight.
    pub fn try_claim_in_flight(&self) -> bool {
        !self.in_flight.swap(true, Ordering::AcqRel)
    }

    /// Release the in-flight slot and dispatch next pending op if any.
    ///
    /// Returns the next pending op's ready channel if one was dispatched.
    pub fn release_in_flight(&self) -> Option<oneshot::Sender<()>> {
        // First, pop the next pending op while holding the lock
        let next = {
            let mut pending = self.pending.lock();
            pending.pop_front()
        };

        if let Some(op) = next {
            // Keep in_flight true and return the ready channel
            Some(op.ready_tx)
        } else {
            // No more pending ops, release the slot
            self.in_flight.store(false, Ordering::Release);
            None
        }
    }

    /// Enqueue a pending operation.
    pub fn enqueue(&self, op: PendingOp) {
        self.pending.lock().push_back(op);
    }
}

/// Per-file ordering manager.
///
/// Ensures at most one structural operation is in-flight per file at any time.
/// This prevents race conditions in the underlying filesystem operations.
pub struct PerFileOrdering {
    /// Map of inode to file state.
    files: DashMap<u64, Arc<FileState>>,
    /// Statistics.
    stats: PerFileStats,
}

/// Statistics for per-file ordering.
#[derive(Debug, Default)]
pub struct PerFileStats {
    /// Number of operations that waited for ordering.
    pub ops_waited: AtomicU64,
    /// Number of operations that proceeded immediately.
    pub ops_immediate: AtomicU64,
    /// Number of barrier waits.
    pub barrier_waits: AtomicU64,
    /// Number of errors propagated to barriers.
    pub errors_propagated: AtomicU64,
}

impl Default for PerFileOrdering {
    fn default() -> Self {
        Self::new()
    }
}

impl PerFileOrdering {
    /// Create a new per-file ordering manager.
    pub fn new() -> Self {
        Self {
            files: DashMap::new(),
            stats: PerFileStats::default(),
        }
    }

    /// Get or create the state for a file.
    pub fn get_or_create(&self, inode: u64) -> Arc<FileState> {
        self.files
            .entry(inode)
            .or_insert_with(|| Arc::new(FileState::new()))
            .clone()
    }

    /// Get the state for a file if it exists.
    pub fn get(&self, inode: u64) -> Option<Arc<FileState>> {
        self.files.get(&inode).map(|r| r.clone())
    }

    /// Try to start a structural operation on a file.
    ///
    /// Returns:
    /// - `Ok(None)` if the operation can proceed immediately
    /// - `Ok(Some(receiver))` if the operation must wait (receive `()` when ready)
    /// - `Err(errno)` if the last operation failed and the error should be propagated
    pub fn try_start(&self, inode: u64, request_id: RequestId) -> Result<Option<oneshot::Receiver<()>>, i32> {
        let state = self.get_or_create(inode);

        // Check for last error (will be cleared by successful barrier)
        if let Some(errno) = state.last_error() {
            self.stats.errors_propagated.fetch_add(1, Ordering::Relaxed);
            return Err(errno);
        }

        // Try to claim the in-flight slot
        if state.try_claim_in_flight() {
            self.stats.ops_immediate.fetch_add(1, Ordering::Relaxed);
            Ok(None) // Can proceed immediately
        } else {
            // Must wait - create channel and enqueue
            let (tx, rx) = oneshot::channel();
            state.enqueue(PendingOp {
                request_id,
                ready_tx: tx,
            });
            self.stats.ops_waited.fetch_add(1, Ordering::Relaxed);
            Ok(Some(rx))
        }
    }

    /// Complete a structural operation on a file.
    ///
    /// This releases the in-flight slot and dispatches the next pending operation
    /// if any.
    pub fn complete(&self, inode: u64, error: Option<i32>) {
        if let Some(state) = self.get(inode) {
            // Record error if any
            if let Some(errno) = error {
                state.set_last_error(errno);
            }

            // Release and dispatch next
            if let Some(ready_tx) = state.release_in_flight() {
                // Signal the next op that it can proceed
                let _ = ready_tx.send(());
            }
        }
    }

    /// Wait for all pending operations on a file to complete (barrier).
    ///
    /// Returns the last error if any operation failed, or `Ok(())` if all succeeded.
    /// Clears the error state on successful return.
    pub async fn barrier(&self, inode: u64) -> Result<(), i32> {
        let state = match self.get(inode) {
            Some(s) => s,
            None => return Ok(()), // No state = no operations = success
        };

        self.stats.barrier_waits.fetch_add(1, Ordering::Relaxed);
        state.barrier_waiters.fetch_add(1, Ordering::Relaxed);

        // Wait until no in-flight and no pending
        loop {
            if !state.has_in_flight() && !state.has_pending() {
                break;
            }
            // Brief yield to allow progress
            tokio::task::yield_now().await;
        }

        state.barrier_waiters.fetch_sub(1, Ordering::Relaxed);

        // Check for error and clear it
        if let Some(errno) = state.last_error() {
            state.clear_last_error();
            return Err(errno);
        }

        Ok(())
    }

    /// Get statistics.
    pub fn stats(&self) -> &PerFileStats {
        &self.stats
    }

    /// Get the number of tracked files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Clean up state for files with no pending operations.
    ///
    /// Call periodically to prevent unbounded memory growth.
    pub fn cleanup_idle(&self) {
        self.files.retain(|_, state| {
            state.has_in_flight() || state.has_pending() || state.barrier_waiters.load(Ordering::Relaxed) > 0
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_state_new() {
        let state = FileState::new();
        assert!(!state.has_in_flight());
        assert!(!state.has_pending());
        assert!(state.last_error().is_none());
    }

    #[test]
    fn test_try_claim_in_flight() {
        let state = FileState::new();

        // First claim succeeds
        assert!(state.try_claim_in_flight());
        assert!(state.has_in_flight());

        // Second claim fails
        assert!(!state.try_claim_in_flight());
    }

    #[test]
    fn test_release_in_flight_no_pending() {
        let state = FileState::new();
        state.try_claim_in_flight();

        let next = state.release_in_flight();
        assert!(next.is_none());
        assert!(!state.has_in_flight());
    }

    #[test]
    fn test_release_in_flight_with_pending() {
        let state = FileState::new();
        state.try_claim_in_flight();

        // Enqueue a pending op
        let (tx, _rx) = oneshot::channel();
        state.enqueue(PendingOp {
            request_id: RequestId::new(1),
            ready_tx: tx,
        });

        // Release should return the pending op's channel
        let next = state.release_in_flight();
        assert!(next.is_some());
        // in_flight should still be true (claimed by next op)
        assert!(state.has_in_flight());
    }

    #[test]
    fn test_error_propagation() {
        let state = FileState::new();
        assert!(state.last_error().is_none());

        state.set_last_error(libc::EIO);
        assert_eq!(state.last_error(), Some(libc::EIO));

        state.clear_last_error();
        assert!(state.last_error().is_none());
    }

    #[test]
    fn test_per_file_ordering_immediate() {
        let ordering = PerFileOrdering::new();

        // First op proceeds immediately
        let result = ordering.try_start(1, RequestId::new(1));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_per_file_ordering_wait() {
        let ordering = PerFileOrdering::new();

        // First op proceeds immediately
        let _ = ordering.try_start(1, RequestId::new(1));

        // Second op must wait
        let result = ordering.try_start(1, RequestId::new(2));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some()); // Has receiver
    }

    #[test]
    fn test_per_file_ordering_different_files() {
        let ordering = PerFileOrdering::new();

        // First file
        let r1 = ordering.try_start(1, RequestId::new(1));
        assert!(r1.unwrap().is_none());

        // Second file (different inode) - should also proceed immediately
        let r2 = ordering.try_start(2, RequestId::new(2));
        assert!(r2.unwrap().is_none());
    }

    #[test]
    fn test_complete_dispatches_next() {
        let ordering = PerFileOrdering::new();

        // Start first op
        let _ = ordering.try_start(1, RequestId::new(1));

        // Queue second op
        let result = ordering.try_start(1, RequestId::new(2));
        let mut rx = result.unwrap().unwrap();

        // Complete first op - should dispatch second
        ordering.complete(1, None);

        // Second op should have received the ready signal
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_error_blocks_subsequent_ops() {
        let ordering = PerFileOrdering::new();

        // Start and complete with error
        let _ = ordering.try_start(1, RequestId::new(1));
        ordering.complete(1, Some(libc::EIO));

        // Next op should get the error
        let result = ordering.try_start(1, RequestId::new(2));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), libc::EIO);
    }

    #[test]
    fn test_cleanup_idle() {
        let ordering = PerFileOrdering::new();

        // Create state for two files
        let _ = ordering.try_start(1, RequestId::new(1));
        let _ = ordering.try_start(2, RequestId::new(2));

        assert_eq!(ordering.file_count(), 2);

        // Complete both
        ordering.complete(1, None);
        ordering.complete(2, None);

        // Cleanup should remove idle files
        ordering.cleanup_idle();
        assert_eq!(ordering.file_count(), 0);
    }

    #[test]
    fn test_stats() {
        let ordering = PerFileOrdering::new();

        // First op immediate
        let _ = ordering.try_start(1, RequestId::new(1));
        // Second op waits
        let _ = ordering.try_start(1, RequestId::new(2));

        assert_eq!(ordering.stats().ops_immediate.load(Ordering::Relaxed), 1);
        assert_eq!(ordering.stats().ops_waited.load(Ordering::Relaxed), 1);
    }
}
