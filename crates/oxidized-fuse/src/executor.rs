//! Async executor for FUSE operations.
//!
//! This module provides an executor that decouples async I/O from the FUSE
//! request handling thread. It solves the "slow cloud storage" problem where
//! operations to backends like Google Drive can take 30+ seconds, blocking
//! the entire filesystem.
//!
//! # Architecture
//!
//! Instead of calling `handle.block_on(async_op)` directly in FUSE callbacks
//! (which blocks the fuser thread), we:
//!
//! 1. Submit the async operation to a dedicated thread pool
//! 2. Wait for completion with a timeout
//! 3. Return ETIMEDOUT if the operation takes too long
//!
//! This allows the fuser thread to handle other requests even when some
//! operations are slow.
//!
//! # Background Tasks
//!
//! The executor also supports spawning background tasks that don't block
//! the caller. This is used for directory refresh: return cached data
//! immediately while refreshing in the background.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use tokio::runtime::Handle;
use tracing::{debug, trace, warn};

use crate::config::SaturationPolicy;

/// Result type for executor operations.
pub type ExecutorResult<T> = Result<T, ExecutorError>;

/// Errors that can occur during async execution.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The operation timed out.
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    /// The executor queue is full and could not accept the task.
    ///
    /// This only occurs with [`SaturationPolicy::ReturnBusy`] or
    /// [`SaturationPolicy::WaitThenError`] when the queue remains full.
    #[error("executor queue full (all workers busy)")]
    QueueFull,

    /// The executor is shutting down.
    #[error("executor is shutting down")]
    Shutdown,

    /// The worker thread panicked.
    #[error("worker thread panicked")]
    WorkerPanic,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ExecutorError {
    /// Converts this error to a libc errno value.
    pub fn to_errno(&self) -> libc::c_int {
        match self {
            ExecutorError::Timeout(_) => libc::ETIMEDOUT,
            ExecutorError::QueueFull => libc::EAGAIN,
            ExecutorError::Shutdown => libc::ESHUTDOWN,
            ExecutorError::WorkerPanic => libc::EIO,
            ExecutorError::Io(_) => libc::EIO,
        }
    }
}

/// A task to be executed by a worker thread.
type BoxedTask = Box<dyn FnOnce() + Send + 'static>;

/// Statistics about executor operations.
#[derive(Debug, Default)]
pub struct ExecutorStats {
    /// Number of tasks submitted.
    pub tasks_submitted: AtomicU64,
    /// Number of tasks completed successfully.
    pub tasks_completed: AtomicU64,
    /// Number of tasks that timed out.
    pub tasks_timed_out: AtomicU64,
    /// Number of tasks rejected due to queue saturation.
    pub tasks_saturated: AtomicU64,
}

impl ExecutorStats {
    /// Creates a new stats instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a task submission.
    pub fn record_submit(&self) {
        self.tasks_submitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successful completion.
    pub fn record_complete(&self) {
        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a timeout.
    pub fn record_timeout(&self) {
        self.tasks_timed_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a task rejected due to queue saturation.
    pub fn record_saturated(&self) {
        self.tasks_saturated.fetch_add(1, Ordering::Relaxed);
    }
}

/// Async executor with dedicated worker threads.
///
/// This executor runs async operations on a dedicated thread pool, preventing
/// slow I/O from blocking the FUSE request handling thread.
pub struct AsyncExecutor {
    /// Channel to send tasks to worker threads.
    task_sender: Sender<BoxedTask>,
    /// Worker thread handles.
    workers: Vec<JoinHandle<()>>,
    /// Tokio runtime handle for async operations.
    runtime_handle: Handle,
    /// Default timeout for operations.
    default_timeout: Duration,
    /// Policy for handling queue saturation.
    saturation_policy: SaturationPolicy,
    /// Statistics about executor operations.
    stats: Arc<ExecutorStats>,
}

impl AsyncExecutor {
    /// Creates a new async executor.
    ///
    /// # Arguments
    ///
    /// * `runtime_handle` - Handle to the tokio runtime for async operations
    /// * `num_workers` - Number of worker threads (typically 16+)
    /// * `default_timeout` - Default timeout for operations
    /// * `saturation_policy` - How to handle queue saturation
    pub fn new(
        runtime_handle: Handle,
        num_workers: usize,
        default_timeout: Duration,
        saturation_policy: SaturationPolicy,
    ) -> Self {
        // Use a bounded channel to provide backpressure
        // Queue depth = 2x workers gives some buffering without unbounded growth
        let (task_sender, task_receiver) = bounded::<BoxedTask>(num_workers * 2);

        let mut workers = Vec::with_capacity(num_workers);

        for i in 0..num_workers {
            let receiver = task_receiver.clone();
            let handle = thread::Builder::new()
                .name(format!("fuse-io-{}", i))
                .spawn(move || {
                    worker_loop(receiver);
                })
                .expect("failed to spawn worker thread");
            workers.push(handle);
        }

        debug!(
            num_workers = num_workers,
            timeout_secs = default_timeout.as_secs(),
            ?saturation_policy,
            "AsyncExecutor started"
        );

        Self {
            task_sender,
            workers,
            runtime_handle,
            default_timeout,
            saturation_policy,
            stats: Arc::new(ExecutorStats::new()),
        }
    }

    /// Returns the executor statistics.
    pub fn stats(&self) -> Arc<ExecutorStats> {
        Arc::clone(&self.stats)
    }

    /// Executes an async operation with timeout.
    ///
    /// The operation runs on a dedicated worker thread, not blocking the caller's
    /// thread pool. If the operation takes longer than the timeout, returns
    /// `ExecutorError::Timeout`.
    ///
    /// # Arguments
    ///
    /// * `future` - The async operation to execute
    ///
    /// # Returns
    ///
    /// The result of the operation, or an error if it times out or fails.
    pub fn execute<F, T>(&self, future: F) -> ExecutorResult<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.execute_with_timeout(future, self.default_timeout)
    }

    /// Executes an async operation with a custom timeout.
    pub fn execute_with_timeout<F, T>(&self, future: F, timeout: Duration) -> ExecutorResult<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.stats.record_submit();

        // Channel to receive the result
        let (result_tx, result_rx) = bounded::<T>(1);
        let runtime_handle = self.runtime_handle.clone();

        // Create a task that runs the future with an inner timeout.
        // This ensures slow futures are actually cancelled, freeing the worker.
        // Without this, timed-out tasks would continue running, blocking workers.
        let task: BoxedTask = Box::new(move || {
            // Enter the runtime context so tokio::time can access the time driver
            let _guard = runtime_handle.enter();
            match runtime_handle.block_on(tokio::time::timeout(timeout, future)) {
                Ok(result) => {
                    // Ignore send error - receiver may have been dropped due to timeout
                    let _ = result_tx.send(result);
                }
                Err(_) => {
                    // Inner timeout fired - future was cancelled, worker is freed
                    // The caller's recv_timeout will also fire around the same time
                    trace!("Inner timeout cancelled future");
                }
            }
        });

        // Send task to worker pool based on saturation policy
        match self.task_sender.try_send(task) {
            Ok(()) => {
                // Task queued successfully
            }
            Err(crossbeam_channel::TrySendError::Full(task)) => {
                // Queue is full - apply saturation policy
                match self.saturation_policy {
                    SaturationPolicy::Block => {
                        // Block until a slot is available (original behavior)
                        warn!("Worker queue full, blocking until slot available");
                        if self.task_sender.send(task).is_err() {
                            return Err(ExecutorError::Shutdown);
                        }
                    }
                    SaturationPolicy::ReturnBusy => {
                        // Return immediately with EAGAIN
                        self.stats.record_saturated();
                        trace!("Worker queue full, returning EAGAIN");
                        return Err(ExecutorError::QueueFull);
                    }
                    SaturationPolicy::WaitThenError(wait_duration) => {
                        // Wait briefly, then fail if still full
                        match self.task_sender.send_timeout(task, wait_duration) {
                            Ok(()) => {
                                // Got a slot after waiting
                            }
                            Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                                self.stats.record_saturated();
                                warn!(
                                    wait_ms = wait_duration.as_millis(),
                                    "Worker queue full after wait, returning error"
                                );
                                return Err(ExecutorError::QueueFull);
                            }
                            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                return Err(ExecutorError::Shutdown);
                            }
                        }
                    }
                }
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                return Err(ExecutorError::Shutdown);
            }
        }

        // Wait for result with timeout
        match result_rx.recv_timeout(timeout) {
            Ok(result) => {
                self.stats.record_complete();
                trace!("Task completed successfully");
                Ok(result)
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                self.stats.record_timeout();
                warn!(timeout_secs = timeout.as_secs(), "Task timed out");
                Err(ExecutorError::Timeout(timeout))
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // Disconnected can happen for two reasons:
                // 1. Inner timeout fired and cancelled the future (expected)
                // 2. Worker panicked (unexpected)
                // In either case, the task didn't complete normally.
                // We report this as a timeout since the inner timeout is the
                // most likely cause when we're actively waiting for a result.
                self.stats.record_timeout();
                trace!("Task cancelled by inner timeout");
                Err(ExecutorError::Timeout(timeout))
            }
        }
    }

    /// Shuts down the executor, waiting for workers to finish.
    pub fn shutdown(self) {
        // Drop the sender to signal workers to exit
        drop(self.task_sender);

        // Wait for all workers to finish
        for (i, handle) in self.workers.into_iter().enumerate() {
            if let Err(e) = handle.join() {
                warn!(worker = i, error = ?e, "Worker thread panicked during shutdown");
            }
        }

        debug!("AsyncExecutor shut down");
    }
}

/// Worker thread loop.
fn worker_loop(receiver: Receiver<BoxedTask>) {
    loop {
        match receiver.recv() {
            Ok(task) => {
                // Execute the task, catching panics
                if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)) {
                    warn!(error = ?e, "Task panicked");
                }
            }
            Err(crossbeam_channel::RecvError) => {
                // Channel closed, exit
                trace!("Worker thread exiting");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    fn create_test_executor() -> (Runtime, AsyncExecutor) {
        let rt = Runtime::new().unwrap();
        let executor = AsyncExecutor::new(
            rt.handle().clone(),
            2,
            Duration::from_secs(5),
            SaturationPolicy::Block,
        );
        (rt, executor)
    }

    fn create_test_executor_with_policy(policy: SaturationPolicy) -> (Runtime, AsyncExecutor) {
        let rt = Runtime::new().unwrap();
        let executor = AsyncExecutor::new(rt.handle().clone(), 2, Duration::from_secs(5), policy);
        (rt, executor)
    }

    #[test]
    fn test_execute_simple() {
        let (_rt, executor) = create_test_executor();

        let result = executor.execute(async { 42 });
        assert_eq!(result.unwrap(), 42);

        executor.shutdown();
    }

    #[test]
    fn test_execute_with_async_work() {
        let (_rt, executor) = create_test_executor();

        let result = executor.execute(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            "done"
        });
        assert_eq!(result.unwrap(), "done");

        executor.shutdown();
    }

    #[test]
    fn test_timeout() {
        let (_rt, executor) = create_test_executor();

        let result = executor.execute_with_timeout(
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                42
            },
            Duration::from_millis(50),
        );

        assert!(matches!(result, Err(ExecutorError::Timeout(_))));

        executor.shutdown();
    }

    #[test]
    fn test_stats() {
        let (_rt, executor) = create_test_executor();

        executor.execute(async { 1 }).unwrap();
        executor.execute(async { 2 }).unwrap();

        let stats = executor.stats();
        assert_eq!(stats.tasks_submitted.load(Ordering::Relaxed), 2);
        assert_eq!(stats.tasks_completed.load(Ordering::Relaxed), 2);

        executor.shutdown();
    }

    #[test]
    fn test_concurrent_execution() {
        let (_rt, executor) = create_test_executor();

        // Submit multiple tasks concurrently using scoped threads
        std::thread::scope(|s| {
            let executor_ref = &executor;
            let handles: Vec<_> = (0..10)
                .map(|i| {
                    s.spawn(move || executor_ref.execute(async move { i * 2 }))
                })
                .collect();

            for (i, handle) in handles.into_iter().enumerate() {
                let result = handle.join().unwrap();
                assert_eq!(result.unwrap(), i * 2);
            }
        });

        executor.shutdown();
    }

    #[test]
    fn test_saturation_policy_return_busy() {
        // Create executor with 1 worker and queue depth of 2 (1 * 2)
        let rt = Runtime::new().unwrap();
        let executor = Arc::new(AsyncExecutor::new(
            rt.handle().clone(),
            1,
            Duration::from_secs(5),
            SaturationPolicy::ReturnBusy,
        ));

        // Use channels to block the worker
        let (block_tx, block_rx) = std::sync::mpsc::channel::<()>();

        // Submit tasks to fill the queue (1 worker + 2 queue slots = 3 tasks needed)
        // First task blocks the worker
        let rx = block_rx;
        let exec_clone = Arc::clone(&executor);
        std::thread::spawn(move || {
            let _ = exec_clone.execute(async move {
                // This blocks the worker thread
                let _ = rx.recv();
                42
            });
        });

        // Give the worker time to pick up the first task
        std::thread::sleep(Duration::from_millis(20));

        // Fill the queue with 2 more tasks
        for _ in 0..2 {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let exec_clone = Arc::clone(&executor);
            std::thread::spawn(move || {
                let _ = exec_clone.execute(async move {
                    let _ = rx.recv();
                    42
                });
            });
            std::mem::forget(tx); // Keep channel open
        }

        std::thread::sleep(Duration::from_millis(20));

        // Now try to execute when queue is full - should return QueueFull immediately
        let result = executor.execute(async { 42 });
        assert!(
            matches!(result, Err(ExecutorError::QueueFull)),
            "Expected QueueFull, got {:?}",
            result
        );

        // Check stats
        let stats = executor.stats();
        assert_eq!(stats.tasks_saturated.load(Ordering::Relaxed), 1);

        // Unblock everything and shutdown
        drop(block_tx);
        // Note: Can't call shutdown() on Arc, but dropping will clean up
    }

    #[test]
    fn test_saturation_policy_wait_then_error() {
        // Create executor with 1 worker and queue depth of 2
        let rt = Runtime::new().unwrap();
        let executor = Arc::new(AsyncExecutor::new(
            rt.handle().clone(),
            1,
            Duration::from_secs(5),
            SaturationPolicy::WaitThenError(Duration::from_millis(50)),
        ));

        // Use channels to block the worker
        let (block_tx, block_rx) = std::sync::mpsc::channel::<()>();

        // First task blocks the worker
        let rx = block_rx;
        let exec_clone = Arc::clone(&executor);
        std::thread::spawn(move || {
            let _ = exec_clone.execute(async move {
                let _ = rx.recv();
                42
            });
        });

        std::thread::sleep(Duration::from_millis(20));

        // Fill the queue
        for _ in 0..2 {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let exec_clone = Arc::clone(&executor);
            std::thread::spawn(move || {
                let _ = exec_clone.execute(async move {
                    let _ = rx.recv();
                    42
                });
            });
            std::mem::forget(tx);
        }

        std::thread::sleep(Duration::from_millis(20));

        // Should wait 50ms then return QueueFull
        let start = std::time::Instant::now();
        let result = executor.execute(async { 42 });
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ExecutorError::QueueFull)),
            "Expected QueueFull, got {:?}",
            result
        );
        assert!(
            elapsed >= Duration::from_millis(40),
            "Should have waited ~50ms, but only waited {:?}",
            elapsed
        );

        // Unblock everything
        drop(block_tx);
        // Note: Can't call shutdown() on Arc, but dropping will clean up
    }
}
