//! Bounded executor for filesystem syscalls.
//!
//! This module provides a dedicated thread pool for executing blocking or
//! potentially-slow filesystem operations. FUSE callbacks submit work to this
//! executor and return immediately, with replies issued asynchronously when
//! work completes.
//!
//! # Design
//!
//! - Fixed number of worker threads (`io_threads`)
//! - Bounded submission queue (reject-fast when full)
//! - Each worker has a minimal tokio runtime for async operations
//! - Results returned via oneshot channels
//!
//! # Thread Safety
//!
//! The executor is `Send + Sync` and can be safely shared across FUSE callback
//! threads.

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use event_listener::Event;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

use oxcrypt_core::vault::VaultOperations;

use super::request::{
    HazardousOp, HazardousOpHandler, HazardousResult, ReadResult, RequestId, StructuralOp,
    StructuralResult,
};

/// Default number of I/O worker threads.
pub const DEFAULT_IO_THREADS: usize = 16;

/// Default capacity of the submission queue.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// A job submitted to the executor.
pub struct ExecutorJob {
    /// Request ID for tracking.
    pub request_id: RequestId,
    /// File handle ID (for reader restoration).
    pub fh: u64,
    /// The operation to execute.
    pub operation: ExecutorOperation,
    /// Channel to send the result back.
    pub result_tx: oneshot::Sender<ExecutorResult>,
    /// Deadline for this job.
    pub deadline: Instant,
}

impl std::fmt::Debug for ExecutorJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutorJob")
            .field("request_id", &self.request_id)
            .field("fh", &self.fh)
            .field("operation", &self.operation)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Operations that can be executed.
pub enum ExecutorOperation {
    /// Read from a VaultFileReader.
    Read {
        /// The reader to use (must be Send).
        reader: Box<oxcrypt_core::fs::streaming::VaultFileReaderSync>,
        /// Byte offset to read from.
        offset: u64,
        /// Number of bytes to read.
        size: usize,
    },
    /// Execute a structural operation (unlink, mkdir, rename, etc.).
    Structural {
        /// The structural operation to execute.
        op: StructuralOp,
        /// Vault operations for executing the operation.
        ops: Arc<VaultOperations>,
    },
    /// Execute a hazardous filesystem operation.
    Hazardous {
        /// The hazardous operation to execute.
        op: HazardousOp,
        /// Handler that performs the operation.
        handler: Arc<dyn HazardousOpHandler>,
    },
}

impl std::fmt::Debug for ExecutorOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorOperation::Read { offset, size, .. } => f
                .debug_struct("Read")
                .field("offset", offset)
                .field("size", size)
                .finish_non_exhaustive(),
            ExecutorOperation::Structural { op, .. } => f
                .debug_struct("Structural")
                .field("op", &op.name())
                .field("inode", &op.primary_inode())
                .finish_non_exhaustive(),
            ExecutorOperation::Hazardous { .. } => {
                f.debug_struct("Hazardous").finish_non_exhaustive()
            }
        }
    }
}

/// Results from executor operations.
pub enum ExecutorResult {
    /// Read completed.
    Read(ReadResult),
    /// Structural operation completed.
    Structural(StructuralResult),
    /// Hazardous operation completed.
    Hazardous(HazardousResult),
}

impl ExecutorResult {
    /// Get the request ID.
    pub fn request_id(&self) -> RequestId {
        match self {
            ExecutorResult::Read(r) => r.id,
            ExecutorResult::Structural(r) => r.id(),
            ExecutorResult::Hazardous(r) => r.id(),
        }
    }
}

/// Statistics for the executor.
#[derive(Debug, Default)]
pub struct ExecutorStats {
    /// Number of jobs submitted.
    pub jobs_submitted: AtomicU64,
    /// Number of jobs completed successfully.
    pub jobs_completed: AtomicU64,
    /// Number of jobs that failed.
    pub jobs_failed: AtomicU64,
    /// Number of jobs rejected due to queue full.
    pub jobs_rejected: AtomicU64,
    /// Current queue depth.
    pub queue_depth: AtomicU64,
    /// Total execution time in nanoseconds.
    pub total_execution_nanos: AtomicU64,
}

impl ExecutorStats {
    /// Create new empty stats.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a job submission.
    pub fn record_submit(&self) {
        self.jobs_submitted.fetch_add(1, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a job completion.
    pub fn record_complete(&self, success: bool, duration: Duration) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
        if success {
            self.jobs_completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.jobs_failed.fetch_add(1, Ordering::Relaxed);
        }
        // Truncation is acceptable - if a single operation takes > 584 years, we have other problems
        #[allow(clippy::cast_possible_truncation)]
        let nanos = duration.as_nanos() as u64;
        self.total_execution_nanos
            .fetch_add(nanos, Ordering::Relaxed);
    }

    /// Record a job rejection.
    pub fn record_reject(&self) {
        self.jobs_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average execution time.
    pub fn avg_execution_time(&self) -> Duration {
        let completed =
            self.jobs_completed.load(Ordering::Relaxed) + self.jobs_failed.load(Ordering::Relaxed);
        if completed == 0 {
            return Duration::ZERO;
        }
        let total_nanos = self.total_execution_nanos.load(Ordering::Relaxed);
        Duration::from_nanos(total_nanos / completed)
    }
}

/// Configuration for the executor.
#[derive(Clone)]
pub struct ExecutorConfig {
    /// Number of worker threads.
    pub io_threads: usize,
    /// Capacity of the submission queue.
    pub queue_capacity: usize,
    /// Optional event to notify when jobs complete.
    /// This allows the scheduler to wake immediately instead of polling.
    pub completion_event: Option<Arc<Event>>,
}

impl std::fmt::Debug for ExecutorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutorConfig")
            .field("io_threads", &self.io_threads)
            .field("queue_capacity", &self.queue_capacity)
            .field("completion_event", &self.completion_event.is_some())
            .finish()
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            io_threads: DEFAULT_IO_THREADS,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            completion_event: None,
        }
    }
}

impl ExecutorConfig {
    /// Create a new config with the given number of threads.
    #[must_use]
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.io_threads = threads;
        self
    }

    /// Create a new config with the given queue capacity.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity;
        self
    }

    /// Set the completion event for notifying when jobs finish.
    ///
    /// When set, workers will notify this event after sending results,
    /// allowing the scheduler to wake immediately instead of polling.
    #[must_use]
    pub fn with_completion_event(mut self, event: Arc<Event>) -> Self {
        self.completion_event = Some(event);
        self
    }
}

/// Error when submitting to the executor.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// Queue is full; request should be rejected with EAGAIN.
    #[error("executor queue full (capacity: {capacity})")]
    QueueFull { capacity: usize },
    /// Executor has been shut down.
    #[error("executor has been shut down")]
    Shutdown,
}

/// A bounded executor for filesystem syscalls.
///
/// Provides a fixed thread pool for executing blocking operations without
/// starving the FUSE callback threads.
pub struct FsSyscallExecutor {
    /// Sender for job submission.
    submit_tx: Sender<ExecutorJob>,
    /// Worker threads.
    workers: Vec<JoinHandle<()>>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Statistics.
    stats: Arc<ExecutorStats>,
    /// Configuration.
    config: ExecutorConfig,
}

impl FsSyscallExecutor {
    /// Create a new executor with default configuration.
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::default())
    }

    /// Create a new executor with custom configuration.
    pub fn with_config(config: ExecutorConfig) -> Self {
        let (submit_tx, submit_rx) = bounded(config.queue_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = ExecutorStats::new();
        let completion_event = config.completion_event.clone();

        let mut workers = Vec::with_capacity(config.io_threads);

        for worker_id in 0..config.io_threads {
            let rx = submit_rx.clone();
            let shutdown = Arc::clone(&shutdown);
            let stats = Arc::clone(&stats);
            let completion_event = completion_event.clone();

            let handle = thread::Builder::new()
                .name(format!("fs-executor-{worker_id}"))
                .spawn(move || {
                    worker_loop(worker_id, rx, shutdown, stats, completion_event);
                })
                .expect("failed to spawn executor worker thread");

            workers.push(handle);
        }

        info!(
            threads = config.io_threads,
            capacity = config.queue_capacity,
            "FS syscall executor started"
        );

        Self {
            submit_tx,
            workers,
            shutdown,
            stats,
            config,
        }
    }

    /// Try to submit a job to the executor.
    ///
    /// Returns `Err(SubmitError::QueueFull)` if the queue is at capacity.
    /// The caller should reply with EAGAIN in this case.
    pub fn try_submit(&self, job: ExecutorJob) -> Result<(), (SubmitError, ExecutorJob)> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err((SubmitError::Shutdown, job));
        }

        match self.submit_tx.try_send(job) {
            Ok(()) => {
                self.stats.record_submit();
                trace!("Job submitted to executor");
                Ok(())
            }
            Err(TrySendError::Full(rejected)) => {
                self.stats.record_reject();
                warn!(
                    capacity = self.config.queue_capacity,
                    depth = self.stats.queue_depth.load(Ordering::Relaxed),
                    "Executor queue full, rejecting request"
                );
                Err((
                    SubmitError::QueueFull {
                        capacity: self.config.queue_capacity,
                    },
                    rejected,
                ))
            }
            Err(TrySendError::Disconnected(rejected)) => {
                error!("Executor channel disconnected");
                Err((SubmitError::Shutdown, rejected))
            }
        }
    }

    /// Get executor statistics.
    pub fn stats(&self) -> &ExecutorStats {
        &self.stats
    }

    /// Get current queue depth.
    pub fn queue_depth(&self) -> u64 {
        self.stats.queue_depth.load(Ordering::Relaxed)
    }

    /// Get configured executor worker count.
    pub fn io_threads(&self) -> usize {
        self.config.io_threads
    }

    /// Check if the executor is healthy (not shut down).
    pub fn is_healthy(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }

    /// Initiate graceful shutdown.
    ///
    /// Sets the shutdown flag. Workers will finish current jobs and exit.
    pub fn shutdown(&self) {
        info!("Initiating executor shutdown");
        self.shutdown.store(true, Ordering::Release);
    }

    /// Wait for all workers to finish.
    ///
    /// Should be called after `shutdown()`.
    pub fn wait(mut self) {
        debug!("Waiting for executor workers to finish");
        for handle in std::mem::take(&mut self.workers) {
            let _ = handle.join();
        }
        info!("Executor shutdown complete");
    }
}

impl Default for FsSyscallExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FsSyscallExecutor {
    fn drop(&mut self) {
        // Signal shutdown but don't wait - Drop can't consume self
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Worker thread main loop.
#[allow(clippy::needless_pass_by_value)] // Arc parameters are idiomatic for thread entry points
fn worker_loop(
    worker_id: usize,
    rx: Receiver<ExecutorJob>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<ExecutorStats>,
    completion_event: Option<Arc<Event>>,
) {
    debug!(worker_id, "Executor worker started");

    loop {
        // Check shutdown flag
        if shutdown.load(Ordering::Acquire) {
            debug!(worker_id, "Worker received shutdown signal");
            break;
        }

        // Try to receive with timeout to periodically check shutdown
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(job) => {
                let start = Instant::now();
                let request_id = job.request_id;

                trace!(worker_id, ?request_id, "Worker processing job");

                // Check if already past deadline
                if Instant::now() > job.deadline {
                    warn!(
                        worker_id,
                        ?request_id,
                        "Job already past deadline, skipping execution"
                    );
                    stats.record_complete(false, start.elapsed());

                    // Return resources (especially the reader) to the scheduler
                    match job.operation {
                        ExecutorOperation::Read { reader, offset, .. } => {
                            let result = ExecutorResult::Read(ReadResult {
                                id: request_id,
                                fh: job.fh,
                                offset,
                                result: Err(libc::ETIMEDOUT),
                                reader,
                            });
                            let _ = job.result_tx.send(result);
                            // Notify dispatcher that a result is ready
                            if let Some(ref event) = completion_event {
                                event.notify(1);
                            }
                        }
                        // For other ops, dropping is fine as they don't hold loaned resources
                        _ => {}
                    }

                    continue;
                }

                // Execute the operation (synchronously)
                let executor_result = match job.operation {
                    ExecutorOperation::Hazardous { op, handler } => {
                        let result = handler.execute(request_id, op);
                        ExecutorResult::Hazardous(result)
                    }
                    other => execute_operation(request_id, job.fh, other),
                };
                let elapsed = start.elapsed();

                let success = match &executor_result {
                    ExecutorResult::Read(r) => r.result.is_ok(),
                    ExecutorResult::Structural(r) => r.error().is_none(),
                    ExecutorResult::Hazardous(r) => match r {
                        HazardousResult::Empty { result, .. } => result.is_ok(),
                        HazardousResult::Directory { result, .. } => result.is_ok(),
                        HazardousResult::DirectoryPlus { result, .. } => result.is_ok(),
                    },
                };

                // Try to send result; if receiver is dropped (timeout occurred), that's fine
                if job.result_tx.send(executor_result).is_err() {
                    trace!(
                        worker_id,
                        ?request_id,
                        "Result receiver dropped (timeout or cancellation)"
                    );
                }

                // Notify dispatcher that a result is ready
                if let Some(ref event) = completion_event {
                    event.notify(1);
                }

                stats.record_complete(success, elapsed);

                trace!(
                    worker_id,
                    ?request_id,
                    elapsed_ms = elapsed.as_millis(),
                    success,
                    "Job completed"
                );
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Normal timeout, check shutdown and loop
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                debug!(worker_id, "Channel disconnected, worker exiting");
                break;
            }
        }
    }

    debug!(worker_id, "Executor worker exiting");
}

/// Execute an operation and return the result.
fn execute_operation(
    request_id: RequestId,
    fh: u64,
    operation: ExecutorOperation,
) -> ExecutorResult {
    match operation {
        ExecutorOperation::Read {
            mut reader,
            offset,
            size,
        } => {
            let result = match reader.read_range(offset, size) {
                Ok(data) => Ok(Bytes::from(data)),
                Err(e) => {
                    warn!(error = %e, "Read operation failed");
                    // Map streaming errors to errno
                    let errno = match e {
                        oxcrypt_core::fs::streaming::StreamingError::FileTooSmall { .. } => {
                            libc::EINVAL
                        }
                        // All other errors map to EIO
                        _ => libc::EIO,
                    };
                    Err(errno)
                }
            };
            ExecutorResult::Read(ReadResult {
                id: request_id,
                fh,
                offset,
                result,
                reader, // Note: This is now Box<VaultFileReaderSync>
            })
        }
        ExecutorOperation::Structural { op, ops } => {
            let result = execute_structural_op(&op, &ops);
            ExecutorResult::Structural(StructuralResult::Empty {
                id: request_id,
                result,
            })
        }
        ExecutorOperation::Hazardous { .. } => {
            unreachable!("Hazardous operations must be executed directly in worker loop");
        }
    }
}

/// Execute a structural operation against the vault.
fn execute_structural_op(op: &StructuralOp, ops: &VaultOperations) -> Result<(), i32> {
    match op {
        StructuralOp::Unlink { dir_id, name, .. } => {
            // Try file first, then symlink
            match ops.delete_file(dir_id, name) {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Try symlink
                    ops.delete_symlink(dir_id, name).map_err(|e| {
                        warn!(error = %e, name, "Failed to delete file/symlink");
                        libc::EIO
                    })
                }
            }
        }
        StructuralOp::Rmdir { dir_id, name, .. } => {
            ops.delete_directory(dir_id, name).map_err(|e| {
                warn!(error = %e, name, "Failed to delete directory");
                libc::EIO
            })
        }
        StructuralOp::Mkdir { dir_id, name, .. } => {
            ops.create_directory(dir_id, name).map(|_| ()).map_err(|e| {
                warn!(error = %e, name, "Failed to create directory");
                libc::EIO
            })
        }
        StructuralOp::Create { dir_id, name, .. } => {
            ops.write_file(dir_id, name, &[]).map(|_| ()).map_err(|e| {
                warn!(error = %e, name, "Failed to create file");
                libc::EIO
            })
        }
        StructuralOp::Rename {
            src_dir_id,
            name,
            dst_dir_id,
            newname,
            ..
        } => {
            // Check if same directory rename or cross-directory move
            if src_dir_id == dst_dir_id {
                ops.rename_file(src_dir_id, name, newname).map_err(|e| {
                    warn!(error = %e, name, newname, "Failed to rename file");
                    libc::EIO
                })
            } else {
                ops.move_and_rename_file(src_dir_id, name, dst_dir_id, newname)
                    .map_err(|e| {
                        warn!(error = %e, name, newname, "Failed to move file");
                        libc::EIO
                    })
            }
        }
        StructuralOp::Symlink {
            dir_id,
            link_target,
            name,
            ..
        } => ops.create_symlink(dir_id, name, link_target).map_err(|e| {
            warn!(error = %e, name, "Failed to create symlink");
            libc::EIO
        }),
        StructuralOp::Setattr { .. } => {
            // Setattr is handled in-memory (attr cache), no vault operation needed
            Ok(())
        }
        StructuralOp::Link { .. } => {
            // Hard links are not supported in Cryptomator vaults
            Err(libc::ENOTSUP)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_config_defaults() {
        let config = ExecutorConfig::default();
        assert_eq!(config.io_threads, DEFAULT_IO_THREADS);
        assert_eq!(config.queue_capacity, DEFAULT_QUEUE_CAPACITY);
    }

    #[test]
    fn test_executor_config_builder() {
        let config = ExecutorConfig::default().with_threads(8).with_capacity(512);
        assert_eq!(config.io_threads, 8);
        assert_eq!(config.queue_capacity, 512);
    }

    #[test]
    fn test_executor_stats() {
        let stats = ExecutorStats::new();

        stats.record_submit();
        assert_eq!(stats.jobs_submitted.load(Ordering::Relaxed), 1);
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 1);

        stats.record_complete(true, Duration::from_millis(100));
        assert_eq!(stats.jobs_completed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 0);

        stats.record_reject();
        assert_eq!(stats.jobs_rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_executor_creation_and_shutdown() {
        let executor = FsSyscallExecutor::with_config(
            ExecutorConfig::default().with_threads(2).with_capacity(10),
        );

        assert!(executor.is_healthy());
        assert_eq!(executor.queue_depth(), 0);

        executor.shutdown();
        executor.wait();
    }

    // Note: test_submit_after_shutdown was removed because it used
    // unsafe { std::mem::zeroed() } which is invalid for Box<VaultFileReader>.
    // Integration tests with real files should be used instead.
}
