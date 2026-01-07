//! Scheduler for async FUSE request handling.
//!
//! This module provides the infrastructure for handling FUSE requests
//! asynchronously. Instead of blocking in FUSE callbacks, requests are
//! enqueued and processed by dedicated worker threads.
//!
//! # Architecture
//!
//! ```text
//! FUSE Callback Thread                  Executor Workers
//! ┌─────────────────────┐               ┌─────────────────┐
//! │ read(ino, fh, ...)  │──enqueue──▶   │ Worker 0        │
//! │   - validate        │               │   - execute op  │
//! │   - try_enqueue     │               │   - send result │
//! │   - return          │               └─────────────────┘
//! └─────────────────────┘               ┌─────────────────┐
//!                                       │ Worker 1        │
//! ┌─────────────────────┐               │   ...           │
//! │ Dispatcher Thread   │◀──results──   └─────────────────┘
//! │   - receive results │               ┌─────────────────┐
//! │   - issue replies   │               │ Worker N        │
//! └─────────────────────┘               └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let scheduler = FuseScheduler::new(config);
//!
//! // In FUSE callback:
//! if let Err(e) = scheduler.try_enqueue_read(request) {
//!     reply.error(libc::EAGAIN);
//!     return;
//! }
//! // Return immediately - scheduler will reply asynchronously
//! ```

pub mod deadline;
pub mod executor;
pub mod lane;
pub mod queue;
pub mod read_cache;
pub mod request;
pub mod single_flight;

pub use deadline::DeadlineHeap;
pub use executor::{
    ExecutorConfig, ExecutorJob, ExecutorOperation, ExecutorResult, ExecutorStats,
    FsSyscallExecutor, SubmitError,
};
pub use lane::{
    classify_metadata, classify_read, classify_structural, Lane, LaneCapacities, LaneDeadlines,
    LaneReservations, BULK_READ_THRESHOLD,
};
pub use queue::{AdmissionError, AggregatedLaneStats, LaneQueues, LaneStats, QueuedRequest};
pub use read_cache::{ReadCache, ReadCacheConfig, ReadCacheKey, ReadCacheStats};
pub use request::{
    CopyRangeRequest, CopyRangeResult, FuseRequest, FuseResult, ReadRequest, ReadResult,
    RequestId, RequestIdGenerator, RequestState,
};
pub use single_flight::{AttachResult, InFlightReads, ReadKey, SingleFlightStats};

use crate::handles::{FuseHandle, FuseHandleTable};
use dashmap::DashMap;
use fuser::ReplyData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

/// Default deadline for read operations.
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(10);

/// Configuration for the scheduler.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Executor configuration.
    pub executor: ExecutorConfig,
    /// Per-lane queue capacities.
    pub lane_capacities: LaneCapacities,
    /// Per-lane deadlines.
    pub lane_deadlines: LaneDeadlines,
    /// Reserved executor slots per lane.
    pub lane_reservations: LaneReservations,
    /// Read cache configuration.
    pub read_cache: ReadCacheConfig,
    /// Whether single-flight deduplication is enabled.
    pub enable_single_flight: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            executor: ExecutorConfig::default(),
            lane_capacities: LaneCapacities::default(),
            lane_deadlines: LaneDeadlines::default(),
            lane_reservations: LaneReservations::default(),
            read_cache: ReadCacheConfig::default(),
            enable_single_flight: true,
        }
    }
}

impl SchedulerConfig {
    /// Create config with custom executor settings.
    #[must_use]
    pub fn with_executor(mut self, config: ExecutorConfig) -> Self {
        self.executor = config;
        self
    }

    /// Set lane capacities.
    #[must_use]
    pub fn with_lane_capacities(mut self, capacities: LaneCapacities) -> Self {
        self.lane_capacities = capacities;
        self
    }

    /// Set lane deadlines.
    #[must_use]
    pub fn with_lane_deadlines(mut self, deadlines: LaneDeadlines) -> Self {
        self.lane_deadlines = deadlines;
        self
    }

    /// Get deadline for a read operation of given size.
    pub fn read_deadline(&self, size: usize) -> Duration {
        let lane = classify_read(size);
        self.lane_deadlines.get(lane)
    }

    /// Set a base timeout that scales all lane deadlines.
    ///
    /// The provided timeout is used as the base for L2 (read foreground).
    /// Other lanes are scaled relative to their default ratios:
    /// - L1 Metadata: base * 0.2 (must be responsive)
    /// - L2 ReadFg: base
    /// - L3 WriteFg: base
    /// - L4 Bulk: base * 3 (allow longer for large operations)
    #[must_use]
    pub fn with_base_timeout(mut self, base: Duration) -> Self {
        self.lane_deadlines = LaneDeadlines {
            control: Duration::from_secs(5),
            metadata: Duration::from_secs_f64(base.as_secs_f64() * 0.2).max(Duration::from_secs(1)),
            read_foreground: base,
            write_structural: base,
            bulk: Duration::from_secs_f64(base.as_secs_f64() * 3.0),
        };
        self
    }

    /// Set read cache configuration.
    #[must_use]
    pub fn with_read_cache(mut self, config: ReadCacheConfig) -> Self {
        self.read_cache = config;
        self
    }

    /// Enable or disable single-flight deduplication.
    #[must_use]
    pub fn with_single_flight(mut self, enable: bool) -> Self {
        self.enable_single_flight = enable;
        self
    }
}

/// Error when enqueuing a request.
#[derive(Debug, thiserror::Error)]
pub enum EnqueueError {
    /// Executor queue is full.
    #[error("executor queue full")]
    QueueFull,
    /// Scheduler is shut down.
    #[error("scheduler shut down")]
    Shutdown,
}

impl From<SubmitError> for EnqueueError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::QueueFull { .. } => EnqueueError::QueueFull,
            SubmitError::Shutdown => EnqueueError::Shutdown,
        }
    }
}

/// Pending read request awaiting executor result.
struct PendingRead {
    /// The FUSE reply handle.
    reply: ReplyData,
    /// Request state for exactly-once reply.
    state: Arc<RequestState>,
    /// Generation counter for deadline heap entry validation.
    generation: u64,
}

/// The main scheduler for async FUSE operations.
///
/// Manages request submission, result dispatching, and reply handling.
pub struct FuseScheduler {
    /// The syscall executor.
    executor: Arc<FsSyscallExecutor>,
    /// Request ID generator.
    id_gen: RequestIdGenerator,
    /// Pending read requests awaiting results.
    pending_reads: Arc<DashMap<RequestId, PendingRead>>,
    /// Deadline heap for timeout tracking.
    deadline_heap: Arc<DeadlineHeap>,
    /// Handle table for restoring readers after async completion.
    handle_table: Arc<FuseHandleTable>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Dispatcher thread handle.
    dispatcher_handle: Option<JoinHandle<()>>,
    /// Receiver for completed results.
    result_rx: Option<std::sync::mpsc::Receiver<(RequestId, oneshot::Receiver<ExecutorResult>)>>,
    /// Sender for result receivers (used by enqueue).
    result_tx: std::sync::mpsc::Sender<(RequestId, oneshot::Receiver<ExecutorResult>)>,
    /// Configuration.
    config: SchedulerConfig,
}

impl FuseScheduler {
    /// Create a new scheduler with default configuration.
    pub fn new(handle_table: Arc<FuseHandleTable>) -> Self {
        Self::with_config(SchedulerConfig::default(), handle_table)
    }

    /// Create a new scheduler with custom configuration.
    pub fn with_config(config: SchedulerConfig, handle_table: Arc<FuseHandleTable>) -> Self {
        let executor = Arc::new(FsSyscallExecutor::with_config(config.executor.clone()));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let pending_reads = Arc::new(DashMap::new());
        let deadline_heap = Arc::new(DeadlineHeap::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        info!("FUSE scheduler created");

        Self {
            executor,
            id_gen: RequestIdGenerator::new(),
            pending_reads,
            deadline_heap,
            handle_table,
            shutdown,
            dispatcher_handle: None,
            result_rx: Some(result_rx),
            result_tx,
            config,
        }
    }

    /// Start the dispatcher thread.
    ///
    /// Must be called after creating the scheduler to begin processing results.
    pub fn start(&mut self) {
        if self.dispatcher_handle.is_some() {
            warn!("Scheduler dispatcher already started");
            return;
        }

        let result_rx = self.result_rx.take().expect("result_rx already taken");
        let pending_reads = Arc::clone(&self.pending_reads);
        let deadline_heap = Arc::clone(&self.deadline_heap);
        let handle_table = Arc::clone(&self.handle_table);
        let shutdown = Arc::clone(&self.shutdown);

        let handle = thread::Builder::new()
            .name("fuse-scheduler-dispatch".to_string())
            .spawn(move || {
                dispatcher_loop(result_rx, pending_reads, deadline_heap, handle_table, shutdown);
            })
            .expect("failed to spawn dispatcher thread");

        self.dispatcher_handle = Some(handle);
        info!("FUSE scheduler dispatcher started");
    }

    /// Try to enqueue a read request.
    ///
    /// On success, returns `Ok(request_id)` and the scheduler owns the reply.
    /// The scheduler will reply asynchronously when the read completes.
    ///
    /// On failure, the scheduler replies with an appropriate error code and
    /// returns `Err`. The reader is consumed and cannot be recovered - the
    /// file handle should be closed or subsequent reads will get EAGAIN.
    ///
    /// # Arguments
    ///
    /// * `fh` - File handle ID (for reader restoration after completion)
    /// * `reader` - The VaultFileReader to read from (ownership transferred)
    /// * `offset` - Byte offset to read from
    /// * `size` - Number of bytes to read
    /// * `reply` - FUSE reply handle (ownership transferred)
    ///
    /// # Returns
    ///
    /// - `Ok(request_id)` - Request enqueued, scheduler will reply asynchronously
    /// - `Err(EnqueueError)` - Failed, scheduler already replied with error
    pub fn try_enqueue_read(
        &self,
        fh: u64,
        reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
        offset: u64,
        size: usize,
        reply: ReplyData,
    ) -> Result<RequestId, EnqueueError> {
        if self.shutdown.load(Ordering::Acquire) {
            reply.error(libc::ESHUTDOWN);
            return Err(EnqueueError::Shutdown);
        }

        let request_id = self.id_gen.next();
        let lane = classify_read(size);
        let deadline = Instant::now() + self.config.lane_deadlines.get(lane);
        let state = Arc::new(RequestState::new());

        // Create oneshot for result
        let (result_tx, result_rx) = oneshot::channel();

        // Create executor job
        let job = ExecutorJob {
            request_id,
            fh,
            operation: ExecutorOperation::Read {
                reader,
                offset,
                size,
            },
            result_tx,
            deadline,
        };

        // Submit to executor
        if let Err(e) = self.executor.try_submit(job) {
            // Job wasn't accepted. The reader is consumed by the dropped job.
            // Reply with EAGAIN so client can retry.
            reply.error(libc::EAGAIN);
            warn!(?request_id, fh, "Executor rejected read request: {}", e);
            return Err(EnqueueError::from(e));
        }

        // Insert into deadline heap for timeout tracking
        let generation = self.deadline_heap.insert(request_id, deadline);

        // Store pending read
        self.pending_reads.insert(
            request_id,
            PendingRead {
                reply,
                state,
                generation,
            },
        );

        // Send result receiver to dispatcher
        if self.result_tx.send((request_id, result_rx)).is_err() {
            // Dispatcher is gone, clean up and reply with error
            if let Some((_, pending)) = self.pending_reads.remove(&request_id) {
                pending.reply.error(libc::ESHUTDOWN);
            }
            // Reader is already submitted to executor, will complete but result ignored
            return Err(EnqueueError::Shutdown);
        }

        trace!(?request_id, fh, offset, size, ?lane, "Read request enqueued");

        Ok(request_id)
    }

    /// Get executor statistics.
    pub fn executor_stats(&self) -> &ExecutorStats {
        self.executor.stats()
    }

    /// Get the number of pending reads.
    pub fn pending_read_count(&self) -> usize {
        self.pending_reads.len()
    }

    /// Check if the scheduler is healthy.
    pub fn is_healthy(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire) && self.executor.is_healthy()
    }

    /// Initiate graceful shutdown.
    pub fn shutdown(&self) {
        info!("Initiating scheduler shutdown");
        self.shutdown.store(true, Ordering::Release);
        self.executor.shutdown();
    }

    /// Wait for shutdown to complete.
    pub fn wait(mut self) {
        self.shutdown();

        // Wait for dispatcher
        if let Some(handle) = self.dispatcher_handle.take() {
            debug!("Waiting for dispatcher thread");
            let _ = handle.join();
        }

        // Executor wait happens on drop via Arc
        info!("Scheduler shutdown complete");
    }
}

impl Drop for FuseScheduler {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Dispatcher thread main loop.
///
/// Receives result receivers and issues FUSE replies when results arrive.
/// Also restores readers to the handle table after completion.
/// Uses deadline heap for efficient timeout detection.
#[allow(clippy::needless_pass_by_value)] // Arc parameters are idiomatic for thread entry points
fn dispatcher_loop(
    rx: std::sync::mpsc::Receiver<(RequestId, oneshot::Receiver<ExecutorResult>)>,
    pending_reads: Arc<DashMap<RequestId, PendingRead>>,
    deadline_heap: Arc<DeadlineHeap>,
    handle_table: Arc<FuseHandleTable>,
    shutdown: Arc<AtomicBool>,
) {
    debug!("Dispatcher loop started");

    // We need to poll multiple oneshot receivers. Use a simple approach:
    // collect receivers and poll them in rounds.
    let mut receivers: Vec<(RequestId, oneshot::Receiver<ExecutorResult>)> = Vec::new();

    loop {
        if shutdown.load(Ordering::Acquire) && receivers.is_empty() {
            debug!("Dispatcher shutting down");
            break;
        }

        // Process expired deadlines from heap (efficient O(log n) per expiration)
        for (request_id, generation) in deadline_heap.pop_expired() {
            // Verify generation matches to detect stale entries
            // (DashMap Ref doesn't support filter, so we check separately)
            let Some(pending) = pending_reads.get(&request_id) else {
                continue;
            };
            if pending.generation != generation {
                // Stale entry - request completed or cancelled
                continue;
            }
            // Valid timeout - claim reply and respond
            if pending.state.claim_reply() {
                warn!(?request_id, "Request timed out via deadline heap");
                drop(pending);
                if let Some((_, pending)) = pending_reads.remove(&request_id) {
                    pending.reply.error(libc::ETIMEDOUT);
                }
            }
        }

        // Try to receive new result receivers (non-blocking)
        loop {
            match rx.try_recv() {
                Ok((id, rx)) => {
                    receivers.push((id, rx));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    debug!("Result channel disconnected");
                    break;
                }
            }
        }

        // Check for completed results
        let mut completed = Vec::new();

        for (i, (request_id, result_rx)) in receivers.iter_mut().enumerate() {
            match result_rx.try_recv() {
                Ok(result) => {
                    completed.push((i, *request_id, Some(result)));
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Deadline expiration is handled by the heap above
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    // Sender dropped without sending - executor crashed?
                    error!(?request_id, "Result sender dropped without sending");
                    completed.push((i, *request_id, None));
                }
            }
        }

        // Process completed results (in reverse order to maintain indices)
        for (i, request_id, result) in completed.into_iter().rev() {
            receivers.swap_remove(i);

            // Get pending read and reply
            if let Some((_, pending)) = pending_reads.remove(&request_id) {
                // Try to claim reply
                if pending.state.claim_reply() {
                    match result {
                        Some(ExecutorResult::Read(read_result)) => {
                            let fh = read_result.fh;
                            let reader = read_result.reader;

                            // Issue FUSE reply
                            match read_result.result {
                                Ok(data) => {
                                    trace!(?request_id, bytes = data.len(), "Replying with data");
                                    pending.reply.data(&data);
                                }
                                Err(errno) => {
                                    trace!(?request_id, errno, "Replying with error");
                                    pending.reply.error(errno);
                                }
                            }

                            // Restore reader to handle table
                            if let Some(mut handle) = handle_table.get_mut(&fh) {
                                if matches!(*handle, FuseHandle::ReaderLoaned) {
                                    *handle = FuseHandle::Reader(reader);
                                    trace!(?request_id, fh, "Reader restored to handle table");
                                } else {
                                    // Handle was modified (closed?) while read was in flight
                                    warn!(
                                        ?request_id,
                                        fh,
                                        "Handle modified during async read, discarding reader"
                                    );
                                }
                            } else {
                                // Handle was removed (file closed) while read was in flight
                                trace!(
                                    ?request_id,
                                    fh,
                                    "Handle removed during async read, discarding reader"
                                );
                            }
                        }
                        None => {
                            // Timeout or error - no reader to restore
                            trace!(?request_id, "Replying with timeout");
                            pending.reply.error(libc::ETIMEDOUT);
                        }
                    }
                } else {
                    trace!(?request_id, "Reply already claimed (timeout race)");
                }
            }
        }

        // Small sleep to avoid busy-waiting
        if receivers.is_empty() {
            thread::sleep(Duration::from_millis(10));
        } else {
            thread::sleep(Duration::from_micros(100));
        }
    }

    // Reply to any remaining pending requests with timeout
    for entry in pending_reads.iter() {
        let request_id = *entry.key();
        warn!(?request_id, "Replying with shutdown error to pending request");
    }
    pending_reads.clear();

    debug!("Dispatcher loop exited");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lane_classification() {
        // Small reads go to L2 (ReadForeground)
        assert_eq!(classify_read(4096), Lane::ReadForeground);
        // Large reads go to L4 (Bulk)
        assert_eq!(classify_read(512 * 1024), Lane::Bulk);
    }

    #[test]
    fn test_scheduler_creation() {
        use crate::handles::FuseHandleTableExt;
        let handle_table = Arc::new(FuseHandleTable::new_fuse());
        let mut scheduler = FuseScheduler::new(handle_table);
        assert!(scheduler.is_healthy());
        assert_eq!(scheduler.pending_read_count(), 0);
        scheduler.start();
        scheduler.shutdown();
    }

    #[test]
    fn test_request_id_generator() {
        let id_gen = RequestIdGenerator::new();
        let id1 = id_gen.next();
        let id2 = id_gen.next();
        assert_ne!(id1, id2);
        assert_eq!(id2.raw(), id1.raw() + 1);
    }

    #[test]
    fn test_enqueue_error_from_submit_error() {
        let e: EnqueueError = SubmitError::QueueFull { capacity: 100 }.into();
        assert!(matches!(e, EnqueueError::QueueFull));

        let e: EnqueueError = SubmitError::Shutdown.into();
        assert!(matches!(e, EnqueueError::Shutdown));
    }
}
