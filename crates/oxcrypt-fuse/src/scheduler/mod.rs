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
//! let scheduler = FuseScheduler::new(handle_table, vault_stats);
//!
//! // In FUSE callback:
//! if let Err(e) = scheduler.try_enqueue_read(request) {
//!     reply.error(libc::EAGAIN);
//!     return;
//! }
//! // Return immediately - scheduler will reply asynchronously
//! ```

pub mod deadline;
pub mod dispatch;
pub mod executor;
pub mod lane;
pub mod per_file;
pub mod queue;
pub mod read_cache;
pub mod request;
pub mod single_flight;
pub mod stats;

pub use deadline::DeadlineHeap;
pub use dispatch::{DispatchConfig, DispatchStats, FairnessDispatcher};
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
    CopyRangeRequest, CopyRangeResult, FuseRequest, FuseResult, QueuedCopyRangeJob, QueuedJob,
    QueuedReadJob, QueuedStructuralJob, ReadRequest, ReadResult, RequestId, RequestIdGenerator,
    RequestState, SetattrParams, StructuralOp, StructuralReply, StructuralRequest, StructuralResult,
};
pub use single_flight::{AttachResult, InFlightReads, ReadKey, SingleFlightStats};
pub use per_file::{FileState, PerFileOrdering, PerFileStats};
pub use stats::{SchedulerSnapshot, SchedulerStats};

use crate::handles::{FuseHandle, FuseHandleTable};
use dashmap::DashMap;
use fuser::{ReplyData, ReplyWrite};
use oxcrypt_mount::VaultStats;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

/// Default deadline for read operations.
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(10);

/// Default global write budget (256 MiB).
pub const DEFAULT_WRITE_BUDGET_GLOBAL: u64 = 256 * 1024 * 1024;

/// Default per-file write budget (32 MiB).
pub const DEFAULT_WRITE_BUDGET_PER_FILE: u64 = 32 * 1024 * 1024;

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
    /// Fairness dispatch configuration.
    pub dispatch: DispatchConfig,
    /// Read cache configuration.
    pub read_cache: ReadCacheConfig,
    /// Whether single-flight deduplication is enabled.
    pub enable_single_flight: bool,
    /// Global write budget in bytes (sum of all dirty write buffers).
    /// When exceeded, new writes return EAGAIN.
    pub write_budget_global: u64,
    /// Per-file write budget in bytes (size of individual dirty write buffer).
    /// When exceeded for a file, writes to that file return EAGAIN.
    pub write_budget_per_file: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            executor: ExecutorConfig::default(),
            lane_capacities: LaneCapacities::default(),
            lane_deadlines: LaneDeadlines::default(),
            lane_reservations: LaneReservations::default(),
            dispatch: DispatchConfig::default(),
            read_cache: ReadCacheConfig::default(),
            enable_single_flight: true,
            write_budget_global: DEFAULT_WRITE_BUDGET_GLOBAL,
            write_budget_per_file: DEFAULT_WRITE_BUDGET_PER_FILE,
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

    /// Set dispatch configuration.
    #[must_use]
    pub fn with_dispatch(mut self, config: DispatchConfig) -> Self {
        self.dispatch = config;
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
    /// A prior operation on the same file failed.
    #[error("prior operation failed with errno {errno}")]
    PriorOpFailed {
        /// The errno from the failed operation.
        errno: i32,
    },
}

impl From<SubmitError> for EnqueueError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::QueueFull { .. } => EnqueueError::QueueFull,
            SubmitError::Shutdown => EnqueueError::Shutdown,
        }
    }
}

/// A stats collector that can produce scheduler snapshots after the scheduler is moved.
///
/// This holds Arc references to all stats components, allowing snapshots to be produced
/// even after the scheduler has been moved into a FUSE session.
#[derive(Clone)]
pub struct SchedulerStatsCollector {
    stats: Arc<SchedulerStats>,
    executor: Arc<FsSyscallExecutor>,
    read_cache: Arc<ReadCache>,
    in_flight: Arc<InFlightReads>,
    per_file: Arc<PerFileOrdering>,
}

impl SchedulerStatsCollector {
    /// Get a complete snapshot of all scheduler metrics.
    pub fn snapshot(&self) -> SchedulerSnapshot {
        let cache_stats = self.read_cache.stats();

        SchedulerSnapshot::from_components(
            &self.stats,
            self.executor.stats(),
            cache_stats.hits.load(Ordering::Relaxed),
            cache_stats.misses.load(Ordering::Relaxed),
            self.read_cache.entry_count(),
            self.read_cache.weighted_size(),
            self.in_flight.stats(),
            self.per_file.stats(),
        )
    }

    /// Convert to a backend-agnostic `SchedulerStatsSnapshot` for the desktop client.
    pub fn to_mount_snapshot(&self) -> oxcrypt_mount::SchedulerStatsSnapshot {
        let snapshot = self.snapshot();
        oxcrypt_mount::SchedulerStatsSnapshot {
            requests_accepted: snapshot.requests_accepted,
            requests_rejected: snapshot.requests_rejected,
            rejection_rate: if snapshot.requests_accepted + snapshot.requests_rejected == 0 {
                0.0
            } else {
                snapshot.requests_rejected as f64
                    / (snapshot.requests_accepted + snapshot.requests_rejected) as f64
            },
            timeouts: snapshot.timeouts,
            timeout_rate: if snapshot.requests_accepted == 0 {
                0.0
            } else {
                snapshot.timeouts as f64 / snapshot.requests_accepted as f64
            },
            late_completions: snapshot.late_completions,
            in_flight_total: snapshot.in_flight_by_lane.iter().sum(),
            in_flight_by_lane: snapshot.in_flight_by_lane,
            executor_jobs_submitted: snapshot.executor_jobs_submitted,
            executor_jobs_completed: snapshot.executor_jobs_completed,
            executor_jobs_failed: snapshot.executor_jobs_failed,
            executor_jobs_rejected: snapshot.executor_jobs_rejected,
            executor_queue_depth: snapshot.executor_queue_depth,
            executor_avg_time_us: snapshot.executor_avg_time.as_micros() as u64,
            read_cache_hits: snapshot.cache_hits,
            read_cache_misses: snapshot.cache_misses,
            read_cache_hit_ratio: snapshot.cache_hit_ratio,
            read_cache_entries: snapshot.cache_entries,
            read_cache_bytes: snapshot.cache_bytes,
            dedup_leaders: snapshot.dedup_leaders,
            dedup_waiters: snapshot.dedup_waiters,
            dedup_ratio: snapshot.dedup_ratio,
            per_file_ops_waited: snapshot.per_file_ops_waited,
            per_file_ops_immediate: snapshot.per_file_ops_immediate,
            per_file_barrier_waits: snapshot.per_file_barrier_waits,
            per_file_errors_propagated: snapshot.per_file_errors_propagated,
        }
    }
}

/// Pending read request awaiting executor result.
struct PendingRead {
    /// Inode for cache key construction.
    ino: u64,
    /// Read key for single-flight completion (None if single-flight disabled).
    read_key: Option<ReadKey>,
    /// Lane for admission control tracking.
    lane: Lane,
    /// The FUSE reply handle.
    reply: ReplyData,
    /// Request state for exactly-once reply.
    state: Arc<RequestState>,
    /// Generation counter for deadline heap entry validation.
    generation: u64,
}

/// Pending copy_file_range request awaiting executor result.
///
/// The executor performs the read, then the dispatcher writes to destination.
struct PendingCopyRange {
    /// Destination file handle.
    fh_out: u64,
    /// Destination inode (for cache invalidation).
    /// TODO: Pass attr_cache to dispatcher and invalidate on completion.
    #[allow(dead_code)]
    ino_out: u64,
    /// Destination offset.
    offset_out: u64,
    /// Lane for admission control tracking.
    lane: Lane,
    /// The FUSE reply handle.
    reply: ReplyWrite,
    /// Request state for exactly-once reply.
    state: Arc<RequestState>,
    /// Generation counter for deadline heap entry validation.
    generation: u64,
}

/// Pending structural request awaiting executor result.
struct PendingStructural {
    /// The structural operation (for per-file ordering completion).
    op: StructuralOp,
    /// Lane for admission control tracking.
    lane: Lane,
    /// The FUSE reply handle.
    reply: StructuralReply,
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
    /// Lane queues for fair scheduling.
    lane_queues: Arc<LaneQueues<QueuedJob>>,
    /// Fairness dispatcher for lane selection.
    dispatcher: Arc<FairnessDispatcher>,
    /// Pending read requests awaiting results.
    pending_reads: Arc<DashMap<RequestId, PendingRead>>,
    /// Pending copy_file_range requests awaiting results.
    pending_copy_ranges: Arc<DashMap<RequestId, PendingCopyRange>>,
    /// Pending structural requests awaiting results.
    pending_structural: Arc<DashMap<RequestId, PendingStructural>>,
    /// Deadline heap for timeout tracking.
    deadline_heap: Arc<DeadlineHeap>,
    /// Handle table for restoring readers after async completion.
    handle_table: Arc<FuseHandleTable>,
    /// Per-file ordering for structural operations.
    per_file: Arc<PerFileOrdering>,
    /// Read cache for decrypted data.
    read_cache: Arc<ReadCache>,
    /// Single-flight deduplication for concurrent reads.
    in_flight: Arc<InFlightReads>,
    /// Aggregated scheduler statistics.
    stats: Arc<SchedulerStats>,
    /// Vault-level statistics (shared with desktop client).
    vault_stats: Arc<VaultStats>,
    /// Pending write operations per destination inode (for barrier semantics).
    /// Incremented on copy_file_range enqueue, decremented on completion.
    /// Used by flush/fsync to wait for pending async writes.
    pending_writes_by_file: Arc<DashMap<u64, AtomicU64>>,
    /// Condition variable signaled when a pending write completes.
    /// Used by wait_pending_writes to avoid spin-waiting.
    writes_complete_notify: Arc<(std::sync::Mutex<()>, std::sync::Condvar)>,
    /// Total dirty write buffer bytes globally (for write budget).
    write_bytes_global: Arc<AtomicU64>,
    /// Dirty write buffer bytes per file (for per-file write budget).
    write_bytes_by_file: Arc<DashMap<u64, AtomicU64>>,
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
    pub fn new(handle_table: Arc<FuseHandleTable>, vault_stats: Arc<VaultStats>) -> Self {
        Self::with_config(SchedulerConfig::default(), handle_table, vault_stats)
    }

    /// Create a new scheduler with custom configuration.
    pub fn with_config(config: SchedulerConfig, handle_table: Arc<FuseHandleTable>, vault_stats: Arc<VaultStats>) -> Self {
        let executor = Arc::new(FsSyscallExecutor::with_config(config.executor.clone()));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let lane_queues = Arc::new(LaneQueues::new(&config.lane_capacities));
        let dispatcher = Arc::new(FairnessDispatcher::with_config(config.dispatch.clone()));
        let pending_reads = Arc::new(DashMap::new());
        let pending_copy_ranges = Arc::new(DashMap::new());
        let pending_structural = Arc::new(DashMap::new());
        let deadline_heap = Arc::new(DeadlineHeap::new());
        let per_file = Arc::new(PerFileOrdering::new());
        let read_cache = Arc::new(ReadCache::with_config(config.read_cache));
        let in_flight = Arc::new(InFlightReads::new());
        let stats = Arc::new(SchedulerStats::new());
        let pending_writes_by_file = Arc::new(DashMap::new());
        let writes_complete_notify = Arc::new((std::sync::Mutex::new(()), std::sync::Condvar::new()));
        let write_bytes_global = Arc::new(AtomicU64::new(0));
        let write_bytes_by_file = Arc::new(DashMap::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        info!("FUSE scheduler created with lane queues and fairness dispatcher");

        Self {
            executor,
            id_gen: RequestIdGenerator::new(),
            lane_queues,
            dispatcher,
            pending_reads,
            pending_copy_ranges,
            pending_structural,
            deadline_heap,
            handle_table,
            per_file,
            read_cache,
            in_flight,
            stats,
            vault_stats,
            pending_writes_by_file,
            writes_complete_notify,
            write_bytes_global,
            write_bytes_by_file,
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
        let executor = Arc::clone(&self.executor);
        let lane_queues = Arc::clone(&self.lane_queues);
        let fairness_dispatcher = Arc::clone(&self.dispatcher);
        let pending_reads = Arc::clone(&self.pending_reads);
        let pending_copy_ranges = Arc::clone(&self.pending_copy_ranges);
        let pending_structural = Arc::clone(&self.pending_structural);
        let deadline_heap = Arc::clone(&self.deadline_heap);
        let handle_table = Arc::clone(&self.handle_table);
        let per_file = Arc::clone(&self.per_file);
        let read_cache = Arc::clone(&self.read_cache);
        let in_flight = Arc::clone(&self.in_flight);
        let stats = Arc::clone(&self.stats);
        let vault_stats = Arc::clone(&self.vault_stats);
        let pending_writes_by_file = Arc::clone(&self.pending_writes_by_file);
        let writes_complete_notify = Arc::clone(&self.writes_complete_notify);
        let shutdown = Arc::clone(&self.shutdown);
        let result_tx = self.result_tx.clone();

        let handle = thread::Builder::new()
            .name("fuse-scheduler-dispatch".to_string())
            .spawn(move || {
                dispatcher_loop(
                    result_rx,
                    result_tx,
                    executor,
                    lane_queues,
                    fairness_dispatcher,
                    pending_reads,
                    pending_copy_ranges,
                    pending_structural,
                    deadline_heap,
                    handle_table,
                    per_file,
                    read_cache,
                    in_flight,
                    stats,
                    vault_stats,
                    pending_writes_by_file,
                    writes_complete_notify,
                    shutdown,
                );
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
    /// This method implements a multi-tier optimization:
    /// 1. **Cache check** - If data is cached, reply immediately
    /// 2. **Single-flight** - If another read for same data is in-flight, wait for it
    /// 3. **Executor** - Otherwise, submit to executor for async read
    ///
    /// On failure, the scheduler replies with an appropriate error code and
    /// returns `Err`. The reader is consumed and cannot be recovered - the
    /// file handle should be closed or subsequent reads will get EAGAIN.
    ///
    /// # Arguments
    ///
    /// * `ino` - Inode number (for cache key)
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
    #[allow(clippy::too_many_arguments)]
    pub fn try_enqueue_read(
        &self,
        ino: u64,
        fh: u64,
        reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
        offset: u64,
        size: usize,
        reply: ReplyData,
    ) -> Result<RequestId, EnqueueError> {
        if self.shutdown.load(Ordering::Acquire) {
            // Restore reader before returning
            self.restore_reader(fh, reader);
            reply.error(libc::ESHUTDOWN);
            return Err(EnqueueError::Shutdown);
        }

        // 1. Check cache first
        // Cache key includes size to distinguish reads of different sizes at same offset
        let cache_key = ReadCacheKey::new(ino, offset, size);
        if let Some(cached_data) = self.read_cache.get(&cache_key) {
            // Cache hit! Reply immediately with cached data
            // Data should be exact size since cache key includes size
            reply.data(&cached_data);
            // Restore reader since we didn't use it
            self.restore_reader(fh, reader);
            self.stats.record_accept();
            // Record stats for desktop client (cache hit still counts as a read)
            self.vault_stats.record_read(cached_data.len() as u64);
            self.vault_stats.finish_read();
            trace!(ino, fh, offset, size, "Read cache hit");
            return Ok(RequestId::new(0)); // Placeholder ID for cache hits
        }

        // 2. Check single-flight deduplication (if enabled)
        let read_key = ReadKey::new(ino, offset, size);
        if self.config.enable_single_flight {
            match self.in_flight.try_attach(read_key) {
                AttachResult::Waiter(mut rx) => {
                    // Another read for the same data is in-flight, wait for it
                    trace!(ino, fh, offset, size, "Single-flight waiter attached");

                    // Spawn a task to wait for the result and reply
                    // The reader is restored immediately since we won't use it
                    self.restore_reader(fh, reader);

                    // Wait for result with timeout to prevent indefinite hangs
                    // if the leader dies or a bug prevents completion.
                    // Use the read_foreground deadline as the timeout for waiters.
                    let stats = Arc::clone(&self.stats);
                    let vault_stats = Arc::clone(&self.vault_stats);
                    let timeout_duration = self.config.lane_deadlines.read_foreground;
                    thread::spawn(move || {
                        // Create a minimal runtime for the timeout operation
                        let rt = match tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build()
                        {
                            Ok(rt) => rt,
                            Err(e) => {
                                tracing::error!("Failed to create waiter runtime: {}", e);
                                reply.error(libc::EIO);
                                stats.record_timeout();
                                vault_stats.finish_read();
                                vault_stats.record_error();
                                return;
                            }
                        };

                        let result = rt.block_on(async {
                            tokio::time::timeout(timeout_duration, rx.recv()).await
                        });

                        match result {
                            Ok(Ok(Ok(data))) => {
                                let data = if data.len() > size {
                                    &data[..size]
                                } else {
                                    &data[..]
                                };
                                reply.data(data);
                                stats.record_accept();
                                // Record stats for desktop client
                                vault_stats.record_read(data.len() as u64);
                                vault_stats.finish_read();
                            }
                            Ok(Ok(Err(errno))) => {
                                reply.error(errno);
                                stats.record_accept();
                                vault_stats.finish_read();
                                vault_stats.record_error();
                            }
                            Ok(Err(_)) => {
                                // Channel closed / lagged - leader dropped without completing
                                reply.error(libc::EIO);
                                stats.record_accept();
                                vault_stats.finish_read();
                                vault_stats.record_error();
                            }
                            Err(_) => {
                                // Timeout - leader took too long
                                tracing::warn!(ino, offset, size, "Single-flight waiter timed out");
                                reply.error(libc::ETIMEDOUT);
                                stats.record_timeout();
                                vault_stats.finish_read();
                                vault_stats.record_error();
                            }
                        }
                    });

                    return Ok(RequestId::new(0)); // Placeholder for waiters
                }
                AttachResult::Leader => {
                    // We're the leader, proceed to executor
                    trace!(ino, fh, offset, size, "Single-flight leader");
                }
            }
        }

        // 3. Enqueue to lane queue (either single-flight disabled or we're the leader)
        let request_id = self.id_gen.next();
        let lane = classify_read(size);
        let deadline = Instant::now() + self.config.lane_deadlines.get(lane);

        // Create queued job
        let queued_job = QueuedJob::Read(QueuedReadJob {
            fh,
            reader,
            offset,
            size,
            deadline,
        });

        // Try to enqueue to lane queue
        if let Err((e, rejected_job)) = self.lane_queues.try_enqueue(lane, request_id, queued_job) {
            // Queue is full - reject request but restore the reader first
            // Extract reader from the rejected job and restore it to handle table
            if let QueuedJob::Read(read_job) = rejected_job {
                self.restore_reader(fh, read_job.reader);
            }
            if self.config.enable_single_flight {
                self.in_flight.cancel(&read_key);
            }
            self.stats.record_reject(lane as usize);
            reply.error(libc::EAGAIN);
            debug!(?request_id, ?lane, "Lane queue full: {}", e);
            return Err(EnqueueError::QueueFull);
        }

        // Insert into deadline heap for timeout tracking
        // Note: generation=0 since we don't track individual heap entries for queued requests
        // The dispatcher will update this when it submits to executor
        let state = Arc::new(RequestState::new());

        // Store pending read with cache info for completion handler
        self.pending_reads.insert(
            request_id,
            PendingRead {
                ino,
                read_key: if self.config.enable_single_flight { Some(read_key) } else { None },
                lane,
                reply,
                state,
                generation: 0, // Will be set by dispatcher when submitted to executor
            },
        );

        self.stats.record_accept();
        trace!(?request_id, fh, offset, size, ?lane, "Read request enqueued to lane queue");

        Ok(request_id)
    }

    /// Restore a reader to the handle table.
    fn restore_reader(&self, fh: u64, reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>) {
        if let Some(mut handle) = self.handle_table.get_mut(&fh) {
            if matches!(*handle, FuseHandle::ReaderLoaned) {
                *handle = FuseHandle::Reader(reader);
            }
        }
    }

    /// Try to enqueue a copy_file_range request (source read portion).
    ///
    /// The executor reads from the source, then the dispatcher writes to the
    /// destination and replies. This allows the FUSE callback to return immediately.
    ///
    /// # Arguments
    ///
    /// * `fh_in` - Source file handle ID
    /// * `reader` - The VaultFileReader to read from (ownership transferred)
    /// * `offset_in` - Source byte offset
    /// * `fh_out` - Destination file handle ID
    /// * `ino_out` - Destination inode (for cache invalidation)
    /// * `offset_out` - Destination byte offset
    /// * `len` - Number of bytes to copy
    /// * `reply` - FUSE reply handle (ownership transferred)
    ///
    /// # Returns
    ///
    /// - `Ok(request_id)` - Request enqueued, scheduler will complete and reply
    /// - `Err(EnqueueError)` - Failed, scheduler already replied with error
    #[allow(clippy::too_many_arguments)]
    pub fn try_enqueue_copy_range(
        &self,
        fh_in: u64,
        reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
        offset_in: u64,
        fh_out: u64,
        ino_out: u64,
        offset_out: u64,
        len: usize,
        reply: ReplyWrite,
    ) -> Result<RequestId, EnqueueError> {
        if self.shutdown.load(Ordering::Acquire) {
            reply.error(libc::ESHUTDOWN);
            return Err(EnqueueError::Shutdown);
        }

        let request_id = self.id_gen.next();
        // copy_file_range is classified as L3 WriteStructural
        let lane = Lane::WriteStructural;
        let deadline = Instant::now() + self.config.lane_deadlines.get(lane);

        // Create queued job
        let queued_job = QueuedJob::CopyRange(QueuedCopyRangeJob {
            fh_in,
            reader,
            offset_in,
            fh_out,
            ino_out,
            offset_out,
            len,
            deadline,
        });

        // Try to enqueue to lane queue
        if let Err((e, rejected_job)) = self.lane_queues.try_enqueue(lane, request_id, queued_job) {
            // Queue is full - reject request but restore the reader first
            // Extract reader from the rejected job and restore it to handle table
            if let QueuedJob::CopyRange(copy_job) = rejected_job {
                self.restore_reader(fh_in, copy_job.reader);
            }
            self.stats.record_reject(lane as usize);
            reply.error(libc::EAGAIN);
            debug!(?request_id, ?lane, "Lane queue full: {}", e);
            return Err(EnqueueError::QueueFull);
        }

        // Track pending write for barrier semantics
        // flush/fsync on ino_out will wait for this to complete
        self.pending_writes_by_file
            .entry(ino_out)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Release);

        let state = Arc::new(RequestState::new());

        // Store pending copy range with destination info
        self.pending_copy_ranges.insert(
            request_id,
            PendingCopyRange {
                fh_out,
                ino_out,
                offset_out,
                lane,
                reply,
                state,
                generation: 0, // Will be set by dispatcher when submitted to executor
            },
        );

        self.stats.record_accept();
        trace!(
            ?request_id,
            fh_in,
            fh_out,
            offset_in,
            offset_out,
            len,
            "copy_file_range request enqueued to lane queue"
        );

        Ok(request_id)
    }

    /// Try to enqueue a structural operation.
    ///
    /// Structural operations (unlink, rmdir, mkdir, create, rename, setattr, symlink, link)
    /// are serialized per-file using per-file ordering to prevent race conditions.
    ///
    /// # Arguments
    ///
    /// * `op` - The structural operation to perform
    /// * `ops` - Vault operations for executing the operation
    /// * `reply` - FUSE reply handle (ownership transferred)
    ///
    /// # Returns
    ///
    /// - `Ok(request_id)` - Request enqueued, scheduler will reply asynchronously
    /// - `Err(EnqueueError)` - Failed, scheduler already replied with error
    pub fn try_enqueue_structural(
        &self,
        op: StructuralOp,
        ops: Arc<oxcrypt_core::vault::VaultOperationsAsync>,
        reply: StructuralReply,
    ) -> Result<RequestId, EnqueueError> {
        if self.shutdown.load(Ordering::Acquire) {
            reply.error(libc::ESHUTDOWN);
            return Err(EnqueueError::Shutdown);
        }

        let request_id = self.id_gen.next();
        // Structural operations go to L3 WriteStructural lane
        let lane = Lane::WriteStructural;
        let deadline = Instant::now() + self.config.lane_deadlines.get(lane);

        // Check per-file ordering for all affected inodes
        // Structural ops must wait for prior ops on the same file to complete
        let affected_inodes = op.affected_inodes();
        for ino in &affected_inodes {
            match self.per_file.try_start(*ino, request_id) {
                Ok(None) => {
                    // Can proceed immediately
                    trace!(?request_id, ino, op = op.name(), "Per-file ordering: proceeding immediately");
                }
                Ok(Some(_rx)) => {
                    // Must wait - the queue will handle serialization
                    // Note: we don't actually wait here because the lane queue handles ordering
                    trace!(?request_id, ino, op = op.name(), "Per-file ordering: queuing behind prior op");
                }
                Err(errno) => {
                    // Prior operation failed - propagate error
                    debug!(?request_id, ino, errno, op = op.name(), "Per-file ordering: prior op failed");
                    reply.error(errno);
                    return Err(EnqueueError::PriorOpFailed { errno });
                }
            }
        }

        // Create queued job
        let queued_job = QueuedJob::Structural(QueuedStructuralJob {
            op: op.clone(),
            ops,
            deadline,
        });

        // Try to enqueue to lane queue
        if let Err((e, _rejected_job)) = self.lane_queues.try_enqueue(lane, request_id, queued_job) {
            // Queue is full - reject request
            // Release per-file ordering since we didn't actually start
            for ino in &affected_inodes {
                self.per_file.complete(*ino, None);
            }
            self.stats.record_reject(lane as usize);
            reply.error(libc::EAGAIN);
            debug!(?request_id, ?lane, "Lane queue full for structural op: {}", e);
            return Err(EnqueueError::QueueFull);
        }

        let state = Arc::new(RequestState::new());

        // Store pending structural request
        self.pending_structural.insert(
            request_id,
            PendingStructural {
                op,
                lane,
                reply,
                state,
                generation: 0, // Will be set by dispatcher when submitted to executor
            },
        );

        self.stats.record_accept();
        trace!(
            ?request_id,
            op_name = self.pending_structural.get(&request_id).map(|p| p.op.name()).unwrap_or("unknown"),
            ?lane,
            "Structural request enqueued to lane queue"
        );

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

    /// Get the per-file ordering manager.
    ///
    /// Used for serializing structural operations on the same file
    /// and implementing barrier semantics for flush/fsync.
    pub fn per_file(&self) -> &Arc<PerFileOrdering> {
        &self.per_file
    }

    /// Wait for all pending async write operations to a file to complete.
    ///
    /// This is a barrier operation that blocks until there are no pending
    /// copy_file_range operations targeting the specified inode. Use this
    /// in `flush` and `fsync` to ensure all async writes are visible before
    /// flushing to disk.
    ///
    /// # Arguments
    ///
    /// * `ino` - The destination inode to wait for
    /// * `timeout` - Maximum time to wait before returning
    ///
    /// # Returns
    ///
    /// * `true` if all pending writes completed within timeout
    /// * `false` if timeout expired with writes still pending
    pub fn wait_pending_writes(&self, ino: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, condvar) = &*self.writes_complete_notify;

        // Check if there are pending writes for this file
        while self
            .pending_writes_by_file
            .get(&ino)
            .map(|c| c.load(Ordering::Acquire) > 0)
            .unwrap_or(false)
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(ino, "Timeout waiting for pending writes");
                return false;
            }

            // Wait on the condvar with timeout - will be notified when any write completes
            let guard = lock.lock().unwrap();
            let _result = condvar.wait_timeout(guard, remaining).unwrap();
            // Loop back to re-check if our specific file's pending writes are done
        }

        true
    }

    /// Check if there are pending writes to a file.
    pub fn has_pending_writes(&self, ino: u64) -> bool {
        self.pending_writes_by_file
            .get(&ino)
            .map(|c| c.load(Ordering::Acquire) > 0)
            .unwrap_or(false)
    }

    /// Check if a write of the given size would exceed the budget.
    ///
    /// Returns `Ok(())` if the write is within budget, or `Err(())` if it would
    /// exceed either the global or per-file budget.
    ///
    /// # Arguments
    ///
    /// * `ino` - Inode of the file being written to
    /// * `size` - Number of bytes to be written
    pub fn check_write_budget(&self, ino: u64, size: u64) -> Result<(), ()> {
        // Check global budget
        let current_global = self.write_bytes_global.load(Ordering::Acquire);
        if current_global.saturating_add(size) > self.config.write_budget_global {
            debug!(
                ino,
                size,
                current_global,
                budget = self.config.write_budget_global,
                "Write would exceed global budget"
            );
            return Err(());
        }

        // Check per-file budget
        let current_file = self
            .write_bytes_by_file
            .get(&ino)
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0);
        if current_file.saturating_add(size) > self.config.write_budget_per_file {
            debug!(
                ino,
                size,
                current_file,
                budget = self.config.write_budget_per_file,
                "Write would exceed per-file budget"
            );
            return Err(());
        }

        Ok(())
    }

    /// Record bytes added to a write buffer.
    ///
    /// Call this after a successful write to track buffer usage for budget enforcement.
    pub fn add_write_bytes(&self, ino: u64, size: u64) {
        self.write_bytes_global.fetch_add(size, Ordering::Release);
        self.write_bytes_by_file
            .entry(ino)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(size, Ordering::Release);
    }

    /// Release bytes from a write buffer.
    ///
    /// Call this when a write buffer is flushed to the vault, releasing the budget.
    #[allow(dead_code)] // May be used for partial releases in the future
    pub fn release_write_bytes(&self, ino: u64, size: u64) {
        self.write_bytes_global.fetch_sub(size, Ordering::Release);
        if let Some(counter) = self.write_bytes_by_file.get(&ino) {
            let old_value = counter.fetch_sub(size, Ordering::Release);
            // Clean up entry if it reaches zero to prevent unbounded DashMap growth
            if old_value == size {
                // Value was exactly `size`, now 0 - try to remove entry
                // Use remove_if to handle race with concurrent adds
                self.write_bytes_by_file.remove_if(&ino, |_, c| {
                    c.load(Ordering::Acquire) == 0
                });
            }
        }
    }

    /// Release all tracked write bytes for a file.
    ///
    /// This releases exactly the amount that was tracked via `add_write_bytes`,
    /// preventing budget counter underflow. Use this after flushing a write buffer
    /// instead of `release_write_bytes(ino, content_len)` which could underflow
    /// if the buffer was partially flushed before.
    ///
    /// Returns the number of bytes that were released.
    pub fn release_all_file_write_bytes(&self, ino: u64) -> u64 {
        // Remove the per-file counter and get its value
        let file_bytes = self
            .write_bytes_by_file
            .remove(&ino)
            .map(|(_, counter)| counter.load(Ordering::Acquire))
            .unwrap_or(0);

        // Subtract from global counter (only what was actually tracked)
        if file_bytes > 0 {
            self.write_bytes_global.fetch_sub(file_bytes, Ordering::Release);
        }

        file_bytes
    }

    /// Get current global write bytes.
    pub fn global_write_bytes(&self) -> u64 {
        self.write_bytes_global.load(Ordering::Relaxed)
    }

    /// Get current write bytes for a file.
    pub fn file_write_bytes(&self, ino: u64) -> u64 {
        self.write_bytes_by_file
            .get(&ino)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get scheduler statistics.
    pub fn stats(&self) -> &Arc<SchedulerStats> {
        &self.stats
    }

    /// Get a complete snapshot of all scheduler metrics.
    ///
    /// This aggregates stats from all scheduler components into a single view.
    pub fn snapshot(&self) -> SchedulerSnapshot {
        let cache_stats = self.read_cache.stats();

        SchedulerSnapshot::from_components(
            &self.stats,
            self.executor.stats(),
            cache_stats.hits.load(Ordering::Relaxed),
            cache_stats.misses.load(Ordering::Relaxed),
            self.read_cache.entry_count(),
            self.read_cache.weighted_size(),
            self.in_flight.stats(),
            self.per_file.stats(),
        )
    }

    /// Create a stats collector that can produce snapshots after the scheduler is moved.
    ///
    /// This returns a `SchedulerStatsCollector` that holds Arc references to all stats
    /// components. It can be extracted before spawning the FUSE session and used to
    /// produce snapshots later without needing access to the scheduler.
    pub fn stats_collector(&self) -> SchedulerStatsCollector {
        SchedulerStatsCollector {
            stats: Arc::clone(&self.stats),
            executor: Arc::clone(&self.executor),
            read_cache: Arc::clone(&self.read_cache),
            in_flight: Arc::clone(&self.in_flight),
            per_file: Arc::clone(&self.per_file),
        }
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
/// This loop:
/// 1. Uses fairness dispatch to dequeue jobs from lane queues
/// 2. Submits dequeued jobs to the executor
/// 3. Processes completed results and issues FUSE replies
/// 4. Handles timeouts via deadline heap
/// 5. Inserts successful reads into cache and notifies single-flight waiters
#[allow(clippy::needless_pass_by_value)] // Arc parameters are idiomatic for thread entry points
#[allow(clippy::too_many_arguments)]
fn dispatcher_loop(
    rx: std::sync::mpsc::Receiver<(RequestId, oneshot::Receiver<ExecutorResult>)>,
    result_tx: std::sync::mpsc::Sender<(RequestId, oneshot::Receiver<ExecutorResult>)>,
    executor: Arc<FsSyscallExecutor>,
    lane_queues: Arc<LaneQueues<QueuedJob>>,
    fairness_dispatcher: Arc<FairnessDispatcher>,
    pending_reads: Arc<DashMap<RequestId, PendingRead>>,
    pending_copy_ranges: Arc<DashMap<RequestId, PendingCopyRange>>,
    pending_structural: Arc<DashMap<RequestId, PendingStructural>>,
    deadline_heap: Arc<DeadlineHeap>,
    handle_table: Arc<FuseHandleTable>,
    per_file: Arc<PerFileOrdering>,
    read_cache: Arc<ReadCache>,
    in_flight: Arc<InFlightReads>,
    stats: Arc<SchedulerStats>,
    vault_stats: Arc<VaultStats>,
    pending_writes_by_file: Arc<DashMap<u64, AtomicU64>>,
    writes_complete_notify: Arc<(std::sync::Mutex<()>, std::sync::Condvar)>,
    shutdown: Arc<AtomicBool>,
) {
    debug!("Dispatcher loop started with fairness dispatch");

    // We need to poll multiple oneshot receivers. Use a simple approach:
    // collect receivers and poll them in rounds.
    let mut receivers: Vec<(RequestId, oneshot::Receiver<ExecutorResult>)> = Vec::new();

    loop {
        let is_shutdown = shutdown.load(Ordering::Acquire);
        let queues_empty = lane_queues.total_stats().total_depth == 0;

        if is_shutdown && receivers.is_empty() && queues_empty {
            debug!("Dispatcher shutting down");
            break;
        }

        // Process expired deadlines from heap (efficient O(log n) per expiration)
        for (request_id, generation) in deadline_heap.pop_expired() {
            // Check pending reads first
            if let Some(pending) = pending_reads.get(&request_id) {
                if pending.generation == generation && pending.state.claim_reply() {
                    let lane_index = pending.lane as usize;
                    warn!(?request_id, "Read request timed out");
                    drop(pending);
                    if let Some((_, pending)) = pending_reads.remove(&request_id) {
                        pending.reply.error(libc::ETIMEDOUT);
                        // Decrement in-flight counter for this lane
                        stats.dec_in_flight(lane_index);
                        stats.record_timeout();
                        // Cancel single-flight if we were leader
                        if let Some(key) = pending.read_key {
                            in_flight.cancel(&key);
                        }
                    }
                }
                continue;
            }

            // Check pending copy ranges
            if let Some(pending) = pending_copy_ranges.get(&request_id) {
                if pending.generation == generation && pending.state.claim_reply() {
                    let lane_index = pending.lane as usize;
                    let ino_out = pending.ino_out;
                    warn!(?request_id, "copy_file_range request timed out");
                    drop(pending);
                    if let Some((_, pending)) = pending_copy_ranges.remove(&request_id) {
                        pending.reply.error(libc::ETIMEDOUT);
                        // Decrement in-flight counter for this lane
                        stats.dec_in_flight(lane_index);
                        stats.record_timeout();
                        // Decrement pending writes counter for barrier semantics
                        // and clean up entry if it reaches zero to prevent unbounded DashMap growth
                        if let Some(counter) = pending_writes_by_file.get(&ino_out) {
                            if counter.fetch_sub(1, Ordering::Release) == 1 {
                                // Was 1, now 0 - try to remove entry to prevent memory leak
                                // Use remove_if to handle race with concurrent inserts
                                pending_writes_by_file.remove_if(&ino_out, |_, c| {
                                    c.load(Ordering::Acquire) == 0
                                });
                            }
                        }
                        // Notify any waiters that a write completed
                        writes_complete_notify.1.notify_all();
                    }
                }
                continue;
            }

            // Check pending structural ops
            if let Some(pending) = pending_structural.get(&request_id) {
                if pending.generation == generation && pending.state.claim_reply() {
                    let lane_index = pending.lane as usize;
                    let affected_inodes = pending.op.affected_inodes();
                    warn!(?request_id, op = pending.op.name(), "Structural request timed out");
                    drop(pending);
                    if let Some((_, pending)) = pending_structural.remove(&request_id) {
                        pending.reply.error(libc::ETIMEDOUT);
                        // Decrement in-flight counter for this lane
                        stats.dec_in_flight(lane_index);
                        stats.record_timeout();
                        // Release per-file ordering for all affected inodes
                        for ino in affected_inodes {
                            per_file.complete(ino, Some(libc::ETIMEDOUT));
                        }
                    }
                }
            }
            // If not found in any map, entry is stale (already completed)
        }

        // === FAIRNESS DISPATCH: Dequeue from lane queues and submit to executor ===
        if !is_shutdown {
            // Build in-flight counts for fairness decision
            let in_flight_counts = [
                stats.in_flight_by_lane[0].load(Ordering::Relaxed),
                stats.in_flight_by_lane[1].load(Ordering::Relaxed),
                stats.in_flight_by_lane[2].load(Ordering::Relaxed),
                stats.in_flight_by_lane[3].load(Ordering::Relaxed),
                stats.in_flight_by_lane[4].load(Ordering::Relaxed),
            ];

            // Calculate free executor slots based on queue depth
            // The executor has a bounded queue, so free slots = max capacity - current depth
            let executor_queue_depth = executor.queue_depth();
            // Default executor capacity is 16 threads, estimate free slots conservatively
            let estimated_free_slots = 16usize.saturating_sub(executor_queue_depth as usize);

            // Try to dispatch jobs from lane queues using fairness policy
            // Dispatch multiple jobs per iteration to improve throughput
            for _ in 0..4 {
                if let Some(queued) = fairness_dispatcher.try_dispatch(&lane_queues, &in_flight_counts, estimated_free_slots) {
                    let request_id = queued.id;
                    let lane = queued.lane;

                    match queued.data {
                        QueuedJob::Read(job) => {
                            dispatch_read_job(
                                request_id,
                                job,
                                lane,
                                &executor,
                                &deadline_heap,
                                &pending_reads,
                                &stats,
                                &in_flight,
                                &result_tx,
                            );
                        }
                        QueuedJob::CopyRange(job) => {
                            dispatch_copy_range_job(
                                request_id,
                                job,
                                lane,
                                &executor,
                                &deadline_heap,
                                &pending_copy_ranges,
                                &stats,
                                &result_tx,
                            );
                        }
                        QueuedJob::Structural(job) => {
                            dispatch_structural_job(
                                request_id,
                                job,
                                lane,
                                &executor,
                                &deadline_heap,
                                &pending_structural,
                                &per_file,
                                &stats,
                                &result_tx,
                            );
                        }
                    }
                } else {
                    // No more jobs to dispatch
                    break;
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

            // Check if this is a pending read
            if let Some((_, pending)) = pending_reads.remove(&request_id) {
                let lane_index = pending.lane as usize;
                if pending.state.claim_reply() {
                    handle_read_completion(
                        request_id,
                        result,
                        pending.ino,
                        pending.read_key,
                        pending.reply,
                        &handle_table,
                        &read_cache,
                        &in_flight,
                        &stats,
                        &vault_stats,
                    );
                    // Decrement in-flight counter for this lane
                    stats.dec_in_flight(lane_index);
                } else {
                    trace!(?request_id, "Read reply already claimed (timeout race)");
                    // Cancel single-flight if we were leader
                    if let Some(key) = pending.read_key {
                        in_flight.cancel(&key);
                    }
                    stats.record_late_completion();
                    // Note: in-flight was already decremented by timeout handler
                }
                continue;
            }

            // Check if this is a pending copy range
            if let Some((_, pending)) = pending_copy_ranges.remove(&request_id) {
                let lane_index = pending.lane as usize;
                let ino_out = pending.ino_out;
                if pending.state.claim_reply() {
                    handle_copy_range_completion(
                        request_id,
                        result,
                        pending,
                        &handle_table,
                    );
                    // Decrement in-flight counter for this lane
                    stats.dec_in_flight(lane_index);
                    // Decrement pending writes counter for barrier semantics
                    // and clean up entry if it reaches zero to prevent unbounded DashMap growth
                    if let Some(counter) = pending_writes_by_file.get(&ino_out) {
                        if counter.fetch_sub(1, Ordering::Release) == 1 {
                            // Was 1, now 0 - try to remove entry to prevent memory leak
                            // Use remove_if to handle race with concurrent inserts
                            pending_writes_by_file.remove_if(&ino_out, |_, c| {
                                c.load(Ordering::Acquire) == 0
                            });
                        }
                    }
                    // Notify any waiters that a write completed
                    writes_complete_notify.1.notify_all();
                } else {
                    trace!(?request_id, "copy_file_range reply already claimed (timeout race)");
                    stats.record_late_completion();
                    // Note: in-flight and pending_writes were already decremented by timeout handler
                }
                continue;
            }

            // Check if this is a pending structural op
            if let Some((_, pending)) = pending_structural.remove(&request_id) {
                let lane_index = pending.lane as usize;
                let affected_inodes = pending.op.affected_inodes();
                if pending.state.claim_reply() {
                    handle_structural_completion(
                        request_id,
                        result,
                        pending,
                        &per_file,
                    );
                    // Decrement in-flight counter for this lane
                    stats.dec_in_flight(lane_index);
                } else {
                    trace!(?request_id, "Structural reply already claimed (timeout race)");
                    stats.record_late_completion();
                    // Note: in-flight and per-file were already handled by timeout handler
                }
                // Release per-file ordering for all affected inodes
                // Note: this is done even on late completion to ensure cleanup
                for ino in affected_inodes {
                    per_file.complete(ino, None);
                }
            }
        }

        // Periodically compact the deadline heap to remove stale entries
        // Only compact when heap is large enough to matter and is mostly stale
        let heap_len = deadline_heap.len();
        if heap_len > 1000 {
            // Count how many pending requests we actually have
            let pending_count = pending_reads.len() + pending_copy_ranges.len() + pending_structural.len();
            // If heap has more than 2x the number of pending requests, it has many stale entries
            if heap_len > pending_count * 2 {
                let removed = deadline_heap.compact(|request_id, _generation| {
                    pending_reads.contains_key(&request_id)
                        || pending_copy_ranges.contains_key(&request_id)
                        || pending_structural.contains_key(&request_id)
                });
                if removed > 0 {
                    trace!(removed, heap_len, pending_count, "Compacted deadline heap");
                }
            }
        }

        // Small sleep to avoid busy-waiting
        // Sleep less if there are jobs in queues to dispatch
        if !queues_empty {
            thread::sleep(Duration::from_micros(50));
        } else if receivers.is_empty() {
            thread::sleep(Duration::from_millis(10));
        } else {
            thread::sleep(Duration::from_micros(100));
        }
    }

    // Drain any remaining queued jobs and restore readers to handle table.
    // These jobs haven't been dispatched yet, so we still have the readers.
    let queued_jobs = lane_queues.drain_all();
    for queued in queued_jobs {
        match queued.data {
            QueuedJob::Read(job) => {
                // Restore reader to handle table so file can still be used
                if let Some(mut handle) = handle_table.get_mut(&job.fh) {
                    if matches!(*handle, FuseHandle::ReaderLoaned) {
                        *handle = FuseHandle::Reader(job.reader);
                    }
                }
                warn!(request_id = ?queued.id, fh = job.fh, "Dropped queued read job on shutdown");
            }
            QueuedJob::CopyRange(job) => {
                // Restore reader to handle table
                if let Some(mut handle) = handle_table.get_mut(&job.fh_in) {
                    if matches!(*handle, FuseHandle::ReaderLoaned) {
                        *handle = FuseHandle::Reader(job.reader);
                    }
                }
                warn!(request_id = ?queued.id, "Dropped queued copy_file_range job on shutdown");
            }
            QueuedJob::Structural(_job) => {
                // Structural jobs don't hold readers, nothing to restore
                warn!(request_id = ?queued.id, "Dropped queued structural job on shutdown");
            }
        }
    }

    // Reply to any remaining pending requests with shutdown error.
    // We must actually call reply.error() to prevent hung processes waiting for replies.
    // Collect keys first to avoid borrow issues, then remove and reply.
    //
    // Note: The reader is currently in the executor worker thread for pending reads,
    // so we can't restore it here. The executor will complete and the reader will
    // be returned, but we claim the reply here so the completion handler doesn't
    // double-reply. The handle will be in ReaderLoaned state until the file is closed.
    let pending_read_keys: Vec<_> = pending_reads.iter().map(|e| *e.key()).collect();
    for request_id in pending_read_keys {
        if let Some((_, pending)) = pending_reads.remove(&request_id) {
            if pending.state.claim_reply() {
                warn!(?request_id, "Replying ESHUTDOWN to pending read");
                pending.reply.error(libc::ESHUTDOWN);
            }
        }
    }

    let pending_copy_keys: Vec<_> = pending_copy_ranges.iter().map(|e| *e.key()).collect();
    for request_id in pending_copy_keys {
        if let Some((_, pending)) = pending_copy_ranges.remove(&request_id) {
            if pending.state.claim_reply() {
                warn!(?request_id, "Replying ESHUTDOWN to pending copy_file_range");
                pending.reply.error(libc::ESHUTDOWN);
            }
        }
    }

    let pending_structural_keys: Vec<_> = pending_structural.iter().map(|e| *e.key()).collect();
    for request_id in pending_structural_keys {
        if let Some((_, pending)) = pending_structural.remove(&request_id)
            && pending.state.claim_reply()
        {
            warn!(?request_id, op = pending.op.name(), "Replying ESHUTDOWN to pending structural op");
            pending.reply.error(libc::ESHUTDOWN);
            // Release per-file ordering
            for ino in pending.op.affected_inodes() {
                per_file.complete(ino, Some(libc::ESHUTDOWN));
            }
        }
    }

    debug!("Dispatcher loop exited");
}

/// Dispatch a read job to the executor.
#[allow(clippy::too_many_arguments)]
fn dispatch_read_job(
    request_id: RequestId,
    job: QueuedReadJob,
    lane: Lane,
    executor: &FsSyscallExecutor,
    deadline_heap: &DeadlineHeap,
    pending_reads: &DashMap<RequestId, PendingRead>,
    stats: &SchedulerStats,
    in_flight: &InFlightReads,
    result_tx: &std::sync::mpsc::Sender<(RequestId, oneshot::Receiver<ExecutorResult>)>,
) {
    // Create oneshot for result
    let (tx, rx) = oneshot::channel();

    // Create executor job
    let executor_job = ExecutorJob {
        request_id,
        fh: job.fh,
        operation: ExecutorOperation::Read {
            reader: job.reader,
            offset: job.offset,
            size: job.size,
        },
        result_tx: tx,
        deadline: job.deadline,
    };

    // Increment in-flight count before submission
    stats.inc_in_flight(lane as usize);

    // Submit to executor
    if let Err(e) = executor.try_submit(executor_job) {
        // Submission failed - reply with error
        warn!(?request_id, "Executor rejected read job: {}", e);
        stats.dec_in_flight(lane as usize);

        // Get the pending read and reply with error
        if let Some((_, pending)) = pending_reads.remove(&request_id) {
            if pending.state.claim_reply() {
                pending.reply.error(libc::EAGAIN);
                // Cancel single-flight if we were leader
                if let Some(key) = pending.read_key {
                    in_flight.cancel(&key);
                }
            }
        }
        return;
    }

    // Insert into deadline heap for timeout tracking
    let generation = deadline_heap.insert(request_id, job.deadline);

    // Update pending read with proper generation
    if let Some(mut pending) = pending_reads.get_mut(&request_id) {
        pending.generation = generation;
    }

    // Send result receiver to self for tracking
    if result_tx.send((request_id, rx)).is_err() {
        warn!(?request_id, "Failed to send result receiver - dispatcher shutting down");
    }

    trace!(?request_id, ?lane, "Read job dispatched to executor");
}

/// Dispatch a copy_file_range job to the executor.
#[allow(clippy::too_many_arguments)]
fn dispatch_copy_range_job(
    request_id: RequestId,
    job: QueuedCopyRangeJob,
    lane: Lane,
    executor: &FsSyscallExecutor,
    deadline_heap: &DeadlineHeap,
    pending_copy_ranges: &DashMap<RequestId, PendingCopyRange>,
    stats: &SchedulerStats,
    result_tx: &std::sync::mpsc::Sender<(RequestId, oneshot::Receiver<ExecutorResult>)>,
) {
    // Create oneshot for result
    let (tx, rx) = oneshot::channel();

    // Create executor job (read from source)
    let executor_job = ExecutorJob {
        request_id,
        fh: job.fh_in,
        operation: ExecutorOperation::Read {
            reader: job.reader,
            offset: job.offset_in,
            size: job.len,
        },
        result_tx: tx,
        deadline: job.deadline,
    };

    // Increment in-flight count before submission
    stats.inc_in_flight(lane as usize);

    // Submit to executor
    if let Err(e) = executor.try_submit(executor_job) {
        // Submission failed - reply with error
        warn!(?request_id, "Executor rejected copy_file_range job: {}", e);
        stats.dec_in_flight(lane as usize);

        // Get the pending copy range and reply with error
        if let Some((_, pending)) = pending_copy_ranges.remove(&request_id) {
            if pending.state.claim_reply() {
                pending.reply.error(libc::EAGAIN);
            }
        }
        return;
    }

    // Insert into deadline heap for timeout tracking
    let generation = deadline_heap.insert(request_id, job.deadline);

    // Update pending copy range with proper generation
    if let Some(mut pending) = pending_copy_ranges.get_mut(&request_id) {
        pending.generation = generation;
    }

    // Send result receiver to self for tracking
    if result_tx.send((request_id, rx)).is_err() {
        warn!(?request_id, "Failed to send result receiver - dispatcher shutting down");
    }

    trace!(?request_id, ?lane, "copy_file_range job dispatched to executor");
}

/// Handle completion of a read request.
///
/// On success:
/// - Inserts data into cache for future reads
/// - Notifies single-flight waiters with the data
/// - Issues FUSE reply
/// - Restores reader to handle table
/// - Records stats to vault_stats for desktop client
#[allow(clippy::too_many_arguments)]
fn handle_read_completion(
    request_id: RequestId,
    result: Option<ExecutorResult>,
    ino: u64,
    read_key: Option<ReadKey>,
    reply: ReplyData,
    handle_table: &FuseHandleTable,
    read_cache: &ReadCache,
    in_flight: &InFlightReads,
    _stats: &SchedulerStats,
    vault_stats: &VaultStats,
) {
    match result {
        Some(ExecutorResult::Read(read_result)) => {
            let fh = read_result.fh;
            let reader = read_result.reader;
            let offset = read_result.offset;

            // Handle the read result
            match read_result.result {
                Ok(data) => {
                    let bytes_read = data.len() as u64;
                    trace!(?request_id, bytes = bytes_read, "Replying with data");

                    // Record stats for desktop client
                    vault_stats.record_read(bytes_read);
                    vault_stats.finish_read();

                    // Insert into cache with size from the actual data
                    // Cache key includes size to distinguish reads of different sizes
                    let cache_key = ReadCacheKey::new(ino, offset, data.len());
                    read_cache.insert(cache_key, data.clone());

                    // Notify single-flight waiters
                    if let Some(key) = read_key {
                        in_flight.complete(&key, Ok(data.clone()));
                    }

                    // Issue FUSE reply
                    reply.data(&data);
                }
                Err(errno) => {
                    trace!(?request_id, errno, "Replying with error");

                    // Record stats even on error (operation completed, just failed)
                    vault_stats.finish_read();
                    vault_stats.record_error();

                    // Notify single-flight waiters of error
                    if let Some(key) = read_key {
                        in_flight.complete(&key, Err(errno));
                    }

                    reply.error(errno);
                }
            }

            // Restore reader to handle table
            if let Some(mut handle) = handle_table.get_mut(&fh) {
                if matches!(*handle, FuseHandle::ReaderLoaned) {
                    *handle = FuseHandle::Reader(reader);
                    trace!(?request_id, fh, "Reader restored to handle table");
                } else {
                    warn!(
                        ?request_id,
                        fh,
                        "Handle modified during async read, discarding reader"
                    );
                }
            } else {
                trace!(
                    ?request_id,
                    fh,
                    "Handle removed during async read, discarding reader"
                );
            }
        }
        Some(ExecutorResult::Structural(_)) => {
            // Structural operations should not be sent to handle_read_completion
            unreachable!("Structural result in read completion handler");
        }
        None => {
            trace!(?request_id, "Replying with EIO (sender dropped)");

            // Record stats for error case
            vault_stats.finish_read();
            vault_stats.record_error();

            // Notify single-flight waiters of error
            if let Some(key) = read_key {
                in_flight.complete(&key, Err(libc::EIO));
            }

            reply.error(libc::EIO);
        }
    }
}

/// Handle completion of a copy_file_range request.
///
/// Writes the read data to the destination buffer and replies with bytes written.
fn handle_copy_range_completion(
    request_id: RequestId,
    result: Option<ExecutorResult>,
    pending: PendingCopyRange,
    handle_table: &FuseHandleTable,
) {
    match result {
        Some(ExecutorResult::Read(read_result)) => {
            let fh_in = read_result.fh;
            let reader = read_result.reader;

            match read_result.result {
                Ok(data) => {
                    // Write to destination buffer
                    let bytes_written = {
                        let Some(mut handle) = handle_table.get_mut(&pending.fh_out) else {
                            // Destination handle was closed during async operation
                            warn!(
                                ?request_id,
                                fh_out = pending.fh_out,
                                "Destination handle closed during copy_file_range"
                            );
                            pending.reply.error(libc::EBADF);
                            // Still restore the source reader
                            restore_reader(request_id, fh_in, reader, handle_table);
                            return;
                        };

                        let Some(buffer) = handle.as_write_buffer_mut() else {
                            warn!(
                                ?request_id,
                                fh_out = pending.fh_out,
                                "Destination not opened for writing"
                            );
                            pending.reply.error(libc::EBADF);
                            drop(handle);
                            restore_reader(request_id, fh_in, reader, handle_table);
                            return;
                        };

                        buffer.write(pending.offset_out, &data)
                    };

                    trace!(
                        ?request_id,
                        bytes_written,
                        "copy_file_range completed"
                    );

                    // Reply with bytes written
                    // bytes_written is from WriteBuffer::write which returns usize
                    // FUSE expects u32, but practical file ops fit in u32
                    #[allow(clippy::cast_possible_truncation)]
                    pending.reply.written(bytes_written as u32);

                    // Restore source reader
                    restore_reader(request_id, fh_in, reader, handle_table);
                }
                Err(errno) => {
                    trace!(?request_id, errno, "copy_file_range read failed");
                    pending.reply.error(errno);
                    // Still restore the source reader
                    restore_reader(request_id, fh_in, reader, handle_table);
                }
            }
        }
        Some(ExecutorResult::Structural(_)) => {
            // Structural operations should not be sent to handle_copy_range_completion
            unreachable!("Structural result in copy_file_range completion handler");
        }
        None => {
            trace!(?request_id, "copy_file_range EIO (sender dropped)");
            pending.reply.error(libc::EIO);
        }
    }
}

/// Restore a reader to the handle table after async operation.
fn restore_reader(
    request_id: RequestId,
    fh: u64,
    reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
    handle_table: &FuseHandleTable,
) {
    if let Some(mut handle) = handle_table.get_mut(&fh) {
        if matches!(*handle, FuseHandle::ReaderLoaned) {
            *handle = FuseHandle::Reader(reader);
            trace!(?request_id, fh, "Reader restored to handle table");
        } else {
            warn!(
                ?request_id,
                fh,
                "Handle modified during async operation, discarding reader"
            );
        }
    } else {
        trace!(
            ?request_id,
            fh,
            "Handle removed during async operation, discarding reader"
        );
    }
}

/// Dispatch a structural job to the executor.
#[allow(clippy::too_many_arguments)]
fn dispatch_structural_job(
    request_id: RequestId,
    job: QueuedStructuralJob,
    lane: Lane,
    executor: &FsSyscallExecutor,
    deadline_heap: &DeadlineHeap,
    pending_structural: &DashMap<RequestId, PendingStructural>,
    per_file: &PerFileOrdering,
    stats: &SchedulerStats,
    result_tx: &std::sync::mpsc::Sender<(RequestId, oneshot::Receiver<ExecutorResult>)>,
) {
    // Create oneshot for result
    let (tx, rx) = oneshot::channel();

    // Create executor job
    let executor_job = ExecutorJob {
        request_id,
        fh: 0, // Structural ops don't have a file handle
        operation: ExecutorOperation::Structural {
            op: job.op.clone(),
            ops: job.ops,
        },
        result_tx: tx,
        deadline: job.deadline,
    };

    // Increment in-flight count before submission
    stats.inc_in_flight(lane as usize);

    // Submit to executor
    if let Err(e) = executor.try_submit(executor_job) {
        // Submission failed - reply with error
        warn!(?request_id, "Executor rejected structural job: {}", e);
        stats.dec_in_flight(lane as usize);

        // Get the pending structural and reply with error
        if let Some((_, pending)) = pending_structural.remove(&request_id)
            && pending.state.claim_reply()
        {
            pending.reply.error(libc::EAGAIN);
            // Release per-file ordering for all affected inodes
            for ino in pending.op.affected_inodes() {
                per_file.complete(ino, Some(libc::EAGAIN));
            }
        }
        return;
    }

    // Insert into deadline heap for timeout tracking
    let generation = deadline_heap.insert(request_id, job.deadline);

    // Update pending structural with proper generation
    if let Some(mut pending) = pending_structural.get_mut(&request_id) {
        pending.generation = generation;
    }

    // Send result receiver to self for tracking
    if result_tx.send((request_id, rx)).is_err() {
        warn!(?request_id, "Failed to send result receiver - dispatcher shutting down");
    }

    let op_name = job.op.name();
    trace!(?request_id, ?lane, op = op_name, "Structural job dispatched to executor");
}

/// Handle completion of a structural request.
fn handle_structural_completion(
    request_id: RequestId,
    result: Option<ExecutorResult>,
    pending: PendingStructural,
    per_file: &PerFileOrdering,
) {
    match result {
        Some(ExecutorResult::Structural(structural_result)) => {
            // Handle the structural result
            match structural_result {
                StructuralResult::Empty { result, .. } => {
                    match result {
                        Ok(()) => {
                            trace!(?request_id, "Structural operation completed successfully");
                            // For empty replies (unlink, rmdir, rename), just reply ok
                            match pending.reply {
                                StructuralReply::Empty(reply) => reply.ok(),
                                _ => {
                                    error!(?request_id, "Mismatched reply type for Empty result");
                                }
                            }
                        }
                        Err(errno) => {
                            trace!(?request_id, errno, "Structural operation failed");
                            pending.reply.error(errno);
                            // Record error in per-file ordering
                            for ino in pending.op.affected_inodes() {
                                per_file.complete(ino, Some(errno));
                            }
                        }
                    }
                }
                StructuralResult::Entry { result, .. } => {
                    // For entry replies (mkdir, symlink, link)
                    match result {
                        Ok((attr, generation)) => {
                            trace!(?request_id, "Entry created successfully");
                            match pending.reply {
                                StructuralReply::Entry(reply) => {
                                    reply.entry(&Duration::from_secs(1), &attr, generation);
                                }
                                _ => {
                                    error!(?request_id, "Mismatched reply type for Entry result");
                                }
                            }
                        }
                        Err(errno) => {
                            trace!(?request_id, errno, "Entry creation failed");
                            pending.reply.error(errno);
                            for ino in pending.op.affected_inodes() {
                                per_file.complete(ino, Some(errno));
                            }
                        }
                    }
                }
                StructuralResult::Create { result, .. } => {
                    // For create replies
                    match result {
                        Ok((attr, generation, fh, flags)) => {
                            trace!(?request_id, fh, "File created successfully");
                            match pending.reply {
                                StructuralReply::Create(reply) => {
                                    reply.created(&Duration::from_secs(1), &attr, generation, fh, flags);
                                }
                                _ => {
                                    error!(?request_id, "Mismatched reply type for Create result");
                                }
                            }
                        }
                        Err(errno) => {
                            trace!(?request_id, errno, "File creation failed");
                            pending.reply.error(errno);
                            for ino in pending.op.affected_inodes() {
                                per_file.complete(ino, Some(errno));
                            }
                        }
                    }
                }
                StructuralResult::Attr { result, .. } => {
                    // For setattr replies
                    match result {
                        Ok(attr) => {
                            trace!(?request_id, "Setattr completed successfully");
                            match pending.reply {
                                StructuralReply::Attr(reply) => {
                                    reply.attr(&Duration::from_secs(1), &attr);
                                }
                                _ => {
                                    error!(?request_id, "Mismatched reply type for Attr result");
                                }
                            }
                        }
                        Err(errno) => {
                            trace!(?request_id, errno, "Setattr failed");
                            pending.reply.error(errno);
                            for ino in pending.op.affected_inodes() {
                                per_file.complete(ino, Some(errno));
                            }
                        }
                    }
                }
            }
        }
        Some(ExecutorResult::Read(_)) => {
            // Read results should not be sent to handle_structural_completion
            unreachable!("Read result in structural completion handler");
        }
        None => {
            trace!(?request_id, "Structural EIO (sender dropped)");
            pending.reply.error(libc::EIO);
            for ino in pending.op.affected_inodes() {
                per_file.complete(ino, Some(libc::EIO));
            }
        }
    }
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
        let vault_stats = Arc::new(VaultStats::new());
        let mut scheduler = FuseScheduler::new(handle_table, vault_stats);
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
