//! Aggregated statistics for the FUSE scheduler.
//!
//! Collects metrics from all scheduler components into a unified view
//! for monitoring and debugging.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::lane::Lane;
use super::queue::LaneQueues;
use super::{ExecutorStats, PerFileStats, SingleFlightStats};
use std::time::{SystemTime, UNIX_EPOCH};

/// Aggregated scheduler statistics.
///
/// Provides a snapshot of all scheduler metrics for monitoring and debugging.
#[derive(Debug, Default)]
pub struct SchedulerStats {
    // Request tracking
    /// Total requests accepted by the scheduler.
    pub requests_accepted: AtomicU64,
    /// Total requests rejected (queue full, shutdown, etc.).
    pub requests_rejected: AtomicU64,

    // Timeout tracking
    /// Requests that timed out before completion.
    pub timeouts: AtomicU64,
    /// Completions that arrived after timeout (late).
    pub late_completions: AtomicU64,

    // Lane-specific rejections (indexed by Lane as usize)
    /// Rejections per lane [L0, L1, L2, L3, L4].
    pub rejections_by_lane: [AtomicU64; 5],

    // Current state
    /// Currently in-flight requests per lane.
    pub in_flight_by_lane: [AtomicU64; 5],
}

impl SchedulerStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an accepted request.
    pub fn record_accept(&self) {
        self.requests_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected request.
    pub fn record_reject(&self, lane_index: usize) {
        self.requests_rejected.fetch_add(1, Ordering::Relaxed);
        if lane_index < 5 {
            self.rejections_by_lane[lane_index].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a timeout.
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a late completion.
    pub fn record_late_completion(&self) {
        self.late_completions.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment in-flight count for a lane.
    pub fn inc_in_flight(&self, lane_index: usize) {
        if lane_index < 5 {
            self.in_flight_by_lane[lane_index].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement in-flight count for a lane.
    pub fn dec_in_flight(&self, lane_index: usize) {
        if lane_index < 5 {
            self.in_flight_by_lane[lane_index].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get total in-flight requests across all lanes.
    pub fn total_in_flight(&self) -> u64 {
        self.in_flight_by_lane
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    /// Get rejection rate (rejected / total attempts).
    pub fn rejection_rate(&self) -> f64 {
        let accepted = self.requests_accepted.load(Ordering::Relaxed);
        let rejected = self.requests_rejected.load(Ordering::Relaxed);
        let total = accepted + rejected;
        if total == 0 {
            0.0
        } else {
            rejected as f64 / total as f64
        }
    }

    /// Get timeout rate (timeouts / accepted).
    pub fn timeout_rate(&self) -> f64 {
        let accepted = self.requests_accepted.load(Ordering::Relaxed);
        let timeouts = self.timeouts.load(Ordering::Relaxed);
        if accepted == 0 {
            0.0
        } else {
            timeouts as f64 / accepted as f64
        }
    }
}

/// A complete snapshot of all scheduler metrics.
///
/// This is a point-in-time view of scheduler health and performance.
#[derive(Debug, Clone)]
pub struct SchedulerSnapshot {
    // Core stats
    /// Requests accepted.
    pub requests_accepted: u64,
    /// Requests rejected.
    pub requests_rejected: u64,
    /// Requests timed out.
    pub timeouts: u64,
    /// Late completions.
    pub late_completions: u64,
    /// Rejections by lane.
    pub rejections_by_lane: [u64; 5],
    /// In-flight by lane.
    pub in_flight_by_lane: [u64; 5],
    /// Current queue depth total.
    pub queue_depth_total: u64,
    /// Current queue depth by lane.
    pub queue_depth_by_lane: [u64; 5],
    /// Oldest queue wait in milliseconds.
    pub oldest_queue_wait_ms: u64,
    /// Last dequeue timestamp (ms since UNIX epoch).
    pub last_dequeue_ms: u64,

    // Executor stats
    /// Jobs submitted to executor.
    pub executor_jobs_submitted: u64,
    /// Jobs completed by executor.
    pub executor_jobs_completed: u64,
    /// Jobs failed in executor.
    pub executor_jobs_failed: u64,
    /// Jobs rejected by executor (queue full).
    pub executor_jobs_rejected: u64,
    /// Current executor queue depth.
    pub executor_queue_depth: u64,
    /// Average execution time.
    pub executor_avg_time: Duration,

    // Read cache stats
    /// Cache hits.
    pub cache_hits: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Cache entries.
    pub cache_entries: u64,
    /// Cache size in bytes.
    pub cache_bytes: u64,
    /// Cache hit ratio.
    pub cache_hit_ratio: f64,

    // Single-flight stats
    /// Single-flight leaders (actual reads).
    pub dedup_leaders: u64,
    /// Single-flight waiters (deduplicated).
    pub dedup_waiters: u64,
    /// Deduplication ratio.
    pub dedup_ratio: f64,

    // Per-file ordering stats
    /// Operations that waited for ordering.
    pub per_file_ops_waited: u64,
    /// Operations that proceeded immediately.
    pub per_file_ops_immediate: u64,
    /// Barrier waits.
    pub per_file_barrier_waits: u64,
    /// Errors propagated to barriers.
    pub per_file_errors_propagated: u64,
}

impl SchedulerSnapshot {
    /// Create a snapshot from component stats.
    pub fn from_components<T>(
        scheduler: &SchedulerStats,
        executor: &ExecutorStats,
        cache_hits: u64,
        cache_misses: u64,
        cache_entries: u64,
        cache_bytes: u64,
        single_flight: &SingleFlightStats,
        per_file: &PerFileStats,
        lane_queues: &LaneQueues<T>,
    ) -> Self {
        let queue_depth_by_lane = [
            lane_queues.depth(Lane::Control),
            lane_queues.depth(Lane::Metadata),
            lane_queues.depth(Lane::ReadForeground),
            lane_queues.depth(Lane::WriteStructural),
            lane_queues.depth(Lane::Bulk),
        ];
        let queue_depth_total = queue_depth_by_lane.iter().sum();

        let now_ms = now_ms();
        let oldest_queue_wait_ms = [
            lane_queues.stats(Lane::Control).oldest_enqueue_ms(),
            lane_queues.stats(Lane::Metadata).oldest_enqueue_ms(),
            lane_queues.stats(Lane::ReadForeground).oldest_enqueue_ms(),
            lane_queues.stats(Lane::WriteStructural).oldest_enqueue_ms(),
            lane_queues.stats(Lane::Bulk).oldest_enqueue_ms(),
        ]
        .into_iter()
        .map(|ts| {
            if ts == 0 {
                0
            } else {
                now_ms.saturating_sub(ts)
            }
        })
        .max()
        .unwrap_or(0);

        let last_dequeue_ms = [
            lane_queues.stats(Lane::Control).last_dequeue_ms(),
            lane_queues.stats(Lane::Metadata).last_dequeue_ms(),
            lane_queues.stats(Lane::ReadForeground).last_dequeue_ms(),
            lane_queues.stats(Lane::WriteStructural).last_dequeue_ms(),
            lane_queues.stats(Lane::Bulk).last_dequeue_ms(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        Self {
            // Core stats
            requests_accepted: scheduler.requests_accepted.load(Ordering::Relaxed),
            requests_rejected: scheduler.requests_rejected.load(Ordering::Relaxed),
            timeouts: scheduler.timeouts.load(Ordering::Relaxed),
            late_completions: scheduler.late_completions.load(Ordering::Relaxed),
            rejections_by_lane: [
                scheduler.rejections_by_lane[0].load(Ordering::Relaxed),
                scheduler.rejections_by_lane[1].load(Ordering::Relaxed),
                scheduler.rejections_by_lane[2].load(Ordering::Relaxed),
                scheduler.rejections_by_lane[3].load(Ordering::Relaxed),
                scheduler.rejections_by_lane[4].load(Ordering::Relaxed),
            ],
            in_flight_by_lane: [
                scheduler.in_flight_by_lane[0].load(Ordering::Relaxed),
                scheduler.in_flight_by_lane[1].load(Ordering::Relaxed),
                scheduler.in_flight_by_lane[2].load(Ordering::Relaxed),
                scheduler.in_flight_by_lane[3].load(Ordering::Relaxed),
                scheduler.in_flight_by_lane[4].load(Ordering::Relaxed),
            ],
            queue_depth_total,
            queue_depth_by_lane,
            oldest_queue_wait_ms,
            last_dequeue_ms,

            // Executor stats
            executor_jobs_submitted: executor.jobs_submitted.load(Ordering::Relaxed),
            executor_jobs_completed: executor.jobs_completed.load(Ordering::Relaxed),
            executor_jobs_failed: executor.jobs_failed.load(Ordering::Relaxed),
            executor_jobs_rejected: executor.jobs_rejected.load(Ordering::Relaxed),
            executor_queue_depth: executor.queue_depth.load(Ordering::Relaxed),
            executor_avg_time: executor.avg_execution_time(),

            // Cache stats
            cache_hits,
            cache_misses,
            cache_entries,
            cache_bytes,
            cache_hit_ratio: if cache_hits + cache_misses == 0 {
                0.0
            } else {
                cache_hits as f64 / (cache_hits + cache_misses) as f64
            },

            // Single-flight stats
            dedup_leaders: single_flight.leaders.load(Ordering::Relaxed),
            dedup_waiters: single_flight.waiters.load(Ordering::Relaxed),
            dedup_ratio: single_flight.dedup_ratio(),

            // Per-file ordering stats
            per_file_ops_waited: per_file.ops_waited.load(Ordering::Relaxed),
            per_file_ops_immediate: per_file.ops_immediate.load(Ordering::Relaxed),
            per_file_barrier_waits: per_file.barrier_waits.load(Ordering::Relaxed),
            per_file_errors_propagated: per_file.errors_propagated.load(Ordering::Relaxed),
        }
    }

    /// Format as a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Scheduler Stats:\n\
             - Requests: {} accepted, {} rejected ({:.1}% rejection rate)\n\
             - Timeouts: {} ({:.1}% of accepted)\n\
             - In-flight: {} total\n\
             - Queue: {} depth, oldest wait {}ms\n\
             - Executor: {} submitted, {} completed, {} failed, queue depth {}\n\
             - Cache: {} hits, {} misses ({:.1}% hit rate), {} entries, {} bytes\n\
             - Dedup: {} leaders, {} waiters ({:.1}% dedup rate)\n\
             - Per-file: {} waited, {} immediate, {} barriers",
            self.requests_accepted,
            self.requests_rejected,
            if self.requests_accepted + self.requests_rejected == 0 {
                0.0
            } else {
                self.requests_rejected as f64
                    / (self.requests_accepted + self.requests_rejected) as f64
                    * 100.0
            },
            self.timeouts,
            if self.requests_accepted == 0 {
                0.0
            } else {
                self.timeouts as f64 / self.requests_accepted as f64 * 100.0
            },
            self.in_flight_by_lane.iter().sum::<u64>(),
            self.queue_depth_total,
            self.oldest_queue_wait_ms,
            self.executor_jobs_submitted,
            self.executor_jobs_completed,
            self.executor_jobs_failed,
            self.executor_queue_depth,
            self.cache_hits,
            self.cache_misses,
            self.cache_hit_ratio * 100.0,
            self.cache_entries,
            self.cache_bytes,
            self.dedup_leaders,
            self.dedup_waiters,
            self.dedup_ratio * 100.0,
            self.per_file_ops_waited,
            self.per_file_ops_immediate,
            self.per_file_barrier_waits,
        )
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::lane::LaneCapacities;
    use crate::scheduler::queue::LaneQueues;

    #[test]
    fn test_scheduler_stats_new() {
        let stats = SchedulerStats::new();
        assert_eq!(stats.requests_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.requests_rejected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_accept() {
        let stats = SchedulerStats::new();
        stats.record_accept();
        stats.record_accept();
        assert_eq!(stats.requests_accepted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_reject() {
        let stats = SchedulerStats::new();
        stats.record_reject(2); // Lane L2
        stats.record_reject(2);
        stats.record_reject(4); // Lane L4

        assert_eq!(stats.requests_rejected.load(Ordering::Relaxed), 3);
        assert_eq!(stats.rejections_by_lane[2].load(Ordering::Relaxed), 2);
        assert_eq!(stats.rejections_by_lane[4].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_in_flight_tracking() {
        let stats = SchedulerStats::new();

        stats.inc_in_flight(1);
        stats.inc_in_flight(1);
        stats.inc_in_flight(2);

        assert_eq!(stats.in_flight_by_lane[1].load(Ordering::Relaxed), 2);
        assert_eq!(stats.in_flight_by_lane[2].load(Ordering::Relaxed), 1);
        assert_eq!(stats.total_in_flight(), 3);

        stats.dec_in_flight(1);
        assert_eq!(stats.in_flight_by_lane[1].load(Ordering::Relaxed), 1);
        assert_eq!(stats.total_in_flight(), 2);
    }

    #[test]
    fn test_rejection_rate() {
        let stats = SchedulerStats::new();

        // 0/0 = 0%
        assert_eq!(stats.rejection_rate(), 0.0);

        // 8 accepted, 2 rejected = 20%
        for _ in 0..8 {
            stats.record_accept();
        }
        stats.record_reject(0);
        stats.record_reject(0);

        let rate = stats.rejection_rate();
        assert!((rate - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_timeout_rate() {
        let stats = SchedulerStats::new();

        // 0/0 = 0%
        assert_eq!(stats.timeout_rate(), 0.0);

        // 10 accepted, 1 timeout = 10%
        for _ in 0..10 {
            stats.record_accept();
        }
        stats.record_timeout();

        let rate = stats.timeout_rate();
        assert!((rate - 0.1).abs() < 0.01);
    }

    #[test]
    fn test_snapshot_summary() {
        let scheduler = SchedulerStats::new();
        scheduler.record_accept();
        scheduler.record_accept();
        scheduler.record_reject(2);

        let executor = ExecutorStats::default();
        let single_flight = SingleFlightStats::default();
        let per_file = PerFileStats::default();
        let lane_queues: LaneQueues<()> = LaneQueues::new(&LaneCapacities::default());

        let snapshot = SchedulerSnapshot::from_components(
            &scheduler,
            &executor,
            10,   // cache_hits
            5,    // cache_misses
            3,    // cache_entries
            1024, // cache_bytes
            &single_flight,
            &per_file,
            &lane_queues,
        );

        let summary = snapshot.summary();
        assert!(summary.contains("2 accepted"));
        assert!(summary.contains("1 rejected"));
        assert!(summary.contains("10 hits"));
    }
}
