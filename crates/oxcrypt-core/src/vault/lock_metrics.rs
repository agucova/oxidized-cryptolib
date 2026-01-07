//! Lock contention metrics for profiling and optimization.

use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics for lock acquisition and contention.
///
/// Thread-safe counters using atomic operations for lock-free updates.
#[derive(Debug, Default)]
pub struct LockMetrics {
    /// Number of successful sync fast path acquisitions
    pub fast_path_hits: AtomicU64,

    /// Number of failed sync fast path attempts (lock contended)
    pub fast_path_misses: AtomicU64,

    /// Number of async lock acquisitions
    pub async_acquisitions: AtomicU64,

    /// Total directory lock requests
    pub directory_lock_requests: AtomicU64,

    /// Total file lock requests
    pub file_lock_requests: AtomicU64,

    /// Number of spawn_blocking calls
    pub blocking_tasks: AtomicU64,

    /// Total time spent in blocking tasks (nanoseconds)
    pub blocking_time_ns: AtomicU64,

    /// Number of file handle insertions
    pub handle_insertions: AtomicU64,

    /// Number of file handle retrievals (get/get_mut)
    pub handle_retrievals: AtomicU64,

    /// Number of file handle removals
    pub handle_removals: AtomicU64,
}

impl LockMetrics {
    /// Create new empty metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful sync fast path acquisition
    #[inline]
    pub fn record_fast_path_hit(&self) {
        self.fast_path_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed sync fast path attempt
    #[inline]
    pub fn record_fast_path_miss(&self) {
        self.fast_path_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an async lock acquisition
    #[inline]
    pub fn record_async_acquisition(&self) {
        self.async_acquisitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a directory lock request
    #[inline]
    pub fn record_directory_lock(&self) {
        self.directory_lock_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a file lock request
    #[inline]
    pub fn record_file_lock(&self) {
        self.file_lock_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a blocking task execution
    #[inline]
    pub fn record_blocking_task(&self, duration_ns: u64) {
        self.blocking_tasks.fetch_add(1, Ordering::Relaxed);
        self.blocking_time_ns
            .fetch_add(duration_ns, Ordering::Relaxed);
    }

    /// Record a file handle insertion
    #[inline]
    pub fn record_handle_insertion(&self) {
        self.handle_insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a file handle retrieval
    #[inline]
    pub fn record_handle_retrieval(&self) {
        self.handle_retrievals.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a file handle removal
    #[inline]
    pub fn record_handle_removal(&self) {
        self.handle_removals.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current snapshot of metrics
    pub fn snapshot(&self) -> LockMetricsSnapshot {
        LockMetricsSnapshot {
            fast_path_hits: self.fast_path_hits.load(Ordering::Relaxed),
            fast_path_misses: self.fast_path_misses.load(Ordering::Relaxed),
            async_acquisitions: self.async_acquisitions.load(Ordering::Relaxed),
            directory_lock_requests: self.directory_lock_requests.load(Ordering::Relaxed),
            file_lock_requests: self.file_lock_requests.load(Ordering::Relaxed),
            blocking_tasks: self.blocking_tasks.load(Ordering::Relaxed),
            blocking_time_ns: self.blocking_time_ns.load(Ordering::Relaxed),
            handle_insertions: self.handle_insertions.load(Ordering::Relaxed),
            handle_retrievals: self.handle_retrievals.load(Ordering::Relaxed),
            handle_removals: self.handle_removals.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero
    pub fn reset(&self) {
        self.fast_path_hits.store(0, Ordering::Relaxed);
        self.fast_path_misses.store(0, Ordering::Relaxed);
        self.async_acquisitions.store(0, Ordering::Relaxed);
        self.directory_lock_requests.store(0, Ordering::Relaxed);
        self.file_lock_requests.store(0, Ordering::Relaxed);
        self.blocking_tasks.store(0, Ordering::Relaxed);
        self.blocking_time_ns.store(0, Ordering::Relaxed);
        self.handle_insertions.store(0, Ordering::Relaxed);
        self.handle_retrievals.store(0, Ordering::Relaxed);
        self.handle_removals.store(0, Ordering::Relaxed);
    }
}

/// Point-in-time snapshot of lock metrics
#[derive(Debug, Clone, Copy)]
pub struct LockMetricsSnapshot {
    pub fast_path_hits: u64,
    pub fast_path_misses: u64,
    pub async_acquisitions: u64,
    pub directory_lock_requests: u64,
    pub file_lock_requests: u64,
    pub blocking_tasks: u64,
    pub blocking_time_ns: u64,
    pub handle_insertions: u64,
    pub handle_retrievals: u64,
    pub handle_removals: u64,
}

impl LockMetricsSnapshot {
    /// Calculate fast path hit rate (0.0 to 1.0)
    pub fn fast_path_hit_rate(&self) -> f64 {
        let total = self.fast_path_hits + self.fast_path_misses;
        if total == 0 {
            0.0
        } else {
            self.fast_path_hits as f64 / total as f64
        }
    }

    /// Calculate total lock attempts
    pub fn total_attempts(&self) -> u64 {
        self.fast_path_hits + self.fast_path_misses + self.async_acquisitions
    }

    /// Print formatted metrics
    pub fn print(&self) {
        let total_attempts = self.total_attempts();
        let hit_rate = self.fast_path_hit_rate() * 100.0;

        println!("\n{}", "=".repeat(70));
        println!("LOCK CONTENTION METRICS");
        println!("{}", "=".repeat(70));

        println!("\nFast Path Performance:");
        println!(
            "  Hits:   {:>10} ({:>5.1}% of attempts)",
            self.fast_path_hits,
            if total_attempts > 0 {
                self.fast_path_hits as f64 / total_attempts as f64 * 100.0
            } else {
                0.0
            }
        );
        println!(
            "  Misses: {:>10} ({:>5.1}% of attempts)",
            self.fast_path_misses,
            if total_attempts > 0 {
                self.fast_path_misses as f64 / total_attempts as f64 * 100.0
            } else {
                0.0
            }
        );
        println!("  Hit Rate: {:.1}%", hit_rate);

        println!("\nAsync Path:");
        println!("  Acquisitions: {:>10}", self.async_acquisitions);

        println!("\nLock Requests:");
        println!("  Directory: {:>10}", self.directory_lock_requests);
        println!("  File:      {:>10}", self.file_lock_requests);
        println!(
            "  Total:     {:>10}",
            self.directory_lock_requests + self.file_lock_requests
        );

        println!("\nBlocking Tasks (spawn_blocking):");
        println!("  Count:     {:>10}", self.blocking_tasks);
        if self.blocking_tasks > 0 {
            let avg_ms = (self.blocking_time_ns as f64 / self.blocking_tasks as f64) / 1_000_000.0;
            let total_s = self.blocking_time_ns as f64 / 1_000_000_000.0;
            println!("  Avg Time:  {:>10.2} ms", avg_ms);
            println!("  Total Time:{:>10.2} s", total_s);
        }

        println!("\nFile Handle Operations:");
        println!("  Insertions: {:>10}", self.handle_insertions);
        println!("  Retrievals: {:>10}", self.handle_retrievals);
        println!("  Removals:   {:>10}", self.handle_removals);
        println!(
            "  Net Open:   {:>10}",
            self.handle_insertions.saturating_sub(self.handle_removals)
        );

        println!("\n{}", "=".repeat(70));
    }
}
