//! Statistics tracking for vault mount backends.
//!
//! This module provides thread-safe, lock-free statistics collection for
//! monitoring vault activity. Statistics include:
//!
//! - Cache hit/miss rates
//! - Read/write operation counts
//! - Bytes transferred (raw, encrypted, decrypted)
//! - Activity tracking for idle/active status
//!
//! # Usage
//!
//! ```
//! use oxcrypt_mount::stats::{VaultStats, CacheStats};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! // Create stats for a mounted vault
//! let stats = Arc::new(VaultStats::new());
//!
//! // Record operations
//! stats.record_read(4096);
//! stats.record_write(1024);
//!
//! // Check activity status
//! if stats.is_active(Duration::from_millis(500)) {
//!     println!("Vault is actively being accessed");
//! }
//!
//! // Get cache hit rate
//! let hit_rate = stats.cache_stats().hit_rate();
//! println!("Cache hit rate: {:.1}%", hit_rate * 100.0);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;

use crate::moka_cache::{CacheHealth, CacheHealthThresholds, CacheWarning};

/// Statistics for cache operations.
///
/// Tracks hits, misses, and entries for computing cache efficiency.
/// All operations are lock-free using atomic counters.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits (successful lookups).
    pub hits: AtomicU64,
    /// Number of cache misses (failed lookups).
    pub misses: AtomicU64,
    /// Number of entries currently in the cache.
    pub entries: AtomicU64,
    /// Number of entries evicted (expired or removed).
    pub evictions: AtomicU64,
}

impl CacheStats {
    /// Create new cache statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache hit.
    #[inline]
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    #[inline]
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an entry being added to the cache.
    #[inline]
    pub fn record_insert(&self) {
        self.entries.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an entry being removed from the cache.
    #[inline]
    pub fn record_remove(&self) {
        self.entries.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a cache eviction (TTL expiry or explicit removal).
    #[inline]
    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of cache hits.
    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get the total number of cache misses.
    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get the current number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.entries.load(Ordering::Relaxed)
    }

    /// Get the total number of evictions.
    pub fn eviction_count(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Compute the cache hit rate as a fraction (0.0 to 1.0).
    ///
    /// Returns 0.0 if no lookups have been performed.
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.entries.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }

    /// Create a snapshot of current values.
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hit_count(),
            misses: self.miss_count(),
            entries: self.entry_count(),
            evictions: self.eviction_count(),
        }
    }

    /// Compute cache health based on current statistics.
    ///
    /// This analyzes hit rate, eviction rate, and returns any applicable warnings.
    /// Use default thresholds or provide custom ones via `health_with_thresholds()`.
    pub fn health(&self) -> CacheHealth {
        self.health_with_thresholds(CacheHealthThresholds::default())
    }

    /// Compute cache health with custom thresholds.
    pub fn health_with_thresholds(&self, thresholds: CacheHealthThresholds) -> CacheHealth {
        let hits = self.hit_count();
        let misses = self.miss_count();
        let entries = self.entry_count();
        let evictions = self.eviction_count();

        let total_lookups = hits + misses;
        let hit_rate = if total_lookups == 0 {
            1.0 // Assume healthy when no data
        } else {
            hits as f64 / total_lookups as f64
        };

        // Eviction rate: evictions per entry (approximation)
        let eviction_rate = if entries == 0 {
            0.0
        } else {
            evictions as f64 / entries as f64
        };

        // Build warnings
        let mut warnings = Vec::new();

        // Low hit rate warning (only if we have enough data)
        if total_lookups >= 10 && hit_rate < thresholds.min_hit_rate {
            warnings.push(CacheWarning::LowHitRate {
                rate: hit_rate,
                threshold: thresholds.min_hit_rate,
            });
        }

        // High eviction rate warning
        if evictions > 0 && eviction_rate > thresholds.max_eviction_rate {
            warnings.push(CacheWarning::HighEvictionRate {
                rate: eviction_rate,
                threshold: thresholds.max_eviction_rate,
            });
        }

        CacheHealth {
            hit_rate,
            eviction_rate,
            negative_hit_ratio: 0.0, // CacheStats doesn't track negative cache separately
            entry_count: entries,
            hits,
            misses,
            evictions,
            warnings,
        }
    }
}

/// A serializable snapshot of cache statistics.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct CacheStatsSnapshot {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries in the cache.
    pub entries: u64,
    /// Number of evictions.
    pub evictions: u64,
}

impl CacheStatsSnapshot {
    /// Compute the cache hit rate as a fraction (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Statistics for operation latency.
///
/// Tracks total nanoseconds and count for computing average latency.
/// All operations are lock-free using atomic counters.
#[derive(Debug, Default)]
pub struct LatencyStats {
    /// Total nanoseconds across all operations.
    total_nanos: AtomicU64,
    /// Number of operations recorded.
    count: AtomicU64,
}

impl LatencyStats {
    /// Create new latency statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a latency measurement.
    ///
    /// # Arguments
    ///
    /// * `elapsed` - Duration of the operation
    #[inline]
    pub fn record(&self, elapsed: Duration) {
        // Safe cast: Duration.as_nanos() returns u128 but fits in u64 for reasonable timeouts
        #[allow(clippy::cast_possible_truncation)]
        let nanos = elapsed.as_nanos() as u64;
        self.total_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the number of operations recorded.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get the average latency in nanoseconds.
    ///
    /// Returns 0.0 if no operations have been recorded.
    pub fn avg_nanos(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.total_nanos.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get the average latency in microseconds.
    pub fn avg_micros(&self) -> f64 {
        self.avg_nanos() / 1000.0
    }

    /// Get the average latency in milliseconds.
    pub fn avg_millis(&self) -> f64 {
        self.avg_nanos() / 1_000_000.0
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.total_nanos.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }
}

/// Activity status for the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityStatus {
    /// No operations in progress, no recent activity.
    Idle,
    /// Operations completed recently (within threshold).
    Active,
    /// Read operation in progress.
    Reading,
    /// Write operation in progress.
    Writing,
}

impl ActivityStatus {
    /// Get a display string for the status.
    pub fn display(&self) -> &'static str {
        match self {
            ActivityStatus::Idle => "idle",
            ActivityStatus::Active => "active",
            ActivityStatus::Reading => "reading",
            ActivityStatus::Writing => "writing",
        }
    }
}

/// Comprehensive statistics for a mounted vault.
///
/// This struct collects various metrics about vault activity that can be
/// displayed in the GUI statistics panel. All operations are thread-safe
/// and designed for minimal performance impact.
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering, which provides:
/// - Lock-free operation (no blocking)
/// - Eventual consistency (counters may be slightly stale when read)
/// - Minimal overhead (single atomic instruction per operation)
///
/// The activity timestamp uses `RwLock` for Instant storage since Instant
/// is not atomic, but the lock is rarely contended (only on activity updates).
#[derive(Debug)]
pub struct VaultStats {
    // === Operation Counts ===
    /// Total number of read operations.
    pub total_reads: AtomicU64,
    /// Total number of write operations.
    pub total_writes: AtomicU64,
    /// Total number of all operations (including metadata, readdir, etc.).
    pub total_ops: AtomicU64,

    // === Bytes Tracking ===
    /// Total bytes read from the vault.
    pub bytes_read: AtomicU64,
    /// Total bytes written to the vault.
    pub bytes_written: AtomicU64,
    /// Total bytes after decryption (plaintext).
    pub bytes_decrypted: AtomicU64,
    /// Total bytes before encryption (plaintext).
    pub bytes_encrypted: AtomicU64,

    // === File Handle Tracking ===
    /// Current number of open files.
    pub open_files: AtomicU64,
    /// Current number of open directories.
    pub open_dirs: AtomicU64,

    // === Cache Statistics ===
    /// Attribute cache statistics (shared Arc for connection to TtlCache).
    cache_stats: Arc<CacheStats>,

    // === Activity Tracking ===
    /// Timestamp of the last operation.
    last_activity: RwLock<Instant>,
    /// Current number of operations in progress.
    ops_in_progress: AtomicU64,
    /// Current read operations in progress.
    reads_in_progress: AtomicU64,
    /// Current write operations in progress.
    writes_in_progress: AtomicU64,

    // === Latency Tracking ===
    /// Read operation latency statistics.
    read_latency: LatencyStats,
    /// Write operation latency statistics.
    write_latency: LatencyStats,
    /// Metadata operation latency statistics.
    metadata_latency: LatencyStats,

    // === Metadata Operation Tracking ===
    /// Total number of metadata operations (lookup, getattr, readdir, etc.).
    pub total_metadata_ops: AtomicU64,

    // === Error Tracking ===
    /// Total number of errors encountered.
    pub total_errors: AtomicU64,

    // === Inode/Entry Tracking ===
    /// Current number of inodes/entries in the filesystem table.
    /// This is updated by the mount backend to track memory usage.
    pub inode_count: AtomicU64,

    // === Session Information ===
    /// When this statistics instance was created.
    session_start: SystemTime,
}

impl Default for VaultStats {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStats {
    /// Create new vault statistics.
    pub fn new() -> Self {
        Self {
            total_reads: AtomicU64::new(0),
            total_writes: AtomicU64::new(0),
            total_ops: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            bytes_decrypted: AtomicU64::new(0),
            bytes_encrypted: AtomicU64::new(0),
            open_files: AtomicU64::new(0),
            open_dirs: AtomicU64::new(0),
            cache_stats: Arc::new(CacheStats::new()),
            last_activity: RwLock::new(Instant::now()),
            ops_in_progress: AtomicU64::new(0),
            reads_in_progress: AtomicU64::new(0),
            writes_in_progress: AtomicU64::new(0),
            read_latency: LatencyStats::new(),
            write_latency: LatencyStats::new(),
            metadata_latency: LatencyStats::new(),
            total_metadata_ops: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            inode_count: AtomicU64::new(0),
            session_start: SystemTime::now(),
        }
    }

    // === Recording Methods ===

    /// Record a read operation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes read
    #[inline]
    pub fn record_read(&self, bytes: u64) {
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Record a write operation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes written
    #[inline]
    pub fn record_write(&self, bytes: u64) {
        self.total_writes.fetch_add(1, Ordering::Relaxed);
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes decrypted.
    #[inline]
    pub fn record_decrypted(&self, bytes: u64) {
        self.bytes_decrypted.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes encrypted.
    #[inline]
    pub fn record_encrypted(&self, bytes: u64) {
        self.bytes_encrypted.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a generic operation (not read/write).
    #[inline]
    pub fn record_op(&self) {
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record a file being opened.
    #[inline]
    pub fn record_file_open(&self) {
        self.open_files.fetch_add(1, Ordering::Relaxed);
        self.record_op();
    }

    /// Record a file being closed.
    #[inline]
    pub fn record_file_close(&self) {
        self.open_files.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a directory being opened.
    #[inline]
    pub fn record_dir_open(&self) {
        self.open_dirs.fetch_add(1, Ordering::Relaxed);
        self.record_op();
    }

    /// Record a directory being closed.
    #[inline]
    pub fn record_dir_close(&self) {
        self.open_dirs.fetch_sub(1, Ordering::Relaxed);
    }

    /// Start tracking an in-progress read.
    #[inline]
    pub fn start_read(&self) {
        self.ops_in_progress.fetch_add(1, Ordering::Relaxed);
        self.reads_in_progress.fetch_add(1, Ordering::Relaxed);
    }

    /// Finish tracking an in-progress read.
    #[inline]
    pub fn finish_read(&self) {
        self.ops_in_progress.fetch_sub(1, Ordering::Relaxed);
        self.reads_in_progress.fetch_sub(1, Ordering::Relaxed);
    }

    /// Start tracking an in-progress write.
    #[inline]
    pub fn start_write(&self) {
        self.ops_in_progress.fetch_add(1, Ordering::Relaxed);
        self.writes_in_progress.fetch_add(1, Ordering::Relaxed);
    }

    /// Finish tracking an in-progress write.
    #[inline]
    pub fn finish_write(&self) {
        self.ops_in_progress.fetch_sub(1, Ordering::Relaxed);
        self.writes_in_progress.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record latency for a read operation.
    ///
    /// # Arguments
    ///
    /// * `elapsed` - Duration of the read operation
    #[inline]
    pub fn record_read_latency(&self, elapsed: Duration) {
        self.read_latency.record(elapsed);
    }

    /// Record latency for a write operation.
    ///
    /// # Arguments
    ///
    /// * `elapsed` - Duration of the write operation
    #[inline]
    pub fn record_write_latency(&self, elapsed: Duration) {
        self.write_latency.record(elapsed);
    }

    /// Record a metadata operation (lookup, getattr, readdir, etc.).
    ///
    /// This increments both the metadata ops counter and total ops counter.
    #[inline]
    pub fn record_metadata_op(&self) {
        self.total_metadata_ops.fetch_add(1, Ordering::Relaxed);
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record latency for a metadata operation.
    ///
    /// # Arguments
    ///
    /// * `elapsed` - Duration of the metadata operation
    #[inline]
    pub fn record_metadata_latency(&self, elapsed: Duration) {
        self.metadata_latency.record(elapsed);
    }

    /// Record an error.
    ///
    /// Call this when a filesystem operation fails.
    #[inline]
    pub fn record_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the inode/entry count.
    ///
    /// Call this periodically from the mount backend to track memory usage.
    #[inline]
    pub fn set_inode_count(&self, count: u64) {
        self.inode_count.store(count, Ordering::Relaxed);
    }

    /// Get the current inode/entry count.
    pub fn get_inode_count(&self) -> u64 {
        self.inode_count.load(Ordering::Relaxed)
    }

    /// Update the last activity timestamp.
    #[inline]
    fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }

    // === Query Methods ===

    /// Get the cache statistics.
    /// Returns a clone of the cache stats Arc for sharing with caches.
    ///
    /// This allows connecting the VaultStats cache tracking to TtlCache instances.
    pub fn cache_stats(&self) -> Arc<CacheStats> {
        Arc::clone(&self.cache_stats)
    }

    /// Get the total number of read operations.
    pub fn read_count(&self) -> u64 {
        self.total_reads.load(Ordering::Relaxed)
    }

    /// Get the total number of write operations.
    pub fn write_count(&self) -> u64 {
        self.total_writes.load(Ordering::Relaxed)
    }

    /// Get the total number of all operations.
    pub fn op_count(&self) -> u64 {
        self.total_ops.load(Ordering::Relaxed)
    }

    /// Get the total bytes read.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Get the total bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Get the total bytes decrypted.
    pub fn bytes_decrypted(&self) -> u64 {
        self.bytes_decrypted.load(Ordering::Relaxed)
    }

    /// Get the total bytes encrypted.
    pub fn bytes_encrypted(&self) -> u64 {
        self.bytes_encrypted.load(Ordering::Relaxed)
    }

    /// Get the number of currently open files.
    pub fn open_file_count(&self) -> u64 {
        self.open_files.load(Ordering::Relaxed)
    }

    /// Get the number of currently open directories.
    pub fn open_dir_count(&self) -> u64 {
        self.open_dirs.load(Ordering::Relaxed)
    }

    /// Check if the vault has had activity within the given duration.
    pub fn is_active(&self, threshold: Duration) -> bool {
        self.last_activity.read().elapsed() < threshold
    }

    /// Get the current activity status.
    pub fn activity_status(&self, idle_threshold: Duration) -> ActivityStatus {
        let reads = self.reads_in_progress.load(Ordering::Relaxed);
        let writes = self.writes_in_progress.load(Ordering::Relaxed);

        if writes > 0 {
            ActivityStatus::Writing
        } else if reads > 0 {
            ActivityStatus::Reading
        } else if self.is_active(idle_threshold) {
            ActivityStatus::Active
        } else {
            ActivityStatus::Idle
        }
    }

    /// Get the duration since the last activity.
    pub fn time_since_activity(&self) -> Duration {
        self.last_activity.read().elapsed()
    }

    /// Get the session start time.
    pub fn session_start(&self) -> SystemTime {
        self.session_start
    }

    /// Get the session duration.
    pub fn session_duration(&self) -> Duration {
        self.session_start.elapsed().unwrap_or(Duration::ZERO)
    }

    /// Get average read latency in milliseconds.
    pub fn avg_read_latency_ms(&self) -> f64 {
        self.read_latency.avg_millis()
    }

    /// Get average write latency in milliseconds.
    pub fn avg_write_latency_ms(&self) -> f64 {
        self.write_latency.avg_millis()
    }

    /// Get the number of read operations with latency tracked.
    pub fn read_latency_count(&self) -> u64 {
        self.read_latency.count()
    }

    /// Get the number of write operations with latency tracked.
    pub fn write_latency_count(&self) -> u64 {
        self.write_latency.count()
    }

    /// Get the total number of metadata operations.
    pub fn metadata_op_count(&self) -> u64 {
        self.total_metadata_ops.load(Ordering::Relaxed)
    }

    /// Get average metadata latency in milliseconds.
    pub fn avg_metadata_latency_ms(&self) -> f64 {
        self.metadata_latency.avg_millis()
    }

    /// Get the number of metadata operations with latency tracked.
    pub fn metadata_latency_count(&self) -> u64 {
        self.metadata_latency.count()
    }

    /// Get the total number of errors.
    pub fn error_count(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        self.total_reads.store(0, Ordering::Relaxed);
        self.total_writes.store(0, Ordering::Relaxed);
        self.total_ops.store(0, Ordering::Relaxed);
        self.total_metadata_ops.store(0, Ordering::Relaxed);
        self.total_errors.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.bytes_decrypted.store(0, Ordering::Relaxed);
        self.bytes_encrypted.store(0, Ordering::Relaxed);
        self.cache_stats.reset();
        self.read_latency.reset();
        self.write_latency.reset();
        self.metadata_latency.reset();
    }

    /// Create a snapshot of current statistics.
    pub fn snapshot(&self) -> VaultStatsSnapshot {
        VaultStatsSnapshot {
            total_reads: self.read_count(),
            total_writes: self.write_count(),
            total_ops: self.op_count(),
            total_metadata_ops: self.metadata_op_count(),
            total_errors: self.error_count(),
            bytes_read: self.bytes_read(),
            bytes_written: self.bytes_written(),
            bytes_decrypted: self.bytes_decrypted(),
            bytes_encrypted: self.bytes_encrypted(),
            open_files: self.open_file_count(),
            open_dirs: self.open_dir_count(),
            cache: self.cache_stats.snapshot(),
            cache_health: self.cache_stats.health(),
            read_latency_avg_ms: self.avg_read_latency_ms(),
            write_latency_avg_ms: self.avg_write_latency_ms(),
            metadata_latency_avg_ms: self.avg_metadata_latency_ms(),
            session_start: self.session_start,
        }
    }

    /// Create a snapshot with custom cache health thresholds.
    ///
    /// This allows the caller to specify custom warning thresholds
    /// for cache health assessment.
    pub fn snapshot_with_thresholds(&self, thresholds: CacheHealthThresholds) -> VaultStatsSnapshot {
        VaultStatsSnapshot {
            total_reads: self.read_count(),
            total_writes: self.write_count(),
            total_ops: self.op_count(),
            total_metadata_ops: self.metadata_op_count(),
            total_errors: self.error_count(),
            bytes_read: self.bytes_read(),
            bytes_written: self.bytes_written(),
            bytes_decrypted: self.bytes_decrypted(),
            bytes_encrypted: self.bytes_encrypted(),
            open_files: self.open_file_count(),
            open_dirs: self.open_dir_count(),
            cache: self.cache_stats.snapshot(),
            cache_health: self.cache_stats.health_with_thresholds(thresholds),
            read_latency_avg_ms: self.avg_read_latency_ms(),
            write_latency_avg_ms: self.avg_write_latency_ms(),
            metadata_latency_avg_ms: self.avg_metadata_latency_ms(),
            session_start: self.session_start,
        }
    }
}

/// A serializable snapshot of vault statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultStatsSnapshot {
    /// Total number of read operations.
    pub total_reads: u64,
    /// Total number of write operations.
    pub total_writes: u64,
    /// Total number of all operations.
    pub total_ops: u64,
    /// Total number of metadata operations.
    pub total_metadata_ops: u64,
    /// Total number of errors.
    pub total_errors: u64,
    /// Total bytes read.
    pub bytes_read: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total bytes decrypted.
    pub bytes_decrypted: u64,
    /// Total bytes encrypted.
    pub bytes_encrypted: u64,
    /// Current number of open files.
    pub open_files: u64,
    /// Current number of open directories.
    pub open_dirs: u64,
    /// Cache statistics snapshot.
    pub cache: CacheStatsSnapshot,
    /// Cache health assessment with warnings.
    pub cache_health: CacheHealth,
    /// Average read latency in milliseconds.
    pub read_latency_avg_ms: f64,
    /// Average write latency in milliseconds.
    pub write_latency_avg_ms: f64,
    /// Average metadata latency in milliseconds.
    pub metadata_latency_avg_ms: f64,
    /// When this session started.
    #[serde(with = "humantime_serde")]
    pub session_start: SystemTime,
}

impl VaultStatsSnapshot {
    /// Get the cache hit rate.
    pub fn cache_hit_rate(&self) -> f64 {
        self.cache.hit_rate()
    }

    /// Check if there are any cache health warnings.
    pub fn has_cache_warnings(&self) -> bool {
        !self.cache_health.warnings.is_empty()
    }

    /// Get cache health warnings.
    pub fn cache_warnings(&self) -> &[CacheWarning] {
        &self.cache_health.warnings
    }
}

/// Format bytes in human-readable form (B, KB, MB, GB, TB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Backend-agnostic scheduler statistics snapshot.
///
/// This represents a point-in-time view of scheduler health and performance,
/// abstracting over backend-specific implementations (FUSE, WebDAV, NFS, etc.).
///
/// Not all backends have schedulers, so this is optional in the `MountHandle` trait.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SchedulerStatsSnapshot {
    // Admission control
    /// Total requests accepted by the scheduler.
    pub requests_accepted: u64,
    /// Total requests rejected (queue full, shutdown, etc.).
    pub requests_rejected: u64,
    /// Rejection rate (rejected / total attempts).
    pub rejection_rate: f64,

    // Timeout tracking
    /// Requests that timed out before completion.
    pub timeouts: u64,
    /// Timeout rate (timeouts / accepted).
    pub timeout_rate: f64,
    /// Late completions (arrived after timeout).
    pub late_completions: u64,

    // Current state
    /// Total requests currently in-flight.
    pub in_flight_total: u64,
    /// In-flight requests per lane [L0-Control, L1-Metadata, L2-ReadFg, L3-WriteFg, L4-Bulk].
    pub in_flight_by_lane: [u64; 5],
    /// Current queue depth total.
    pub queue_depth_total: u64,
    /// Current queue depth per lane [L0-Control, L1-Metadata, L2-ReadFg, L3-WriteFg, L4-Bulk].
    pub queue_depth_by_lane: [u64; 5],
    /// Oldest queue wait in milliseconds.
    pub oldest_queue_wait_ms: u64,
    /// Last dequeue timestamp (ms since UNIX epoch).
    pub last_dequeue_ms: u64,

    // Executor stats
    /// Jobs submitted to the executor.
    pub executor_jobs_submitted: u64,
    /// Jobs completed by the executor.
    pub executor_jobs_completed: u64,
    /// Jobs failed in the executor.
    pub executor_jobs_failed: u64,
    /// Jobs rejected by the executor (queue full).
    pub executor_jobs_rejected: u64,
    /// Current executor queue depth.
    pub executor_queue_depth: u64,
    /// Average execution time in microseconds.
    pub executor_avg_time_us: u64,

    // Read cache stats (decrypted content cache, distinct from attribute cache)
    /// Read cache hits.
    pub read_cache_hits: u64,
    /// Read cache misses.
    pub read_cache_misses: u64,
    /// Read cache hit ratio.
    pub read_cache_hit_ratio: f64,
    /// Read cache entries.
    pub read_cache_entries: u64,
    /// Read cache size in bytes.
    pub read_cache_bytes: u64,

    // Single-flight deduplication stats
    /// Single-flight leaders (actual reads performed).
    pub dedup_leaders: u64,
    /// Single-flight waiters (deduplicated reads).
    pub dedup_waiters: u64,
    /// Deduplication ratio (waiters / total).
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

impl SchedulerStatsSnapshot {
    /// Create an empty snapshot (all zeros).
    pub fn new() -> Self {
        Self::default()
    }

    /// Format as a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Scheduler: {} accepted, {} rejected ({:.1}% rate), {} timeouts ({:.1}% rate)\n\
             In-flight: {} total, Queue: {} depth, oldest wait {}ms\n\
             Executor: {} submitted, {} completed, queue depth {}\n\
             Read cache: {:.1}% hit rate ({} hits, {} misses), {} entries, {}\n\
             Dedup: {:.1}% ratio ({} leaders, {} waiters)",
            self.requests_accepted,
            self.requests_rejected,
            self.rejection_rate * 100.0,
            self.timeouts,
            self.timeout_rate * 100.0,
            self.in_flight_total,
            self.queue_depth_total,
            self.oldest_queue_wait_ms,
            self.executor_jobs_submitted,
            self.executor_jobs_completed,
            self.executor_queue_depth,
            self.read_cache_hit_ratio * 100.0,
            self.read_cache_hits,
            self.read_cache_misses,
            self.read_cache_entries,
            format_bytes(self.read_cache_bytes),
            self.dedup_ratio * 100.0,
            self.dedup_leaders,
            self.dedup_waiters,
        )
    }

    /// Check if the scheduler is healthy (not overloaded).
    ///
    /// Returns `true` if rejection rate < 5% and timeout rate < 1%.
    pub fn is_healthy(&self) -> bool {
        self.rejection_rate < 0.05 && self.timeout_rate < 0.01
    }

    /// Check if the scheduler is experiencing backpressure.
    ///
    /// Returns `true` if rejection rate >= 5% or queue depth > 100.
    pub fn is_backpressured(&self) -> bool {
        self.rejection_rate >= 0.05 || self.executor_queue_depth > 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_stats_basic() {
        let stats = CacheStats::new();

        stats.record_hit();
        stats.record_hit();
        stats.record_miss();

        assert_eq!(stats.hit_count(), 2);
        assert_eq!(stats.miss_count(), 1);
        assert!((stats.hit_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_cache_stats_zero_rate() {
        let stats = CacheStats::new();
        assert!((stats.hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_vault_stats_operations() {
        let stats = VaultStats::new();

        stats.record_read(1024);
        stats.record_read(2048);
        stats.record_write(512);

        assert_eq!(stats.read_count(), 2);
        assert_eq!(stats.write_count(), 1);
        assert_eq!(stats.op_count(), 3);
        assert_eq!(stats.bytes_read(), 3072);
        assert_eq!(stats.bytes_written(), 512);
    }

    #[test]
    fn test_vault_stats_activity() {
        let stats = VaultStats::new();

        // Initially should be idle (or active if just created)
        stats.record_read(100);
        assert!(stats.is_active(Duration::from_secs(1)));

        // Simulate idle time (we can't actually wait, so test the logic)
        assert!(!stats.is_active(Duration::ZERO));
    }

    #[test]
    fn test_vault_stats_concurrent() {
        use std::sync::Arc;

        let stats = Arc::new(VaultStats::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let stats = Arc::clone(&stats);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    stats.record_read(100);
                    stats.record_write(50);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stats.read_count(), 1000);
        assert_eq!(stats.write_count(), 1000);
        assert_eq!(stats.bytes_read(), 100_000);
        assert_eq!(stats.bytes_written(), 50_000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_activity_status() {
        let stats = VaultStats::new();

        // Start with idle (no recent ops after construction delay)
        // Since we just created it, it might be active
        stats.start_read();
        assert_eq!(
            stats.activity_status(Duration::from_secs(1)),
            ActivityStatus::Reading
        );
        stats.finish_read();

        stats.start_write();
        assert_eq!(
            stats.activity_status(Duration::from_secs(1)),
            ActivityStatus::Writing
        );
        stats.finish_write();
    }

    #[test]
    fn test_snapshot_serialization() {
        let stats = VaultStats::new();
        stats.record_read(1024);
        stats.record_write(512);
        stats.cache_stats().record_hit();
        stats.cache_stats().record_miss();

        let snapshot = stats.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: VaultStatsSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_reads, 1);
        assert_eq!(restored.total_writes, 1);
        assert_eq!(restored.bytes_read, 1024);
    }

    #[test]
    fn test_latency_stats_basic() {
        let stats = LatencyStats::new();

        // Initially no ops
        assert_eq!(stats.count(), 0);
        assert!((stats.avg_nanos() - 0.0).abs() < f64::EPSILON);

        // Record some durations
        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));

        assert_eq!(stats.count(), 3);
        // Average should be 20ms
        let avg_ms = stats.avg_millis();
        assert!((avg_ms - 20.0).abs() < 0.1, "avg_ms = {avg_ms}");
    }

    #[test]
    fn test_latency_stats_reset() {
        let stats = LatencyStats::new();
        stats.record(Duration::from_millis(100));
        assert_eq!(stats.count(), 1);

        stats.reset();
        assert_eq!(stats.count(), 0);
        assert!((stats.avg_nanos() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_vault_stats_latency() {
        let stats = VaultStats::new();

        stats.record_read_latency(Duration::from_millis(5));
        stats.record_read_latency(Duration::from_millis(15));
        stats.record_write_latency(Duration::from_millis(10));

        assert_eq!(stats.read_latency_count(), 2);
        assert_eq!(stats.write_latency_count(), 1);

        // Average read latency should be 10ms
        let avg_read = stats.avg_read_latency_ms();
        assert!((avg_read - 10.0).abs() < 0.1, "avg_read = {avg_read}");

        // Average write latency should be 10ms
        let avg_write = stats.avg_write_latency_ms();
        assert!((avg_write - 10.0).abs() < 0.1, "avg_write = {avg_write}");
    }

    #[test]
    fn test_snapshot_includes_latency() {
        let stats = VaultStats::new();
        stats.record_read_latency(Duration::from_millis(8));
        stats.record_write_latency(Duration::from_millis(12));

        let snapshot = stats.snapshot();

        assert!((snapshot.read_latency_avg_ms - 8.0).abs() < 0.1);
        assert!((snapshot.write_latency_avg_ms - 12.0).abs() < 0.1);
    }

    #[test]
    fn test_vault_stats_metadata_ops() {
        let stats = VaultStats::new();

        // Initially no metadata ops
        assert_eq!(stats.metadata_op_count(), 0);
        assert_eq!(stats.metadata_latency_count(), 0);

        // Record some metadata operations
        stats.record_metadata_op();
        stats.record_metadata_op();
        stats.record_metadata_op();

        assert_eq!(stats.metadata_op_count(), 3);
        // Metadata ops should also count as total ops
        assert_eq!(stats.op_count(), 3);

        // Record latency for metadata ops
        stats.record_metadata_latency(Duration::from_millis(5));
        stats.record_metadata_latency(Duration::from_millis(15));

        assert_eq!(stats.metadata_latency_count(), 2);
        // Average should be 10ms
        let avg = stats.avg_metadata_latency_ms();
        assert!((avg - 10.0).abs() < 0.1, "avg_metadata_latency = {avg}");
    }

    #[test]
    fn test_vault_stats_errors() {
        let stats = VaultStats::new();

        // Initially no errors
        assert_eq!(stats.error_count(), 0);

        // Record some errors
        stats.record_error();
        stats.record_error();

        assert_eq!(stats.error_count(), 2);
    }

    #[test]
    fn test_vault_stats_reset_includes_new_fields() {
        let stats = VaultStats::new();

        // Add some data
        stats.record_metadata_op();
        stats.record_metadata_latency(Duration::from_millis(10));
        stats.record_error();

        assert!(stats.metadata_op_count() > 0);
        assert!(stats.error_count() > 0);

        // Reset should clear everything
        stats.reset();

        assert_eq!(stats.metadata_op_count(), 0);
        assert_eq!(stats.metadata_latency_count(), 0);
        assert_eq!(stats.error_count(), 0);
    }

    #[test]
    fn test_snapshot_includes_metadata_and_errors() {
        let stats = VaultStats::new();

        stats.record_metadata_op();
        stats.record_metadata_op();
        stats.record_metadata_latency(Duration::from_millis(6));
        stats.record_error();

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.total_metadata_ops, 2);
        assert_eq!(snapshot.total_errors, 1);
        assert!((snapshot.metadata_latency_avg_ms - 6.0).abs() < 0.1);

        // Verify serialization includes new fields
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"total_metadata_ops\":2"));
        assert!(json.contains("\"total_errors\":1"));
        assert!(json.contains("metadata_latency_avg_ms"));
    }
}
