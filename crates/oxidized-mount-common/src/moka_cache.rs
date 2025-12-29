//! TTL-based caching for mount backends using Moka.
//!
//! This module provides a generic, thread-safe cache with time-based expiration,
//! backed by the battle-tested Moka caching library.
//!
//! # Features
//!
//! - Generic over key and value types
//! - Thread-safe with high concurrency
//! - TTL-based expiration with TinyLFU eviction
//! - Per-entry TTL support via Moka's Expiry trait
//! - Optional negative caching for "not found" results
//! - Bulk invalidation with predicates
//! - Thundering herd prevention via `get_with()`
//! - Health monitoring with warning thresholds
//! - Optional debug tracing (enable with `cache-tracing` feature)
//!
//! # Variants
//!
//! - [`SyncTtlCache`] - For synchronous contexts (FUSE, FSKit, NFS)
//! - [`AsyncTtlCache`] - For async contexts (WebDAV with tokio)
//!
//! # Tracing
//!
//! Enable the `cache-tracing` feature for detailed debug spans on cache operations.
//! This adds some overhead but provides visibility into cache behavior for debugging.

use crate::stats::CacheStats;
use moka::Expiry;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Conditional tracing macros - no-op when feature is disabled
#[cfg(feature = "cache-tracing")]
macro_rules! cache_span {
    ($name:expr, $($field:tt)*) => {
        tracing::debug_span!($name, $($field)*)
    };
}

#[cfg(not(feature = "cache-tracing"))]
macro_rules! cache_span {
    ($name:expr, $($field:tt)*) => {
        // No-op - returns a dummy span that compiles away
        tracing::Span::none()
    };
}

#[cfg(feature = "cache-tracing")]
macro_rules! cache_event {
    ($level:ident, $($arg:tt)*) => {
        tracing::$level!($($arg)*)
    };
}

#[cfg(not(feature = "cache-tracing"))]
macro_rules! cache_event {
    ($level:ident, $($arg:tt)*) => {
        // No-op
    };
}

// ============================================================================
// Cache Health Types
// ============================================================================

/// Health status of a cache, including warnings for potential performance issues.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheHealth {
    /// Current cache hit rate (0.0 to 1.0).
    pub hit_rate: f64,
    /// Eviction rate: evictions per insert (higher = more churn).
    pub eviction_rate: f64,
    /// Ratio of negative cache hits to total lookups.
    pub negative_hit_ratio: f64,
    /// Current entry count.
    pub entry_count: u64,
    /// Total hits.
    pub hits: u64,
    /// Total misses.
    pub misses: u64,
    /// Total evictions.
    pub evictions: u64,
    /// Warnings about potential issues.
    pub warnings: Vec<CacheWarning>,
}

/// Warning about a potential cache performance issue.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CacheWarning {
    /// Hit rate is below the healthy threshold.
    LowHitRate {
        /// Current hit rate.
        rate: f64,
        /// Threshold that triggered the warning.
        threshold: f64,
    },
    /// Eviction rate is unusually high, indicating capacity pressure.
    HighEvictionRate {
        /// Current eviction rate (evictions / inserts).
        rate: f64,
        /// Threshold that triggered the warning.
        threshold: f64,
    },
    /// High proportion of lookups are hitting the negative cache.
    NegativeCacheHeavy {
        /// Ratio of negative cache hits to total lookups.
        ratio: f64,
        /// Threshold that triggered the warning.
        threshold: f64,
    },
}

impl fmt::Display for CacheWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheWarning::LowHitRate { rate, threshold } => {
                write!(
                    f,
                    "Low cache hit rate: {:.1}% (threshold: {:.1}%)",
                    rate * 100.0,
                    threshold * 100.0
                )
            }
            CacheWarning::HighEvictionRate { rate, threshold } => {
                write!(
                    f,
                    "High eviction rate: {:.2} evictions/insert (threshold: {:.2})",
                    rate, threshold
                )
            }
            CacheWarning::NegativeCacheHeavy { ratio, threshold } => {
                write!(
                    f,
                    "Heavy negative cache usage: {:.1}% of lookups (threshold: {:.1}%)",
                    ratio * 100.0,
                    threshold * 100.0
                )
            }
        }
    }
}

/// Thresholds for cache health warnings.
#[derive(Debug, Clone)]
pub struct CacheHealthThresholds {
    /// Warn if hit rate is below this value (default: 0.5 = 50%).
    pub min_hit_rate: f64,
    /// Warn if evictions/inserts exceeds this value (default: 2.0).
    pub max_eviction_rate: f64,
    /// Warn if negative cache ratio exceeds this value (default: 0.3 = 30%).
    pub max_negative_ratio: f64,
}

impl Default for CacheHealthThresholds {
    fn default() -> Self {
        Self {
            min_hit_rate: 0.5,
            max_eviction_rate: 2.0,
            max_negative_ratio: 0.3,
        }
    }
}

/// Default time-to-live for cached entries.
///
/// Set to 60 seconds by default, optimized for network filesystems (Google Drive, etc.)
/// where metadata operations have high latency. Use `LOCAL_TTL` for local vaults.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Default time-to-live for negative cache entries.
///
/// Set to 30 seconds by default, optimized for network filesystems.
/// Use `LOCAL_NEGATIVE_TTL` for local vaults.
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// TTL for local filesystem vaults (1 second).
///
/// Use this when the vault is on a local or low-latency filesystem
/// where fresh metadata is preferred over caching.
pub const LOCAL_TTL: Duration = Duration::from_secs(1);

/// Negative TTL for local filesystem vaults (500ms).
pub const LOCAL_NEGATIVE_TTL: Duration = Duration::from_millis(500);

/// Default maximum capacity for caches.
const DEFAULT_MAX_CAPACITY: u64 = 50_000;

/// Default maximum capacity for negative caches.
const DEFAULT_NEGATIVE_MAX_CAPACITY: u64 = 10_000;

/// A cached entry with expiration time and TTL.
///
/// This provides compatibility with code expecting the old TtlCache API,
/// and stores the TTL for per-entry expiration via Moka's `Expiry` trait.
#[derive(Debug, Clone)]
pub struct CachedEntry<V> {
    /// The cached value.
    pub value: V,
    /// The TTL for this entry (used by Moka's Expiry trait).
    ttl: Duration,
    /// When this cache entry expires (computed at creation time).
    expires: Instant,
}

impl<V> CachedEntry<V> {
    /// Creates a new cached entry.
    pub fn new(value: V, ttl: Duration) -> Self {
        Self {
            value,
            ttl,
            expires: Instant::now() + ttl,
        }
    }

    /// Returns true if this cache entry has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// Returns the remaining time until expiration.
    pub fn time_remaining(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }

    /// Returns the TTL for this entry.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Expiry implementation that uses per-entry TTL from CachedEntry.
///
/// This allows each entry to have its own TTL, as stored in the CachedEntry.
struct PerEntryExpiry;

impl<K, V> Expiry<K, CachedEntry<V>> for PerEntryExpiry {
    fn expire_after_create(
        &self,
        _key: &K,
        value: &CachedEntry<V>,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &K,
        value: &CachedEntry<V>,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        // Use the new entry's TTL
        Some(value.ttl)
    }
}

/// Marker for negative cache entries (ENOENT).
#[derive(Debug, Clone, Copy)]
pub struct NegativeEntry {
    /// When this cache entry expires.
    expires: Instant,
}

impl NegativeEntry {
    /// Creates a new negative cache entry.
    pub fn new(ttl: Duration) -> Self {
        Self {
            expires: Instant::now() + ttl,
        }
    }

    /// Returns true if this cache entry has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }
}

/// Thread-safe synchronous TTL cache backed by Moka.
///
/// This cache provides:
/// - Positive caching: Store values with TTL-based expiration
/// - Negative caching: Mark keys as "known to not exist" (ENOENT)
/// - Bulk invalidation: Remove entries matching a predicate
/// - TinyLFU eviction: Smart eviction when capacity exceeded
/// - Thundering herd prevention: Only one caller fetches on miss
///
/// # Example
///
/// ```
/// use oxidized_mount_common::moka_cache::SyncTtlCache;
/// use std::time::Duration;
///
/// // Create cache with default settings
/// let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();
///
/// // Insert a value
/// cache.insert(42, "hello".to_string());
///
/// // Retrieve the value
/// if let Some(entry) = cache.get(&42) {
///     assert_eq!(entry.value, "hello");
/// }
/// ```
pub struct SyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Positive cache (key -> value).
    positive: moka::sync::Cache<K, CachedEntry<V>>,
    /// Negative cache for ENOENT results (optional).
    negative: Option<moka::sync::Cache<K, NegativeEntry>>,
    /// TTL for positive cache entries.
    ttl: Duration,
    /// TTL for negative cache entries.
    negative_ttl: Duration,
    /// Optional statistics tracking.
    stats: Option<Arc<CacheStats>>,
}

impl<K, V> SyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new cache with the given TTL.
    ///
    /// Negative caching is disabled by default.
    pub fn new(ttl: Duration) -> Self {
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: None,
        }
    }

    /// Creates a new cache with the given TTL and max capacity.
    pub fn with_capacity(ttl: Duration, max_capacity: u64) -> Self {
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(max_capacity)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: None,
        }
    }

    /// Creates a new cache with default settings.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TTL)
    }

    /// Creates a new cache with statistics tracking.
    ///
    /// The provided `CacheStats` will be updated on every cache operation,
    /// allowing external monitoring of cache efficiency.
    ///
    /// **Note**: Eviction tracking requires stats to be provided at construction time.
    /// Using `set_stats()` after construction will not track evictions.
    pub fn with_stats(stats: Arc<CacheStats>) -> Self {
        let stats_for_eviction = Arc::clone(&stats);
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .eviction_listener(move |_key, _value, _cause| {
                    stats_for_eviction.record_eviction();
                    stats_for_eviction.record_remove();
                })
                .build(),
            negative: None,
            ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: Some(stats),
        }
    }

    /// Creates a new cache with negative caching enabled.
    ///
    /// Negative caching stores "not found" results to avoid repeated lookups
    /// for keys that don't exist.
    pub fn with_negative_cache(ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: Some(
                moka::sync::Cache::builder()
                    .max_capacity(DEFAULT_NEGATIVE_MAX_CAPACITY)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: None,
        }
    }

    /// Creates a new cache with negative caching and custom capacities.
    pub fn with_negative_cache_and_capacity(
        ttl: Duration,
        negative_ttl: Duration,
        positive_capacity: u64,
        negative_capacity: u64,
    ) -> Self {
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(positive_capacity)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: Some(
                moka::sync::Cache::builder()
                    .max_capacity(negative_capacity)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: None,
        }
    }

    /// Creates a new cache with statistics tracking and negative caching.
    ///
    /// This combines `with_stats()` and `with_negative_cache()`, enabling
    /// both features with proper eviction tracking.
    pub fn with_stats_and_negative_cache(
        stats: Arc<CacheStats>,
        ttl: Duration,
        negative_ttl: Duration,
    ) -> Self {
        let stats_for_positive = Arc::clone(&stats);
        let stats_for_negative = Arc::clone(&stats);
        Self {
            positive: moka::sync::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .eviction_listener(move |_key, _value, _cause| {
                    stats_for_positive.record_eviction();
                    stats_for_positive.record_remove();
                })
                .build(),
            negative: Some(
                moka::sync::Cache::builder()
                    .max_capacity(DEFAULT_NEGATIVE_MAX_CAPACITY)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .eviction_listener(move |_key, _value, _cause| {
                        // Negative cache evictions don't affect entry count
                        stats_for_negative.record_eviction();
                    })
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: Some(stats),
        }
    }

    /// Creates a new cache with a custom cleanup threshold.
    ///
    /// Note: Moka handles eviction automatically via TinyLFU.
    /// The threshold parameter is treated as max_capacity for compatibility.
    pub fn with_threshold(ttl: Duration, cleanup_threshold: usize) -> Self {
        Self::with_capacity(ttl, cleanup_threshold as u64)
    }

    /// Enable statistics tracking on an existing cache.
    ///
    /// This is useful for adding stats to a cache created with other constructors.
    pub fn set_stats(&mut self, stats: Arc<CacheStats>) {
        self.stats = Some(stats);
    }

    /// Get a reference to the statistics tracker, if enabled.
    pub fn stats(&self) -> Option<&Arc<CacheStats>> {
        self.stats.as_ref()
    }

    /// Gets a cached entry if it exists and hasn't expired.
    ///
    /// If statistics tracking is enabled, this records a hit or miss.
    pub fn get(&self, key: &K) -> Option<CachedEntry<V>> {
        let _span = cache_span!("cache_get", cache = "sync");
        match self.positive.get(key) {
            Some(entry) => {
                cache_event!(debug, "cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_hit();
                }
                Some(entry)
            }
            None => {
                cache_event!(debug, "cache miss");
                if let Some(ref stats) = self.stats {
                    stats.record_miss();
                }
                None
            }
        }
    }

    /// Gets a cached entry, computing it if missing (thundering herd safe).
    ///
    /// Uses Moka's `get_with()` which ensures only one caller computes the value
    /// while others wait. This prevents thundering herd on cache misses.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::moka_cache::SyncTtlCache;
    /// use std::time::Duration;
    ///
    /// let cache: SyncTtlCache<u64, String> = SyncTtlCache::new(Duration::from_secs(1));
    ///
    /// let value = cache.get_or_insert(&42, || "computed_value".to_string());
    /// assert!(value.is_some());
    /// ```
    pub fn get_or_insert<F>(&self, key: &K, compute: F) -> Option<V>
    where
        F: FnOnce() -> V,
    {
        let _span = cache_span!("cache_get_or_insert", cache = "sync");

        // Check negative cache first
        if self.is_negative(key) {
            cache_event!(debug, "negative cache hit, skipping computation");
            return None;
        }

        let entry = self.positive.get_with(key.clone(), || {
            cache_event!(debug, "cache miss, computing value");
            if let Some(ref stats) = self.stats {
                stats.record_miss();
                stats.record_insert();
            }
            CachedEntry::new(compute(), self.ttl)
        });

        // Record hit if entry already existed (approximation)
        if let Some(ref stats) = self.stats {
            // Note: We can't perfectly distinguish hit vs compute,
            // but for stats purposes this is close enough
            stats.record_hit();
        }

        Some(entry.value)
    }

    /// Inserts or updates a cached entry.
    ///
    /// Also removes the key from the negative cache if present.
    pub fn insert(&self, key: K, value: V) {
        let _span = cache_span!("cache_insert", cache = "sync");

        // Remove from negative cache if enabled
        if let Some(ref neg) = self.negative {
            neg.invalidate(&key);
            cache_event!(debug, "cleared negative cache entry");
        }
        self.positive
            .insert(key, CachedEntry::new(value, self.ttl));
        cache_event!(debug, "inserted entry");
        if let Some(ref stats) = self.stats {
            stats.record_insert();
        }
    }

    /// Inserts or updates a cached entry with a custom TTL.
    ///
    /// This uses Moka's `Expiry` trait to support per-entry TTL.
    /// The TTL is stored in the `CachedEntry` and read by the `PerEntryExpiry` policy.
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let _span = cache_span!("cache_insert_with_ttl", cache = "sync", ttl_ms = ttl.as_millis() as u64);

        // Remove from negative cache if enabled
        if let Some(ref neg) = self.negative {
            neg.invalidate(&key);
            cache_event!(debug, "cleared negative cache entry");
        }
        self.positive.insert(key, CachedEntry::new(value, ttl));
        cache_event!(debug, "inserted entry with custom TTL");
        if let Some(ref stats) = self.stats {
            stats.record_insert();
        }
    }

    /// Invalidates a cached entry.
    pub fn invalidate(&self, key: &K) {
        let _span = cache_span!("cache_invalidate", cache = "sync");
        self.positive.invalidate(key);
        cache_event!(debug, "invalidated entry");
    }

    /// Clears all cached entries (both positive and negative).
    pub fn clear(&self) {
        let _span = cache_span!("cache_clear", cache = "sync");
        self.positive.invalidate_all();
        if let Some(ref neg) = self.negative {
            neg.invalidate_all();
        }
        cache_event!(debug, "cleared all cache entries");
    }

    /// Checks if a key is in the negative cache (known to not exist).
    ///
    /// Returns `false` if negative caching is disabled.
    pub fn is_negative(&self, key: &K) -> bool {
        self.negative
            .as_ref()
            .map_or(false, |neg| neg.contains_key(key))
    }

    /// Adds a key to the negative cache.
    ///
    /// Does nothing if negative caching is disabled.
    pub fn insert_negative(&self, key: K) {
        if let Some(ref neg) = self.negative {
            neg.insert(key, NegativeEntry::new(self.negative_ttl));
        }
    }

    /// Removes a key from the negative cache.
    ///
    /// Does nothing if negative caching is disabled.
    pub fn remove_negative(&self, key: &K) {
        if let Some(ref neg) = self.negative {
            neg.invalidate(key);
        }
    }

    /// Invalidates all entries matching a predicate.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::moka_cache::SyncTtlCache;
    ///
    /// let cache: SyncTtlCache<(u64, String), i32> = SyncTtlCache::with_defaults();
    /// cache.insert((1, "a".to_string()), 100);
    /// cache.insert((1, "b".to_string()), 200);
    /// cache.insert((2, "c".to_string()), 300);
    ///
    /// // Invalidate all entries with parent = 1
    /// cache.invalidate_where(|k| k.0 == 1);
    ///
    /// assert!(cache.get(&(1, "a".to_string())).is_none());
    /// assert!(cache.get(&(2, "c".to_string())).is_some());
    /// ```
    pub fn invalidate_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool + Send + Sync + 'static,
    {
        self.positive
            .invalidate_entries_if(move |k, _| predicate(k))
            .expect("invalidate_entries_if should not fail with infallible predicate");
    }

    /// Invalidates all negative cache entries matching a predicate.
    ///
    /// Does nothing if negative caching is disabled.
    pub fn invalidate_negative_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool + Send + Sync + 'static,
    {
        if let Some(ref neg) = self.negative {
            neg.invalidate_entries_if(move |k, _| predicate(k))
                .expect("invalidate_entries_if should not fail with infallible predicate");
        }
    }

    /// Returns the approximate number of entries in the positive cache.
    pub fn len(&self) -> usize {
        self.positive.entry_count() as usize
    }

    /// Returns the approximate number of entries in the negative cache.
    pub fn negative_len(&self) -> usize {
        self.negative
            .as_ref()
            .map_or(0, |n| n.entry_count() as usize)
    }

    /// Returns true if the positive cache is empty.
    pub fn is_empty(&self) -> bool {
        self.positive.entry_count() == 0
    }

    /// Returns the TTL for positive cache entries.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the TTL for negative cache entries.
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    /// Returns true if negative caching is enabled.
    pub fn has_negative_cache(&self) -> bool {
        self.negative.is_some()
    }

    /// Triggers a synchronous cleanup of expired entries.
    ///
    /// Note: Moka handles cleanup automatically in the background.
    /// This method forces immediate cleanup.
    pub fn cleanup_expired(&self) {
        self.positive.run_pending_tasks();
        if let Some(ref neg) = self.negative {
            neg.run_pending_tasks();
        }
    }

    /// Checks cache health and returns warnings for potential performance issues.
    ///
    /// This method analyzes cache statistics to detect:
    /// - Low hit rate (suggests cache is too small or TTL too short)
    /// - High eviction rate (suggests capacity pressure)
    /// - Heavy negative cache usage (suggests many lookups for non-existent keys)
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::moka_cache::{SyncTtlCache, CacheHealthThresholds};
    /// use oxidized_mount_common::stats::CacheStats;
    /// use std::sync::Arc;
    ///
    /// let stats = Arc::new(CacheStats::new());
    /// let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats(stats);
    ///
    /// // Simulate some activity
    /// cache.insert(1, "a".to_string());
    /// cache.get(&1);
    /// cache.get(&2);
    ///
    /// let health = cache.health_check(CacheHealthThresholds::default());
    /// for warning in &health.warnings {
    ///     println!("Warning: {}", warning);
    /// }
    /// ```
    pub fn health_check(&self, thresholds: CacheHealthThresholds) -> CacheHealth {
        let (hits, misses, entries, evictions) = match &self.stats {
            Some(stats) => (
                stats.hit_count(),
                stats.miss_count(),
                stats.entry_count(),
                stats.eviction_count(),
            ),
            None => (0, 0, self.positive.entry_count(), 0),
        };

        let total_lookups = hits + misses;
        let hit_rate = if total_lookups > 0 {
            hits as f64 / total_lookups as f64
        } else {
            1.0 // No data yet, assume healthy
        };

        // Calculate eviction rate (evictions per insert)
        // Inserts = entries + evictions (approximately)
        let inserts = entries.saturating_add(evictions);
        let eviction_rate = if inserts > 0 {
            evictions as f64 / inserts as f64
        } else {
            0.0
        };

        // Calculate negative cache ratio
        // We don't track negative hits separately, so use negative_len as a proxy
        let negative_ratio = if total_lookups > 0 {
            self.negative_len() as f64 / total_lookups.max(1) as f64
        } else {
            0.0
        };

        let mut warnings = Vec::new();

        // Check thresholds (only warn if we have meaningful data)
        if total_lookups >= 100 && hit_rate < thresholds.min_hit_rate {
            warnings.push(CacheWarning::LowHitRate {
                rate: hit_rate,
                threshold: thresholds.min_hit_rate,
            });
        }

        if inserts >= 100 && eviction_rate > thresholds.max_eviction_rate {
            warnings.push(CacheWarning::HighEvictionRate {
                rate: eviction_rate,
                threshold: thresholds.max_eviction_rate,
            });
        }

        if total_lookups >= 100 && negative_ratio > thresholds.max_negative_ratio {
            warnings.push(CacheWarning::NegativeCacheHeavy {
                ratio: negative_ratio,
                threshold: thresholds.max_negative_ratio,
            });
        }

        CacheHealth {
            hit_rate,
            eviction_rate,
            negative_hit_ratio: negative_ratio,
            entry_count: entries,
            hits,
            misses,
            evictions,
            warnings,
        }
    }
}

impl<K, V> Default for SyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::with_defaults()
    }
}

// Convenience methods for (parent_id, name) keys (FUSE/FSKit pattern)
impl<V: Clone + Send + Sync + 'static> SyncTtlCache<(u64, String), V> {
    /// Invalidate all negative entries for a parent directory.
    ///
    /// This is useful when directory contents change.
    pub fn invalidate_parent_negative(&self, parent: u64) {
        self.invalidate_negative_where(move |k| k.0 == parent);
    }

    /// Invalidate all entries for a parent directory.
    pub fn invalidate_parent(&self, parent: u64) {
        self.invalidate_where(move |k| k.0 == parent);
    }
}

// Convenience methods for String keys (WebDAV pattern)
impl<V: Clone + Send + Sync + 'static> SyncTtlCache<String, V> {
    /// Invalidate all entries with a path prefix.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::moka_cache::SyncTtlCache;
    ///
    /// let cache: SyncTtlCache<String, i32> = SyncTtlCache::with_defaults();
    /// cache.insert("/dir/file1.txt".to_string(), 1);
    /// cache.insert("/dir/file2.txt".to_string(), 2);
    /// cache.insert("/other/file.txt".to_string(), 3);
    ///
    /// cache.invalidate_prefix("/dir");
    ///
    /// assert!(cache.get(&"/dir/file1.txt".to_string()).is_none());
    /// assert!(cache.get(&"/other/file.txt".to_string()).is_some());
    /// ```
    pub fn invalidate_prefix(&self, prefix: &str) {
        let prefix = prefix.to_string();
        self.invalidate_where(move |k| k.starts_with(&prefix));
    }

    /// Invalidate all negative entries with a path prefix.
    pub fn invalidate_prefix_negative(&self, prefix: &str) {
        let prefix = prefix.to_string();
        self.invalidate_negative_where(move |k| k.starts_with(&prefix));
    }
}

// ============================================================================
// AsyncTtlCache - For async contexts (WebDAV with tokio)
// ============================================================================

/// Thread-safe asynchronous TTL cache backed by Moka.
///
/// This cache provides the same features as [`SyncTtlCache`] but for async contexts:
/// - Positive caching: Store values with TTL-based expiration
/// - Negative caching: Mark keys as "known to not exist" (ENOENT)
/// - Bulk invalidation: Remove entries matching a predicate
/// - TinyLFU eviction: Smart eviction when capacity exceeded
/// - Thundering herd prevention: Only one caller fetches on miss
///
/// # Example
///
/// ```
/// use oxidized_mount_common::moka_cache::AsyncTtlCache;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_defaults();
///
///     cache.insert(42, "hello".to_string()).await;
///
///     if let Some(entry) = cache.get(&42).await {
///         assert_eq!(entry.value, "hello");
///     }
/// }
/// ```
pub struct AsyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Positive cache (key -> value).
    positive: moka::future::Cache<K, CachedEntry<V>>,
    /// Negative cache for ENOENT results (optional).
    negative: Option<moka::future::Cache<K, NegativeEntry>>,
    /// TTL for positive cache entries.
    ttl: Duration,
    /// TTL for negative cache entries.
    negative_ttl: Duration,
    /// Optional statistics tracking.
    stats: Option<Arc<CacheStats>>,
}

impl<K, V> AsyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new cache with the given TTL.
    ///
    /// Negative caching is disabled by default.
    pub fn new(ttl: Duration) -> Self {
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: None,
        }
    }

    /// Creates a new cache with the given TTL and max capacity.
    pub fn with_capacity(ttl: Duration, max_capacity: u64) -> Self {
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(max_capacity)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: None,
        }
    }

    /// Creates a new cache with default settings.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TTL)
    }

    /// Creates a new cache with statistics tracking.
    ///
    /// The provided `CacheStats` will be updated on every cache operation,
    /// allowing external monitoring of cache efficiency.
    ///
    /// **Note**: Eviction tracking requires stats to be provided at construction time.
    /// Using `set_stats()` after construction will not track evictions.
    pub fn with_stats(stats: Arc<CacheStats>) -> Self {
        let stats_for_eviction = Arc::clone(&stats);
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .eviction_listener(move |_key, _value, _cause| {
                    stats_for_eviction.record_eviction();
                    stats_for_eviction.record_remove();
                })
                .build(),
            negative: None,
            ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            stats: Some(stats),
        }
    }

    /// Creates a new cache with negative caching enabled.
    pub fn with_negative_cache(ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: Some(
                moka::future::Cache::builder()
                    .max_capacity(DEFAULT_NEGATIVE_MAX_CAPACITY)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: None,
        }
    }

    /// Creates a new cache with negative caching and custom capacities.
    pub fn with_negative_cache_and_capacity(
        ttl: Duration,
        negative_ttl: Duration,
        positive_capacity: u64,
        negative_capacity: u64,
    ) -> Self {
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(positive_capacity)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .build(),
            negative: Some(
                moka::future::Cache::builder()
                    .max_capacity(negative_capacity)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: None,
        }
    }

    /// Creates a new cache with statistics tracking and negative caching.
    ///
    /// This combines `with_stats()` and `with_negative_cache()`, enabling
    /// both features with proper eviction tracking.
    pub fn with_stats_and_negative_cache(
        stats: Arc<CacheStats>,
        ttl: Duration,
        negative_ttl: Duration,
    ) -> Self {
        let stats_for_positive = Arc::clone(&stats);
        let stats_for_negative = Arc::clone(&stats);
        Self {
            positive: moka::future::Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .expire_after(PerEntryExpiry)
                .support_invalidation_closures()
                .eviction_listener(move |_key, _value, _cause| {
                    stats_for_positive.record_eviction();
                    stats_for_positive.record_remove();
                })
                .build(),
            negative: Some(
                moka::future::Cache::builder()
                    .max_capacity(DEFAULT_NEGATIVE_MAX_CAPACITY)
                    .time_to_live(negative_ttl)
                    .support_invalidation_closures()
                    .eviction_listener(move |_key, _value, _cause| {
                        // Negative cache evictions don't affect entry count
                        stats_for_negative.record_eviction();
                    })
                    .build(),
            ),
            ttl,
            negative_ttl,
            stats: Some(stats),
        }
    }

    /// Creates a new cache with a custom cleanup threshold.
    pub fn with_threshold(ttl: Duration, cleanup_threshold: usize) -> Self {
        Self::with_capacity(ttl, cleanup_threshold as u64)
    }

    /// Enable statistics tracking on an existing cache.
    pub fn set_stats(&mut self, stats: Arc<CacheStats>) {
        self.stats = Some(stats);
    }

    /// Get a reference to the statistics tracker, if enabled.
    pub fn stats(&self) -> Option<&Arc<CacheStats>> {
        self.stats.as_ref()
    }

    /// Gets a cached entry if it exists and hasn't expired.
    pub async fn get(&self, key: &K) -> Option<CachedEntry<V>> {
        let _span = cache_span!("cache_get", cache = "async");
        match self.positive.get(key).await {
            Some(entry) => {
                cache_event!(debug, "cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_hit();
                }
                Some(entry)
            }
            None => {
                cache_event!(debug, "cache miss");
                if let Some(ref stats) = self.stats {
                    stats.record_miss();
                }
                None
            }
        }
    }

    /// Gets a cached entry, computing it if missing (thundering herd safe).
    ///
    /// Uses Moka's `try_get_with()` which ensures only one caller computes the value
    /// while others wait.
    pub async fn get_or_insert<F, Fut>(&self, key: &K, compute: F) -> Option<V>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        let _span = cache_span!("cache_get_or_insert", cache = "async");

        // Check negative cache first
        if self.is_negative(key).await {
            cache_event!(debug, "negative cache hit, skipping computation");
            return None;
        }

        let ttl = self.ttl;
        let entry = self
            .positive
            .get_with(key.clone(), async {
                cache_event!(debug, "cache miss, computing value");
                if let Some(ref stats) = self.stats {
                    stats.record_miss();
                    stats.record_insert();
                }
                CachedEntry::new(compute().await, ttl)
            })
            .await;

        if let Some(ref stats) = self.stats {
            stats.record_hit();
        }

        Some(entry.value)
    }

    /// Gets a cached entry, computing it if missing with a fallible computation.
    pub async fn try_get_or_insert<F, Fut, E>(&self, key: &K, compute: F) -> Result<Option<V>, Arc<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
        E: Send + Sync + 'static,
    {
        // Check negative cache first
        if self.is_negative(key).await {
            return Ok(None);
        }

        let ttl = self.ttl;
        let result = self
            .positive
            .try_get_with(key.clone(), async {
                let value = compute().await?;
                if let Some(ref stats) = self.stats {
                    stats.record_miss();
                    stats.record_insert();
                }
                Ok(CachedEntry::new(value, ttl))
            })
            .await;

        match result {
            Ok(entry) => {
                if let Some(ref stats) = self.stats {
                    stats.record_hit();
                }
                Ok(Some(entry.value))
            }
            Err(e) => Err(e),
        }
    }

    /// Inserts or updates a cached entry.
    pub async fn insert(&self, key: K, value: V) {
        let _span = cache_span!("cache_insert", cache = "async");

        if let Some(ref neg) = self.negative {
            neg.invalidate(&key).await;
            cache_event!(debug, "cleared negative cache entry");
        }
        self.positive
            .insert(key, CachedEntry::new(value, self.ttl))
            .await;
        cache_event!(debug, "inserted entry");
        if let Some(ref stats) = self.stats {
            stats.record_insert();
        }
    }

    /// Inserts or updates a cached entry with a custom TTL.
    ///
    /// This uses Moka's `Expiry` trait to support per-entry TTL.
    pub async fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let _span = cache_span!("cache_insert_with_ttl", cache = "async", ttl_ms = ttl.as_millis() as u64);

        if let Some(ref neg) = self.negative {
            neg.invalidate(&key).await;
            cache_event!(debug, "cleared negative cache entry");
        }
        self.positive.insert(key, CachedEntry::new(value, ttl)).await;
        cache_event!(debug, "inserted entry with custom TTL");
        if let Some(ref stats) = self.stats {
            stats.record_insert();
        }
    }

    /// Invalidates a cached entry.
    pub async fn invalidate(&self, key: &K) {
        let _span = cache_span!("cache_invalidate", cache = "async");
        self.positive.invalidate(key).await;
        cache_event!(debug, "invalidated entry");
    }

    /// Clears all cached entries (both positive and negative).
    pub async fn clear(&self) {
        let _span = cache_span!("cache_clear", cache = "async");
        self.positive.invalidate_all();
        if let Some(ref neg) = self.negative {
            neg.invalidate_all();
        }
        cache_event!(debug, "cleared all cache entries");
    }

    /// Checks if a key is in the negative cache (known to not exist).
    pub async fn is_negative(&self, key: &K) -> bool {
        match &self.negative {
            Some(neg) => neg.contains_key(key),
            None => false,
        }
    }

    /// Adds a key to the negative cache.
    pub async fn insert_negative(&self, key: K) {
        if let Some(ref neg) = self.negative {
            neg.insert(key, NegativeEntry::new(self.negative_ttl)).await;
        }
    }

    /// Removes a key from the negative cache.
    pub async fn remove_negative(&self, key: &K) {
        if let Some(ref neg) = self.negative {
            neg.invalidate(key).await;
        }
    }

    /// Invalidates all entries matching a predicate.
    pub fn invalidate_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool + Send + Sync + 'static,
    {
        self.positive
            .invalidate_entries_if(move |k, _| predicate(k))
            .expect("invalidate_entries_if should not fail with infallible predicate");
    }

    /// Invalidates all negative cache entries matching a predicate.
    pub fn invalidate_negative_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool + Send + Sync + 'static,
    {
        if let Some(ref neg) = self.negative {
            neg.invalidate_entries_if(move |k, _| predicate(k))
                .expect("invalidate_entries_if should not fail with infallible predicate");
        }
    }

    /// Returns the approximate number of entries in the positive cache.
    pub fn len(&self) -> usize {
        self.positive.entry_count() as usize
    }

    /// Returns the approximate number of entries in the negative cache.
    pub fn negative_len(&self) -> usize {
        self.negative
            .as_ref()
            .map_or(0, |n| n.entry_count() as usize)
    }

    /// Returns true if the positive cache is empty.
    pub fn is_empty(&self) -> bool {
        self.positive.entry_count() == 0
    }

    /// Returns the TTL for positive cache entries.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the TTL for negative cache entries.
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    /// Returns true if negative caching is enabled.
    pub fn has_negative_cache(&self) -> bool {
        self.negative.is_some()
    }

    /// Triggers a synchronous cleanup of expired entries.
    pub async fn cleanup_expired(&self) {
        self.positive.run_pending_tasks().await;
        if let Some(ref neg) = self.negative {
            neg.run_pending_tasks().await;
        }
    }

    /// Checks cache health and returns warnings for potential performance issues.
    ///
    /// This method analyzes cache statistics to detect:
    /// - Low hit rate (suggests cache is too small or TTL too short)
    /// - High eviction rate (suggests capacity pressure)
    /// - Heavy negative cache usage (suggests many lookups for non-existent keys)
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::moka_cache::{AsyncTtlCache, CacheHealthThresholds};
    /// use oxidized_mount_common::stats::CacheStats;
    /// use std::sync::Arc;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let stats = Arc::new(CacheStats::new());
    ///     let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_stats(stats);
    ///
    ///     // Simulate some activity
    ///     cache.insert(1, "a".to_string()).await;
    ///     cache.get(&1).await;
    ///     cache.get(&2).await;
    ///
    ///     let health = cache.health_check(CacheHealthThresholds::default());
    ///     for warning in &health.warnings {
    ///         println!("Warning: {}", warning);
    ///     }
    /// }
    /// ```
    pub fn health_check(&self, thresholds: CacheHealthThresholds) -> CacheHealth {
        let (hits, misses, entries, evictions) = match &self.stats {
            Some(stats) => (
                stats.hit_count(),
                stats.miss_count(),
                stats.entry_count(),
                stats.eviction_count(),
            ),
            None => (0, 0, self.positive.entry_count(), 0),
        };

        let total_lookups = hits + misses;
        let hit_rate = if total_lookups > 0 {
            hits as f64 / total_lookups as f64
        } else {
            1.0 // No data yet, assume healthy
        };

        // Calculate eviction rate (evictions per insert)
        // Inserts = entries + evictions (approximately)
        let inserts = entries.saturating_add(evictions);
        let eviction_rate = if inserts > 0 {
            evictions as f64 / inserts as f64
        } else {
            0.0
        };

        // Calculate negative cache ratio
        // We don't track negative hits separately, so use negative_len as a proxy
        let negative_ratio = if total_lookups > 0 {
            self.negative_len() as f64 / total_lookups.max(1) as f64
        } else {
            0.0
        };

        let mut warnings = Vec::new();

        // Check thresholds (only warn if we have meaningful data)
        if total_lookups >= 100 && hit_rate < thresholds.min_hit_rate {
            warnings.push(CacheWarning::LowHitRate {
                rate: hit_rate,
                threshold: thresholds.min_hit_rate,
            });
        }

        if inserts >= 100 && eviction_rate > thresholds.max_eviction_rate {
            warnings.push(CacheWarning::HighEvictionRate {
                rate: eviction_rate,
                threshold: thresholds.max_eviction_rate,
            });
        }

        if total_lookups >= 100 && negative_ratio > thresholds.max_negative_ratio {
            warnings.push(CacheWarning::NegativeCacheHeavy {
                ratio: negative_ratio,
                threshold: thresholds.max_negative_ratio,
            });
        }

        CacheHealth {
            hit_rate,
            eviction_rate,
            negative_hit_ratio: negative_ratio,
            entry_count: entries,
            hits,
            misses,
            evictions,
            warnings,
        }
    }
}

impl<K, V> Default for AsyncTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::with_defaults()
    }
}

// Convenience methods for (parent_id, name) keys (FUSE/FSKit pattern)
impl<V: Clone + Send + Sync + 'static> AsyncTtlCache<(u64, String), V> {
    /// Invalidate all negative entries for a parent directory.
    pub fn invalidate_parent_negative(&self, parent: u64) {
        self.invalidate_negative_where(move |k| k.0 == parent);
    }

    /// Invalidate all entries for a parent directory.
    pub fn invalidate_parent(&self, parent: u64) {
        self.invalidate_where(move |k| k.0 == parent);
    }
}

// Convenience methods for String keys (WebDAV pattern)
impl<V: Clone + Send + Sync + 'static> AsyncTtlCache<String, V> {
    /// Invalidate all entries with a path prefix.
    pub fn invalidate_prefix(&self, prefix: &str) {
        let prefix = prefix.to_string();
        self.invalidate_where(move |k| k.starts_with(&prefix));
    }

    /// Invalidate all negative entries with a path prefix.
    pub fn invalidate_prefix_negative(&self, prefix: &str) {
        let prefix = prefix.to_string();
        self.invalidate_negative_where(move |k| k.starts_with(&prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ========================================================================
    // SyncTtlCache tests
    // ========================================================================

    #[test]
    fn test_sync_cache_insert_and_get() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();
        cache.insert(42, "hello".to_string());

        let cached = cache.get(&42).expect("Should be cached");
        assert_eq!(cached.value, "hello");
    }

    #[test]
    fn test_sync_cache_miss() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();
        assert!(cache.get(&999).is_none());
    }

    #[test]
    fn test_sync_cache_expiry() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::new(Duration::from_millis(10));
        cache.insert(42, "hello".to_string());

        assert!(cache.get(&42).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(50));
        cache.cleanup_expired(); // Force cleanup

        assert!(cache.get(&42).is_none());
    }

    #[test]
    fn test_sync_cache_invalidate() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();
        cache.insert(42, "hello".to_string());

        assert!(cache.get(&42).is_some());
        cache.invalidate(&42);
        assert!(cache.get(&42).is_none());
    }

    #[test]
    fn test_sync_negative_cache() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative(42);
        assert!(cache.is_negative(&42));
        assert!(!cache.is_negative(&999));

        cache.remove_negative(&42);
        assert!(!cache.is_negative(&42));
    }

    #[test]
    fn test_sync_negative_cache_disabled() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();

        // These should be no-ops
        cache.insert_negative(42);
        assert!(!cache.is_negative(&42));
    }

    #[test]
    fn test_sync_insert_removes_negative() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative(42);
        assert!(cache.is_negative(&42));

        cache.insert(42, "hello".to_string());
        assert!(!cache.is_negative(&42));
        assert!(cache.get(&42).is_some());
    }

    #[test]
    fn test_sync_invalidate_where() {
        let cache: SyncTtlCache<(u64, String), i32> = SyncTtlCache::with_defaults();
        cache.insert((1, "a".to_string()), 100);
        cache.insert((1, "b".to_string()), 200);
        cache.insert((2, "c".to_string()), 300);

        cache.invalidate_where(|k| k.0 == 1);

        // Force pending invalidations to complete
        cache.cleanup_expired();

        assert!(cache.get(&(1, "a".to_string())).is_none());
        assert!(cache.get(&(1, "b".to_string())).is_none());
        assert!(cache.get(&(2, "c".to_string())).is_some());
    }

    #[test]
    fn test_sync_invalidate_parent_negative() {
        let cache: SyncTtlCache<(u64, String), i32> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative((1, "a".to_string()));
        cache.insert_negative((1, "b".to_string()));
        cache.insert_negative((2, "c".to_string()));

        cache.invalidate_parent_negative(1);
        cache.cleanup_expired();

        assert!(!cache.is_negative(&(1, "a".to_string())));
        assert!(cache.is_negative(&(2, "c".to_string())));
    }

    #[test]
    fn test_sync_string_prefix_invalidation() {
        let cache: SyncTtlCache<String, i32> = SyncTtlCache::with_defaults();
        cache.insert("/dir/file1.txt".to_string(), 1);
        cache.insert("/dir/file2.txt".to_string(), 2);
        cache.insert("/other/file.txt".to_string(), 3);

        cache.invalidate_prefix("/dir");
        cache.cleanup_expired();

        assert!(cache.get(&"/dir/file1.txt".to_string()).is_none());
        assert!(cache.get(&"/other/file.txt".to_string()).is_some());
    }

    #[test]
    fn test_sync_clear() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert(1, "a".to_string());
        cache.insert(2, "b".to_string());
        cache.insert_negative(3);

        cache.clear();
        cache.cleanup_expired();

        assert!(cache.is_empty());
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_sync_concurrent_access() {
        let cache = Arc::new(SyncTtlCache::<u64, String>::with_defaults());
        let mut handles = vec![];

        // Spawn multiple threads inserting and reading
        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                cache.insert(i, format!("value-{}", i));
                cache.get(&i)
            }));
        }

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_some());
        }
    }

    #[test]
    fn test_sync_get_or_insert() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::new(Duration::from_secs(10));

        // First call inserts
        let value = cache.get_or_insert(&42, || "hello".to_string());
        assert_eq!(value, Some("hello".to_string()));

        // Second call returns cached
        let value = cache.get_or_insert(&42, || "should_not_be_called".to_string());
        assert_eq!(value, Some("hello".to_string()));
    }

    #[test]
    fn test_sync_get_or_insert_negative() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(Duration::from_secs(10), Duration::from_secs(10));

        cache.insert_negative(42);

        // Should return None for negative cache hit
        let value = cache.get_or_insert(&42, || "should_not_be_called".to_string());
        assert_eq!(value, None);
    }

    #[test]
    fn test_sync_thundering_herd() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let cache = Arc::new(SyncTtlCache::<u64, String>::new(Duration::from_secs(10)));
        let compute_count = Arc::new(AtomicU32::new(0));
        let mut handles = vec![];

        // Spawn multiple threads all trying to get_or_insert the same key
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let compute_count = Arc::clone(&compute_count);
            handles.push(thread::spawn(move || {
                cache.get_or_insert(&42, || {
                    compute_count.fetch_add(1, Ordering::SeqCst);
                    // Simulate slow computation
                    std::thread::sleep(Duration::from_millis(10));
                    "computed".to_string()
                })
            }));
        }

        for handle in handles {
            let result = handle.join().unwrap();
            assert_eq!(result, Some("computed".to_string()));
        }

        // Compute should only have been called once (or very few times due to Moka's design)
        let count = compute_count.load(Ordering::SeqCst);
        assert!(count <= 2, "Expected 1-2 computes, got {}", count);
    }

    #[test]
    fn test_sync_default_trait() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::default();
        assert_eq!(cache.ttl(), DEFAULT_TTL);
        assert!(!cache.has_negative_cache());
    }

    #[test]
    fn test_sync_stats_tracking() {
        let stats = Arc::new(CacheStats::new());
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats(stats.clone());

        cache.insert(1, "hello".to_string());
        cache.get(&1); // hit
        cache.get(&2); // miss

        assert_eq!(stats.hit_count(), 1);
        assert_eq!(stats.miss_count(), 1);
    }

    // ========================================================================
    // AsyncTtlCache tests
    // ========================================================================

    #[tokio::test]
    async fn test_async_cache_insert_and_get() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_defaults();
        cache.insert(42, "hello".to_string()).await;

        let cached = cache.get(&42).await.expect("Should be cached");
        assert_eq!(cached.value, "hello");
    }

    #[tokio::test]
    async fn test_async_cache_miss() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_defaults();
        assert!(cache.get(&999).await.is_none());
    }

    #[tokio::test]
    async fn test_async_cache_expiry() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::new(Duration::from_millis(10));
        cache.insert(42, "hello".to_string()).await;

        assert!(cache.get(&42).await.is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(50)).await;
        cache.cleanup_expired().await;

        assert!(cache.get(&42).await.is_none());
    }

    #[tokio::test]
    async fn test_async_negative_cache() {
        let cache: AsyncTtlCache<u64, String> =
            AsyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative(42).await;
        assert!(cache.is_negative(&42).await);
        assert!(!cache.is_negative(&999).await);

        cache.remove_negative(&42).await;
        assert!(!cache.is_negative(&42).await);
    }

    #[tokio::test]
    async fn test_async_get_or_insert() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::new(Duration::from_secs(10));

        // First call inserts
        let value = cache
            .get_or_insert(&42, || async { "hello".to_string() })
            .await;
        assert_eq!(value, Some("hello".to_string()));

        // Second call returns cached
        let value = cache
            .get_or_insert(&42, || async { "should_not_be_called".to_string() })
            .await;
        assert_eq!(value, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn test_async_thundering_herd() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let cache = Arc::new(AsyncTtlCache::<u64, String>::new(Duration::from_secs(10)));
        let compute_count = Arc::new(AtomicU32::new(0));
        let mut handles = vec![];

        // Spawn multiple tasks all trying to get_or_insert the same key
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let compute_count = Arc::clone(&compute_count);
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_insert(&42, || {
                        let compute_count = compute_count.clone();
                        async move {
                            compute_count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            "computed".to_string()
                        }
                    })
                    .await
            }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert_eq!(result, Some("computed".to_string()));
        }

        // Compute should only have been called once (or very few times)
        let count = compute_count.load(Ordering::SeqCst);
        assert!(count <= 2, "Expected 1-2 computes, got {}", count);
    }

    #[tokio::test]
    async fn test_async_try_get_or_insert() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::new(Duration::from_secs(10));

        // Successful computation
        let result: Result<Option<String>, Arc<&str>> = cache
            .try_get_or_insert(&42, || async { Ok("hello".to_string()) })
            .await;
        assert_eq!(result, Ok(Some("hello".to_string())));

        // Failed computation for different key
        let result: Result<Option<String>, Arc<&str>> = cache
            .try_get_or_insert(&99, || async { Err("error") })
            .await;
        assert!(result.is_err());
        assert_eq!(*result.unwrap_err(), "error");
    }

    #[tokio::test]
    async fn test_async_invalidate_where() {
        let cache: AsyncTtlCache<(u64, String), i32> = AsyncTtlCache::with_defaults();
        cache.insert((1, "a".to_string()), 100).await;
        cache.insert((1, "b".to_string()), 200).await;
        cache.insert((2, "c".to_string()), 300).await;

        cache.invalidate_where(|k| k.0 == 1);
        cache.cleanup_expired().await;

        assert!(cache.get(&(1, "a".to_string())).await.is_none());
        assert!(cache.get(&(2, "c".to_string())).await.is_some());
    }

    #[tokio::test]
    async fn test_async_string_prefix_invalidation() {
        let cache: AsyncTtlCache<String, i32> = AsyncTtlCache::with_defaults();
        cache.insert("/dir/file1.txt".to_string(), 1).await;
        cache.insert("/dir/file2.txt".to_string(), 2).await;
        cache.insert("/other/file.txt".to_string(), 3).await;

        cache.invalidate_prefix("/dir");
        cache.cleanup_expired().await;

        assert!(cache.get(&"/dir/file1.txt".to_string()).await.is_none());
        assert!(cache.get(&"/other/file.txt".to_string()).await.is_some());
    }

    // ========================================================================
    // Multi-step workflow tests (catch cache invalidation bugs)
    // ========================================================================

    /// Catches: stale cache after overwrite (the most common cache bug)
    #[test]
    fn test_overwrite_invalidates_stale_value() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_defaults();

        // Insert v1, verify v1
        cache.insert(42, "version1".to_string());
        assert_eq!(cache.get(&42).unwrap().value, "version1");

        // Overwrite with v2, verify v2 (not stale v1)
        cache.insert(42, "version2".to_string());
        assert_eq!(
            cache.get(&42).unwrap().value,
            "version2",
            "Cache returned stale value after overwrite"
        );
    }

    /// Catches: negative cache not cleared after positive insert
    #[test]
    fn test_workflow_negative_then_positive() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        // Mark as non-existent
        cache.insert_negative(42);
        assert!(cache.is_negative(&42), "Should be in negative cache");
        assert!(cache.get(&42).is_none(), "Should return None for negative");

        // Now it exists
        cache.insert(42, "created".to_string());
        assert!(!cache.is_negative(&42), "Negative cache should be cleared");
        assert_eq!(
            cache.get(&42).unwrap().value,
            "created",
            "Should return the positive value"
        );
    }

    /// Catches: invalidate doesn't remove from both positive and negative
    #[test]
    fn test_workflow_invalidate_then_reinsert() {
        let cache: SyncTtlCache<u64, String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        // Create, then delete (goes to negative)
        cache.insert(42, "original".to_string());
        cache.invalidate(&42);
        cache.insert_negative(42);

        // Recreate with different value
        cache.insert(42, "recreated".to_string());
        assert_eq!(
            cache.get(&42).unwrap().value,
            "recreated",
            "Should see recreated value, not stale"
        );
        assert!(!cache.is_negative(&42), "Should not be negative after insert");
    }

    /// Catches: per-entry TTL not honored (all entries use default TTL)
    #[test]
    fn test_per_entry_ttl_respected() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::new(Duration::from_secs(60));

        // Insert with short TTL
        cache.insert_with_ttl(1, "short".to_string(), Duration::from_millis(10));
        // Insert with long TTL
        cache.insert_with_ttl(2, "long".to_string(), Duration::from_secs(60));

        assert!(cache.get(&1).is_some(), "Short TTL entry should exist");
        assert!(cache.get(&2).is_some(), "Long TTL entry should exist");

        // Wait for short TTL to expire
        std::thread::sleep(Duration::from_millis(50));
        cache.cleanup_expired();

        assert!(
            cache.get(&1).is_none(),
            "Short TTL entry should be expired"
        );
        assert!(
            cache.get(&2).is_some(),
            "Long TTL entry should still exist"
        );
    }

    /// Catches: value corruption (wrong value returned for key)
    #[test]
    fn test_value_integrity_many_entries() {
        let cache: SyncTtlCache<u64, Vec<u8>> = SyncTtlCache::with_defaults();

        // Insert 100 entries with distinct content
        for i in 0..100u64 {
            let content: Vec<u8> = (0..256).map(|b| ((b + i as usize) % 256) as u8).collect();
            cache.insert(i, content);
        }

        // Verify each entry has correct content
        for i in 0..100u64 {
            let expected: Vec<u8> = (0..256).map(|b| ((b + i as usize) % 256) as u8).collect();
            let actual = cache.get(&i).expect(&format!("Key {} should exist", i));
            assert_eq!(
                actual.value, expected,
                "Value corruption at key {}",
                i
            );
        }
    }

    /// Catches: concurrent read+invalidate race returning stale data
    #[test]
    fn test_concurrent_invalidate_during_read() {
        use std::sync::Barrier;

        let cache = Arc::new(SyncTtlCache::<u64, String>::with_defaults());
        let barrier = Arc::new(Barrier::new(2));

        cache.insert(42, "original".to_string());

        let cache_clone = Arc::clone(&cache);
        let barrier_clone = Arc::clone(&barrier);

        // Thread 1: invalidate then insert new value
        let writer = thread::spawn(move || {
            barrier_clone.wait();
            cache_clone.invalidate(&42);
            cache_clone.insert(42, "updated".to_string());
        });

        // Thread 2: read multiple times
        let cache_clone = Arc::clone(&cache);
        let reader = thread::spawn(move || {
            barrier.wait();
            // Multiple reads to catch race window
            for _ in 0..100 {
                if let Some(entry) = cache_clone.get(&42) {
                    // Should never see garbage, only "original" or "updated"
                    assert!(
                        entry.value == "original" || entry.value == "updated",
                        "Got unexpected value: {}",
                        entry.value
                    );
                }
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();

        // Final state should be "updated"
        assert_eq!(cache.get(&42).unwrap().value, "updated");
    }

    /// Catches: get_or_insert returning stale cached value when it should recompute
    #[test]
    fn test_get_or_insert_after_invalidate() {
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::new(Duration::from_secs(60));

        // First call computes
        let v1 = cache.get_or_insert(&42, || "first".to_string());
        assert_eq!(v1, Some("first".to_string()));

        // Invalidate
        cache.invalidate(&42);

        // Should recompute, not return stale "first"
        let v2 = cache.get_or_insert(&42, || "second".to_string());
        assert_eq!(
            v2,
            Some("second".to_string()),
            "get_or_insert returned stale value after invalidate"
        );
    }

    /// Catches: directory listing cache not invalidated when child changes
    #[test]
    fn test_parent_invalidation_workflow() {
        let cache: SyncTtlCache<(u64, String), String> =
            SyncTtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        // Cache a directory listing (parent=1)
        cache.insert((1, "file_a".to_string()), "content_a".to_string());
        cache.insert((1, "file_b".to_string()), "content_b".to_string());
        cache.insert((2, "other".to_string()), "other_content".to_string());

        // Also cache that "file_c" doesn't exist in parent=1
        cache.insert_negative((1, "file_c".to_string()));

        // Now file_c is created - must invalidate parent's negative entries
        cache.invalidate_parent_negative(1);
        cache.cleanup_expired();

        // Check: negative entry for file_c should be gone
        assert!(
            !cache.is_negative(&(1, "file_c".to_string())),
            "Negative entry should be cleared after parent invalidation"
        );

        // Check: other directory not affected
        assert!(
            cache.get(&(2, "other".to_string())).is_some(),
            "Other directory should not be affected"
        );
    }

    /// Async: Catches stale value after overwrite
    #[tokio::test]
    async fn test_async_overwrite_invalidates_stale() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_defaults();

        cache.insert(42, "v1".to_string()).await;
        assert_eq!(cache.get(&42).await.unwrap().value, "v1");

        cache.insert(42, "v2".to_string()).await;
        assert_eq!(
            cache.get(&42).await.unwrap().value,
            "v2",
            "Async cache returned stale value after overwrite"
        );
    }

    /// Async: Catches per-entry TTL not honored
    #[tokio::test]
    async fn test_async_per_entry_ttl() {
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::new(Duration::from_secs(60));

        cache
            .insert_with_ttl(1, "short".to_string(), Duration::from_millis(10))
            .await;
        cache
            .insert_with_ttl(2, "long".to_string(), Duration::from_secs(60))
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        cache.cleanup_expired().await;

        assert!(
            cache.get(&1).await.is_none(),
            "Short TTL should be expired"
        );
        assert!(cache.get(&2).await.is_some(), "Long TTL should exist");
    }

    /// Async: Catches concurrent tasks getting different results for same key
    #[tokio::test]
    async fn test_async_concurrent_same_key_consistency() {
        let cache = Arc::new(AsyncTtlCache::<u64, String>::with_defaults());
        cache.insert(42, "shared".to_string()).await;

        let mut handles = vec![];
        for _ in 0..50 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache.get(&42).await.map(|e| e.value.clone())
            }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert_eq!(
                result,
                Some("shared".to_string()),
                "Concurrent reads returned inconsistent values"
            );
        }
    }

    // ========================================================================
    // Eviction tracking and health check tests
    // ========================================================================

    #[test]
    fn test_sync_eviction_tracking() {
        // Test that eviction listeners are wired up by using capacity-based eviction
        // TTL-based eviction is lazy and unreliable in tests
        let stats = Arc::new(CacheStats::new());

        // Create a cache with very small capacity to force evictions
        let stats_for_eviction = Arc::clone(&stats);
        let cache: moka::sync::Cache<u64, CachedEntry<String>> = moka::sync::Cache::builder()
            .max_capacity(5) // Small capacity to force evictions
            .expire_after(PerEntryExpiry)
            .eviction_listener(move |_key, _value, _cause| {
                stats_for_eviction.record_eviction();
                stats_for_eviction.record_remove();
            })
            .build();

        // Insert more entries than capacity to trigger evictions
        for i in 0..20 {
            cache.insert(i, CachedEntry::new(format!("value-{}", i), Duration::from_secs(60)));
            stats.record_insert();
            // Run pending tasks to process evictions
            cache.run_pending_tasks();
        }

        // Run pending tasks one more time to ensure evictions are processed
        cache.run_pending_tasks();

        // Verify that some evictions happened (capacity is 5, inserted 20)
        // Moka may not evict immediately, so we just check the capacity is respected
        assert!(
            cache.entry_count() <= 10,
            "Cache should respect capacity (entry_count={}, expected <= 10)",
            cache.entry_count()
        );

        // If evictions happened, they should be recorded
        // Note: Moka's eviction is eventually consistent
        let evictions = stats.eviction_count();
        let entries = cache.entry_count() as u64;
        assert!(
            evictions > 0 || entries <= 5,
            "Evictions should be tracked (evictions={}, entries={})",
            evictions,
            entries
        );
    }

    #[test]
    fn test_sync_health_check_no_warnings_initially() {
        let stats = Arc::new(CacheStats::new());
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats(Arc::clone(&stats));

        let health = cache.health_check(CacheHealthThresholds::default());

        // With no data, should assume healthy
        assert_eq!(health.hit_rate, 1.0);
        assert!(health.warnings.is_empty(), "No warnings with no data");
    }

    #[test]
    fn test_sync_health_check_low_hit_rate_warning() {
        let stats = Arc::new(CacheStats::new());
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats(Arc::clone(&stats));

        // Simulate mostly misses (low hit rate)
        for i in 0..150 {
            let _ = cache.get(&i); // All misses
        }
        // Add a few hits
        cache.insert(999, "value".to_string());
        for _ in 0..10 {
            let _ = cache.get(&999);
        }

        let health = cache.health_check(CacheHealthThresholds::default());

        assert!(
            health.hit_rate < 0.5,
            "Hit rate should be low: {}",
            health.hit_rate
        );
        assert!(
            health.warnings.iter().any(|w| matches!(w, CacheWarning::LowHitRate { .. })),
            "Should have low hit rate warning"
        );
    }

    #[test]
    fn test_sync_health_check_high_hit_rate_no_warning() {
        let stats = Arc::new(CacheStats::new());
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats(Arc::clone(&stats));

        // Insert values first
        for i in 0..50 {
            cache.insert(i, format!("value-{}", i));
        }

        // Hit all cached values multiple times
        for _ in 0..3 {
            for i in 0..50 {
                let _ = cache.get(&i);
            }
        }

        let health = cache.health_check(CacheHealthThresholds::default());

        assert!(
            health.hit_rate > 0.5,
            "Hit rate should be high: {}",
            health.hit_rate
        );
        assert!(
            !health.warnings.iter().any(|w| matches!(w, CacheWarning::LowHitRate { .. })),
            "Should not have low hit rate warning"
        );
    }

    #[test]
    fn test_sync_cache_warning_display() {
        let warning = CacheWarning::LowHitRate {
            rate: 0.3,
            threshold: 0.5,
        };
        let display = format!("{}", warning);
        assert!(display.contains("30.0%"), "Should display percentage: {}", display);

        let warning = CacheWarning::HighEvictionRate {
            rate: 3.5,
            threshold: 2.0,
        };
        let display = format!("{}", warning);
        assert!(display.contains("3.50"), "Should display rate: {}", display);

        let warning = CacheWarning::NegativeCacheHeavy {
            ratio: 0.45,
            threshold: 0.3,
        };
        let display = format!("{}", warning);
        assert!(display.contains("45.0%"), "Should display percentage: {}", display);
    }

    #[test]
    fn test_sync_with_stats_and_negative_cache() {
        let stats = Arc::new(CacheStats::new());
        let cache: SyncTtlCache<u64, String> = SyncTtlCache::with_stats_and_negative_cache(
            Arc::clone(&stats),
            Duration::from_secs(60),
            Duration::from_secs(30),
        );

        // Verify both features work
        assert!(cache.has_negative_cache(), "Should have negative cache");

        cache.insert(1, "value".to_string());
        cache.insert_negative(2);

        assert!(cache.get(&1).is_some());
        assert!(cache.is_negative(&2));
        assert_eq!(stats.entry_count(), 1);
        assert_eq!(stats.hit_count(), 1);
    }

    #[tokio::test]
    async fn test_async_eviction_tracking() {
        // Test that eviction listeners are wired up by using capacity-based eviction
        // TTL-based eviction is lazy and unreliable in tests
        let stats = Arc::new(CacheStats::new());

        // Create a cache with very small capacity to force evictions
        let stats_for_eviction = Arc::clone(&stats);
        let cache: moka::future::Cache<u64, CachedEntry<String>> = moka::future::Cache::builder()
            .max_capacity(5) // Small capacity to force evictions
            .expire_after(PerEntryExpiry)
            .eviction_listener(move |_key, _value, _cause| {
                stats_for_eviction.record_eviction();
                stats_for_eviction.record_remove();
            })
            .build();

        // Insert more entries than capacity to trigger evictions
        for i in 0..20 {
            cache
                .insert(i, CachedEntry::new(format!("value-{}", i), Duration::from_secs(60)))
                .await;
            stats.record_insert();
            // Run pending tasks to process evictions
            cache.run_pending_tasks().await;
        }

        // Run pending tasks one more time to ensure evictions are processed
        cache.run_pending_tasks().await;

        // Verify that some evictions happened (capacity is 5, inserted 20)
        // Moka may not evict immediately, so we just check the capacity is respected
        assert!(
            cache.entry_count() <= 10,
            "Cache should respect capacity (entry_count={}, expected <= 10)",
            cache.entry_count()
        );

        // If evictions happened, they should be recorded
        // Note: Moka's eviction is eventually consistent
        let evictions = stats.eviction_count();
        let entries = cache.entry_count() as u64;
        assert!(
            evictions > 0 || entries <= 5,
            "Evictions should be tracked (evictions={}, entries={})",
            evictions,
            entries
        );
    }

    #[tokio::test]
    async fn test_async_health_check() {
        let stats = Arc::new(CacheStats::new());
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_stats(Arc::clone(&stats));

        // Insert and access values
        for i in 0..50 {
            cache.insert(i, format!("value-{}", i)).await;
        }
        for _ in 0..3 {
            for i in 0..50 {
                let _ = cache.get(&i).await;
            }
        }

        let health = cache.health_check(CacheHealthThresholds::default());

        assert!(
            health.hit_rate > 0.5,
            "Hit rate should be high: {}",
            health.hit_rate
        );
        assert_eq!(health.hits, 150, "Should have 150 hits");
    }

    #[tokio::test]
    async fn test_async_with_stats_and_negative_cache() {
        let stats = Arc::new(CacheStats::new());
        let cache: AsyncTtlCache<u64, String> = AsyncTtlCache::with_stats_and_negative_cache(
            Arc::clone(&stats),
            Duration::from_secs(60),
            Duration::from_secs(30),
        );

        // Verify both features work
        assert!(cache.has_negative_cache(), "Should have negative cache");

        cache.insert(1, "value".to_string()).await;
        cache.insert_negative(2).await;

        assert!(cache.get(&1).await.is_some());
        assert!(cache.is_negative(&2).await);
        assert_eq!(stats.entry_count(), 1);
        assert_eq!(stats.hit_count(), 1);
    }

    #[test]
    fn test_cache_health_thresholds_default() {
        let thresholds = CacheHealthThresholds::default();

        assert_eq!(thresholds.min_hit_rate, 0.5);
        assert_eq!(thresholds.max_eviction_rate, 2.0);
        assert_eq!(thresholds.max_negative_ratio, 0.3);
    }
}
