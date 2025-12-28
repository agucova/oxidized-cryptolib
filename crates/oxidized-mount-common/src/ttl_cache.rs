//! TTL-based caching for mount backends.
//!
//! This module provides a generic, thread-safe cache with time-based expiration.
//! It supports both positive and negative caching (for ENOENT results).
//!
//! # Features
//!
//! - Generic over key and value types
//! - Thread-safe using `DashMap`
//! - TTL-based expiration with automatic cleanup
//! - Optional negative caching for "not found" results
//! - Bulk invalidation with predicates

use crate::stats::CacheStats;
use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default time-to-live for cached entries (1 second).
pub const DEFAULT_TTL: Duration = Duration::from_secs(1);

/// Default time-to-live for negative cache entries (500ms).
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_millis(500);

/// Threshold for triggering automatic cache cleanup.
/// When cache exceeds this many entries, expired entries are removed.
const CLEANUP_THRESHOLD: usize = 10_000;

/// A cached entry with expiration time.
#[derive(Debug, Clone)]
pub struct CachedEntry<V> {
    /// The cached value.
    pub value: V,
    /// When this cache entry expires.
    expires: Instant,
}

impl<V> CachedEntry<V> {
    /// Creates a new cached entry.
    pub fn new(value: V, ttl: Duration) -> Self {
        Self {
            value,
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

/// Thread-safe TTL cache with optional negative caching.
///
/// This cache provides:
/// - Positive caching: Store values with TTL-based expiration
/// - Negative caching: Mark keys as "known to not exist" (ENOENT)
/// - Bulk invalidation: Remove entries matching a predicate
/// - Automatic cleanup: Remove expired entries when threshold exceeded
/// - Optional statistics tracking: Hit/miss rates and entry counts
///
/// # Example
///
/// ```
/// use oxidized_mount_common::TtlCache;
/// use std::time::Duration;
///
/// // Create cache with default settings
/// let cache: TtlCache<u64, String> = TtlCache::with_defaults();
///
/// // Insert a value
/// cache.insert(42, "hello".to_string());
///
/// // Retrieve the value
/// if let Some(entry) = cache.get(&42) {
///     assert_eq!(entry.value, "hello");
/// }
/// ```
///
/// # Statistics Tracking
///
/// To enable statistics tracking, use [`with_stats`](TtlCache::with_stats):
///
/// ```
/// use oxidized_mount_common::{TtlCache, CacheStats};
/// use std::sync::Arc;
///
/// let stats = Arc::new(CacheStats::new());
/// let cache: TtlCache<u64, String> = TtlCache::with_stats(stats.clone());
///
/// cache.insert(1, "hello".to_string());
/// cache.get(&1);  // hit
/// cache.get(&2);  // miss
///
/// assert_eq!(stats.hit_count(), 1);
/// assert_eq!(stats.miss_count(), 1);
/// ```
pub struct TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Cached entries (key -> value).
    entries: DashMap<K, CachedEntry<V>>,
    /// Negative cache for ENOENT results (optional).
    negative: Option<DashMap<K, NegativeEntry>>,
    /// TTL for positive cache entries.
    ttl: Duration,
    /// TTL for negative cache entries.
    negative_ttl: Duration,
    /// Threshold for triggering cleanup.
    cleanup_threshold: usize,
    /// Optional statistics tracking.
    stats: Option<Arc<CacheStats>>,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Creates a new cache with the given TTL.
    ///
    /// Negative caching is disabled by default.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            cleanup_threshold: CLEANUP_THRESHOLD,
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
    pub fn with_stats(stats: Arc<CacheStats>) -> Self {
        Self {
            entries: DashMap::new(),
            negative: None,
            ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            cleanup_threshold: CLEANUP_THRESHOLD,
            stats: Some(stats),
        }
    }

    /// Creates a new cache with negative caching enabled.
    ///
    /// Negative caching stores "not found" results to avoid repeated lookups
    /// for keys that don't exist.
    pub fn with_negative_cache(ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            negative: Some(DashMap::new()),
            ttl,
            negative_ttl,
            cleanup_threshold: CLEANUP_THRESHOLD,
            stats: None,
        }
    }

    /// Creates a new cache with a custom cleanup threshold.
    pub fn with_threshold(ttl: Duration, cleanup_threshold: usize) -> Self {
        Self {
            entries: DashMap::new(),
            negative: None,
            ttl,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            cleanup_threshold,
            stats: None,
        }
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
        if let Some(entry) = self.entries.get(key) {
            if !entry.is_expired() {
                if let Some(ref stats) = self.stats {
                    stats.record_hit();
                }
                return Some(entry.clone());
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(key);
            if let Some(ref stats) = self.stats {
                stats.record_eviction();
                stats.record_remove();
            }
        }
        if let Some(ref stats) = self.stats {
            stats.record_miss();
        }
        None
    }

    /// Inserts or updates a cached entry.
    ///
    /// Triggers automatic cleanup when cache exceeds threshold.
    /// Also removes the key from the negative cache if present.
    pub fn insert(&self, key: K, value: V) {
        // Remove from negative cache if enabled
        if let Some(ref neg) = self.negative {
            neg.remove(&key);
        }
        let was_new = self
            .entries
            .insert(key, CachedEntry::new(value, self.ttl))
            .is_none();
        if was_new
            && let Some(ref stats) = self.stats {
                stats.record_insert();
            }
        self.maybe_cleanup();
    }

    /// Inserts or updates a cached entry with a custom TTL.
    ///
    /// Triggers automatic cleanup when cache exceeds threshold.
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        // Remove from negative cache if enabled
        if let Some(ref neg) = self.negative {
            neg.remove(&key);
        }
        let was_new = self
            .entries
            .insert(key, CachedEntry::new(value, ttl))
            .is_none();
        if was_new
            && let Some(ref stats) = self.stats {
                stats.record_insert();
            }
        self.maybe_cleanup();
    }

    /// Invalidates a cached entry.
    pub fn invalidate(&self, key: &K) {
        self.entries.remove(key);
    }

    /// Clears all cached entries (both positive and negative).
    pub fn clear(&self) {
        self.entries.clear();
        if let Some(ref neg) = self.negative {
            neg.clear();
        }
    }

    /// Checks if a key is in the negative cache (known to not exist).
    ///
    /// Returns `false` if negative caching is disabled.
    pub fn is_negative(&self, key: &K) -> bool {
        if let Some(ref neg) = self.negative
            && let Some(entry) = neg.get(key) {
                if !entry.is_expired() {
                    return true;
                }
                // Entry expired, remove it
                drop(entry);
                neg.remove(key);
            }
        false
    }

    /// Adds a key to the negative cache.
    ///
    /// Does nothing if negative caching is disabled.
    /// Triggers automatic cleanup when cache exceeds threshold.
    pub fn insert_negative(&self, key: K) {
        if let Some(ref neg) = self.negative {
            neg.insert(key, NegativeEntry::new(self.negative_ttl));
            self.maybe_cleanup();
        }
    }

    /// Removes a key from the negative cache.
    ///
    /// Does nothing if negative caching is disabled.
    pub fn remove_negative(&self, key: &K) {
        if let Some(ref neg) = self.negative {
            neg.remove(key);
        }
    }

    /// Invalidates all entries matching a predicate.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::TtlCache;
    ///
    /// let cache: TtlCache<(u64, String), i32> = TtlCache::with_defaults();
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
        F: Fn(&K) -> bool,
    {
        self.entries.retain(|k, _| !predicate(k));
    }

    /// Invalidates all negative cache entries matching a predicate.
    ///
    /// Does nothing if negative caching is disabled.
    pub fn invalidate_negative_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool,
    {
        if let Some(ref neg) = self.negative {
            neg.retain(|k, _| !predicate(k));
        }
    }

    /// Returns the number of entries in the positive cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of entries in the negative cache.
    pub fn negative_len(&self) -> usize {
        self.negative.as_ref().map_or(0, |n| n.len())
    }

    /// Returns true if the positive cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

    /// Triggers cleanup if cache exceeds threshold.
    fn maybe_cleanup(&self) {
        let total = self.entries.len() + self.negative_len();
        if total > self.cleanup_threshold {
            self.cleanup_expired();
        }
    }

    /// Removes all expired entries from both caches.
    pub fn cleanup_expired(&self) {
        self.entries.retain(|_, v| !v.is_expired());
        if let Some(ref neg) = self.negative {
            neg.retain(|_, v| !v.is_expired());
        }
    }
}

impl<K, V> Default for TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::with_defaults()
    }
}

// Convenience methods for (parent_id, name) keys (FUSE/FSKit pattern)
impl<V: Clone> TtlCache<(u64, String), V> {
    /// Invalidate all negative entries for a parent directory.
    ///
    /// This is useful when directory contents change.
    pub fn invalidate_parent_negative(&self, parent: u64) {
        self.invalidate_negative_where(|k| k.0 == parent);
    }

    /// Invalidate all entries for a parent directory.
    pub fn invalidate_parent(&self, parent: u64) {
        self.invalidate_where(|k| k.0 == parent);
    }
}

// Convenience methods for String keys (WebDAV pattern)
impl<V: Clone> TtlCache<String, V> {
    /// Invalidate all entries with a path prefix.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidized_mount_common::TtlCache;
    ///
    /// let cache: TtlCache<String, i32> = TtlCache::with_defaults();
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
        self.invalidate_where(|k| k.starts_with(prefix));
    }

    /// Invalidate all negative entries with a path prefix.
    pub fn invalidate_prefix_negative(&self, prefix: &str) {
        self.invalidate_negative_where(|k| k.starts_with(prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_cache_insert_and_get() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();
        cache.insert(42, "hello".to_string());

        let cached = cache.get(&42).expect("Should be cached");
        assert_eq!(cached.value, "hello");
    }

    #[test]
    fn test_cache_miss() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();
        assert!(cache.get(&999).is_none());
    }

    #[test]
    fn test_cache_expiry() {
        let cache: TtlCache<u64, String> = TtlCache::new(Duration::from_millis(10));
        cache.insert(42, "hello".to_string());

        assert!(cache.get(&42).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&42).is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();
        cache.insert(42, "hello".to_string());

        assert!(cache.get(&42).is_some());
        cache.invalidate(&42);
        assert!(cache.get(&42).is_none());
    }

    #[test]
    fn test_insert_with_custom_ttl() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();

        // Insert with a very short TTL
        cache.insert_with_ttl(42, "hello".to_string(), Duration::from_millis(10));
        assert!(cache.get(&42).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&42).is_none());
    }

    #[test]
    fn test_negative_cache() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative(42);
        assert!(cache.is_negative(&42));
        assert!(!cache.is_negative(&999));

        cache.remove_negative(&42);
        assert!(!cache.is_negative(&42));
    }

    #[test]
    fn test_negative_cache_disabled() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();

        // These should be no-ops
        cache.insert_negative(42);
        assert!(!cache.is_negative(&42));
    }

    #[test]
    fn test_negative_cache_expiry() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(Duration::from_secs(1), Duration::from_millis(10));

        cache.insert_negative(42);
        assert!(cache.is_negative(&42));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(!cache.is_negative(&42));
    }

    #[test]
    fn test_insert_removes_negative() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative(42);
        assert!(cache.is_negative(&42));

        cache.insert(42, "hello".to_string());
        assert!(!cache.is_negative(&42));
        assert!(cache.get(&42).is_some());
    }

    #[test]
    fn test_invalidate_where() {
        let cache: TtlCache<(u64, String), i32> = TtlCache::with_defaults();
        cache.insert((1, "a".to_string()), 100);
        cache.insert((1, "b".to_string()), 200);
        cache.insert((2, "c".to_string()), 300);

        assert_eq!(cache.len(), 3);

        cache.invalidate_where(|k| k.0 == 1);

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&(1, "a".to_string())).is_none());
        assert!(cache.get(&(1, "b".to_string())).is_none());
        assert!(cache.get(&(2, "c".to_string())).is_some());
    }

    #[test]
    fn test_invalidate_parent_negative() {
        let cache: TtlCache<(u64, String), i32> =
            TtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert_negative((1, "a".to_string()));
        cache.insert_negative((1, "b".to_string()));
        cache.insert_negative((2, "c".to_string()));

        assert_eq!(cache.negative_len(), 3);

        cache.invalidate_parent_negative(1);

        assert_eq!(cache.negative_len(), 1);
        assert!(!cache.is_negative(&(1, "a".to_string())));
        assert!(cache.is_negative(&(2, "c".to_string())));
    }

    #[test]
    fn test_string_prefix_invalidation() {
        let cache: TtlCache<String, i32> = TtlCache::with_defaults();
        cache.insert("/dir/file1.txt".to_string(), 1);
        cache.insert("/dir/file2.txt".to_string(), 2);
        cache.insert("/other/file.txt".to_string(), 3);

        assert_eq!(cache.len(), 3);

        cache.invalidate_prefix("/dir");

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&"/dir/file1.txt".to_string()).is_none());
        assert!(cache.get(&"/other/file.txt".to_string()).is_some());
    }

    #[test]
    fn test_clear() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL);

        cache.insert(1, "a".to_string());
        cache.insert(2, "b".to_string());
        cache.insert_negative(3);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.negative_len(), 1);

        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(Duration::from_millis(10), Duration::from_millis(10));

        cache.insert(1, "a".to_string());
        cache.insert(2, "b".to_string());
        cache.insert_negative(3);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.negative_len(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        cache.cleanup_expired();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_cached_entry_time_remaining() {
        let entry = CachedEntry::new("value", Duration::from_secs(10));

        let remaining = entry.time_remaining();
        assert!(remaining > Duration::from_secs(9));
        assert!(remaining <= Duration::from_secs(10));
    }

    #[test]
    fn test_cache_ttl_accessors() {
        let cache: TtlCache<u64, String> =
            TtlCache::with_negative_cache(Duration::from_secs(5), Duration::from_secs(2));

        assert_eq!(cache.ttl(), Duration::from_secs(5));
        assert_eq!(cache.negative_ttl(), Duration::from_secs(2));
        assert!(cache.has_negative_cache());
    }

    #[test]
    fn test_cache_no_negative_cache() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();
        assert!(!cache.has_negative_cache());
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        let cache = Arc::new(TtlCache::<u64, String>::with_defaults());
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

        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_len_and_is_empty() {
        let cache: TtlCache<u64, String> = TtlCache::with_defaults();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert(1, "a".to_string());
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);

        cache.insert(2, "b".to_string());
        assert_eq!(cache.len(), 2);

        cache.invalidate(&1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_default_trait() {
        let cache: TtlCache<u64, String> = TtlCache::default();
        assert_eq!(cache.ttl(), DEFAULT_TTL);
        assert!(!cache.has_negative_cache());
    }

    // ========================================================================
    // Edge case tests targeting specific bug classes
    // ========================================================================

    #[test]
    fn test_entry_expires_at_exact_ttl() {
        // Bug class: Off-by-one in expiry check
        // Implementation uses >=, so entry expires AT the TTL boundary
        let cache: TtlCache<u64, u64> = TtlCache::new(Duration::from_millis(50));
        cache.insert(1, 100);

        // Sleep until just past TTL
        std::thread::sleep(Duration::from_millis(55));

        // Entry should be expired
        assert!(
            cache.get(&1).is_none(),
            "Entry should expire at or after TTL"
        );
    }

    #[test]
    fn test_cleanup_triggers_at_threshold() {
        // Bug class: Cleanup threshold not properly triggering
        let cache: TtlCache<u64, u64> = TtlCache::with_threshold(
            Duration::from_millis(5), // Very short TTL
            10,                       // Low threshold for testing
        );

        // Insert entries that will expire
        for i in 0..10 {
            cache.insert(i, i);
        }

        // Wait for entries to expire
        std::thread::sleep(Duration::from_millis(10));

        // Insert more entries to trigger cleanup
        // Cleanup should remove expired entries
        for i in 10..21 {
            cache.insert(i, i);
        }

        // Old expired entries should be cleaned up
        // Note: We can't guarantee exact cleanup timing, but len should be bounded
        // The cache should have cleaned up at least some expired entries
        let len = cache.len();
        assert!(
            len <= 15,
            "Cleanup should have removed some expired entries, got len={}",
            len
        );
    }

    #[test]
    fn test_negative_positive_mutual_exclusion() {
        // Bug class: Key exists in both positive and negative cache
        let cache: TtlCache<u64, u64> =
            TtlCache::with_negative_cache(Duration::from_secs(10), Duration::from_secs(10));

        // Insert into negative cache
        cache.insert_negative(1);
        assert!(cache.is_negative(&1));
        assert!(cache.get(&1).is_none());

        // Insert positive should remove negative
        cache.insert(1, 100);
        assert!(!cache.is_negative(&1), "Positive insert should remove negative");
        assert!(cache.get(&1).is_some());

        // Verify the invariant: can't be in both
        let in_positive = cache.get(&1).is_some();
        let in_negative = cache.is_negative(&1);
        assert!(
            !(in_positive && in_negative),
            "Key should never be in both positive and negative cache"
        );
    }

    #[test]
    fn test_get_removes_expired_entry() {
        // Bug class: Expired entries not cleaned up on access
        let cache: TtlCache<u64, u64> = TtlCache::new(Duration::from_millis(10));
        cache.insert(1, 100);

        std::thread::sleep(Duration::from_millis(15));

        // First get should find expired entry and remove it
        assert!(cache.get(&1).is_none());

        // Verify entry was actually removed from the DashMap
        // (implementation removes expired entries on get)
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_concurrent_insert_same_key() {
        // Bug class: Race condition when multiple threads insert same key
        let cache = Arc::new(TtlCache::<u64, u64>::with_defaults());
        let mut handles = vec![];

        // Spawn threads that all insert the same key with different values
        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                cache.insert(1, i);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have exactly one entry with one of the values
        assert_eq!(cache.len(), 1);
        let value = cache.get(&1).expect("Should have entry").value;
        assert!(value < 10, "Value should be one of the inserted values");
    }

    #[test]
    fn test_invalidate_nonexistent_key() {
        // Bug class: Invalidate on missing key causes issues
        let cache: TtlCache<u64, u64> = TtlCache::with_defaults();

        // Should be a no-op, not panic
        cache.invalidate(&999);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_overwrites_value() {
        // Bug class: Insert doesn't update existing value
        let cache: TtlCache<u64, u64> = TtlCache::with_defaults();

        cache.insert(1, 100);
        assert_eq!(cache.get(&1).unwrap().value, 100);

        cache.insert(1, 200);
        assert_eq!(cache.get(&1).unwrap().value, 200);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_invalidate_where_empty_cache() {
        // Bug class: Predicate invalidation on empty cache
        let cache: TtlCache<u64, u64> = TtlCache::with_defaults();

        // Should be a no-op, not panic
        cache.invalidate_where(|_| true);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cleanup_only_on_insert() {
        // Bug class: Read-only workloads never trigger cleanup
        // This documents the current behavior where cleanup is only triggered on insert
        let cache: TtlCache<u64, u64> = TtlCache::with_threshold(
            Duration::from_millis(5), // Very short TTL
            5,                        // Low threshold
        );

        // Insert entries
        for i in 0..5 {
            cache.insert(i, i);
        }

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        // Only reading - cleanup should NOT be triggered
        for i in 0..5 {
            let _ = cache.get(&i);
        }

        // Entries are removed individually on get (because they're expired)
        // but maybe_cleanup() is not called, so this test just documents behavior
        assert_eq!(
            cache.len(),
            0,
            "Expired entries removed on individual get calls"
        );
    }
}
