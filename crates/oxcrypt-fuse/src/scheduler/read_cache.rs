//! Read cache for decrypted file chunks.
//!
//! Caches decrypted data using `bytes::Bytes` for efficient zero-copy sharing.
//! The cache is bounded by total bytes rather than entry count.

use bytes::Bytes;
use moka::sync::Cache;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Key for cached read data.
///
/// Uses inode + byte offset + size as the key since file handles can be reused
/// and reads of different sizes at the same offset must be distinguished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReadCacheKey {
    /// Inode number of the file.
    pub inode: u64,
    /// Starting byte offset of this cached chunk.
    pub offset: u64,
    /// Size of the cached data in bytes.
    /// Two reads at the same offset with different sizes are distinct cache entries.
    pub size: usize,
}

impl ReadCacheKey {
    /// Create a new cache key.
    pub fn new(inode: u64, offset: u64, size: usize) -> Self {
        Self { inode, offset, size }
    }
}

/// Default maximum cache size in bytes (512 MiB).
pub const DEFAULT_CACHE_BYTES: u64 = 512 * 1024 * 1024;

/// Default TTL for cached entries (5 minutes).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Statistics for the read cache.
#[derive(Debug, Default)]
pub struct ReadCacheStats {
    /// Number of cache hits.
    pub hits: AtomicU64,
    /// Number of cache misses.
    pub misses: AtomicU64,
    /// Number of entries inserted.
    pub inserts: AtomicU64,
    /// Number of entries evicted.
    pub evictions: AtomicU64,
}

impl ReadCacheStats {
    /// Record a cache hit.
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an insert.
    pub fn record_insert(&self) {
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }

    /// Get hit ratio (0.0 - 1.0).
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

/// Configuration for the read cache.
#[derive(Debug, Clone, Copy)]
pub struct ReadCacheConfig {
    /// Maximum cache size in bytes.
    pub max_bytes: u64,
    /// Time-to-live for cached entries.
    pub ttl: Duration,
}

impl Default for ReadCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_CACHE_BYTES,
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

/// Cache for decrypted read data.
///
/// Uses `bytes::Bytes` for zero-copy sharing of cached data.
/// Bounded by total bytes using moka's weigher.
pub struct ReadCache {
    cache: Cache<ReadCacheKey, Bytes>,
    stats: ReadCacheStats,
}

impl ReadCache {
    /// Create a new read cache with default configuration.
    pub fn new() -> Self {
        Self::with_config(ReadCacheConfig::default())
    }

    /// Create a new read cache with custom configuration.
    pub fn with_config(config: ReadCacheConfig) -> Self {
        let cache = Cache::builder()
            // Use weigher for byte-based capacity
            .weigher(|_key: &ReadCacheKey, value: &Bytes| -> u32 {
                // Weight is the size of the cached data
                // Cap at u32::MAX to avoid overflow (moka requirement)
                // The truncation is intentional and safe due to the min() call
                #[allow(clippy::cast_possible_truncation)]
                let weight = value.len().min(u32::MAX as usize) as u32;
                weight
            })
            // Maximum capacity in "weight units" (bytes)
            .max_capacity(config.max_bytes)
            // Time-to-live
            .time_to_live(config.ttl)
            .build();

        Self {
            cache,
            stats: ReadCacheStats::default(),
        }
    }

    /// Get cached data for a key.
    ///
    /// Returns `Some(data)` if found, `None` if not cached.
    /// The returned `Bytes` is a zero-copy reference to cached data.
    pub fn get(&self, key: &ReadCacheKey) -> Option<Bytes> {
        match self.cache.get(key) {
            Some(data) => {
                self.stats.record_hit();
                Some(data)
            }
            None => {
                self.stats.record_miss();
                None
            }
        }
    }

    /// Insert data into the cache.
    ///
    /// If an entry with the same key exists, it is replaced.
    pub fn insert(&self, key: ReadCacheKey, data: Bytes) {
        self.stats.record_insert();
        self.cache.insert(key, data);
    }

    /// Invalidate all entries for an inode.
    ///
    /// Used when a file is modified or closed.
    pub fn invalidate_inode(&self, inode: u64) {
        // Note: invalidate_entries_if returns a PredicateId that can be used for debugging,
        // but we don't need it here
        let _ = self.cache.invalidate_entries_if(move |key, _| key.inode == inode);
    }

    /// Invalidate a specific entry.
    pub fn invalidate(&self, key: &ReadCacheKey) {
        self.cache.invalidate(key);
    }

    /// Get the current entry count.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Get the current weighted size (approximate bytes cached).
    pub fn weighted_size(&self) -> u64 {
        self.cache.weighted_size()
    }

    /// Get cache statistics.
    pub fn stats(&self) -> &ReadCacheStats {
        &self.stats
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

impl Default for ReadCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_miss() {
        let cache = ReadCache::new();
        let data = Bytes::from_static(b"hello world");
        let key = ReadCacheKey::new(1, 0, data.len());

        // Miss
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.misses.load(Ordering::Relaxed), 1);

        // Insert
        cache.insert(key, data.clone());

        // Hit
        let cached = cache.get(&key).unwrap();
        assert_eq!(cached, data);
        assert_eq!(cache.stats.hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_invalidate_specific() {
        let cache = ReadCache::new();
        let data = Bytes::from_static(b"data");
        let key = ReadCacheKey::new(1, 0, data.len());

        // Insert and verify
        cache.insert(key, data);
        assert!(cache.get(&key).is_some());

        // Invalidate specific key
        cache.invalidate(&key);

        // Should be gone
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_hit_ratio() {
        let cache = ReadCache::new();
        let data = Bytes::from_static(b"data");
        let key = ReadCacheKey::new(1, 0, data.len());

        // Insert data
        cache.insert(key, data);

        // 3 hits, 2 misses
        cache.get(&key);
        cache.get(&key);
        cache.get(&key);
        cache.get(&ReadCacheKey::new(2, 0, 100)); // Miss - different inode
        cache.get(&ReadCacheKey::new(3, 0, 100)); // Miss - different inode

        let ratio = cache.stats.hit_ratio();
        assert!((ratio - 0.6).abs() < 0.01);
    }

    #[test]
    fn test_different_sizes_are_distinct() {
        // Regression test: reads at same offset with different sizes must be distinct
        let cache = ReadCache::new();
        let small_data = Bytes::from_static(b"small");
        let large_data = Bytes::from_static(b"large data here");

        let small_key = ReadCacheKey::new(1, 0, small_data.len());
        let large_key = ReadCacheKey::new(1, 0, large_data.len());

        // Insert small read
        cache.insert(small_key, small_data.clone());

        // Large read at same offset should miss (different size)
        assert!(cache.get(&large_key).is_none());

        // Small read should still hit
        let cached = cache.get(&small_key).unwrap();
        assert_eq!(cached, small_data);

        // Insert large read
        cache.insert(large_key, large_data.clone());

        // Both should now hit with correct data
        assert_eq!(cache.get(&small_key).unwrap(), small_data);
        assert_eq!(cache.get(&large_key).unwrap(), large_data);
    }
}
