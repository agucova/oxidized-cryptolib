//! Attribute caching for the FSKit filesystem.
//!
//! This module provides TTL-based caching of file attributes to reduce
//! repeated calls to the underlying vault operations. It uses the shared
//! [`TtlCache`](oxidized_mount_common::TtlCache) from `oxidized-mount-common`.

use fskit_rs::ItemAttributes;
use oxidized_mount_common::{CacheStats, CachedEntry, TtlCache, DEFAULT_TTL};
use std::sync::Arc;
use std::time::Duration;

// Re-export for backwards compatibility
pub use oxidized_mount_common::DEFAULT_TTL as DEFAULT_ATTR_TTL;

/// A cached file attribute with expiration time.
///
/// This is a type alias for the shared [`CachedEntry`] with [`ItemAttributes`].
pub type CachedAttr = CachedEntry<ItemAttributes>;

/// Thread-safe cache for file attributes.
///
/// This cache helps reduce the number of calls to the underlying vault
/// by caching recently accessed file attributes. Uses [`TtlCache`] internally.
pub struct AttrCache {
    /// The underlying cache.
    cache: TtlCache<u64, ItemAttributes>,
}

impl AttrCache {
    /// Creates a new attribute cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: TtlCache::new(ttl),
        }
    }

    /// Creates a new attribute cache with default TTL.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TTL)
    }

    /// Enables statistics tracking on this cache.
    ///
    /// The provided `CacheStats` will be updated on every cache operation,
    /// allowing external monitoring of cache efficiency.
    pub fn set_stats(&mut self, stats: Arc<CacheStats>) {
        self.cache.set_stats(stats);
    }

    /// Gets a cached attribute if it exists and hasn't expired.
    pub fn get(&self, item_id: u64) -> Option<CachedAttr> {
        self.cache.get(&item_id)
    }

    /// Inserts or updates a cached attribute.
    pub fn insert(&self, item_id: u64, attrs: ItemAttributes) {
        self.cache.insert(item_id, attrs);
    }

    /// Invalidates a cached attribute.
    pub fn invalidate(&self, item_id: u64) {
        self.cache.invalidate(&item_id);
    }

    /// Clears all cached entries.
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Removes all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        self.cache.cleanup_expired();
    }
}

impl Default for AttrCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_attrs(item_id: u64) -> ItemAttributes {
        ItemAttributes {
            file_id: Some(item_id),
            size: Some(100),
            ..Default::default()
        }
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = AttrCache::with_defaults();
        let attrs = make_test_attrs(1);

        cache.insert(1, attrs.clone());

        let cached = cache.get(1).expect("Should be cached");
        assert_eq!(cached.value.file_id, attrs.file_id);
        assert_eq!(cached.value.size, attrs.size);
    }

    #[test]
    fn test_cache_miss() {
        let cache = AttrCache::with_defaults();
        assert!(cache.get(999).is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = AttrCache::with_defaults();
        cache.insert(1, make_test_attrs(1));

        assert!(cache.get(1).is_some());

        cache.invalidate(1);

        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_cache_expiry() {
        let cache = AttrCache::new(Duration::from_millis(10));
        cache.insert(1, make_test_attrs(1));

        assert!(cache.get(1).is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = AttrCache::with_defaults();
        cache.insert(1, make_test_attrs(1));
        cache.insert(2, make_test_attrs(2));

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert!(cache.is_empty());
    }
}
