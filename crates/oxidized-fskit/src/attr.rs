//! Attribute caching for the FSKit filesystem.
//!
//! This module provides TTL-based caching of file attributes to reduce
//! repeated calls to the underlying vault operations.

use dashmap::DashMap;
use fskit_rs::ItemAttributes;
use std::time::{Duration, Instant};

/// Default time-to-live for cached attributes (1 second).
pub const DEFAULT_ATTR_TTL: Duration = Duration::from_secs(1);

/// Threshold for triggering automatic cache cleanup.
/// When cache exceeds this many entries, expired entries are removed.
const CLEANUP_THRESHOLD: usize = 10_000;

/// A cached file attribute with expiration time.
#[derive(Debug, Clone)]
pub struct CachedAttr {
    /// The cached file attributes.
    pub attrs: ItemAttributes,
    /// When this cache entry expires.
    expires: Instant,
}

impl CachedAttr {
    /// Creates a new cached attribute entry.
    pub fn new(attrs: ItemAttributes, ttl: Duration) -> Self {
        Self {
            attrs,
            expires: Instant::now() + ttl,
        }
    }

    /// Returns true if this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }
}

/// Thread-safe cache for file attributes.
///
/// This cache helps reduce the number of calls to the underlying vault
/// by caching recently accessed file attributes.
pub struct AttrCache {
    /// Cached entries (item_id -> attributes).
    entries: DashMap<u64, CachedAttr>,
    /// TTL for cache entries.
    ttl: Duration,
}

impl AttrCache {
    /// Creates a new attribute cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Creates a new attribute cache with default TTL.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_ATTR_TTL)
    }

    /// Gets a cached attribute if it exists and hasn't expired.
    pub fn get(&self, item_id: u64) -> Option<CachedAttr> {
        if let Some(entry) = self.entries.get(&item_id) {
            if !entry.is_expired() {
                return Some(entry.clone());
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(&item_id);
        }
        None
    }

    /// Inserts or updates a cached attribute.
    ///
    /// Triggers automatic cleanup when cache exceeds threshold.
    pub fn insert(&self, item_id: u64, attrs: ItemAttributes) {
        self.entries.insert(item_id, CachedAttr::new(attrs, self.ttl));
        self.maybe_cleanup();
    }

    /// Invalidates a cached attribute.
    pub fn invalidate(&self, item_id: u64) {
        self.entries.remove(&item_id);
    }

    /// Clears all cached entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Triggers cleanup if cache exceeds threshold.
    fn maybe_cleanup(&self) {
        if self.entries.len() > CLEANUP_THRESHOLD {
            self.cleanup_expired();
        }
    }

    /// Removes all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        self.entries.retain(|_, v| !v.is_expired());
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
        assert_eq!(cached.attrs.file_id, attrs.file_id);
        assert_eq!(cached.attrs.size, attrs.size);
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
