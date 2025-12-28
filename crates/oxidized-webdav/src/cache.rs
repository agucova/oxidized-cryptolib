//! Metadata caching for the WebDAV filesystem.
//!
//! This module provides TTL-based caching of file/directory metadata to reduce
//! repeated vault operations on PROPFIND requests.

use crate::metadata::CryptomatorMetaData;
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Default time-to-live for cached metadata (1 second).
pub const DEFAULT_METADATA_TTL: Duration = Duration::from_secs(1);

/// Threshold for triggering automatic cache cleanup.
/// When cache exceeds this many entries, expired entries are removed.
const CLEANUP_THRESHOLD: usize = 10_000;

/// A cached metadata entry with expiration time.
#[derive(Debug, Clone)]
pub struct CachedMetadata {
    /// The cached metadata.
    pub metadata: CryptomatorMetaData,
    /// When this cache entry expires.
    expires: Instant,
}

impl CachedMetadata {
    /// Creates a new cached metadata entry.
    pub fn new(metadata: CryptomatorMetaData, ttl: Duration) -> Self {
        Self {
            metadata,
            expires: Instant::now() + ttl,
        }
    }

    /// Returns true if this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }
}

/// Thread-safe cache for file/directory metadata.
///
/// This cache helps reduce the number of vault operations by caching
/// recently accessed metadata, keyed by path.
pub struct MetadataCache {
    /// Cached entries (path -> metadata).
    entries: DashMap<String, CachedMetadata>,
    /// TTL for cache entries.
    ttl: Duration,
}

impl MetadataCache {
    /// Creates a new metadata cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Creates a new metadata cache with default TTL.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_METADATA_TTL)
    }

    /// Gets cached metadata if it exists and hasn't expired.
    pub fn get(&self, path: &str) -> Option<CachedMetadata> {
        if let Some(entry) = self.entries.get(path) {
            if !entry.is_expired() {
                return Some(entry.clone());
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(path);
        }
        None
    }

    /// Inserts or updates cached metadata.
    ///
    /// Triggers automatic cleanup when cache exceeds threshold.
    pub fn insert(&self, path: String, metadata: CryptomatorMetaData) {
        self.entries
            .insert(path, CachedMetadata::new(metadata, self.ttl));
        self.maybe_cleanup();
    }

    /// Invalidates cached metadata for a path.
    pub fn invalidate(&self, path: &str) {
        self.entries.remove(path);
    }

    /// Invalidates all cached metadata under a path prefix.
    ///
    /// Useful for invalidating a directory and its contents.
    pub fn invalidate_prefix(&self, prefix: &str) {
        self.entries.retain(|k, _| !k.starts_with(prefix));
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

impl Default for MetadataCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dav_server::fs::DavMetaData;

    fn make_test_metadata() -> CryptomatorMetaData {
        CryptomatorMetaData::file_with_size("test.txt".to_string(), 100)
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = MetadataCache::with_defaults();
        let meta = make_test_metadata();

        cache.insert("/test.txt".to_string(), meta.clone());

        let cached = cache.get("/test.txt").expect("Should be cached");
        assert!(cached.metadata.is_file());
    }

    #[test]
    fn test_cache_miss() {
        let cache = MetadataCache::with_defaults();
        assert!(cache.get("/nonexistent").is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = MetadataCache::with_defaults();
        cache.insert("/test.txt".to_string(), make_test_metadata());

        assert!(cache.get("/test.txt").is_some());

        cache.invalidate("/test.txt");

        assert!(cache.get("/test.txt").is_none());
    }

    #[test]
    fn test_cache_invalidate_prefix() {
        let cache = MetadataCache::with_defaults();
        cache.insert("/dir/file1.txt".to_string(), make_test_metadata());
        cache.insert("/dir/file2.txt".to_string(), make_test_metadata());
        cache.insert("/other/file.txt".to_string(), make_test_metadata());

        assert_eq!(cache.len(), 3);

        cache.invalidate_prefix("/dir");

        assert_eq!(cache.len(), 1);
        assert!(cache.get("/other/file.txt").is_some());
    }

    #[test]
    fn test_cache_expiry() {
        let cache = MetadataCache::new(Duration::from_millis(10));
        cache.insert("/test.txt".to_string(), make_test_metadata());

        assert!(cache.get("/test.txt").is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get("/test.txt").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = MetadataCache::with_defaults();
        cache.insert("/test1.txt".to_string(), make_test_metadata());
        cache.insert("/test2.txt".to_string(), make_test_metadata());

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert!(cache.is_empty());
    }
}
