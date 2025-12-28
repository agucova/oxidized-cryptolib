//! Attribute caching for the FUSE filesystem.
//!
//! This module provides TTL-based caching of file attributes to reduce
//! repeated calls to the underlying vault operations. It uses the shared
//! [`TtlCache`](oxidized_mount_common::TtlCache) from `oxidized-mount-common`.

use fuser::FileAttr;
use oxidized_mount_common::{CachedEntry, TtlCache, DEFAULT_NEGATIVE_TTL, DEFAULT_TTL};
use std::time::Duration;

// Re-export constants for backwards compatibility
pub use oxidized_mount_common::{
    DEFAULT_NEGATIVE_TTL as DEFAULT_NEGATIVE_TTL_COMPAT, DEFAULT_TTL as DEFAULT_ATTR_TTL,
};

/// A cached file attribute with expiration time.
///
/// This is a type alias for the shared [`CachedEntry`] with [`FileAttr`].
pub type CachedAttr = CachedEntry<FileAttr>;

/// Thread-safe cache for file attributes.
///
/// This cache helps reduce the number of calls to the underlying vault
/// by caching recently accessed file attributes. Uses two internal
/// [`TtlCache`] instances:
/// - Positive cache: inode -> attributes
/// - Negative cache: (parent_inode, name) -> ENOENT
pub struct AttrCache {
    /// Cached positive entries (inode -> attributes).
    entries: TtlCache<u64, FileAttr>,
    /// Cached negative entries (parent_inode, name) -> ENOENT.
    /// Uses a separate cache because the key type differs.
    /// The value is `()` since we only care about presence and expiration.
    negative: TtlCache<(u64, String), ()>,
}

impl AttrCache {
    /// Creates a new attribute cache with the given TTLs.
    pub fn new(attr_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: TtlCache::new(attr_ttl),
            negative: TtlCache::new(negative_ttl),
        }
    }

    /// Creates a new attribute cache with default TTLs.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_NEGATIVE_TTL)
    }

    /// Gets a cached attribute if it exists and hasn't expired.
    pub fn get(&self, inode: u64) -> Option<CachedAttr> {
        self.entries.get(&inode)
    }

    /// Inserts or updates a cached attribute.
    pub fn insert(&self, inode: u64, attr: FileAttr) {
        self.entries.insert(inode, attr);
    }

    /// Inserts or updates a cached attribute with a custom TTL.
    pub fn insert_with_ttl(&self, inode: u64, attr: FileAttr, ttl: Duration) {
        self.entries.insert_with_ttl(inode, attr, ttl);
    }

    /// Invalidates a cached attribute.
    pub fn invalidate(&self, inode: u64) {
        self.entries.invalidate(&inode);
    }

    /// Checks if a path is in the negative cache (known to not exist).
    pub fn is_negative(&self, parent: u64, name: &str) -> bool {
        self.negative
            .get(&(parent, name.to_string()))
            .is_some_and(|entry| !entry.is_expired())
    }

    /// Adds a path to the negative cache.
    pub fn insert_negative(&self, parent: u64, name: String) {
        self.negative.insert((parent, name), ());
    }

    /// Removes a path from the negative cache (when it's created).
    pub fn remove_negative(&self, parent: u64, name: &str) {
        self.negative.invalidate(&(parent, name.to_string()));
    }

    /// Invalidates all negative cache entries for a parent directory.
    /// Call this when the directory contents change.
    pub fn invalidate_parent_negative(&self, parent: u64) {
        self.negative.invalidate_where(|k| k.0 == parent);
    }

    /// Clears all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        self.entries.cleanup_expired();
        self.negative.cleanup_expired();
    }

    /// Returns the number of entries in the positive cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the positive cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries in the negative cache.
    pub fn negative_len(&self) -> usize {
        self.negative.len()
    }

    /// Returns the attribute TTL.
    pub fn attr_ttl(&self) -> Duration {
        self.entries.ttl()
    }
}

impl Default for AttrCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Cache entry for a directory listing.
#[derive(Debug, Clone)]
pub struct DirListingEntry {
    /// Inode number.
    pub inode: u64,
    /// File type.
    pub file_type: fuser::FileType,
    /// Filename.
    pub name: String,
}

/// Cache for directory listings.
///
/// FUSE calls `readdir` multiple times with an offset to read directories
/// in chunks. Caching the full listing improves performance.
///
/// This is a thin wrapper around [`TtlCache`] for directory listings.
pub struct DirCache {
    /// The underlying cache.
    cache: TtlCache<u64, Vec<DirListingEntry>>,
}

impl DirCache {
    /// Creates a new directory cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: TtlCache::new(ttl),
        }
    }

    /// Gets a cached directory listing if it exists and hasn't expired.
    pub fn get(&self, parent: u64) -> Option<Vec<DirListingEntry>> {
        self.cache.get(&parent).map(|entry| entry.value)
    }

    /// Inserts a directory listing into the cache.
    pub fn insert(&self, parent: u64, entries: Vec<DirListingEntry>) {
        self.cache.insert(parent, entries);
    }

    /// Invalidates a cached directory listing.
    pub fn invalidate(&self, parent: u64) {
        self.cache.invalidate(&parent);
    }

    /// Clears all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        self.cache.cleanup_expired();
    }
}

impl Default for DirCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn make_test_attr(inode: u64) -> FileAttr {
        FileAttr {
            ino: inode,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: fuser::FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = AttrCache::with_defaults();
        let attr = make_test_attr(42);

        cache.insert(42, attr);

        let cached = cache.get(42).unwrap();
        assert_eq!(cached.value.ino, 42);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = AttrCache::new(Duration::from_millis(10), Duration::from_millis(10));
        let attr = make_test_attr(42);

        cache.insert(42, attr);
        assert!(cache.get(42).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn test_negative_cache() {
        let cache = AttrCache::with_defaults();

        cache.insert_negative(1, "nonexistent".to_string());
        assert!(cache.is_negative(1, "nonexistent"));
        assert!(!cache.is_negative(1, "other"));

        cache.remove_negative(1, "nonexistent");
        assert!(!cache.is_negative(1, "nonexistent"));
    }

    #[test]
    fn test_invalidate() {
        let cache = AttrCache::with_defaults();
        let attr = make_test_attr(42);

        cache.insert(42, attr);
        assert!(cache.get(42).is_some());

        cache.invalidate(42);
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn test_insert_with_custom_ttl() {
        let cache = AttrCache::with_defaults();
        let attr = make_test_attr(42);

        // Insert with a very short TTL
        cache.insert_with_ttl(42, attr, Duration::from_millis(10));
        assert!(cache.get(42).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn test_invalidate_parent_negative() {
        let cache = AttrCache::with_defaults();

        // Add negative entries for parent 1
        cache.insert_negative(1, "file1".to_string());
        cache.insert_negative(1, "file2".to_string());
        // Add negative entry for parent 2
        cache.insert_negative(2, "file3".to_string());

        assert!(cache.is_negative(1, "file1"));
        assert!(cache.is_negative(1, "file2"));
        assert!(cache.is_negative(2, "file3"));
        assert_eq!(cache.negative_len(), 3);

        // Invalidate all negative entries for parent 1
        cache.invalidate_parent_negative(1);

        assert!(!cache.is_negative(1, "file1"));
        assert!(!cache.is_negative(1, "file2"));
        assert!(cache.is_negative(2, "file3")); // Still there
        assert_eq!(cache.negative_len(), 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = AttrCache::new(Duration::from_millis(10), Duration::from_millis(10));

        // Insert some entries
        cache.insert(1, make_test_attr(1));
        cache.insert(2, make_test_attr(2));
        cache.insert_negative(1, "gone".to_string());

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.negative_len(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        // Entries are still in the map but expired
        cache.cleanup_expired();

        // Now they should be gone
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_negative_cache_expiry() {
        let cache = AttrCache::new(Duration::from_secs(1), Duration::from_millis(10));

        cache.insert_negative(1, "temp".to_string());
        assert!(cache.is_negative(1, "temp"));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(!cache.is_negative(1, "temp"));
    }

    #[test]
    fn test_cached_attr_time_remaining() {
        let attr = make_test_attr(1);
        let cached = CachedEntry::new(attr, Duration::from_secs(10));

        // Should have close to 10 seconds remaining
        let remaining = cached.time_remaining();
        assert!(remaining > Duration::from_secs(9));
        assert!(remaining <= Duration::from_secs(10));
    }

    #[test]
    fn test_dir_cache_insert_and_get() {
        let cache = DirCache::default();
        let entries = vec![
            DirListingEntry {
                inode: 2,
                file_type: fuser::FileType::Directory,
                name: ".".to_string(),
            },
            DirListingEntry {
                inode: 1,
                file_type: fuser::FileType::Directory,
                name: "..".to_string(),
            },
            DirListingEntry {
                inode: 3,
                file_type: fuser::FileType::RegularFile,
                name: "file.txt".to_string(),
            },
        ];

        cache.insert(2, entries);
        let cached = cache.get(2).unwrap();
        assert_eq!(cached.len(), 3);
        assert_eq!(cached[2].name, "file.txt");
    }

    #[test]
    fn test_dir_cache_expiry() {
        let cache = DirCache::new(Duration::from_millis(10));
        let entries = vec![DirListingEntry {
            inode: 3,
            file_type: fuser::FileType::RegularFile,
            name: "test".to_string(),
        }];

        cache.insert(1, entries);
        assert!(cache.get(1).is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_dir_cache_invalidate() {
        let cache = DirCache::default();
        let entries = vec![DirListingEntry {
            inode: 3,
            file_type: fuser::FileType::RegularFile,
            name: "test".to_string(),
        }];

        cache.insert(1, entries);
        assert!(cache.get(1).is_some());

        cache.invalidate(1);
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_dir_cache_cleanup_expired() {
        let cache = DirCache::new(Duration::from_millis(10));

        cache.insert(
            1,
            vec![DirListingEntry {
                inode: 2,
                file_type: fuser::FileType::RegularFile,
                name: "a".to_string(),
            }],
        );
        cache.insert(
            2,
            vec![DirListingEntry {
                inode: 3,
                file_type: fuser::FileType::RegularFile,
                name: "b".to_string(),
            }],
        );

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        cache.cleanup_expired();

        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_none());
    }

    #[test]
    fn test_concurrent_attr_cache_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(AttrCache::with_defaults());
        let mut handles = vec![];

        // Spawn multiple threads inserting and reading
        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                let inode = i as u64;
                cache.insert(inode, make_test_attr(inode));
                cache.get(inode)
            }));
        }

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_some());
        }

        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_attr_cache_len_and_is_empty() {
        let cache = AttrCache::with_defaults();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert(1, make_test_attr(1));
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);

        cache.insert(2, make_test_attr(2));
        assert_eq!(cache.len(), 2);

        cache.invalidate(1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_attr_cache_attr_ttl() {
        let cache = AttrCache::new(Duration::from_secs(5), Duration::from_secs(2));
        assert_eq!(cache.attr_ttl(), Duration::from_secs(5));
    }

    #[test]
    fn test_cached_dir_listing_is_expired() {
        let entries = vec![DirListingEntry {
            inode: 1,
            file_type: fuser::FileType::RegularFile,
            name: "test".to_string(),
        }];

        let cache = DirCache::new(Duration::from_millis(10));
        cache.insert(1, entries);

        // Entry should not be expired initially
        assert!(cache.get(1).is_some());

        std::thread::sleep(Duration::from_millis(20));

        // Entry should be expired now
        assert!(cache.get(1).is_none());
    }
}
