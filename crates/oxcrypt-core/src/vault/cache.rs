//! Vault operation caching infrastructure.
//!
//! This module provides thread-safe caching for expensive cryptographic operations
//! that produce deterministic results. All caches use lock-free data structures
//! for concurrent access without contention.

use dashmap::DashMap;

/// Cache key for encrypted filenames: (directory_id, plaintext_name)
type EncryptedNameCacheKey = (String, String);

/// Encrypted filename cache value: base64url-encoded encrypted name
type EncryptedNameCacheValue = String;

/// Thread-safe cache for vault operations.
///
/// This cache stores results of deterministic cryptographic operations to avoid
/// redundant expensive computations. All operations use AES-SIV which is deterministic,
/// so results can be safely cached indefinitely without invalidation.
///
/// # Thread Safety
///
/// `VaultCache` uses `DashMap` internally, providing lock-free concurrent access.
/// It can be safely shared across threads via `Arc<VaultCache>`.
///
/// # Usage
///
/// ```ignore
/// let cache = Arc::new(VaultCache::new());
///
/// // Share between sync and async operations
/// let async_ops = VaultOperationsAsync::with_cache(vault_path, master_key, cache.clone());
/// let sync_ops = async_ops.as_sync(); // Shares the same cache
/// ```
#[derive(Debug, Default)]
pub struct VaultCache {
    /// Encrypted filename cache: (dir_id, name) -> encrypted_name
    ///
    /// Caches the result of AES-SIV encryption for filenames. Since AES-SIV is
    /// deterministic, the same (dir_id, name) tuple always produces the same
    /// encrypted result.
    ///
    /// Key: (directory_id, plaintext_filename)
    /// Value: base64url-encoded encrypted filename
    encrypted_names: DashMap<EncryptedNameCacheKey, EncryptedNameCacheValue>,
}

impl VaultCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an encrypted filename from the cache.
    ///
    /// Returns `None` if the entry is not cached.
    #[inline]
    pub fn get_encrypted_name(&self, dir_id: &str, name: &str) -> Option<String> {
        let key = (dir_id.to_string(), name.to_string());
        self.encrypted_names.get(&key).map(|v| v.clone())
    }

    /// Store an encrypted filename in the cache.
    #[inline]
    pub fn insert_encrypted_name(&self, dir_id: &str, name: &str, encrypted: String) {
        let key = (dir_id.to_string(), name.to_string());
        self.encrypted_names.insert(key, encrypted);
    }

    /// Get cache statistics for monitoring and debugging.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            encrypted_name_entries: self.encrypted_names.len(),
        }
    }

    /// Clear all cached entries.
    ///
    /// This is primarily useful for testing. In production, caches never need
    /// clearing since encryption is deterministic.
    #[cfg(test)]
    pub fn clear(&self) {
        self.encrypted_names.clear();
    }
}

/// Statistics about cache usage.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Number of cached encrypted filename entries
    pub encrypted_name_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = VaultCache::new();
        let stats = cache.stats();
        assert_eq!(stats.encrypted_name_entries, 0);
    }

    #[test]
    fn test_encrypted_name_cache() {
        let cache = VaultCache::new();

        // Cache miss
        assert_eq!(cache.get_encrypted_name("dir1", "file.txt"), None);

        // Insert
        cache.insert_encrypted_name("dir1", "file.txt", "encrypted123".to_string());

        // Cache hit
        assert_eq!(
            cache.get_encrypted_name("dir1", "file.txt"),
            Some("encrypted123".to_string())
        );

        // Different dir_id = different cache entry
        assert_eq!(cache.get_encrypted_name("dir2", "file.txt"), None);
    }

    #[test]
    fn test_cache_stats() {
        let cache = VaultCache::new();
        cache.insert_encrypted_name("dir1", "file1.txt", "enc1".to_string());
        cache.insert_encrypted_name("dir1", "file2.txt", "enc2".to_string());

        let stats = cache.stats();
        assert_eq!(stats.encrypted_name_entries, 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache = VaultCache::new();
        cache.insert_encrypted_name("dir1", "file.txt", "enc".to_string());
        assert_eq!(cache.stats().encrypted_name_entries, 1);

        cache.clear();
        assert_eq!(cache.stats().encrypted_name_entries, 0);
    }

    #[test]
    fn test_cache_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(VaultCache::new());
        let mut handles = vec![];

        // Spawn 10 threads, each inserting 100 entries
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let name = format!("file{j}.txt");
                    let encrypted = format!("enc{i}_{j}");
                    cache_clone.insert_encrypted_name("dir1", &name, encrypted);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all entries were inserted
        let stats = cache.stats();
        assert_eq!(stats.encrypted_name_entries, 100); // Same filenames, last write wins
    }
}
