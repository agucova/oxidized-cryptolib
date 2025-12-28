//! Concurrent access locking for vault operations.
//!
//! This module provides thread-safe locking primitives for vault operations,
//! enabling multiple concurrent readers while ensuring exclusive write access.
//! The locking strategy follows a consistent ordering to prevent deadlocks.
//!
//! # Locking Strategy
//!
//! - **Directory locks**: Protect directory listing and metadata operations
//! - **File locks**: Protect individual file read/write operations
//! - **Ordering**: Directories locked before files; multiple directories locked by ID order
//!
//! # Deadlock Prevention
//!
//! 1. Lock directories in lexicographic order of `DirId`
//! 2. Acquire directory locks before file locks
//! 3. Never upgrade read locks to write locks
//! 4. Lock multiple files in lexicographic filename order
//!
//! # Global Lock Registry
//!
//! The [`VaultLockRegistry`] ensures that all instances operating on the same
//! vault path share the same [`VaultLockManager`]. This is critical for proper
//! synchronization when multiple `VaultOperationsAsync` instances are created
//! for the same vault.

use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use super::path::DirId;

/// Global lock registry singleton.
static GLOBAL_LOCK_REGISTRY: OnceLock<VaultLockRegistry> = OnceLock::new();

/// Registry mapping vault paths to their shared lock managers.
///
/// This ensures that all instances of `VaultOperationsAsync` operating on the
/// same vault path share the same lock manager, providing proper synchronization
/// even when multiple instances are created independently.
///
/// # Thread Safety
///
/// The registry is thread-safe and can be accessed from multiple threads
/// simultaneously. It uses `DashMap` for concurrent access.
///
/// # Example
///
/// ```ignore
/// use oxidized_cryptolib::vault::locks::VaultLockRegistry;
/// use std::path::Path;
///
/// let registry = VaultLockRegistry::global();
///
/// // Get or create a lock manager for a vault
/// let lock_manager = registry.get_or_create(Path::new("/path/to/vault"));
///
/// // Another call with the same path returns the same manager
/// let same_manager = registry.get_or_create(Path::new("/path/to/vault"));
/// assert!(Arc::ptr_eq(&lock_manager, &same_manager));
/// ```
#[derive(Debug, Default)]
pub struct VaultLockRegistry {
    /// Map from canonicalized vault paths to their lock managers.
    managers: DashMap<PathBuf, Arc<VaultLockManager>>,
}

impl VaultLockRegistry {
    /// Create a new empty lock registry.
    pub fn new() -> Self {
        Self {
            managers: DashMap::new(),
        }
    }

    /// Get the global lock registry singleton.
    ///
    /// This is the preferred way to access the registry, ensuring all
    /// vault operations share the same synchronization infrastructure.
    pub fn global() -> &'static Self {
        GLOBAL_LOCK_REGISTRY.get_or_init(Self::new)
    }

    /// Get or create a lock manager for a vault path.
    ///
    /// If a lock manager already exists for this path (after canonicalization),
    /// it is returned. Otherwise, a new one is created and cached.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault root directory
    ///
    /// # Note
    ///
    /// The path is canonicalized to ensure that different representations
    /// of the same path (e.g., with symlinks or `..` components) map to
    /// the same lock manager.
    pub fn get_or_create(&self, vault_path: &Path) -> Arc<VaultLockManager> {
        // Canonicalize the path to handle symlinks, .., etc.
        // If canonicalization fails (e.g., path doesn't exist yet), use the original path.
        let canonical_path = vault_path.canonicalize().unwrap_or_else(|_| vault_path.to_path_buf());

        self.managers
            .entry(canonical_path)
            .or_insert_with(|| Arc::new(VaultLockManager::new()))
            .clone()
    }

    /// Remove a lock manager for a vault path.
    ///
    /// This is typically called when closing a vault to free resources.
    /// Returns the removed manager if one existed.
    ///
    /// # Note
    ///
    /// This only removes from the registry. Any existing references to the
    /// lock manager will continue to work until all clones are dropped.
    pub fn remove(&self, vault_path: &Path) -> Option<Arc<VaultLockManager>> {
        let canonical_path = vault_path.canonicalize().unwrap_or_else(|_| vault_path.to_path_buf());
        self.managers.remove(&canonical_path).map(|(_, v)| v)
    }

    /// Get the number of registered vault lock managers.
    pub fn len(&self) -> usize {
        self.managers.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.managers.is_empty()
    }

    /// Clear all registered lock managers.
    ///
    /// # Warning
    ///
    /// This should only be used for testing or cleanup during shutdown.
    /// Any existing operations using the old managers may behave unexpectedly.
    pub fn clear(&self) {
        self.managers.clear();
    }
}

/// File lock key: (parent directory ID, filename).
pub type FileLockKey = (DirId, String);

/// Central manager for vault locks.
///
/// Provides per-directory and per-file reader-writer locks.
/// Locks are created lazily on first access and cached for reuse.
///
/// # Example
///
/// ```ignore
/// use oxidized_cryptolib::vault::locks::VaultLockManager;
/// use oxidized_cryptolib::vault::DirId;
///
/// let manager = VaultLockManager::new();
/// let root = DirId::root();
///
/// // Acquire a read lock on the root directory
/// let lock = manager.directory_lock(&root);
/// let guard = lock.read().await;
/// // ... perform read operations ...
/// drop(guard);
/// ```
#[derive(Debug, Default)]
pub struct VaultLockManager {
    /// Per-directory locks for listing and directory metadata operations.
    directory_locks: DashMap<DirId, Arc<RwLock<()>>>,

    /// Per-file locks for file read/write operations.
    /// Key: (parent_dir_id, filename) to uniquely identify files.
    file_locks: DashMap<FileLockKey, Arc<RwLock<()>>>,
}

impl VaultLockManager {
    /// Create a new lock manager.
    pub fn new() -> Self {
        Self {
            directory_locks: DashMap::new(),
            file_locks: DashMap::new(),
        }
    }

    /// Get or create a directory lock.
    ///
    /// Returns an `Arc<RwLock<()>>` that can be used to acquire read or write access.
    /// The lock is cached for future use.
    pub fn directory_lock(&self, dir_id: &DirId) -> Arc<RwLock<()>> {
        self.directory_locks
            .entry(dir_id.clone())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    /// Get or create a file lock.
    ///
    /// Returns an `Arc<RwLock<()>>` that can be used to acquire read or write access.
    /// The lock is cached for future use.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - The parent directory ID
    /// * `filename` - The decrypted filename
    pub fn file_lock(&self, dir_id: &DirId, filename: &str) -> Arc<RwLock<()>> {
        let key = (dir_id.clone(), filename.to_string());
        self.file_locks
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    /// Acquire read locks on a directory in consistent order.
    ///
    /// This method acquires an owned read guard that can be held across await points.
    pub async fn directory_read(&self, dir_id: &DirId) -> OwnedRwLockReadGuard<()> {
        let lock = self.directory_lock(dir_id);
        lock.read_owned().await
    }

    /// Acquire write lock on a directory.
    ///
    /// This method acquires an owned write guard that can be held across await points.
    pub async fn directory_write(&self, dir_id: &DirId) -> OwnedRwLockWriteGuard<()> {
        let lock = self.directory_lock(dir_id);
        lock.write_owned().await
    }

    /// Acquire read lock on a file.
    ///
    /// This method acquires an owned read guard that can be held across await points.
    pub async fn file_read(&self, dir_id: &DirId, filename: &str) -> OwnedRwLockReadGuard<()> {
        let lock = self.file_lock(dir_id, filename);
        lock.read_owned().await
    }

    /// Acquire write lock on a file.
    ///
    /// This method acquires an owned write guard that can be held across await points.
    pub async fn file_write(&self, dir_id: &DirId, filename: &str) -> OwnedRwLockWriteGuard<()> {
        let lock = self.file_lock(dir_id, filename);
        lock.write_owned().await
    }

    /// Acquire write locks on multiple directories in consistent order.
    ///
    /// Directories are locked in lexicographic order of their IDs to prevent deadlocks.
    /// Returns guards in the same order as the sorted directory IDs.
    ///
    /// # Arguments
    ///
    /// * `dir_ids` - Slice of directory IDs to lock
    ///
    /// # Returns
    ///
    /// Vector of (DirId, WriteGuard) pairs in sorted order.
    pub async fn lock_directories_write_ordered(
        &self,
        dir_ids: &[&DirId],
    ) -> Vec<(DirId, OwnedRwLockWriteGuard<()>)> {
        // Sort by DirId string for consistent ordering
        let mut sorted: Vec<_> = dir_ids.iter().map(|&id| id.clone()).collect();
        sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        sorted.dedup();

        let mut guards = Vec::with_capacity(sorted.len());
        for dir_id in sorted {
            let lock = self.directory_lock(&dir_id);
            let guard = lock.write_owned().await;
            guards.push((dir_id, guard));
        }
        guards
    }

    /// Acquire write locks on multiple files in the same directory in consistent order.
    ///
    /// Files are locked in lexicographic order of their filenames to prevent deadlocks.
    ///
    /// # Arguments
    ///
    /// * `dir_id` - The parent directory ID
    /// * `filenames` - Slice of filenames to lock
    ///
    /// # Returns
    ///
    /// Vector of (filename, WriteGuard) pairs in sorted order.
    pub async fn lock_files_write_ordered(
        &self,
        dir_id: &DirId,
        filenames: &[&str],
    ) -> Vec<(String, OwnedRwLockWriteGuard<()>)> {
        // Sort filenames for consistent ordering
        let mut sorted: Vec<_> = filenames.iter().map(|&s| s.to_string()).collect();
        sorted.sort();
        sorted.dedup();

        let mut guards = Vec::with_capacity(sorted.len());
        for filename in sorted {
            let lock = self.file_lock(dir_id, &filename);
            let guard = lock.write_owned().await;
            guards.push((filename, guard));
        }
        guards
    }

    /// Remove unused locks from the cache.
    ///
    /// This removes locks where the `Arc` has only one strong reference
    /// (held by the cache itself), meaning no operations are using it.
    ///
    /// Call this periodically to prevent unbounded memory growth.
    pub fn cleanup_unused_locks(&self) {
        self.directory_locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        self.file_locks.retain(|_, lock| Arc::strong_count(lock) > 1);
    }

    /// Get the number of cached directory locks.
    pub fn directory_lock_count(&self) -> usize {
        self.directory_locks.len()
    }

    /// Get the number of cached file locks.
    pub fn file_lock_count(&self) -> usize {
        self.file_locks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_directory_lock_creation() {
        let manager = VaultLockManager::new();
        let dir_id = DirId::from_raw("test-dir-123");

        // First access should create the lock
        assert_eq!(manager.directory_lock_count(), 0);
        let _lock = manager.directory_lock(&dir_id);
        assert_eq!(manager.directory_lock_count(), 1);

        // Second access should reuse the lock
        let _lock2 = manager.directory_lock(&dir_id);
        assert_eq!(manager.directory_lock_count(), 1);
    }

    #[tokio::test]
    async fn test_file_lock_creation() {
        let manager = VaultLockManager::new();
        let dir_id = DirId::from_raw("test-dir-123");

        assert_eq!(manager.file_lock_count(), 0);
        let _lock = manager.file_lock(&dir_id, "file.txt");
        assert_eq!(manager.file_lock_count(), 1);

        // Different file, same directory
        let _lock2 = manager.file_lock(&dir_id, "other.txt");
        assert_eq!(manager.file_lock_count(), 2);

        // Same file, reuse lock
        let _lock3 = manager.file_lock(&dir_id, "file.txt");
        assert_eq!(manager.file_lock_count(), 2);
    }

    #[tokio::test]
    async fn test_concurrent_directory_reads() {
        let manager = Arc::new(VaultLockManager::new());
        let dir_id = DirId::from_raw("test-dir");

        // Acquire two read locks concurrently - should succeed
        let manager2 = manager.clone();
        let dir_id2 = dir_id.clone();

        let handle1 = tokio::spawn(async move {
            let _guard = manager2.directory_read(&dir_id2).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let handle2 = tokio::spawn({
            let manager = manager.clone();
            let dir_id = dir_id.clone();
            async move {
                let _guard = manager.directory_read(&dir_id).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        // Both should complete without timeout
        let result = timeout(Duration::from_millis(200), async {
            handle1.await.unwrap();
            handle2.await.unwrap();
        })
        .await;

        assert!(result.is_ok(), "Concurrent reads should not block");
    }

    #[tokio::test]
    async fn test_write_blocks_read() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let manager = Arc::new(VaultLockManager::new());
        let dir_id = DirId::from_raw("test-dir");
        let read_acquired = Arc::new(AtomicBool::new(false));

        // Acquire write lock
        let write_guard = manager.directory_write(&dir_id).await;

        // Try to acquire read lock - should block
        let manager2 = manager.clone();
        let dir_id2 = dir_id.clone();
        let read_acquired2 = read_acquired.clone();
        let read_handle = tokio::spawn(async move {
            let _guard = manager2.directory_read(&dir_id2).await;
            read_acquired2.store(true, Ordering::SeqCst);
        });

        // Give the spawned task a chance to attempt the read lock
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Read should NOT have completed while write is held
        assert!(
            !read_acquired.load(Ordering::SeqCst),
            "Read should be blocked while write lock is held"
        );

        // Drop write lock
        drop(write_guard);

        // Now read should complete
        let result = timeout(Duration::from_millis(100), read_handle).await;
        assert!(result.is_ok(), "Read should complete after write is released");
        assert!(
            read_acquired.load(Ordering::SeqCst),
            "Read lock should have been acquired after write released"
        );
    }

    #[tokio::test]
    async fn test_ordered_directory_locking() {
        let manager = VaultLockManager::new();
        let dir_a = DirId::from_raw("aaa");
        let dir_b = DirId::from_raw("bbb");
        let dir_c = DirId::from_raw("ccc");

        // Lock in arbitrary order, should come out sorted
        let guards = manager
            .lock_directories_write_ordered(&[&dir_c, &dir_a, &dir_b])
            .await;

        assert_eq!(guards.len(), 3);
        assert_eq!(guards[0].0.as_str(), "aaa");
        assert_eq!(guards[1].0.as_str(), "bbb");
        assert_eq!(guards[2].0.as_str(), "ccc");
    }

    #[tokio::test]
    async fn test_ordered_directory_locking_dedup() {
        let manager = VaultLockManager::new();
        let dir_a = DirId::from_raw("aaa");

        // Duplicate entries should be deduplicated
        let guards = manager
            .lock_directories_write_ordered(&[&dir_a, &dir_a, &dir_a])
            .await;

        assert_eq!(guards.len(), 1);
    }

    #[tokio::test]
    async fn test_ordered_file_locking() {
        let manager = VaultLockManager::new();
        let dir_id = DirId::from_raw("test-dir");

        // Lock files in arbitrary order, should come out sorted
        let guards = manager
            .lock_files_write_ordered(&dir_id, &["zebra.txt", "alpha.txt", "middle.txt"])
            .await;

        assert_eq!(guards.len(), 3);
        assert_eq!(guards[0].0, "alpha.txt");
        assert_eq!(guards[1].0, "middle.txt");
        assert_eq!(guards[2].0, "zebra.txt");
    }

    #[tokio::test]
    async fn test_cleanup_unused_locks() {
        let manager = VaultLockManager::new();
        let dir_id = DirId::from_raw("test-dir");

        // Create and drop a lock
        {
            let _guard = manager.directory_read(&dir_id).await;
        }

        assert_eq!(manager.directory_lock_count(), 1);

        // Cleanup should remove the unused lock
        manager.cleanup_unused_locks();
        assert_eq!(manager.directory_lock_count(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_preserves_used_locks() {
        let manager = VaultLockManager::new();
        let dir_id = DirId::from_raw("test-dir");

        // Keep a lock alive
        let _guard = manager.directory_read(&dir_id).await;

        assert_eq!(manager.directory_lock_count(), 1);

        // Cleanup should NOT remove the lock that's in use
        manager.cleanup_unused_locks();
        assert_eq!(manager.directory_lock_count(), 1);
    }

    #[tokio::test]
    async fn test_root_directory_locking() {
        let manager = VaultLockManager::new();
        let root = DirId::root();

        // Root directory should be lockable like any other
        let _guard = manager.directory_write(&root).await;
        assert_eq!(manager.directory_lock_count(), 1);
    }
}
