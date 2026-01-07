//! FUSE filesystem implementation for Cryptomator vaults.
//!
//! This module implements the fuser `Filesystem` trait for mounting
//! Cryptomator vaults as native filesystems.
//!
//! # FUSE API Compliance Audit
//!
//! ## Reference Documents
//! - libfuse `fuse_lowlevel_ops`: <https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html>
//! - fuser crate: <https://docs.rs/fuser/latest/fuser/trait.Filesystem.html>
//! - libfuse header: `include/fuse_lowlevel.h`
//!
//! ## Audit Summary
//!
//! | Operation | Status | Notes |
//! |-----------|--------|-------|
//! | init/destroy | OK | |
//! | lookup | OK | Correctly increments nlookup via `get_or_insert` |
//! | forget/batch_forget | OK | Correctly decrements nlookup, evicts at 0 |
//! | getattr | OK | |
//! | setattr | PARTIAL | Does not handle setuid/setgid bit reset |
//! | readlink | OK | |
//! | open/release | OK | |
//! | read/write | OK | |
//! | flush/fsync | OK | |
//! | opendir/releasedir | OK | |
//! | readdir | OK | Uses `get_or_insert_no_lookup_inc` (per spec) |
//! | readdirplus | OK | Correctly increments nlookup for non-. entries |
//! | create | OK | |
//! | mkdir/rmdir | OK | |
//! | unlink | OK | |
//! | symlink | OK | |
//! | rename | OK | RENAME_NOREPLACE and RENAME_EXCHANGE supported (Linux only) |
//! | access | OK | |
//! | statfs | OK | |
//! | fallocate | OK | Only mode=0 supported (correct for non-sparse FS) |
//! | copy_file_range | OK | |
//! | lseek | OK | SEEK_DATA/SEEK_HOLE handled correctly for non-sparse |
//!
//! ## Notes
//!
//! - RENAME_EXCHANGE for directories requires same parent (cross-parent returns EXDEV)
//! - RENAME_EXCHANGE for files works across directories with re-encryption

use crate::attr::{AttrCache, DirCache, DirListingEntry, DEFAULT_ATTR_TTL};
use crate::config::MountConfig;
use crate::error::{FuseError, FuseResult, ToErrno};
use crate::handles::{FuseHandle, FuseHandleTable, WriteBuffer};
use crate::inode::{InodeKind, InodeTable};
use crate::scheduler::{FuseScheduler, SchedulerConfig};
use dashmap::DashMap;

use filetime::FileTime;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen, ReplyWrite, Request,
    TimeOrNow,
};
use libc::c_int;
use oxcrypt_core::fs::encrypted_to_plaintext_size_or_zero;
use oxcrypt_core::vault::{DirId, VaultOperationsAsync, VaultPath};
use oxcrypt_mount::VaultStats;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, error, info, trace, warn};

/// Block size for filesystem statistics.
const BLOCK_SIZE: u32 = 4096;

/// Default file permissions (rw-r--r--).
const DEFAULT_FILE_PERM: u16 = 0o644;

/// Default directory permissions (rwxr-xr-x).
const DEFAULT_DIR_PERM: u16 = 0o755;

/// FUSE filesystem for Cryptomator vaults.
///
/// Implements the fuser `Filesystem` trait to provide a mountable filesystem
/// backed by an encrypted Cryptomator vault.
pub struct CryptomatorFS {
    /// Handle to tokio runtime for async operations.
    /// Points to either our owned runtime or an external one.
    handle: Handle,
    /// Owned tokio runtime (when we create our own).
    /// Must be kept alive for the handle to remain valid.
    /// IMPORTANT: Declared after handle so it drops last (Rust drops fields in declaration order).
    _owned_runtime: Option<Runtime>,
    /// Default timeout for I/O operations.
    default_timeout: Duration,
    /// Extended timeout for write/data operations (5 minutes).
    write_timeout: Duration,
    /// Statistics for async bridge operations.
    stats: Arc<crate::async_bridge::BridgeStats>,
    /// Async vault operations (shared via Arc for thread safety).
    ops: Arc<VaultOperationsAsync>,
    /// Inode table for path/inode mapping.
    inodes: InodeTable,
    /// Attribute cache for file metadata.
    attr_cache: AttrCache,
    /// Directory listing cache.
    dir_cache: DirCache,
    /// File handle table for open files (shared with scheduler for reader restoration).
    handle_table: Arc<FuseHandleTable>,
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
    /// Statistics for monitoring vault activity.
    vault_stats: Arc<VaultStats>,
    /// Mount configuration (TTLs, concurrency, etc.).
    #[allow(dead_code)]
    config: MountConfig,
    /// Open handle tracker for POSIX-compliant deferred deletion.
    open_handle_tracker: crate::handles::OpenHandleTracker,
    /// Kernel notifier for cache invalidation (injected post-mount).
    /// This is set by the backend after spawning the FUSE session.
    notifier: OnceLock<fuser::Notifier>,
    /// Tracks current WriteBuffer sizes per inode for mmap consistency.
    ///
    /// When a file is opened for writing, the WriteBuffer may grow beyond
    /// what's on disk. For mmap to work correctly, getattr must return the
    /// current buffer size, not the on-disk size. This map tracks the
    /// maximum known buffer size per inode.
    ///
    /// Updated by: write(), setattr() (extend), fallocate(), copy_file_range()
    /// Checked by: getattr(), lookup(), readdir()
    /// Cleared by: release() (after flush to disk)
    buffer_sizes: DashMap<u64, u64>,
    /// Cached sync operations for fast path (sync VaultOperations instance).
    ///
    /// Lazily created on first use to avoid async overhead for metadata operations.
    /// Shares the same master key and vault configuration as the async ops.
    /// Wrapped in Arc for cheap cloning.
    sync_ops_cache: std::sync::Mutex<Option<Arc<oxcrypt_core::vault::VaultOperations>>>,
    /// Scheduler for async FUSE request handling.
    ///
    /// Created during construction but started in `init()`. Handles reads
    /// asynchronously to prevent blocking FUSE callback threads on slow I/O.
    scheduler: Option<FuseScheduler>,
}

impl CryptomatorFS {
    /// Creates a new CryptomatorFS from a vault path and password.
    ///
    /// Uses the default configuration optimized for network filesystems
    /// (60s cache TTL). Use [`with_config`](Self::with_config) for custom settings.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The vault configuration cannot be read
    /// - The master key cannot be extracted (wrong password)
    /// - The async vault operations cannot be initialized
    pub fn new(vault_path: &Path, password: &str) -> Result<Self, FuseError> {
        Self::with_config(vault_path, password, MountConfig::default())
    }

    /// Creates a new CryptomatorFS with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    /// * `config` - Mount configuration (TTLs, concurrency, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be opened.
    pub fn with_config(
        vault_path: &Path,
        password: &str,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(2048)
            .build()
            .map_err(|e| {
                FuseError::Io(std::io::Error::other(format!(
                    "Failed to create tokio runtime: {e}"
                )))
            })?;
        let handle = runtime.handle().clone();
        Self::with_runtime_internal(vault_path, password, Some(runtime), handle, config)
    }

    /// Creates a new CryptomatorFS using an external tokio runtime handle.
    ///
    /// This is useful when you want the filesystem to use a runtime that has
    /// additional instrumentation (e.g., tokio-console) or when integrating
    /// with an existing async application.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    /// * `handle` - Handle to an existing tokio runtime
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be opened.
    ///
    /// # Panics
    ///
    /// The external runtime must remain alive for the lifetime of this filesystem.
    /// If the runtime is dropped, subsequent operations will panic.
    pub fn with_runtime_handle(
        vault_path: &Path,
        password: &str,
        handle: Handle,
    ) -> Result<Self, FuseError> {
        Self::with_runtime_internal(vault_path, password, None, handle, MountConfig::default())
    }

    /// Creates a new CryptomatorFS with an external runtime and custom configuration.
    ///
    /// Combines the benefits of [`with_runtime_handle`](Self::with_runtime_handle)
    /// (external runtime for tokio-console) with custom configuration.
    pub fn with_runtime_handle_and_config(
        vault_path: &Path,
        password: &str,
        handle: Handle,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        Self::with_runtime_internal(vault_path, password, None, handle, config)
    }

    /// Internal constructor used by all public constructors.
    fn with_runtime_internal(
        vault_path: &Path,
        password: &str,
        owned_runtime: Option<Runtime>,
        handle: Handle,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        // Open vault - extracts key, reads config, configures cipher combo automatically
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| {
                FuseError::Io(std::io::Error::other(format!("Failed to open vault: {e}")))
            })?
            .into_shared();

        // Get current user/group
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let vault_stats = Arc::new(VaultStats::new());

        // Create attribute cache with configured TTLs
        let mut attr_cache = AttrCache::new(config.attr_ttl, config.negative_ttl);
        attr_cache.set_stats(vault_stats.cache_stats());

        // Initialize async bridge with timeouts
        let default_timeout = config.io_timeout;
        let write_timeout = Duration::from_secs(300); // 5 minutes for data operations
        let stats = crate::async_bridge::BridgeStats::new();

        info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
            attr_ttl_secs = config.attr_ttl.as_secs(),
            negative_ttl_ms = config.negative_ttl.as_millis(),
            default_timeout_secs = default_timeout.as_secs(),
            write_timeout_secs = write_timeout.as_secs(),
            "CryptomatorFS initialized"
        );

        // Create handle table (shared with scheduler for reader restoration)
        let handle_table = Arc::new(FuseHandleTable::new_auto_id());

        // Create scheduler (but don't start yet - started in init())
        let scheduler = FuseScheduler::with_config(
            SchedulerConfig::default().with_base_timeout(default_timeout),
            Arc::clone(&handle_table),
            Arc::clone(&vault_stats),
        );

        Ok(Self {
            ops,
            inodes: InodeTable::new(),
            attr_cache,
            dir_cache: DirCache::default(),
            handle_table,
            _owned_runtime: owned_runtime,
            handle,
            default_timeout,
            write_timeout,
            stats,
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
            vault_stats,
            config,
            open_handle_tracker: crate::handles::OpenHandleTracker::new(),
            notifier: OnceLock::new(),
            buffer_sizes: DashMap::new(),
            sync_ops_cache: std::sync::Mutex::new(None),
            scheduler: Some(scheduler),
        })
    }

    /// Returns a clone of the vault stats Arc for external access.
    ///
    /// This allows the mount handle to expose stats to the GUI.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.vault_stats)
    }

    /// Returns async bridge statistics for monitoring operation performance.
    pub fn bridge_stats(&self) -> &crate::async_bridge::BridgeStats {
        &self.stats
    }

    /// Returns a reference to the lock metrics for profiling.
    pub fn lock_metrics(&self) -> &Arc<oxcrypt_core::vault::lock_metrics::LockMetrics> {
        self.ops.lock_metrics()
    }

    /// Returns a reference to the OnceLock for kernel cache invalidation notifier.
    ///
    /// This is called by the backend after spawning the FUSE session to inject
    /// the notifier for kernel cache invalidation.
    pub fn notifier_cell(&self) -> &OnceLock<fuser::Notifier> {
        &self.notifier
    }

    /// Returns a scheduler stats collector for monitoring scheduler health.
    ///
    /// The collector holds Arc references to scheduler components and can produce
    /// snapshots even after the filesystem is moved into a FUSE session.
    /// Returns `None` if the scheduler hasn't been initialized.
    pub fn scheduler_stats_collector(&self) -> Option<crate::scheduler::SchedulerStatsCollector> {
        self.scheduler.as_ref().map(|s| s.stats_collector())
    }

    /// Creates a new CryptomatorFS with custom UID/GID.
    pub fn with_ownership(vault_path: &Path, password: &str, uid: u32, gid: u32) -> Result<Self, FuseError> {
        let mut fs = Self::new(vault_path, password)?;
        fs.uid = uid;
        fs.gid = gid;
        Ok(fs)
    }

    /// Gets a clone of the vault operations Arc for use in async context.
    ///
    /// This is now infallible since Arc::clone() never fails.
    fn ops_clone(&self) -> Arc<VaultOperationsAsync> {
        Arc::clone(&self.ops)
    }

    /// Gets or creates a cached sync operations instance for fast path.
    ///
    /// On first call, creates a `VaultOperations` instance by cloning the master key.
    /// Subsequent calls return an Arc clone of the cached instance (cheap Arc::clone).
    ///
    /// Used by sync fast paths to avoid async task spawning overhead.
    fn get_or_create_sync_ops(&self) -> FuseResult<Arc<oxcrypt_core::vault::VaultOperations>> {
        let mut cache = self.sync_ops_cache.lock().unwrap();
        if cache.is_none() {
            let sync_ops = self.ops.as_sync()
                .map_err(|e| FuseError::Io(std::io::Error::other(
                    format!("Failed to create sync operations: {e}")
                )))?;
            *cache = Some(Arc::new(sync_ops));
        }
        Ok(Arc::clone(cache.as_ref().unwrap()))
    }

    /// Converts an entry name to a stable offset cookie for readdir iteration.
    ///
    /// This uses a hash-based approach to encode entry names as i64 offsets, allowing
    /// directory iteration to resume correctly even if the directory is modified between
    /// readdir calls (e.g., during recursive deletion with fs::remove_dir_all).
    ///
    /// # Implementation
    ///
    /// - Returns 0 for special entries "." and ".." (these are always at the start)
    /// - For other names, computes a 64-bit hash and ensures it's positive (bit 63 = 0)
    /// - Hash collisions are extremely rare (1 in 2^63) and would only cause entries
    ///   to be treated as duplicates (benign for readdir)
    ///
    /// # Example
    ///
    /// ```text
    /// readdir(offset=0) -> returns ".", offset=0
    ///                   -> returns "..", offset=0
    ///                   -> returns "file1.txt", offset=hash("file1.txt")=12345
    /// ... directory is modified, "file1.txt" is deleted ...
    /// readdir(offset=12345) -> resumes after "file1.txt" (which no longer exists)
    ///                       -> returns "file2.txt", offset=hash("file2.txt")=67890
    /// ```
    fn name_to_offset(name: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Hash the name to a u64, then convert to positive i64
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let hash = hasher.finish();

        // Ensure positive by masking off the sign bit (top bit = 0)
        // This gives us 2^63 possible offsets, which is more than enough
        let masked = hash & 0x7FFF_FFFF_FFFF_FFFF;
        let offset = i64::from_ne_bytes(masked.to_ne_bytes());

        // Ensure offset is never 0, since offset=0 means "start from beginning"
        // If hash happens to be 0, use 1 instead
        if offset == 0 {
            1
        } else {
            offset
        }
    }

    /// Executes an async operation using the spawn+oneshot pattern.
    ///
    /// Spawns the future on the tokio runtime and blocks on a oneshot channel.
    /// Operations that exceed the configured timeout will return ETIMEDOUT.
    fn exec<F, T>(&self, future: F) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        crate::async_bridge::execute(&self.handle, self.default_timeout, Some(&self.stats), future)
    }

    /// Executes an async operation that returns a Result, flattening bridge errors.
    ///
    /// This is a convenience wrapper for operations that already return Result.
    #[allow(dead_code)]
    fn exec_result<F, T, E>(&self, future: F) -> Result<T, i32>
    where
        F: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: ToErrno + Send + 'static,
    {
        match self.exec(future) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => Err(e.to_errno()),
            Err(bridge_err) => Err(bridge_err.to_errno()),
        }
    }

    /// Executes an async operation with a custom timeout.
    ///
    /// Used for operations that need longer timeouts (e.g., write operations).
    fn exec_with_timeout<F, T>(&self, future: F, timeout: Duration) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        crate::async_bridge::execute(&self.handle, timeout, Some(&self.stats), future)
    }

    /// Flush a write buffer to the vault without closing the handle.
    ///
    /// This is used by both `flush()` and `fsync()` FUSE operations.
    /// Returns:
    /// - `Ok(Some(path))` if a dirty buffer was written to the given encrypted path
    /// - `Ok(None)` if the handle is a reader or the buffer was clean
    /// - `Err(errno)` on write failure
    fn flush_handle(&self, ino: u64, fh: u64) -> Result<Option<PathBuf>, c_int> {
        let mut handle = self.handle_table.get_mut(&fh).ok_or(libc::EBADF)?;

        if let Some(buffer) = handle.as_write_buffer_mut()
            && buffer.is_dirty() {
                let ops = self.ops_clone();
                let dir_id = buffer.dir_id().clone();
                let filename = buffer.filename().to_string();

                // Move content out instead of copying (optimization)
                let content = buffer.take_content_for_flush();

                // Drop the handle lock before blocking I/O
                drop(handle);

                // Write to vault with extended timeout (5 minutes).
                // Data operations get longer timeout than metadata ops to avoid data loss.
                let write_result = self.exec_with_timeout(
                    async move {
                        ops.write_file(&dir_id, &filename, &content).await
                            .map(|path| (path, content)) // Return both path and content
                    },
                    self.write_timeout,
                );

                // Handle the result
                match write_result {
                    Ok(Ok((encrypted_path, returned_content))) => {
                        // Success - restore the (now clean) content
                        if let Some(mut handle) = self.handle_table.get_mut(&fh)
                            && let Some(buffer) = handle.as_write_buffer_mut() {
                                buffer.restore_content(returned_content);
                            }

                        // Release all tracked write budget now that data is persisted.
                        // We must release exactly what was tracked (via add_write_bytes),
                        // not the full content_len, to prevent counter underflow when
                        // a buffer accumulates writes across multiple flush cycles.
                        if let Some(ref scheduler) = self.scheduler {
                            scheduler.release_all_file_write_bytes(ino);
                        }

                        self.attr_cache.invalidate(ino);
                        return Ok(Some(encrypted_path));
                    }
                    Ok(Err(write_err)) => {
                        // Write error - can't restore content (was consumed)
                        return Err(crate::error::write_error_to_errno(&write_err));
                    }
                    Err(exec_err) => {
                        // Executor error (timeout, queue full, etc.)
                        return Err(exec_err.to_errno());
                    }
                }
            }
        // Readers or clean buffers don't need flushing
        Ok(None)
    }

    /// Sync a file handle's data to disk.
    ///
    /// This looks up the encrypted path for the file and calls fsync/fdatasync
    /// on the underlying storage. Used by the `fsync()` FUSE operation.
    ///
    /// # Arguments
    /// * `fh` - File handle
    /// * `datasync` - If true, only sync data (fdatasync). If false, sync data+metadata.
    fn sync_handle_to_disk(&self, fh: u64, datasync: bool) -> Result<(), c_int> {
        let handle = self.handle_table.get(&fh).ok_or(libc::EBADF)?;

        // Only WriteBuffers need syncing (readers don't modify anything)
        let (dir_id, filename) = match handle.value() {
            FuseHandle::WriteBuffer(buffer) => {
                (buffer.dir_id().clone(), buffer.filename().to_string())
            }
            _ => return Ok(()), // Readers don't need sync
        };
        drop(handle);

        // Find the encrypted path
        let ops = self.ops_clone();
        let ops_for_sync = self.ops_clone();

        let find_result = self.exec_with_timeout(
            async move { ops.find_file(&dir_id, &filename).await },
            self.default_timeout,
        );

        let encrypted_path = match find_result {
            Ok(Ok(Some(info))) => info.encrypted_path,
            Ok(Ok(None)) => {
                // File doesn't exist in vault yet (opened for write but never written)
                // Nothing to sync - this is fine
                return Ok(());
            }
            Ok(Err(_)) => return Err(libc::EIO),
            Err(e) => return Err(e.to_errno()),
        };

        // Sync the encrypted file to disk
        let sync_result = self.exec_with_timeout(
            async move { ops_for_sync.sync_encrypted_file(&encrypted_path, datasync).await },
            self.write_timeout,
        );

        match sync_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(libc::EIO),
            Err(e) => Err(e.to_errno()),
        }
    }

    /// Creates a FileAttr for a directory.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_dir_attr(&self, inode: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: inode,
            size: 0,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Directory,
            perm: DEFAULT_DIR_PERM,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Creates a FileAttr for a regular file.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_file_attr(&self, inode: u64, size: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: inode,
            size,
            blocks: size.div_ceil(u64::from(BLOCK_SIZE)),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: DEFAULT_FILE_PERM,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Returns the effective file size for an inode, accounting for in-memory buffers.
    ///
    /// For mmap to work correctly, the kernel must know the current file size
    /// even before it's flushed to disk. This returns max(disk_size, buffer_size)
    /// to ensure the kernel sees the true current size.
    #[inline]
    fn effective_file_size(&self, inode: u64, disk_size: u64) -> u64 {
        self.buffer_sizes
            .get(&inode)
            .map_or(disk_size, |s| (*s).max(disk_size))
    }

    /// Updates the tracked buffer size for an inode.
    ///
    /// Called after write operations that may extend the file.
    #[inline]
    fn update_buffer_size(&self, inode: u64, new_size: u64) {
        self.buffer_sizes
            .entry(inode)
            .and_modify(|s| *s = (*s).max(new_size))
            .or_insert(new_size);
    }

    /// Sets the exact tracked buffer size for an inode.
    /// Unlike update_buffer_size, this doesn't use max() - it sets the exact value.
    /// Use this for truncate operations where the size is being reduced.
    #[inline]
    fn set_buffer_size(&self, inode: u64, size: u64) {
        self.buffer_sizes.insert(inode, size);
    }

    /// Clears the tracked buffer size for an inode.
    ///
    /// Called after release() flushes the buffer to disk.
    #[inline]
    fn clear_buffer_size(&self, inode: u64) {
        self.buffer_sizes.remove(&inode);
    }

    /// Creates a FileAttr for a symlink.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_symlink_attr(&self, inode: u64, target_len: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: inode,
            size: target_len,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Reads the modification time from an encrypted file path.
    ///
    /// Returns `None` if the file doesn't exist or the metadata can't be read.
    #[inline]
    fn get_mtime(path: &Path) -> Option<SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    /// Looks up a child entry in a directory using O(1) path lookups.
    ///
    /// Uses `find_file`, `find_directory`, and `find_symlink` which calculate
    /// the expected encrypted path directly instead of listing all entries.
    /// All three lookups run in parallel to minimize latency on network filesystems.
    /// Try sync lookup of a child entry (fast path).
    ///
    /// Attempts to look up a child entry using sync operations without async overhead.
    /// Returns `Ok(Some(...))` if successful, `Ok(None)` if lock contended (use async path).
    ///
    /// This is an optimization to avoid async task spawning for metadata operations
    /// when directory locks are available immediately.
    fn try_lookup_child_sync(
        &self,
        _parent_inode: u64,
        name: &str,
        parent_path: &VaultPath,
        dir_id: &DirId,
    ) -> FuseResult<Option<(u64, FileAttr, FileType)>> {
        // Try non-blocking lock
        let _guard = match self.ops.try_directory_read_sync(dir_id) {
            Some(g) => g,
            None => return Ok(None), // Contended → use async path
        };

        // Get sync ops (cached)
        let sync_ops = self.get_or_create_sync_ops()?;
        let child_path = parent_path.join(name);

        // Try file first (most common case)
        if let Ok(Some(file_info)) = sync_ops.find_file(dir_id, name) {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::File {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let disk_size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
            let effective_size = self.effective_file_size(inode, disk_size);
            let mtime = Self::get_mtime(&file_info.encrypted_path);
            let attr = self.make_file_attr(inode, effective_size, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::RegularFile)));
        }

        // Try directory
        if let Ok(Some(dir_info)) = sync_ops.find_directory(dir_id, name) {
            let correct_kind = InodeKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let inode = self.inodes.get_or_insert(&child_path, &correct_kind);
            self.inodes.update_kind(inode, correct_kind);
            let mtime = Self::get_mtime(&dir_info.encrypted_path);
            let attr = self.make_dir_attr(inode, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::Directory)));
        }

        // Try symlink
        if let Ok(Some(symlink_info)) = sync_ops.find_symlink(dir_id, name) {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let mtime = Self::get_mtime(&symlink_info.encrypted_path);
            let attr = self.make_symlink_attr(inode, symlink_info.target.len() as u64, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::Symlink)));
        }

        // Not found - return None to use async path which will handle errors properly
        Ok(None)
    }

    fn lookup_child(
        &self,
        parent_inode: u64,
        name: &str,
    ) -> FuseResult<(u64, FileAttr, FileType)> {
        let parent_entry = self.inodes.get(parent_inode).ok_or(FuseError::InvalidInode(parent_inode))?;

        let dir_id = parent_entry.dir_id().ok_or(FuseError::PathResolution(
            "Parent is not a directory".to_string(),
        ))?;

        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        let child_path = parent_path.join(name);

        // Fast path: If the inode already exists in our table (e.g., from create() before
        // release() has flushed to vault), return it immediately without going to the vault.
        // This prevents a race condition where lookup during write returns ENOENT because
        // the file isn't in the vault yet, which would add a negative cache entry.
        //
        // IMPORTANT: Skip this fast path if the inode is marked for deferred deletion,
        // as those files should appear as ENOENT even though they still exist in the vault.
        if let Some(existing_inode) = self.inodes.get_inode(&child_path) {
            // Check if file is marked for deferred deletion
            if self.open_handle_tracker.is_marked_for_deletion(existing_inode) {
                return Err(FuseError::PathResolution("File marked for deletion".to_string()));
            }

            if let Some(entry) = self.inodes.get(existing_inode) {
                let (attr, file_type) = match &entry.kind {
                    InodeKind::File { .. } => {
                        // Check attr cache first, otherwise use effective size (for mmap consistency)
                        // For fast path fallback, use None for mtime - the full lookup will set it properly
                        let attr = self.attr_cache.get(existing_inode).map_or_else(|| {
                                // Use effective size to account for in-memory buffer
                                let size = self.effective_file_size(existing_inode, 0);
                                self.make_file_attr(existing_inode, size, None)
                            }, |cached| cached.value);
                        (attr, FileType::RegularFile)
                    }
                    InodeKind::Directory { .. } => {
                        let attr = self.attr_cache.get(existing_inode).map_or_else(|| self.make_dir_attr(existing_inode, None), |cached| cached.value);
                        (attr, FileType::Directory)
                    }
                    InodeKind::Symlink { .. } => {
                        // Use size 0 for symlink if not cached (rare case)
                        let attr = self.attr_cache.get(existing_inode).map_or_else(|| self.make_symlink_attr(existing_inode, 0, None), |cached| cached.value);
                        (attr, FileType::Symlink)
                    }
                    InodeKind::Root => {
                        let attr = self.make_dir_attr(existing_inode, None);
                        (attr, FileType::Directory)
                    }
                };
                return Ok((existing_inode, attr, file_type));
            }
        }

        // Try sync fast path (avoids async task overhead if lock available)
        if let Some(result) = self.try_lookup_child_sync(parent_inode, name, &parent_path, &dir_id)? {
            return Ok(result);
        }

        // Clone ops for async use
        let ops = self.ops_clone();
        let name_owned = name.to_string();

        // Run all three lookups in parallel - critical for high-latency backends like Google Drive
        // This reduces 3 sequential network round-trips to 1 parallel operation
        // Uses async bridge to prevent slow cloud storage from blocking FUSE thread
        let dir_id_for_lookup = dir_id.clone();
        let (file_result, dir_result, symlink_result) = self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_for_lookup, &name_owned),
                ops.find_directory(&dir_id_for_lookup, &name_owned),
                ops.find_symlink(&dir_id_for_lookup, &name_owned)
            )
        }).map_err(FuseError::Bridge)?;

        // Check file result first (most common case)
        if let Ok(Some(file_info)) = file_result {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::File {
                    dir_id,
                    name: name.to_string(),
                },
            );
            let disk_size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
            // Use effective size to account for in-memory buffer (mmap consistency)
            let effective_size = self.effective_file_size(inode, disk_size);
            let mtime = Self::get_mtime(&file_info.encrypted_path);
            let attr = self.make_file_attr(inode, effective_size, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::RegularFile));
        }

        // Check directory result
        if let Ok(Some(dir_info)) = dir_result {
            let correct_kind = InodeKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let inode = self.inodes.get_or_insert(&child_path, &correct_kind);
            // Always update the kind to ensure correct DirId (may have been placeholder)
            self.inodes.update_kind(inode, correct_kind);
            let mtime = Self::get_mtime(&dir_info.encrypted_path);
            let attr = self.make_dir_attr(inode, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Directory));
        }

        // Check symlink result
        if let Ok(Some(symlink_info)) = symlink_result {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let mtime = Self::get_mtime(&symlink_info.encrypted_path);
            let attr = self.make_symlink_attr(inode, symlink_info.target.len() as u64, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Symlink));
        }

        // Propagate any errors from the lookups
        file_result?;
        dir_result?;
        symlink_result?;

        // Not found
        Err(FuseError::PathResolution(format!("'{name}' not found")))
    }

    /// Lists all entries in a directory.
    ///
    /// Uses `list_all` to fetch files, directories, and symlinks in a single
    /// operation with parallel I/O, replacing 3 sequential blocking calls.
    /// Uses the async bridge to prevent slow cloud storage from blocking the FUSE thread.
    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        let ops = self.ops_clone();
        let dir_id = dir_id.clone();

        // Execute with timeout to prevent slow cloud storage from blocking FUSE
        let (files, dirs, symlinks) = self.exec(async move {
            ops.list_all(&dir_id).await
        }).map_err(FuseError::Bridge)??;

        // Build entries using iterator chain instead of three separate loops
        let entries: Vec<DirListingEntry> = dirs
            .into_iter()
            .map(|d| DirListingEntry {
                inode: 0, // Will be resolved on lookup
                file_type: FileType::Directory,
                dir_id: Some(d.directory_id),
                name: d.name,
            })
            .chain(files.into_iter().map(|f| DirListingEntry {
                inode: 0,
                file_type: FileType::RegularFile,
                dir_id: None,
                name: f.name,
            }))
            .chain(symlinks.into_iter().map(|s| DirListingEntry {
                inode: 0,
                file_type: FileType::Symlink,
                dir_id: None,
                name: s.name,
            }))
            .collect();

        Ok(entries)
    }

    /// Helper for copy_file_range: write data to destination and reply.
    ///
    /// Used for synchronous copy paths (ReadBuffer/WriteBuffer sources).
    fn copy_file_range_write_dest(
        &mut self,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        data: &[u8],
        reply: ReplyWrite,
    ) {
        let Some(mut handle) = self.handle_table.get_mut(&fh_out) else {
            reply.error(libc::EBADF);
            return;
        };

        let Some(buffer) = handle.as_write_buffer_mut() else {
            // Destination must be opened for writing
            reply.error(libc::EBADF);
            return;
        };

        // FUSE guarantees offset_out is non-negative
        #[allow(clippy::cast_sign_loss)]
        let bytes_written = buffer.write(offset_out as u64, data);
        let new_size = buffer.len();
        drop(handle);

        // Track buffer size for mmap consistency
        self.update_buffer_size(ino_out, new_size);
        // Invalidate attr cache for destination
        self.attr_cache.invalidate(ino_out);

        // FUSE kernel caps request sizes well below u32::MAX in practice.
        // Truncation here would cause offset desync, but kernel limits prevent this.
        #[allow(clippy::cast_possible_truncation)]
        reply.written(bytes_written as u32);
    }
}

impl Drop for CryptomatorFS {
    fn drop(&mut self) {
        tracing::debug!("CryptomatorFS::drop - starting shutdown");

        // 1. Clear handle table (flushes buffers, closes files)
        // This ensures no more file operations are pending
        self.handle_table.clear();

        // 2. Executor, handle, and runtime will drop in correct order
        // The field reordering ensures:
        //   - executor drops first (closes task channel, workers exit)
        //   - handle drops second (releases runtime handle)
        //   - _owned_runtime drops LAST (actual runtime shutdown)
        // This prevents panics from block_on() calls on dropped runtimes

        tracing::info!("CryptomatorFS::drop - shutdown complete");
    }
}

impl Filesystem for CryptomatorFS {
    /// Initialize the filesystem.
    ///
    /// # FUSE Spec
    /// Called once when the filesystem is mounted. The `config` parameter allows
    /// setting capabilities and connection parameters. This is the place to:
    /// - Enable async reads (`FUSE_ASYNC_READ`)
    /// - Set max_write, max_readahead
    /// - Enable writeback caching if supported
    ///
    /// # Implementation
    /// - Enables `FUSE_ASYNC_READ` for better read performance
    /// - Returns `Ok(())` to allow mount to proceed
    ///
    /// # Compliance: ✓ COMPLIANT
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        info!("FUSE filesystem initialized");

        // Start the scheduler for async request handling
        if let Some(ref mut scheduler) = self.scheduler {
            scheduler.start();
            info!("FUSE scheduler started");
        }

        // Enable async reads for better performance with concurrent readers
        config.add_capabilities(fuser::consts::FUSE_ASYNC_READ).ok();

        // Enable writeback cache for better mmap support.
        // This ensures the kernel keeps the page cache consistent and enables
        // all mmap modes, which prevents SIGBUS crashes with applications like
        // SQLite that use mmap for WAL shared memory files.
        config
            .add_capabilities(fuser::consts::FUSE_WRITEBACK_CACHE)
            .ok();

        // Increase max background requests from default 16 to 32.
        // This improves throughput when the underlying vault storage is on a slow
        // backend (e.g., Google Drive, network storage) where some files are cached
        // and others are not. More pending requests reduces stalls from head-of-line
        // blocking. The congestion threshold auto-adjusts to 3/4 of this value (24).
        if let Err(e) = config.set_max_background(32) {
            warn!("Failed to set max_background to 32, got: {}", e);
        }

        Ok(())
    }

    /// Clean up the filesystem on unmount.
    ///
    /// # FUSE Spec
    /// Called when the filesystem is unmounted. All open files have been released
    /// and all pending operations completed. This is the last callback before the
    /// filesystem is destroyed.
    ///
    /// # Implementation
    /// - Logs unmount; Rust's RAII handles cleanup of VaultOperationsAsync,
    ///   InodeTable, caches, and handle table.
    ///
    /// # Compliance: ✓ COMPLIANT
    fn destroy(&mut self) {
        info!("FUSE filesystem destroyed");
    }

    /// Look up a directory entry by name and get its attributes.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.lookup`)
    ///
    /// The lookup count of the found inode is incremented by one for each successful
    /// call to `fuse_reply_entry`. The filesystem should track lookup counts and only
    /// evict inodes when the count reaches zero (via `forget`).
    ///
    /// Valid replies: `fuse_reply_entry` (success) or `fuse_reply_err` (failure).
    ///
    /// The `generation` number in the reply should be non-zero and unique across
    /// the filesystem's lifetime if the FS will be exported over NFS.
    ///
    /// # Implementation Notes
    ///
    /// - Calls `get_or_insert` which increments nlookup (correct per spec)
    /// - Uses negative cache to avoid repeated lookups for missing entries
    /// - Generation is always 0 (acceptable since we don't support NFS export)
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, "lookup");

        // Check negative cache
        if self.attr_cache.is_negative(parent, name_str) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        }

        match self.lookup_child(parent, name_str) {
            Ok((_inode, attr, _file_type)) => {
                // nlookup is incremented in lookup_child via get_or_insert (correct per spec)
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                // Add to negative cache
                self.attr_cache.insert_negative(parent, name_str.to_string());
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(e.to_errno());
            }
        }
        // Track inode table size for memory monitoring
        self.vault_stats
            .set_inode_count(self.inodes.len() as u64);
    }

    /// Forget about an inode.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.forget`)
    ///
    /// Called when the kernel removes an inode from its internal caches. The `nlookup`
    /// parameter indicates how many lookup references to release. The filesystem should
    /// defer actual inode removal until the lookup count reaches zero.
    ///
    /// On unmount, the kernel may not send forget messages for all referenced inodes;
    /// the lookup count implicitly drops to zero.
    ///
    /// Valid reply: none (no response needed).
    ///
    /// # Implementation Notes
    ///
    /// - Root inode (1) is never evicted
    /// - When nlookup reaches 0, inode is removed from the path↔inode mappings
    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        trace!(inode = ino, nlookup = nlookup, "forget");
        self.inodes.forget(ino, nlookup);
        // Track inode table size for memory monitoring
        self.vault_stats
            .set_inode_count(self.inodes.len() as u64);
    }

    /// Batch forget for multiple inodes.
    ///
    /// # FUSE Spec
    ///
    /// Semantically identical to multiple individual `forget` calls, but batched for
    /// performance. Each entry specifies a nodeid and its nlookup decrement count.
    fn batch_forget(&mut self, _req: &Request<'_>, nodes: &[fuser::fuse_forget_one]) {
        trace!(count = nodes.len(), "batch_forget");
        for node in nodes {
            self.inodes.forget(node.nodeid, node.nlookup);
        }
        // Track inode table size for memory monitoring
        self.vault_stats
            .set_inode_count(self.inodes.len() as u64);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(inode = ino, "getattr");

        // Check cache first
        if let Some(cached) = self.attr_cache.get(ino) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            // CRITICAL for mmap: When there's an active write buffer, the cached
            // attr might have a stale size. We need to:
            // 1. Return zero TTL to prevent kernel from caching
            // 2. Update the size to reflect the current buffer size
            if let Some(buffer_size) = self.buffer_sizes.get(&ino) {
                let effective_size = (*buffer_size).max(cached.value.size);
                debug!(inode = ino, cached_size = cached.value.size, effective_size,
                       "getattr: cache hit but updating size and using zero TTL for actively buffered file");
                let mut attr = cached.value;
                attr.size = effective_size;
                reply.attr(&Duration::ZERO, &attr);
            } else {
                reply.attr(&cached.time_remaining(), &cached.value);
            }
            return;
        }

        // Get inode entry
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let attr = match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => self.make_dir_attr(ino, None),
            InodeKind::File { dir_id, name } => {
                // Get file size from vault using O(1) lookup instead of O(n) list+search
                let ops = self.ops_clone();
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                    Ok(Ok(Some(info))) => {
                        let disk_size = encrypted_to_plaintext_size_or_zero(info.encrypted_size);
                        // Use effective size to account for in-memory buffer (mmap consistency)
                        let effective_size = self.effective_file_size(ino, disk_size);
                        if effective_size != disk_size {
                            debug!(inode = ino, disk_size, effective_size, "getattr: using effective size from buffer");
                        }
                        let mtime = Self::get_mtime(&info.encrypted_path);
                        self.make_file_attr(ino, effective_size, mtime)
                    }
                    Ok(Ok(None)) => {
                        // File not found in vault, but might be newly created
                        // (exists only in WriteBuffer, not yet flushed to disk)
                        // Check if there's an active write buffer for this inode
                        if let Some(buffer_size) = self.buffer_sizes.get(&ino) {
                            // File exists in memory but not yet on disk - return synthetic attr
                            debug!(inode = ino, buffer_size = *buffer_size,
                                   "getattr: file not in vault but has active buffer");
                            self.make_file_attr(ino, *buffer_size, None)
                        } else {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(libc::ENOENT);
                            return;
                        }
                    }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Get symlink info including encrypted_path for mtime
                let ops = self.ops_clone();
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.exec(async move { ops.find_symlink(&dir_id, &name).await }) {
                    Ok(Ok(Some(info))) => {
                        let mtime = Self::get_mtime(&info.encrypted_path);
                        self.make_symlink_attr(ino, info.target.len() as u64, mtime)
                    }
                    Ok(Ok(None)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                }
            }
        };

        self.attr_cache.insert(ino, attr);
        self.vault_stats.record_metadata_latency(start.elapsed());

        // Use zero TTL for files with active write buffers to prevent kernel from
        // caching stale size, which causes SIGBUS when mmap accesses extended regions.
        let ttl = if self.buffer_sizes.contains_key(&ino) {
            debug!(inode = ino, "getattr: using zero TTL for actively buffered file");
            Duration::ZERO
        } else {
            DEFAULT_ATTR_TTL
        };
        reply.attr(&ttl, &attr);
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        trace!(inode = ino, "readlink");

        let Some(entry) = self.inodes.get(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::Symlink { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        drop(entry);

        let ops = self.ops_clone();

        match self.exec(async move { ops.read_symlink(&dir_id, &name).await }) {
            Ok(Ok(target)) => {
                reply.data(target.as_bytes());
            }
            Ok(Err(e)) => {
                reply.error(crate::error::vault_error_to_errno(&e));
            }
            Err(exec_err) => {
                reply.error(exec_err.to_errno());
            }
        }
    }

    /// Open a file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.open`)
    ///
    /// Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC which are
    /// filtered by the kernel) are available in `flags`. The filesystem may store an
    /// arbitrary file handle in the reply; this handle will be passed to subsequent
    /// read/write/flush/release calls.
    ///
    /// Access mode should be checked unless `default_permissions` mount option is set.
    ///
    /// **Writeback caching note**: The kernel may send read requests even for O_WRONLY
    /// files when writeback caching is enabled.
    ///
    /// Valid replies: `fuse_reply_open` (success) or `fuse_reply_err` (failure).
    ///
    /// # Implementation Notes
    ///
    /// - For read-only opens: creates a streaming VaultFileReader
    /// - For write opens: creates a WriteBuffer with existing content (or empty if O_TRUNC)
    /// - File handles are stored in FuseHandleTable
    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        trace!(inode = ino, flags = flags, "open");

        let Some(entry) = self.inodes.get(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            InodeKind::Directory { .. } | InodeKind::Root => {
                reply.error(libc::EISDIR);
                return;
            }
            InodeKind::Symlink { .. } => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        drop(entry);

        let ops = self.ops_clone();

        // Check if opening for write
        let is_write = (flags & libc::O_ACCMODE) != libc::O_RDONLY;
        let is_trunc = (flags & libc::O_TRUNC) != 0;

        if is_write {
            // Open for writing using WriteBuffer for random-access support
            let existing_content = if is_trunc {
                // O_TRUNC: start with empty buffer
                Vec::new()
            } else {
                // Read existing content if file exists (with timeout)
                let ops_clone = Arc::clone(&ops);
                let dir_id_clone = dir_id.clone();
                let name_clone = name.clone();
                match self.exec(async move { ops_clone.read_file(&dir_id_clone, &name_clone).await }) {
                    Ok(Ok(file)) => file.content,
                    Ok(Err(_)) | Err(_) => Vec::new(), // File doesn't exist, start empty
                }
            };

            let initial_size = existing_content.len() as u64;
            let buffer = WriteBuffer::new(dir_id, name, existing_content);
            let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));
            self.open_handle_tracker.add_handle(ino);
            // Track initial buffer size for mmap consistency
            self.update_buffer_size(ino, initial_size);
            self.vault_stats.record_file_open();
            reply.opened(fh, 0);
        } else {
            // Open for reading - use streaming reader without holding vault locks.
            // Unlike open_file(), open_file_unlocked() releases locks after opening
            // the OS file handle, allowing concurrent directory operations (unlink, etc.)
            match self.exec(async move { ops.open_file_unlocked(&dir_id, &name).await }) {
                Ok(Ok(reader)) => {
                    // Store streaming reader in handle table
                    let fh = self
                        .handle_table
                        .insert_auto(FuseHandle::Reader(Box::new(reader)));
                    self.open_handle_tracker.add_handle(ino);
                    self.vault_stats.record_file_open();
                    reply.opened(fh, 0);
                }
                Ok(Err(e)) => {
                    reply.error(crate::error::vault_error_to_errno(&e));
                }
                Err(exec_err) => {
                    reply.error(exec_err.to_errno());
                }
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        trace!(inode = ino, fh = fh, offset = offset, size = size, "read");

        // Get the handle from our table
        let Some(mut handle) = self.handle_table.get_mut(&fh) else {
            reply.error(libc::EBADF);
            return;
        };

        match &mut *handle {
            FuseHandle::Reader(_) => {
                // Async read path: loan reader to scheduler, return immediately
                // Take the reader by replacing with ReaderLoaned placeholder
                let old_handle = std::mem::replace(&mut *handle, FuseHandle::ReaderLoaned);
                let reader = match old_handle {
                    FuseHandle::Reader(r) => r,
                    _ => unreachable!("just matched Reader variant"),
                };

                // Drop the handle lock before enqueuing to avoid deadlock
                drop(handle);

                // Enqueue to scheduler - it will reply and restore the reader
                let scheduler = self
                    .scheduler
                    .as_ref()
                    .expect("scheduler not initialized");

                let offset_u64 = u64::try_from(offset).unwrap_or(0);
                let size_usize = usize::try_from(size).unwrap_or(0);

                self.vault_stats.start_read();
                match scheduler.try_enqueue_read(ino, fh, reader, offset_u64, size_usize, reply) {
                    Ok(request_id) => {
                        trace!(?request_id, fh, offset_u64, size_usize, "Read enqueued to scheduler");
                        // Return immediately - scheduler will reply asynchronously
                        // Stats will be updated when the dispatcher receives the result
                    }
                    Err(e) => {
                        // Enqueue failed - scheduler already replied with error.
                        // The reader is consumed, handle remains in ReaderLoaned state.
                        // Subsequent reads will get EAGAIN until file is closed/reopened.
                        self.vault_stats.finish_read();
                        warn!(error = %e, fh, "Failed to enqueue read request (scheduler replied with error)");
                    }
                }
                return;
            }
            FuseHandle::ReaderLoaned => {
                // Reader is currently being used by the scheduler for a previous read
                // Return EAGAIN to tell the kernel to retry
                trace!(fh, "Read while reader is loaned, returning EAGAIN");
                reply.error(libc::EAGAIN);
                return;
            }
            FuseHandle::ReadBuffer(content) => {
                // Read from in-memory buffer (preferred path, no locks held)
                // FUSE guarantees offset is non-negative (it's from kernel read requests)
                // On 32-bit: offsets beyond 4GB would fail earlier in VFS layer
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset = offset as usize;
                let end = std::cmp::min(offset + size as usize, content.len());
                let data = if offset < content.len() {
                    &content[offset..end]
                } else {
                    &[]
                };
                self.vault_stats.record_read(data.len() as u64);
                reply.data(data);
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Read from write buffer (for read-after-write in same handle)
                // FUSE guarantees offset is non-negative (it's from kernel read requests)
                #[allow(clippy::cast_sign_loss)]
                let offset_u64 = offset as u64;
                let data = buffer.read(offset_u64, size as usize);
                self.vault_stats.record_read(data.len() as u64);
                reply.data(data);
            }
        }
    }

    /// Release an open file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.release`)
    ///
    /// Called when ALL references to an open file are gone (all file descriptors
    /// closed and all memory mappings unmapped). There is exactly ONE `release` call
    /// for every `open` call.
    ///
    /// The filesystem may reply with an error, but it will NOT propagate to the
    /// triggering `close()` or `munmap()` call.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success, errors ignored by caller).
    ///
    /// # Implementation Notes
    ///
    /// - Removes file handle from handle table
    /// - For write buffers: writes dirty data to vault before releasing
    /// - For readers: simply drops the handle
    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        trace!(fh = fh, "release");

        // Remove handle from table
        let Some(handle) = self.handle_table.remove(&fh) else {
            // Handle already released or never existed
            reply.ok();
            return;
        };

        match handle {
            FuseHandle::Reader(_) => {
                // Streaming reader just needs to be dropped (releases locks)
                self.vault_stats.record_file_close();
                debug!(fh = fh, "Reader released");
            }
            FuseHandle::ReaderLoaned => {
                // Reader was loaned to the scheduler for an async read.
                // The scheduler will discard the reader when it completes since
                // the handle table entry is now gone. Just record the close.
                self.vault_stats.record_file_close();
                debug!(fh = fh, "ReaderLoaned released (scheduler will discard reader when done)");
            }
            FuseHandle::ReadBuffer(_) => {
                // In-memory read buffer just needs to be dropped
                self.vault_stats.record_file_close();
                debug!(fh = fh, "ReadBuffer released");
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Write buffer back to vault if dirty
                if buffer.is_dirty() {
                    let ops = self.ops_clone();

                    let dir_id = buffer.dir_id().clone();
                    let filename = buffer.filename().to_string();
                    let filename_for_log = filename.clone();
                    let content = buffer.into_content();
                    let content_len = content.len();

                    // Use extended timeout for data operations.
                    // Still use timeout to prevent indefinite hangs, but much longer
                    // than metadata operations (5 minutes vs 30 seconds default).
                    self.vault_stats.start_write();
                    let start = Instant::now();
                    match self.exec_with_timeout(
                        async move {
                            ops.write_file(&dir_id, &filename, &content).await
                        },
                        self.write_timeout,
                    ) {
                        Ok(Ok(_)) => {
                            let elapsed = start.elapsed();
                            self.vault_stats.finish_write();
                            self.vault_stats.record_write(content_len as u64);
                            self.vault_stats.record_write_latency(elapsed);
                            self.vault_stats.record_encrypted(content_len as u64);
                            debug!(fh = fh, filename = %filename_for_log, size = content_len, "WriteBuffer flushed");
                            // Invalidate attr cache since file changed
                            self.attr_cache.invalidate(ino);
                            self.vault_stats.record_file_close();
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.finish_write();
                            self.vault_stats.record_write_latency(start.elapsed());
                            error!(error = %e, "Failed to write buffer back to vault");
                            self.vault_stats.record_file_close();
                            reply.error(crate::error::write_error_to_errno(&e));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.finish_write();
                            self.vault_stats.record_write_latency(start.elapsed());
                            error!(error = %exec_err, "Write timed out or operation failed");
                            self.vault_stats.record_file_close();
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    }
                } else {
                    self.vault_stats.record_file_close();
                    debug!(fh = fh, "WriteBuffer released (not dirty)");
                }
                // Note: Don't clear buffer_sizes here - wait until after remove_handle
                // to check if there are still other open handles for this inode
            }
        }

        // Check for deferred deletion (POSIX compliance)
        // If this was the last handle and the file was unlinked, delete it now
        let deferred = self.open_handle_tracker.remove_handle(ino);

        // Only clear buffer_sizes tracking when the last handle for this inode is closed.
        // This prevents the kernel from caching stale file sizes with 60s TTL while
        // other handles are still actively writing to the file.
        if !self.open_handle_tracker.has_open_handles(ino) {
            self.clear_buffer_size(ino);
        }

        if let Some(deferred) = deferred {
            let filename = deferred.name.clone();
            debug!(
                ino = ino,
                filename = %filename,
                "Performing deferred deletion after last handle closed"
            );

            // Get the file's path before deleting so we can clean up the inode mapping
            let file_path = self.inodes.get(ino).map(|entry| entry.path.clone());

            let ops = self.ops_clone();
            // Try to delete the file from vault (use default timeout)
            match self.exec(
                async move { ops.delete_file(&deferred.dir_id, &deferred.name).await }
            ) {
                Ok(Ok(())) => {
                    debug!(filename = %filename, "Deferred deletion completed");
                    // Clean up the inode mapping now that the file is deleted
                    if let Some(path) = file_path {
                        self.inodes.invalidate_path(&path);
                        debug!(path = %path, "Invalidated inode mapping for deleted file");
                    }
                }
                Ok(Err(e)) => {
                    error!(error = %e, filename = %filename, "Deferred deletion failed (vault error)");
                    // Don't return error - file handle was already closed successfully
                }
                Err(e) => {
                    error!(error = %e, filename = %filename, "Deferred deletion failed (operation error)");
                    // Don't return error - file handle was already closed successfully
                }
            }
        }

        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        trace!(inode = ino, "opendir");

        // Verify it's a directory
        let Some(entry) = self.inodes.get(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => {
                self.vault_stats.record_dir_open();
                reply.opened(0, 0);
            }
            _ => {
                reply.error(libc::ENOTDIR);
            }
        }
    }

    /// Read directory entries.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.readdir`)
    ///
    /// Send a buffer filled with directory entries using `reply.add()`. The `offset`
    /// parameter is the offset of the next entry to return; it should be a value
    /// previously returned by a `reply.add()` call (typically the entry index + 1).
    ///
    /// **IMPORTANT**: Per the spec, "Returning a directory entry from readdir() does
    /// NOT affect its lookup count." This is different from `readdirplus`.
    ///
    /// # Implementation Notes
    ///
    /// Uses `get_or_insert_no_lookup_inc()` which allocates or retrieves inodes WITHOUT
    /// incrementing the nlookup count, as required by the FUSE specification.
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(inode = ino, offset = offset, "readdir");

        // Get directory entry
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dir_id) = entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let current_path = entry.path.clone();
        drop(entry);

        // Get parent inode (for ".." entry)
        let parent_inode = current_path
            .parent()
            .and_then(|parent| self.inodes.get_inode(&parent))
            .unwrap_or(crate::inode::ROOT_INODE);

        // Check dir cache first
        let entries = if let Some(cached) = self.dir_cache.get(ino) {
            debug!(
                inode = ino,
                offset = offset,
                cached_count = cached.len(),
                "readdir: CACHE HIT"
            );
            cached
        } else {
            // List directory contents
            match self.list_directory(&dir_id) {
                Ok(entries) => {
                    debug!(
                        inode = ino,
                        offset = offset,
                        entry_count = entries.len(),
                        "readdir: CACHE MISS - listing directory"
                    );
                    self.dir_cache.insert(ino, entries.clone());
                    entries
                }
                Err(e) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(e.to_errno());
                    return;
                }
            }
        };

        // Add . and ..
        let mut all_entries = vec![
            DirListingEntry {
                inode: ino,
                file_type: FileType::Directory,
                dir_id: None,
                name: ".".to_string(),
            },
            DirListingEntry {
                inode: parent_inode,
                file_type: FileType::Directory,
                dir_id: None,
                name: "..".to_string(),
            },
        ];
        all_entries.extend(entries);

        // Sort entries by name for stable iteration across cache invalidations
        // This ensures that even if the cache is rebuilt during iteration,
        // we can reliably resume from the last returned name.
        all_entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Find starting position based on offset
        // offset=0 means start from beginning
        // offset>0 encodes a hash of the last returned entry name - resume after that entry
        let start_idx = if offset == 0 {
            0
        } else {
            // Find the entry whose hash matches this offset
            // We return the index of the NEXT entry (the one after the match)
            let found = all_entries
                .iter()
                .position(|e| Self::name_to_offset(&e.name) == offset)
                .map_or_else(
                    || {
                        // Offset not found - the entry with this offset was likely deleted during iteration
                        // (directory cache was invalidated and rebuilt without it).
                        //
                        // We can't reliably determine our position in the iteration because:
                        // 1. Hashes don't preserve lexicographic ordering
                        // 2. We don't know which entries were already returned before the deletion
                        //
                        // Conservative strategy: restart from the beginning.
                        // This ensures we don't skip entries, though we may return duplicates.
                        // The kernel/client handles duplicates correctly by tracking seen entries.
                        warn!(
                            "readdir resume: offset {} NOT FOUND in {} entries (entry deleted during iteration), restarting from beginning",
                            offset,
                            all_entries.len()
                        );
                        0 // Restart from beginning instead of returning empty
                    },
                    |idx| {
                        debug!(
                            "readdir resume: found offset {} at idx {}, name={}, starting from idx {}",
                            offset,
                            idx,
                            all_entries[idx].name,
                            idx + 1
                        );
                        idx + 1
                    },
                );
            found
        };

        // Return entries starting from start_idx
        for entry in all_entries.iter().skip(start_idx) {
            // Allocate inode for entry if needed
            let entry_inode = if entry.name == "." {
                ino
            } else if entry.name == ".." {
                parent_inode
            } else {
                // Allocate a real inode for the entry
                let child_path = current_path.join(&entry.name);
                let kind = match entry.file_type {
                    FileType::Directory => InodeKind::Directory {
                        // Use actual dir_id from listing, or root as fallback for . and ..
                        dir_id: entry.dir_id.clone().unwrap_or_else(DirId::root),
                    },
                    FileType::Symlink => InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: entry.name.clone(),
                    },
                    _ => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: entry.name.clone(),
                    },
                };
                // Use no_lookup_inc variant: per FUSE spec, readdir does NOT affect
                // lookup count. Only lookup/create/mkdir/symlink/readdirplus do.
                self.inodes.get_or_insert_no_lookup_inc(&child_path, &kind)
            };

            // Compute next offset as hash of current entry name
            // This allows resuming iteration even if the directory is modified
            let next_offset = Self::name_to_offset(&entry.name);

            // buffer.add returns true if buffer is full
            if reply.add(entry_inode, next_offset, entry.file_type, &entry.name) {
                break;
            }
        }

        self.vault_stats.record_metadata_latency(start.elapsed());
        reply.ok();
    }

    /// Read directory entries with attributes (readdirplus).
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.readdirplus`)
    ///
    /// Like `readdir`, but also returns file attributes for each entry. This allows
    /// the kernel to cache attributes, avoiding subsequent `getattr` calls.
    ///
    /// **IMPORTANT**: Unlike `readdir`, "the lookup count of every entry returned by
    /// readdirplus(), except '.' and '..', is incremented by one" on success.
    ///
    /// # Implementation Notes
    ///
    /// - Correctly increments nlookup via `get_or_insert()` for non-. entries
    /// - "." and ".." use existing inodes without incrementing nlookup
    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(inode = ino, offset = offset, "readdirplus");

        // Get directory entry
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dir_id) = entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let current_path = entry.path.clone();
        drop(entry);

        // Get parent inode (for ".." entry)
        let parent_inode = current_path
            .parent()
            .and_then(|parent| self.inodes.get_inode(&parent))
            .unwrap_or(crate::inode::ROOT_INODE);

        // We need to list directory contents with file sizes for readdirplus
        // Use list_all to fetch all entries in a single operation with parallel I/O
        let ops = self.ops_clone();
        let dir_id_clone = dir_id.clone();

        // Execute via async executor with timeout
        let (files, dirs, symlinks) =
            match self.exec(async move { ops.list_all(&dir_id_clone).await }) {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(crate::error::vault_error_to_errno(&e));
                    return;
                }
                Err(exec_err) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    error!(error = %exec_err, "list_all timed out in readdirplus");
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

        // Build entries with sizes using iterator chain instead of three separate loops
        let mut all_entries: Vec<(String, FileType, u64, Option<DirId>)> = [
            (".".to_string(), FileType::Directory, 0, None),
            ("..".to_string(), FileType::Directory, 0, None),
        ]
        .into_iter()
        .chain(dirs.into_iter().map(|d| {
            (d.name, FileType::Directory, 0, Some(d.directory_id))
        }))
        .chain(files.into_iter().map(|f| {
            let plaintext_size = encrypted_to_plaintext_size_or_zero(f.encrypted_size);
            (f.name, FileType::RegularFile, plaintext_size, None)
        }))
        .chain(symlinks.into_iter().map(|s| {
            let target_len = s.target.len() as u64;
            (s.name, FileType::Symlink, target_len, None)
        }))
        .collect();

        // Sort entries by name for stable iteration across cache invalidations
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Find starting position based on offset
        // offset=0 means start from beginning
        // offset>0 encodes a hash of the last returned entry name - resume after that entry
        let start_idx = if offset == 0 {
            0
        } else {
            // Find the entry whose hash matches this offset
            // We return the index of the NEXT entry (the one after the match)
            all_entries
                .iter()
                .position(|e| Self::name_to_offset(&e.0) == offset)
                .map_or_else(
                    || {
                        // Offset not found - entry was deleted during iteration.
                        // Restart from beginning to avoid skipping entries (see readdir for detailed explanation).
                        warn!(
                            "readdirplus resume: offset {} NOT FOUND in {} entries (entry deleted during iteration), restarting from beginning",
                            offset,
                            all_entries.len()
                        );
                        0 // Restart from beginning instead of returning empty
                    },
                    |idx| {
                        debug!(
                            "readdirplus resume: found offset {} at idx {}, name={}, starting from idx {}",
                            offset,
                            idx,
                            all_entries[idx].0,
                            idx + 1
                        );
                        idx + 1
                    },
                )
        };

        // Return entries starting from start_idx with attributes
        for (name, file_type, size, maybe_subdir_id) in all_entries.iter().skip(start_idx)
        {
            // Allocate inode for entry if needed
            // Note: For readdir entries, we use None for mtime (falls back to now).
            // The actual mtime will be fetched when getattr is called on the entry.
            let (entry_inode, attr) = if name == "." {
                (ino, self.make_dir_attr(ino, None))
            } else if name == ".." {
                (parent_inode, self.make_dir_attr(parent_inode, None))
            } else {
                // Allocate a real inode for the entry
                let child_path = current_path.join(name);
                let kind = match file_type {
                    FileType::Directory => InodeKind::Directory {
                        // Dir entries from listing have actual dir_id; root fallback is for safety
                        dir_id: maybe_subdir_id.clone().unwrap_or_else(DirId::root),
                    },
                    FileType::Symlink => InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: name.clone(),
                    },
                    _ => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: name.clone(),
                    },
                };
                let entry_inode = self.inodes.get_or_insert(&child_path, &kind);

                let attr = match file_type {
                    FileType::Directory => self.make_dir_attr(entry_inode, None),
                    FileType::RegularFile => {
                        // Use effective size to account for in-memory buffer (mmap consistency)
                        let effective_size = self.effective_file_size(entry_inode, *size);
                        self.make_file_attr(entry_inode, effective_size, None)
                    }
                    FileType::Symlink => self.make_symlink_attr(entry_inode, *size, None),
                    _ => {
                        let effective_size = self.effective_file_size(entry_inode, *size);
                        self.make_file_attr(entry_inode, effective_size, None)
                    }
                };

                // Cache the attribute
                self.attr_cache.insert(entry_inode, attr);

                (entry_inode, attr)
            };

            // Compute next offset as hash of current entry name
            let next_offset = Self::name_to_offset(name);

            // buffer.add returns true if buffer is full
            if reply.add(entry_inode, next_offset, name, &DEFAULT_ATTR_TTL, &attr, 0) {
                break;
            }
        }

        self.vault_stats.record_metadata_latency(start.elapsed());
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        self.vault_stats.record_dir_close();
        reply.ok();
    }

    /// Flush cached data for an open file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.flush`)
    ///
    /// Called on each `close()` of an opened file. May be called multiple times for
    /// the same file handle if the descriptor was duplicated (via `dup()`).
    ///
    /// **Note**: This is NOT the same as `fsync`. The POSIX `close()` does not
    /// guarantee that delayed I/O has completed. Flush should also release any
    /// POSIX locks belonging to the `lock_owner`.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success).
    ///
    /// # Implementation Notes
    ///
    /// - Writes dirty buffer contents to the vault
    /// - Does not release the file handle (that's `release`'s job)
    /// - Lock release is a no-op since we don't implement POSIX locks
    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        trace!(inode = ino, fh = fh, "flush");

        // Wait for any pending async writes (copy_file_range) to complete
        // before flushing, to ensure all data is visible in the buffer.
        if let Some(ref scheduler) = self.scheduler {
            if scheduler.has_pending_writes(ino) {
                trace!(ino, "Waiting for pending async writes before flush");
                if !scheduler.wait_pending_writes(ino, self.write_timeout) {
                    // Timeout waiting for pending writes - might have stale data
                    warn!(ino, "Timeout waiting for pending async writes in flush");
                    reply.error(libc::ETIMEDOUT);
                    return;
                }
            }
        }

        // Flush writes data to the vault (kernel buffer cache).
        // We don't sync to disk here - that's fsync's job.
        match self.flush_handle(ino, fh) {
            Ok(_) => reply.ok(), // Ignore the returned path
            Err(errno) => reply.error(errno),
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        trace!(inode = ino, fh = fh, datasync = datasync, "fsync");

        // Wait for any pending async writes (copy_file_range) to complete
        // before syncing, to ensure all data is visible in the buffer.
        if let Some(ref scheduler) = self.scheduler {
            if scheduler.has_pending_writes(ino) {
                trace!(ino, "Waiting for pending async writes before fsync");
                if !scheduler.wait_pending_writes(ino, self.write_timeout) {
                    // Timeout waiting for pending writes - might have stale data
                    warn!(ino, "Timeout waiting for pending async writes in fsync");
                    reply.error(libc::ETIMEDOUT);
                    return;
                }
            }
        }

        // First, flush any dirty data to the vault
        if let Err(errno) = self.flush_handle(ino, fh) {
            reply.error(errno);
            return;
        }

        // Then sync the encrypted file to disk
        // The datasync flag determines whether to sync metadata too:
        // - datasync=false (fsync): sync data and metadata
        // - datasync=true (fdatasync): sync data only
        match self.sync_handle_to_disk(fh, datasync) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        trace!(inode = ino, "fsyncdir");
        // Directories are written synchronously in Cryptomator (dir.c9r files),
        // so fsyncdir is a no-op.
        reply.ok();
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        trace!(inode = ino, mask = mask, "access");

        // Cryptomator doesn't store Unix permissions, so we use synthetic defaults:
        // - Files: 644 (rw-r--r--)
        // - Directories: 755 (rwxr-xr-x)
        // All files are owned by the mounting user.
        //
        // Simply verify the inode exists and return success.
        // The mounting user has full access to everything.
        if self.inodes.get(ino).is_some() {
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
        }
    }

    /// Set file attributes.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.setattr`)
    ///
    /// Modifies file attributes. The bitmask indicates which fields are valid.
    /// Must reply with the new attributes on success.
    ///
    /// **setuid/setgid note**: When FUSE_CAP_HANDLE_KILLPRIV is enabled, the
    /// filesystem must reset setuid/setgid bits when the file size or owner changes.
    /// This is a security requirement to prevent privilege escalation.
    ///
    /// # Implementation Notes
    ///
    /// - chmod/chown are silently accepted but ignored (Cryptomator doesn't store Unix permissions)
    ///   This matches the behavior of vfat and other filesystems without permission support.
    /// - truncate (size change) is fully supported
    /// - atime/mtime changes are silently accepted for compatibility (touch, tar, rsync)
    ///   but not actually stored (Cryptomator doesn't preserve timestamps)
    ///
    /// # Partial Compliance
    ///
    /// Does not handle setuid/setgid bit reset on truncate. This is acceptable because:
    /// 1. Cryptomator doesn't store Unix permissions at all
    /// 2. Our synthetic permissions never include setuid/setgid bits
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(
            inode = ino,
            mode = ?mode,
            uid = ?uid,
            gid = ?gid,
            size = ?size,
            "setattr"
        );

        // Cryptomator doesn't store Unix permissions or timestamps.
        // We silently ignore chmod/chown/atime/mtime changes for compatibility.
        // This matches the behavior of vfat and other filesystems without permission support.
        // Only truncate (size change) is actually processed.

        // Get current inode info
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        // Handle size change (truncate)
        if let Some(new_size) = size {
            match &entry.kind {
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    let file_name = name.clone();
                    drop(entry);

                    debug!(inode = ino, new_size = new_size, fh = ?fh, file = %file_name, "setattr: truncate request");

                    // If we have an open file handle, truncate the buffer
                    if let Some(fh) = fh
                        && let Some(mut handle) = self.handle_table.get_mut(&fh)
                            && let Some(buffer) = handle.as_write_buffer_mut() {
                                debug!(inode = ino, old_size = buffer.len(), new_size = new_size, "setattr: found open write buffer");
                                let old_size = buffer.len();
                                buffer.truncate(new_size);

                                // CRITICAL: For mmap compatibility, if we're extending the file,
                                // we MUST flush to disk immediately. Otherwise the kernel will
                                // report the new size but the file on disk is still the old size,
                                // causing SIGBUS when applications (like SQLite WAL) mmap the
                                // extended region.
                                if new_size > old_size {
                                    // Take content for flush - resize to new_size before writing
                                    // so the file on disk matches what we report to the kernel.
                                    // This is critical for mmap consistency.
                                    let mut content = buffer.take_content_for_flush();
                                    // On 32-bit: file sizes beyond 4GB would fail earlier in allocation
                                    #[allow(clippy::cast_possible_truncation)]
                                    content.resize(new_size as usize, 0);
                                    let content_for_write = content.clone();
                                    let dir_id_write = dir_id.clone();
                                    let name_write = name.clone();
                                    drop(handle);

                                    let ops = self.ops_clone();
                                    match self.exec(async move {
                                        ops.write_file(&dir_id_write, &name_write, &content_for_write).await
                                    }) {
                                        Ok(Ok(_)) => {
                                            // Restore resized content and mark clean
                                            if let Some(mut handle) = self.handle_table.get_mut(&fh)
                                                && let Some(buffer) = handle.as_write_buffer_mut() {
                                                    buffer.restore_content(content);
                                                }
                                            // Track buffer size for mmap consistency
                                            self.update_buffer_size(ino, new_size);
                                            // Just modified file, so mtime = now is correct
                                            let attr = self.make_file_attr(ino, new_size, None);
                                            self.attr_cache.insert(ino, attr);
                                            self.vault_stats.record_metadata_latency(start.elapsed());
                                            // Use zero TTL - file has active buffer, kernel must not cache size
                                            reply.attr(&Duration::ZERO, &attr);
                                        }
                                        Ok(Err(e)) => {
                                            // Restore content but mark dirty for retry
                                            if let Some(mut handle) = self.handle_table.get_mut(&fh)
                                                && let Some(buffer) = handle.as_write_buffer_mut() {
                                                    buffer.restore_content(content);
                                                    buffer.mark_dirty();
                                                }
                                            self.vault_stats.record_error();
                                            self.vault_stats.record_metadata_latency(start.elapsed());
                                            reply.error(crate::error::write_error_to_errno(&e));
                                        }
                                        Err(exec_err) => {
                                            if let Some(mut handle) = self.handle_table.get_mut(&fh)
                                                && let Some(buffer) = handle.as_write_buffer_mut() {
                                                    buffer.restore_content(content);
                                                    buffer.mark_dirty();
                                                }
                                            self.vault_stats.record_error();
                                            self.vault_stats.record_metadata_latency(start.elapsed());
                                            reply.error(exec_err.to_errno());
                                        }
                                    }
                                    return;
                                }

                                // Truncating to smaller size: just update buffer (no flush needed)
                                drop(handle);

                                // Set exact buffer size for mmap consistency (use set, not update, since we're shrinking)
                                self.set_buffer_size(ino, new_size);
                                // Just modified file, so mtime = now is correct
                                let attr = self.make_file_attr(ino, new_size, None);
                                self.attr_cache.insert(ino, attr);
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                // Use zero TTL - file has active buffer, kernel must not cache size
                                reply.attr(&Duration::ZERO, &attr);
                                return;
                            }

                    // No open handle - read file, truncate, write back
                    debug!(inode = ino, new_size = new_size, file = %file_name, "setattr: no open write buffer, using read-modify-write");
                    let ops = self.ops_clone();
                    let dir_id_read = dir_id.clone();
                    let name_read = name.clone();

                    // Read existing content (or empty if file doesn't exist)
                    let read_result =
                        self.exec(async move { ops.read_file(&dir_id_read, &name_read).await });
                    let (mut content, old_size) = match read_result {
                        Ok(Ok(file)) => {
                            let size = file.content.len() as u64;
                            (file.content, size)
                        }
                        Ok(Err(_)) | Err(_) => (Vec::new(), 0),
                    };

                    // Track if we're extending (for TTL decision)
                    let is_extending = new_size > old_size;

                    // Truncate or extend
                    // On 32-bit: file sizes beyond 4GB would fail earlier in allocation
                    #[allow(clippy::cast_possible_truncation)]
                    content.resize(new_size as usize, 0);

                    // Write back
                    let ops = self.ops_clone();
                    let dir_id_write = dir_id.clone();
                    let name_write = name.clone();

                    match self.exec(async move {
                        ops.write_file(&dir_id_write, &name_write, &content).await
                    }) {
                        Ok(Ok(_)) => {
                            // Just modified file, so mtime = now is correct
                            let attr = self.make_file_attr(ino, new_size, None);
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            // CRITICAL for mmap: When extending via fallback path (no open WriteBuffer),
                            // we must:
                            // 1. Return zero TTL to prevent kernel from caching size
                            // 2. NOT insert into attr_cache - otherwise next getattr returns
                            //    cached entry with time_remaining() (up to 60s), causing kernel
                            //    to cache stale size → SIGBUS on mmap if file extended again
                            if is_extending {
                                self.attr_cache.invalidate(ino);
                                reply.attr(&Duration::ZERO, &attr);
                            } else {
                                self.attr_cache.insert(ino, attr);
                                reply.attr(&DEFAULT_ATTR_TTL, &attr);
                            }
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(crate::error::write_error_to_errno(&e));
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                        }
                    }
                    return;
                }
                InodeKind::Directory { .. } | InodeKind::Root => {
                    // Can't truncate directories
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EISDIR);
                    return;
                }
                InodeKind::Symlink { .. } => {
                    // Can't truncate symlinks
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EINVAL);
                    return;
                }
            }
        }

        // Handle atime/mtime changes - update timestamps on encrypted files
        // (touch, tar, rsync use these)
        if atime.is_some() || mtime.is_some() {
            // Convert TimeOrNow to FileTime
            let atime_ft = atime.map(|t| match t {
                TimeOrNow::Now => FileTime::now(),
                TimeOrNow::SpecificTime(st) => FileTime::from(st),
            });
            let mtime_ft = mtime.map(|t| match t {
                TimeOrNow::Now => FileTime::now(),
                TimeOrNow::SpecificTime(st) => FileTime::from(st),
            });

            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => {
                    // For directories, we don't have easy access to the encrypted path
                    // without the parent info. Timestamps on directories are less
                    // critical than on files, so we just silently succeed here.
                    drop(entry);
                    self.make_dir_attr(ino, None)
                }
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    let ops = self.ops_clone();
                    match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                        Ok(Ok(Some(file_info))) => {
                            // Update timestamps on the encrypted file
                            if let Err(e) = filetime::set_file_times(
                                &file_info.encrypted_path,
                                atime_ft.unwrap_or(FileTime::now()),
                                mtime_ft.unwrap_or(FileTime::now()),
                            ) {
                                warn!("Failed to set file times: {:?}", e);
                            }
                            let file_size =
                                encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
                            let new_mtime = Self::get_mtime(&file_info.encrypted_path);
                            self.make_file_attr(ino, file_size, new_mtime)
                        }
                        Ok(Ok(None)) => {
                            self.make_file_attr(ino, 0, None)
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(crate::error::vault_error_to_errno(&e));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    }
                }
                InodeKind::Symlink { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    let ops = self.ops_clone();
                    match self.exec(async move { ops.find_symlink(&dir_id, &name).await }) {
                        Ok(Ok(Some(info))) => {
                            // Update timestamps on the encrypted symlink file
                            if let Err(e) = filetime::set_file_times(
                                &info.encrypted_path,
                                atime_ft.unwrap_or(FileTime::now()),
                                mtime_ft.unwrap_or(FileTime::now()),
                            ) {
                                warn!("Failed to set symlink times: {:?}", e);
                            }
                            let new_mtime = Self::get_mtime(&info.encrypted_path);
                            self.make_symlink_attr(ino, info.target.len() as u64, new_mtime)
                        }
                        Ok(Ok(None)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(libc::ENOENT);
                            return;
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(crate::error::vault_error_to_errno(&e));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    }
                }
            };

            self.attr_cache.insert(ino, attr);
            self.vault_stats.record_metadata_latency(start.elapsed());
            // Use zero TTL if file has active buffer to prevent kernel caching stale size
            let ttl = if self.buffer_sizes.contains_key(&ino) {
                Duration::ZERO
            } else {
                DEFAULT_ATTR_TTL
            };
            reply.attr(&ttl, &attr);
            return;
        }

        // No size/time changes requested (chmod or chown) - return current attributes
        // Cryptomator doesn't store permissions, so we silently succeed with current attrs.
        // This is similar to vfat and other filesystems without permission support.
        //
        // IMPORTANT: We avoid expensive file lookups here because:
        // 1. chmod/chown don't actually change anything in Cryptomator vaults
        // 2. During bulk operations (like tar extraction), files may have just been
        //    created and closed, and doing a lookup can fail due to timing issues
        // 3. The kernel just needs us to return success with valid attrs
        if let Some(cached) = self.attr_cache.get(ino) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.attr(&cached.time_remaining(), &cached.value);
        } else {
            // No cache hit - return synthetic attrs based on inode type
            // This avoids expensive vault I/O for mode-only changes
            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => {
                    drop(entry);
                    self.make_dir_attr(ino, None)
                }
                InodeKind::File { .. } => {
                    drop(entry);
                    // Use buffer size if available, otherwise size 0
                    // (the actual size will be fetched on next getattr)
                    let size = self.buffer_sizes.get(&ino).map_or(0, |r| *r);
                    self.make_file_attr(ino, size, None)
                }
                InodeKind::Symlink { .. } => {
                    drop(entry);
                    // Symlink with unknown target length - use 0
                    // (the actual size will be fetched on next getattr)
                    self.make_symlink_attr(ino, 0, None)
                }
            };
            // Don't cache this synthetic attr - let getattr do the real lookup
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.attr(&Duration::ZERO, &attr);
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        // Query real filesystem statistics from underlying storage
        match nix::sys::statvfs::statvfs(&self.vault_path) {
            Ok(stat) => {
                // On Linux, cap name_max at 254 because Nautilus (GNOME Files) tests
                // namelen+1 when checking filename validity. Using 255 causes Nautilus
                // to incorrectly reject valid filenames at the boundary.
                // See: https://github.com/cryptomator/fuse-nio-adapter (DEFAULT_MAX_FILENAMELENGTH)
                // name_max from statvfs is typically 255, which fits in u32
                #[allow(clippy::cast_possible_truncation)]
                #[cfg(target_os = "linux")]
                let name_max = std::cmp::min(stat.name_max() as u32, 254);
                #[allow(clippy::cast_possible_truncation)]
                #[cfg(not(target_os = "linux"))]
                let name_max = stat.name_max() as u32;

                // fragment_size is typically 4096-8192, which fits in u32
                #[allow(clippy::cast_possible_truncation)]
                let fragment_size = stat.fragment_size() as u32;

                reply.statfs(
                    u64::from(stat.blocks()),             // Total blocks
                    u64::from(stat.blocks_free()),        // Free blocks
                    u64::from(stat.blocks_available()),   // Available blocks (non-root)
                    u64::from(stat.files()),              // Total inodes
                    u64::from(stat.files_free()),         // Free inodes
                    fragment_size,                    // Block size
                    name_max,                         // Max filename length
                    fragment_size,                    // Fragment size
                );
            }
            Err(e) => {
                debug!(error = %e, "Failed to get statfs, using defaults");
                // On Linux, use 254 for namelen (Nautilus compatibility).
                #[cfg(target_os = "linux")]
                let default_namelen = 254u32;
                #[cfg(not(target_os = "linux"))]
                let default_namelen = 255u32;

                // Fallback to reasonable defaults
                reply.statfs(
                    1000000,         // blocks
                    500000,          // bfree
                    500000,          // bavail
                    1000000,         // files
                    500000,          // ffree
                    BLOCK_SIZE,      // bsize
                    default_namelen, // namelen
                    BLOCK_SIZE,      // frsize
                );
            }
        }
    }

    // ==================== Write Operations ====================

    /// Create and open a file atomically.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.create`)
    ///
    /// Atomically creates and opens a new file. If the filesystem does not implement
    /// this, the kernel will fall back to `mknod` + `open`.
    ///
    /// This is preferred over mknod+open because it's atomic and avoids race conditions
    /// where another process could modify the file between creation and opening.
    ///
    /// Valid replies: `fuse_reply_create` (success) or `fuse_reply_err` (failure).
    ///
    /// # Implementation Notes
    ///
    /// - Creates a WriteBuffer marked dirty (ensures file is written even if empty)
    /// - Allocates inode via `get_or_insert` (increments nlookup, correct per spec)
    /// - Invalidates parent's negative cache and dir listing cache
    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, "create");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before create
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EEXIST);
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_))) ||
                    matches!(dir_res, Ok(Some(_))) ||
                    matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EEXIST);
            return;
        }

        // Create the file with a new WriteBuffer marked dirty
        // (File will be written to vault on release, even if empty)
        let buffer = WriteBuffer::new_for_create(dir_id.clone(), name_str.to_string());
        let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));

        // Allocate inode
        let inode = self.inodes.get_or_insert(
            &child_path,
            &InodeKind::File {
                dir_id: dir_id.clone(),
                name: name_str.to_string(),
            },
        );

        // TODO: Re-enable when open_handle_tracker is added back
        // Track open handle for POSIX-compliant deferred deletion
        // self.open_handle_tracker.add_handle(inode);

        // Just created, so mtime = now is correct
        let attr = self.make_file_attr(inode, 0, None);
        self.attr_cache.insert(inode, attr);

        // Invalidate parent's negative cache and dir cache
        self.attr_cache.remove_negative(parent, name_str);
        self.dir_cache.invalidate(parent);

        self.vault_stats.record_metadata_latency(start.elapsed());
        reply.created(&DEFAULT_ATTR_TTL, &attr, 0, fh, 0);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        trace!(
            inode = ino,
            fh = fh,
            offset = offset,
            size = data.len(),
            "write"
        );

        // Get the handle from our table
        let Some(mut handle) = self.handle_table.get_mut(&fh) else {
            reply.error(libc::EBADF);
            return;
        };

        let Some(buffer) = handle.as_write_buffer_mut() else {
            // Trying to write to a read-only handle
            reply.error(libc::EBADF);
            return;
        };

        // Check write budget before proceeding
        // This prevents unbounded dirty data accumulation under slow backends
        if let Some(ref scheduler) = self.scheduler {
            let write_size = data.len() as u64;
            if scheduler.check_write_budget(ino, write_size).is_err() {
                trace!(
                    ino,
                    write_size,
                    "Write rejected due to budget limit (EAGAIN)"
                );
                drop(handle); // Release lock before replying
                reply.error(libc::EAGAIN);
                return;
            }
        }

        // Track buffer size before write for delta calculation
        let old_size = buffer.len();

        // Write data at offset (WriteBuffer handles buffer expansion)
        self.vault_stats.start_write();
        // FUSE guarantees offset is non-negative (it's from kernel write requests)
        #[allow(clippy::cast_sign_loss)]
        let bytes_written = buffer.write(offset as u64, data);
        let new_size = buffer.len();
        self.vault_stats.finish_write();
        self.vault_stats.record_write(bytes_written as u64);
        self.vault_stats.record_encrypted(bytes_written as u64);

        // Track buffer size for mmap consistency (getattr must see current size)
        self.update_buffer_size(ino, new_size);

        // Track write bytes for budget enforcement
        // Only track the delta (new bytes added), not overwrites
        if let Some(ref scheduler) = self.scheduler {
            if new_size > old_size {
                scheduler.add_write_bytes(ino, (new_size - old_size) as u64);
            }
        }

        // Invalidate attr cache for this inode (will be recalculated with effective_file_size)
        self.attr_cache.invalidate(ino);
        // bytes_written is from buffer.write() which returns amount written (limited by data.len())
        // data.len() is u32 from FUSE API, so bytes_written will fit in u32
        #[allow(clippy::cast_possible_truncation)]
        reply.written(bytes_written as u32);
    }

    /// mknod - Create file node (debug implementation)
    ///
    /// This is called when the kernel can't use create() for some reason.
    /// Adding this to debug if macOS is using mknod instead of create.
    fn mknod(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // mknod is not used for regular files when create() is implemented
        // Returning ENOSYS causes the kernel to fall back to create() for regular files
        reply.error(libc::ENOSYS);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, "mkdir");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(parent_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before mkdir
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EEXIST);
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = parent_dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_))) ||
                    matches!(dir_res, Ok(Some(_))) ||
                    matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EEXIST);
            return;
        }

        let ops = self.ops_clone();
        let parent_dir_id_clone = parent_dir_id.clone();
        let name_owned = name_str.to_string();

        // Create directory
        match self.exec(async move { ops.create_directory(&parent_dir_id_clone, &name_owned).await })
        {
            Ok(Ok(new_dir_id)) => {
                // Allocate inode
                let child_path = parent_path.join(name_str);
                let inode = self.inodes.get_or_insert(
                    &child_path,
                    &InodeKind::Directory {
                        dir_id: new_dir_id.clone(),
                    },
                );

                // DEBUG: Track inode allocation and vault UUID
                tracing::info!(
                    "mkdir: allocated inode={} with dir_id={} for path={}",
                    inode, new_dir_id, child_path
                );

                // Just created, so mtime = now is correct
                let attr = self.make_dir_attr(inode, None);
                self.attr_cache.insert(inode, attr);

                // Invalidate parent caches
                self.attr_cache.remove_negative(parent, name_str);
                self.dir_cache.invalidate(parent);

                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(exec_err.to_errno());
            }
        }
    }

    /// Remove a file or symlink.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.unlink`)
    ///
    /// Removes a file. If the inode's lookup count is nonzero, the filesystem should
    /// defer actual inode removal until the count reaches zero (via `forget`).
    ///
    /// Valid reply: `fuse_reply_err` (0 for success).
    ///
    /// # Implementation Notes
    ///
    /// - Tries to delete as file first, then as symlink
    /// - Invalidates path mapping (but inode entry remains until `forget`)
    /// - Invalidates parent's directory cache
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, "unlink");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Get the child's inode to check for open handles (POSIX compliance)
        let child_path = parent_path.join(name_str);
        let child_inode = self.inodes.get_inode(&child_path);

        // Check if file has open handles - if so, defer deletion
        if let Some(ino) = child_inode
            && self.open_handle_tracker.has_open_handles(ino) {
                // POSIX: unlink removes directory entry immediately but defers file deletion
                self.open_handle_tracker
                    .mark_for_deletion(ino, dir_id.clone(), name_str.to_string());
                // Invalidate directory cache (file disappears from directory listings)
                // but KEEP the inode path mapping so lookup can find it and return ENOENT
                self.dir_cache.invalidate(parent);

                // Notify kernel to invalidate its dcache entry for this file
                // This forces the kernel to call lookup() again, which will return ENOENT
                if let Some(notifier) = self.notifier.get()
                    && let Err(e) = notifier.inval_entry(parent, name) {
                        trace!("Failed to notify kernel of deferred deletion: {}", e);
                    }

                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.ok();
                return;
            }

        let ops = self.ops_clone();
        let dir_id_file = dir_id.clone();
        let name_file = name_str.to_string();

        // No open handles - proceed with actual deletion
        // Try to delete as file first
        match self.exec(async move { ops.delete_file(&dir_id_file, &name_file).await }) {
            Ok(Ok(())) => {
                // Invalidate caches
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.vault_stats.record_metadata_latency(start.elapsed());

                // Notify kernel of deletion (file deletion)
                if let Some(notifier) = self.notifier.get() {
                    // Use child_inode if available, otherwise skip notification
                    if let Some(ino) = child_inode
                        && let Err(e) = notifier.delete(parent, ino, name) {
                            trace!("Failed to notify kernel of deletion (file): {}", e);
                        }
                }

                reply.ok();
            }
            Ok(Err(_)) | Err(_) => {
                // Try as symlink
                let ops = self.ops_clone();
                let dir_id_symlink = dir_id.clone();
                let name_symlink = name_str.to_string();

                match self.exec(async move { ops.delete_symlink(&dir_id_symlink, &name_symlink).await })
                {
                    Ok(Ok(())) => {
                        self.inodes.invalidate_path(&child_path);
                        self.dir_cache.invalidate(parent);
                        self.vault_stats.record_metadata_latency(start.elapsed());

                        // Notify kernel of deletion (symlink deletion)
                        if let Some(notifier) = self.notifier.get() {
                            // Use child_inode if available, otherwise skip notification
                            if let Some(ino) = child_inode
                                && let Err(e) = notifier.delete(parent, ino, name) {
                                    trace!("Failed to notify kernel of deletion (symlink): {}", e);
                                }
                        }

                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::write_error_to_errno(&e));
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                    }
                }
            }
        }
    }

    /// Remove a directory.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.rmdir`)
    ///
    /// Removes an empty directory. If the inode's lookup count is nonzero, the
    /// filesystem should defer actual inode removal until the count reaches zero.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success, ENOTEMPTY if not empty).
    ///
    /// # Implementation Notes
    ///
    /// - On macOS, first cleans up AppleDouble files (`._*`) and `.DS_Store`
    ///   that Finder creates automatically. These prevent rmdir from succeeding
    ///   with ENOTEMPTY even though user sees directory as empty.
    /// - Delegates to vault's `delete_directory` which checks for empty
    /// - Invalidates path mapping and parent's directory cache
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, "rmdir");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(parent_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // On macOS, clean up AppleDouble files before attempting directory deletion.
        // Finder automatically creates ._* (AppleDouble resource forks) and .DS_Store
        // files in directories. These must be deleted first or rmdir fails with ENOTEMPTY.
        #[cfg(target_os = "macos")]
        {
            // First, find the target directory to get its DirId
            let ops = self.ops_clone();
            let parent_dir_id_clone = parent_dir_id.clone();
            let name_owned = name_str.to_string();

            let target_dir_id = match self.exec(async move {
                ops.find_directory(&parent_dir_id_clone, &name_owned).await
            }) {
                Ok(Ok(Some(dir_info))) => dir_info.directory_id,
                Ok(Ok(None)) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::ENOENT);
                    return;
                }
                Ok(Err(e)) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(crate::error::vault_error_to_errno(&e));
                    return;
                }
                Err(exec_err) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

            // List files in the target directory and delete AppleDouble/DS_Store files
            let ops = self.ops_clone();
            let target_dir_id_clone = target_dir_id.clone();

            let files_to_delete: Vec<String> = match self.exec(async move {
                ops.list_files(&target_dir_id_clone).await
            }) {
                Ok(Ok(files)) => files
                    .into_iter()
                    .filter(|f| f.name.starts_with("._") || f.name == ".DS_Store")
                    .map(|f| f.name)
                    .collect(),
                Ok(Err(e)) => {
                    // If we can't list files, try delete_directory anyway - it will fail with
                    // ENOTEMPTY if there are actually files present
                    debug!(error = %e, "Failed to list files for AppleDouble cleanup, continuing with rmdir");
                    Vec::new()
                }
                Err(exec_err) => {
                    debug!(error = %exec_err, "Exec error listing files for AppleDouble cleanup, continuing with rmdir");
                    Vec::new()
                }
            };

            // Delete each AppleDouble file
            for file_name in files_to_delete {
                let ops = self.ops_clone();
                let target_dir_id_clone = target_dir_id.clone();
                let file_name_clone = file_name.clone();

                match self.exec(async move {
                    ops.delete_file(&target_dir_id_clone, &file_name_clone).await
                }) {
                    Ok(Ok(())) => {
                        trace!(file = %file_name, "Deleted AppleDouble file before rmdir");
                    }
                    Ok(Err(e)) => {
                        // Log but continue - the file might have been deleted concurrently
                        debug!(file = %file_name, error = %e, "Failed to delete AppleDouble file");
                    }
                    Err(exec_err) => {
                        debug!(file = %file_name, error = %exec_err, "Exec error deleting AppleDouble file");
                    }
                }
            }
        }

        let ops = self.ops_clone();
        let parent_dir_id_clone = parent_dir_id.clone();
        let name_owned = name_str.to_string();

        // Delete directory
        match self.exec(async move {
            ops.delete_directory(&parent_dir_id_clone, &name_owned).await
        }) {
            Ok(Ok(())) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);

                // Get child inode before invalidating path
                let child_inode = self.inodes.get_inode(&child_path);

                // DEBUG: Track inode invalidation
                if let Some(ino) = child_inode
                    && let Some(entry) = self.inodes.get(ino) {
                        tracing::info!(
                            "rmdir: invalidating inode={} with dir_id={:?} for path={}",
                            ino,
                            entry.dir_id(),
                            child_path
                        );
                    }

                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.vault_stats.record_metadata_latency(start.elapsed());

                // Notify kernel of deletion to evict from dcache
                // This prevents kernel from caching stale inode numbers across iterations
                if let Some(notifier) = self.notifier.get()
                    && let Some(ino) = child_inode
                        && let Err(e) = notifier.delete(parent, ino, name) {
                            trace!("Failed to notify kernel of directory deletion: {}", e);
                        }

                reply.ok();
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(exec_err.to_errno());
            }
        }
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = link_name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };

        let Some(target_str) = target.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };

        trace!(parent = parent, name = name_str, target = target_str, "symlink");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            // DEBUG: Track failed parent lookup
            tracing::error!(
                "symlink: parent inode={} NOT FOUND in InodeTable (kernel passed stale inode?)",
                parent
            );
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            reply.error(libc::ENOTDIR);
            return;
        };

        // DEBUG: Track parent lookup and vault UUID extraction
        tracing::info!(
            "symlink: parent inode={} found, dir_id={}, path={}",
            parent, dir_id, parent_entry.path
        );

        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before symlink
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            reply.error(libc::EEXIST);
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_))) ||
                matches!(dir_res, Ok(Some(_))) ||
                matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            reply.error(libc::EEXIST);
            return;
        }

        let ops = self.ops_clone();
        let dir_id_clone = dir_id.clone();
        let name_owned = name_str.to_string();
        let target_owned = target_str.to_string();

        // Create symlink
        match self.exec(async move {
            ops.create_symlink(&dir_id_clone, &name_owned, &target_owned)
                .await
        }) {
            Ok(Ok(())) => {
                // Allocate inode
                let child_path = parent_path.join(name_str);
                let inode = self.inodes.get_or_insert(
                    &child_path,
                    &InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: name_str.to_string(),
                    },
                );

                // Just created, so mtime = now is correct
                let attr = self.make_symlink_attr(inode, target_str.len() as u64, None);
                self.attr_cache.insert(inode, attr);

                // Invalidate parent caches
                self.attr_cache.remove_negative(parent, name_str);
                self.dir_cache.invalidate(parent);

                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Ok(Err(e)) => {
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                reply.error(exec_err.to_errno());
            }
        }
    }

    /// Create a hard link (not supported).
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.link`)
    ///
    /// Creates a hard link from `newparent/newname` pointing to the existing inode `ino`.
    /// The target inode's link count should be incremented on success.
    ///
    /// # Implementation
    ///
    /// Cryptomator Vault Format 8 does not support hard links - each file has exactly one
    /// encrypted representation in the vault. Hardlinks are typically used for:
    /// - Space optimization (multiple names pointing to same data)
    /// - Atomic file replacement (link then unlink pattern)
    ///
    /// Applications that use hardlinks (like git's object database) gracefully fall back
    /// to file copies when link() returns ENOSYS. This is expected behavior and not an error.
    ///
    /// **Returns**: ENOSYS (function not implemented) without logging, since this is
    /// expected and applications handle it gracefully.
    fn link(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _newparent: u64,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Silently return ENOSYS - hardlinks not supported by Cryptomator format.
        // No trace/warn logging since this is expected (git operations frequently try
        // to use hardlinks as an optimization, then fall back to copying).
        reply.error(libc::ENOSYS);
    }

    /// Rename a file or directory.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.rename`)
    ///
    /// Atomically renames a file/directory from `name` in `parent` to `newname` in
    /// `newparent`. If the target exists, it should be atomically replaced.
    ///
    /// The `flags` parameter supports:
    /// - `RENAME_NOREPLACE` (1): Fail with EEXIST if target already exists
    /// - `RENAME_EXCHANGE` (2): Atomically exchange source and target (both must exist)
    ///
    /// # BUG (SPEC VIOLATION)
    ///
    /// This implementation ignores the `flags` parameter entirely:
    /// - `RENAME_NOREPLACE` is not checked; target is always overwritten if it exists
    /// - `RENAME_EXCHANGE` is not implemented; should atomically swap two entries
    ///
    /// **FIX**: Check flags and implement:
    /// ```ignore
    /// if flags & libc::RENAME_NOREPLACE != 0 {
    ///     // Check if target exists and fail with EEXIST if so
    /// }
    /// if flags & libc::RENAME_EXCHANGE != 0 {
    ///     // Atomically exchange source and target
    /// }
    /// ```
    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        let Some(newname_str) = newname.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EINVAL);
            return;
        };

        trace!(
            parent = parent,
            name = name_str,
            newparent = newparent,
            newname = newname_str,
            "rename"
        );

        // Get source parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(src_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let src_parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Get destination parent directory
        let Some(newparent_entry) = self.inodes.get(newparent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        };

        let Some(dest_dir_id) = newparent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTDIR);
            return;
        };
        let dest_parent_path = newparent_entry.path.clone();
        drop(newparent_entry);

        // Handle rename flags
        #[cfg(target_os = "linux")]
        {
            // RENAME_EXCHANGE: atomic swap of source and target
            if _flags & libc::RENAME_EXCHANGE != 0 {
                trace!("rename: handling RENAME_EXCHANGE");

                // Build paths for both entries
                let src_path = src_parent_path.join(name_str);
                let dest_path = dest_parent_path.join(newname_str);

                // Look up both inodes - both must exist for exchange
                let src_inode = match self.inodes.get_inode(&src_path) {
                    Some(inode) => inode,
                    None => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                let dest_inode = match self.inodes.get_inode(&dest_path) {
                    Some(inode) => inode,
                    None => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                // Get entry kinds
                let src_entry = match self.inodes.get(src_inode) {
                    Some(e) => e,
                    None => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };
                let src_is_dir = src_entry.kind.is_directory();
                let src_is_file = src_entry.kind.is_file();
                drop(src_entry);

                let dest_entry = match self.inodes.get(dest_inode) {
                    Some(e) => e,
                    None => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };
                let dest_is_dir = dest_entry.kind.is_directory();
                let dest_is_file = dest_entry.kind.is_file();
                drop(dest_entry);

                // Both must be same type (file/file or dir/dir)
                if src_is_dir != dest_is_dir {
                    debug!(
                        "rename: RENAME_EXCHANGE type mismatch (src_is_dir={}, dest_is_dir={})",
                        src_is_dir, dest_is_dir
                    );
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EINVAL);
                    return;
                }

                // Perform the swap
                let result = if src_is_file {
                    // File swap - can be cross-directory
                    let ops = self.ops_clone();
                    let src_dir = src_dir_id.clone();
                    let dest_dir = dest_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_files(&src_dir, &name_a, &dest_dir, &name_b)
                            .await
                    })
                } else if src_is_dir {
                    // Directory swap - must be same parent
                    if parent != newparent {
                        debug!("rename: RENAME_EXCHANGE cross-directory dir swap not supported");
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::EXDEV);
                        return;
                    }

                    let ops = self.ops_clone();
                    let parent_dir = src_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_directories(&parent_dir, &name_a, &name_b)
                            .await
                    })
                } else {
                    // Symlink - treat like file swap
                    let ops = self.ops_clone();
                    let src_dir = src_dir_id.clone();
                    let dest_dir = dest_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_files(&src_dir, &name_a, &dest_dir, &name_b)
                            .await
                    })
                };

                match result {
                    Ok(Ok(())) => {
                        // Update inode mappings - swap the paths
                        self.inodes.swap_paths(src_inode, dest_inode, &src_path, &dest_path);

                        // Also swap the InodeKind entries - each inode now has the other's name/location
                        // src_inode was at (src_dir_id, name_str), now at (dest_dir_id, newname_str)
                        // dest_inode was at (dest_dir_id, newname_str), now at (src_dir_id, name_str)
                        if src_is_file {
                            self.inodes.update_kind(
                                src_inode,
                                InodeKind::File {
                                    dir_id: dest_dir_id.clone(),
                                    name: newname_str.to_string(),
                                },
                            );
                            self.inodes.update_kind(
                                dest_inode,
                                InodeKind::File {
                                    dir_id: src_dir_id.clone(),
                                    name: name_str.to_string(),
                                },
                            );
                        } else if src_is_dir {
                            // For directories, the dir_id (the directory's own ID) doesn't change,
                            // only the path. The swap_paths already handled path updates.
                            // InodeKind::Directory { dir_id } stays the same for each.
                        } else {
                            // Symlinks
                            self.inodes.update_kind(
                                src_inode,
                                InodeKind::Symlink {
                                    dir_id: dest_dir_id.clone(),
                                    name: newname_str.to_string(),
                                },
                            );
                            self.inodes.update_kind(
                                dest_inode,
                                InodeKind::Symlink {
                                    dir_id: src_dir_id.clone(),
                                    name: name_str.to_string(),
                                },
                            );
                        }

                        // Invalidate attribute caches for both inodes
                        self.attr_cache.invalidate(src_inode);
                        self.attr_cache.invalidate(dest_inode);

                        // Invalidate directory caches for both parents
                        self.dir_cache.invalidate(parent);
                        if parent != newparent {
                            self.dir_cache.invalidate(newparent);
                        }

                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        error!("rename: RENAME_EXCHANGE failed: {}", e);
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::write_error_to_errno(&e));
                    }
                    Err(exec_err) => {
                        error!("rename: RENAME_EXCHANGE exec error: {:?}", exec_err);
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                    }
                }
                return;
            }

            // RENAME_NOREPLACE: fail if target exists (check file, dir, and symlink)
            if _flags & libc::RENAME_NOREPLACE != 0 {
                // Use O(1) lookups to check if target exists as file, directory, or symlink
                let ops_file = self.ops_clone();
                let dest_dir_id_file = dest_dir_id.clone();
                let newname_file = newname_str.to_string();

                let target_exists =
                    match self.exec(async move { ops_file.find_file(&dest_dir_id_file, &newname_file).await })
                    {
                        Ok(Ok(Some(_))) => true,
                        Ok(Ok(None)) => {
                            let ops_dir = self.ops_clone();
                            let dest_dir_id_dir = dest_dir_id.clone();
                            let newname_dir = newname_str.to_string();
                            match self.exec(async move {
                                ops_dir.find_directory(&dest_dir_id_dir, &newname_dir).await
                            }) {
                                Ok(Ok(Some(_))) => true,
                                Ok(Ok(None)) => {
                                    let ops_sym = self.ops_clone();
                                    let dest_dir_id_sym = dest_dir_id.clone();
                                    let newname_sym = newname_str.to_string();
                                    match self.exec(async move {
                                        ops_sym.find_symlink(&dest_dir_id_sym, &newname_sym).await
                                    }) {
                                        Ok(Ok(Some(_))) => true,
                                        Ok(Ok(None)) => false,
                                        Ok(Err(e)) => {
                                            self.vault_stats.record_error();
                                            self.vault_stats.record_metadata_latency(start.elapsed());
                                            reply.error(e.to_errno());
                                            return;
                                        }
                                        Err(exec_err) => {
                                            self.vault_stats.record_error();
                                            self.vault_stats.record_metadata_latency(start.elapsed());
                                            reply.error(exec_err.to_errno());
                                            return;
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    self.vault_stats.record_error();
                                    self.vault_stats.record_metadata_latency(start.elapsed());
                                    reply.error(e.to_errno());
                                    return;
                                }
                                Err(exec_err) => {
                                    self.vault_stats.record_error();
                                    self.vault_stats.record_metadata_latency(start.elapsed());
                                    reply.error(exec_err.to_errno());
                                    return;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(e.to_errno());
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    };

                if target_exists {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EEXIST);
                    return;
                }
            }
        }

        // Step 1: Determine source entry type (file, directory, or symlink)
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum SourceType {
            File,
            Directory,
            Symlink,
        }

        // First try cached inode lookup for entry type
        let source_type = {
            let src_path = src_parent_path.join(name_str);
            if let Some(inode) = self.inodes.get_inode(&src_path) {
                if let Some(entry) = self.inodes.get(inode) {
                    if entry.kind.is_directory() {
                        Some(SourceType::Directory)
                    } else if entry.kind.is_symlink() {
                        Some(SourceType::Symlink)
                    } else {
                        Some(SourceType::File)
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Fallback to vault ops if not in cache
        let source_type = match source_type {
            Some(t) => t,
            None => {
                // Check if it's a file
                let ops_f = self.ops_clone();
                let src_dir_f = src_dir_id.clone();
                let name_f = name_str.to_string();
                let is_file = match self.exec(async move { ops_f.find_file(&src_dir_f, &name_f).await }) {
                    Ok(Ok(Some(_))) => true,
                    Ok(Ok(None)) => false,
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(e.to_errno());
                        return;
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                };

                if is_file {
                    SourceType::File
                } else {
                    // Check if it's a directory
                    let ops_d = self.ops_clone();
                    let src_dir_d = src_dir_id.clone();
                    let name_d = name_str.to_string();
                    let is_dir = match self.exec(async move { ops_d.find_directory(&src_dir_d, &name_d).await }) {
                        Ok(Ok(Some(_))) => true,
                        Ok(Ok(None)) => false,
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(e.to_errno());
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    };

                    if is_dir {
                        SourceType::Directory
                    } else {
                        // Check if it's a symlink
                        let ops_s = self.ops_clone();
                        let src_dir_s = src_dir_id.clone();
                        let name_s = name_str.to_string();
                        let is_sym = match self.exec(async move { ops_s.find_symlink(&src_dir_s, &name_s).await }) {
                            Ok(Ok(Some(_))) => true,
                            Ok(Ok(None)) => false,
                            Ok(Err(e)) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(e.to_errno());
                                return;
                            }
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        };

                        if is_sym {
                            SourceType::Symlink
                        } else {
                            // Source doesn't exist
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(libc::ENOENT);
                            return;
                        }
                    }
                }
            }
        };

        trace!("rename: source type = {:?}", source_type);

        // Step 2: Handle overwrite semantics (POSIX rename replaces target if it exists)
        // Check if RENAME_NOREPLACE was set - if so, we already handled it above
        #[cfg(target_os = "linux")]
        let noreplace = _flags & libc::RENAME_NOREPLACE != 0;
        #[cfg(not(target_os = "linux"))]
        let noreplace = false;

        if !noreplace {
            // Check if destination exists as file
            let ops_df = self.ops_clone();
            let dest_dir_df = dest_dir_id.clone();
            let newname_df = newname_str.to_string();
            let dest_file_exists = match self.exec(async move { ops_df.find_file(&dest_dir_df, &newname_df).await }) {
                Ok(Ok(Some(_))) => true,
                Ok(Ok(None)) => false,
                Ok(Err(e)) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(e.to_errno());
                    return;
                }
                Err(exec_err) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

            // Check if destination exists as directory
            // Note: find_directory may return an error if the entry exists but is not a directory
            // (e.g., NotADirectory). These type-mismatch errors mean "not a directory", not a fatal error.
            let ops_dd = self.ops_clone();
            let dest_dir_dd = dest_dir_id.clone();
            let newname_dd = newname_str.to_string();
            let dest_dir_exists = match self.exec(async move { ops_dd.find_directory(&dest_dir_dd, &newname_dd).await }) {
                Ok(Ok(Some(_))) => true,
                Ok(Ok(None)) => false,
                Ok(Err(e)) => {
                    // Check if this is a type-mismatch error (entry exists but wrong type)
                    let errno = e.to_errno();
                    if errno == libc::ENOTDIR || errno == libc::EISDIR || errno == libc::EIO {
                        // EIO can happen when find_directory encounters a file instead of directory
                        // due to io_error_category mapping - treat as "not a directory"
                        false
                    } else {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(errno);
                        return;
                    }
                }
                Err(exec_err) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

            // Check if destination exists as symlink
            // Same logic: type-mismatch errors mean "not a symlink", not a fatal error.
            let ops_ds = self.ops_clone();
            let dest_dir_ds = dest_dir_id.clone();
            let newname_ds = newname_str.to_string();
            let dest_sym_exists = match self.exec(async move { ops_ds.find_symlink(&dest_dir_ds, &newname_ds).await }) {
                Ok(Ok(Some(_))) => true,
                Ok(Ok(None)) => false,
                Ok(Err(e)) => {
                    // Check if this is a type-mismatch error
                    let errno = e.to_errno();
                    if errno == libc::ENOTDIR || errno == libc::EISDIR || errno == libc::EIO {
                        // EIO can happen due to io_error_category mapping - treat as "not a symlink"
                        false
                    } else {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(errno);
                        return;
                    }
                }
                Err(exec_err) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

            // Handle type mismatches and overwrite
            if dest_dir_exists {
                match source_type {
                    SourceType::Directory => {
                        // dir -> dir: check if target is empty, then delete
                        let ops_del = self.ops_clone();
                        let dest_dir_del = dest_dir_id.clone();
                        let newname_del = newname_str.to_string();
                        match self.exec(async move { ops_del.delete_directory(&dest_dir_del, &newname_del).await }) {
                            Ok(Ok(())) => { /* deleted successfully */ }
                            Ok(Err(e)) => {
                                // If deletion failed (e.g., not empty), return error
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(crate::error::write_error_to_errno(&e));
                                return;
                            }
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        }
                        // Invalidate destination inode
                        let dest_path = dest_parent_path.join(newname_str);
                        if let Some(dest_inode) = self.inodes.get_inode(&dest_path) {
                            self.inodes.invalidate_path(&dest_path);
                            self.attr_cache.invalidate(dest_inode);
                        }
                    }
                    SourceType::File | SourceType::Symlink => {
                        // file/symlink -> dir: EISDIR
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::EISDIR);
                        return;
                    }
                }
            } else if dest_file_exists {
                match source_type {
                    SourceType::File | SourceType::Symlink => {
                        // file/symlink -> file: delete target file
                        let ops_del = self.ops_clone();
                        let dest_dir_del = dest_dir_id.clone();
                        let newname_del = newname_str.to_string();
                        match self.exec(async move { ops_del.delete_file(&dest_dir_del, &newname_del).await }) {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(crate::error::write_error_to_errno(&e));
                                return;
                            }
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        }
                        // Invalidate destination inode
                        let dest_path = dest_parent_path.join(newname_str);
                        if let Some(dest_inode) = self.inodes.get_inode(&dest_path) {
                            self.inodes.invalidate_path(&dest_path);
                            self.attr_cache.invalidate(dest_inode);
                        }
                    }
                    SourceType::Directory => {
                        // dir -> file: ENOTDIR
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOTDIR);
                        return;
                    }
                }
            } else if dest_sym_exists {
                // Destination is a symlink - delete it (symlinks can be overwritten by any type)
                let ops_del = self.ops_clone();
                let dest_dir_del = dest_dir_id.clone();
                let newname_del = newname_str.to_string();
                match self.exec(async move { ops_del.delete_symlink(&dest_dir_del, &newname_del).await }) {
                    Ok(Ok(())) => { /* deleted successfully */ }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::write_error_to_errno(&e));
                        return;
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                }
                // Invalidate destination inode
                let dest_path = dest_parent_path.join(newname_str);
                if let Some(dest_inode) = self.inodes.get_inode(&dest_path) {
                    self.inodes.invalidate_path(&dest_path);
                    self.attr_cache.invalidate(dest_inode);
                }
            }
        }

        // Step 3: Perform the rename based on source type
        let name_owned = name_str.to_string();
        let newname_owned = newname_str.to_string();

        let result = match source_type {
            SourceType::File => {
                // Use the appropriate file rename operation
                if parent == newparent {
                    let ops = self.ops_clone();
                    let dir = src_dir_id.clone();
                    self.exec(async move { ops.rename_file(&dir, &name_owned, &newname_owned).await })
                } else if name_str == newname_str {
                    let ops = self.ops_clone();
                    let src = src_dir_id.clone();
                    let dest = dest_dir_id.clone();
                    self.exec(async move { ops.move_file(&src, &name_owned, &dest).await })
                } else {
                    let ops = self.ops_clone();
                    let src = src_dir_id.clone();
                    let dest = dest_dir_id.clone();
                    self.exec(async move { ops.move_and_rename_file(&src, &name_owned, &dest, &newname_owned).await })
                }
            }
            SourceType::Directory => {
                // Use directory rename operations
                let ops = self.ops_clone();
                let src = src_dir_id.clone();
                let dest = dest_dir_id.clone();
                self.exec(async move { ops.move_and_rename_directory(&src, &name_owned, &dest, &newname_owned).await })
            }
            SourceType::Symlink => {
                // Use symlink rename operations
                let ops = self.ops_clone();
                let src = src_dir_id.clone();
                let dest = dest_dir_id.clone();
                self.exec(async move { ops.move_and_rename_symlink(&src, &name_owned, &dest, &newname_owned).await })
            }
        };

        match result {
            Ok(Ok(())) => {
                // Update inode mapping
                let old_path = src_parent_path.join(name_str);
                let new_path = dest_parent_path.join(newname_str);

                if let Some(inode) = self.inodes.get_inode(&old_path) {
                    self.inodes.update_path(inode, &old_path, new_path);

                    // Also update the InodeKind with the new name and parent dir_id
                    // This is critical: InodeKind::File/Symlink stores the name used for vault lookups
                    let new_kind = match source_type {
                        SourceType::File => InodeKind::File {
                            dir_id: dest_dir_id.clone(),
                            name: newname_str.to_string(),
                        },
                        SourceType::Directory => {
                            // For directories, we need to preserve the original dir_id
                            // (the directory's own ID doesn't change on rename)
                            if let Some(entry) = self.inodes.get(inode) {
                                if let Some(original_dir_id) = entry.dir_id() {
                                    InodeKind::Directory {
                                        dir_id: original_dir_id,
                                    }
                                } else {
                                    // Shouldn't happen - directory should have dir_id
                                    InodeKind::Directory {
                                        dir_id: DirId::root(),
                                    }
                                }
                            } else {
                                InodeKind::Directory {
                                    dir_id: DirId::root(),
                                }
                            }
                        }
                        SourceType::Symlink => InodeKind::Symlink {
                            dir_id: dest_dir_id.clone(),
                            name: newname_str.to_string(),
                        },
                    };
                    self.inodes.update_kind(inode, new_kind);

                    self.attr_cache.invalidate(inode);
                }

                // Invalidate caches
                self.dir_cache.invalidate(parent);
                if parent != newparent {
                    self.dir_cache.invalidate(newparent);
                }

                // Invalidate negative cache for the new name (it now exists)
                self.attr_cache.remove_negative(newparent, newname_str);

                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.ok();
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(exec_err.to_errno());
            }
        }
    }

    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        trace!(
            inode = ino,
            fh = fh,
            offset = offset,
            length = length,
            mode = mode,
            "fallocate"
        );

        // Only support mode=0 (allocate space / extend file)
        // FALLOC_FL_PUNCH_HOLE and other modes are not supported
        // because Cryptomator doesn't support sparse files.
        if mode != 0 {
            reply.error(libc::ENOTSUP);
            return;
        }

        // Get inode info
        let Some(entry) = self.inodes.get(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            InodeKind::Directory { .. } | InodeKind::Root => {
                reply.error(libc::EISDIR);
                return;
            }
            InodeKind::Symlink { .. } => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        drop(entry);

        // FUSE guarantees offset and length are non-negative (they're from kernel fallocate requests)
        #[allow(clippy::cast_sign_loss)]
        let new_size = (offset + length) as u64;

        // If we have an open file handle, extend the buffer
        if let Some(mut handle) = self.handle_table.get_mut(&fh)
            && let Some(buffer) = handle.as_write_buffer_mut() {
                // Only extend, don't shrink
                if new_size > buffer.len() {
                    buffer.truncate(new_size);
                    // Track buffer size for mmap consistency
                    self.update_buffer_size(ino, new_size);
                }
                drop(handle);

                self.attr_cache.invalidate(ino);
                reply.ok();
                return;
            }

        // No open handle - read file, extend if needed, write back
        let ops = self.ops_clone();
        let dir_id_read = dir_id.clone();
        let name_read = name.clone();

        // Read existing content
        let mut content =
            match self.exec(async move { ops.read_file(&dir_id_read, &name_read).await }) {
                Ok(Ok(file)) => file.content,
                Ok(Err(_)) | Err(_) => Vec::new(),
            };

        // Extend if needed (don't shrink)
        // On 32-bit: file sizes beyond 4GB would fail earlier in allocation
        #[allow(clippy::cast_possible_truncation)]
        if new_size as usize > content.len() {
            #[allow(clippy::cast_possible_truncation)]
            content.resize(new_size as usize, 0);

            // Write back
            let ops = self.ops_clone();
            let dir_id_write = dir_id.clone();
            let name_write = name.clone();

            match self.exec(async move {
                ops.write_file(&dir_id_write, &name_write, &content).await
            }) {
                Ok(Ok(_)) => {
                    self.attr_cache.invalidate(ino);
                    reply.ok();
                }
                Ok(Err(e)) => {
                    reply.error(crate::error::write_error_to_errno(&e));
                }
                Err(exec_err) => {
                    reply.error(exec_err.to_errno());
                }
            }
        } else {
            // File is already large enough
            reply.ok();
        }
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        trace!(
            ino_in = ino_in,
            ino_out = ino_out,
            offset_in = offset_in,
            offset_out = offset_out,
            len = len,
            "copy_file_range"
        );

        // Get source handle
        let Some(mut handle_in) = self.handle_table.get_mut(&fh_in) else {
            reply.error(libc::EBADF);
            return;
        };

        match &mut *handle_in {
            FuseHandle::Reader(_) => {
                // Async copy path: loan reader to scheduler, return immediately
                // Take the reader by replacing with ReaderLoaned placeholder
                let old_handle = std::mem::replace(&mut *handle_in, FuseHandle::ReaderLoaned);
                let reader = match old_handle {
                    FuseHandle::Reader(r) => r,
                    _ => unreachable!("just matched Reader variant"),
                };

                // Drop the handle lock before enqueuing to avoid deadlock
                drop(handle_in);

                // Enqueue to scheduler - it will read, write to dest, and reply
                let scheduler = self
                    .scheduler
                    .as_ref()
                    .expect("scheduler not initialized");

                // FUSE guarantees offsets are non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset_in_u64 = offset_in as u64;
                #[allow(clippy::cast_sign_loss)]
                let offset_out_u64 = offset_out as u64;
                #[allow(clippy::cast_possible_truncation)]
                let len_usize = len as usize;

                match scheduler.try_enqueue_copy_range(
                    fh_in,
                    reader,
                    offset_in_u64,
                    fh_out,
                    ino_out,
                    offset_out_u64,
                    len_usize,
                    reply,
                ) {
                    Ok(request_id) => {
                        trace!(
                            ?request_id,
                            fh_in,
                            fh_out,
                            offset_in_u64,
                            offset_out_u64,
                            len_usize,
                            "copy_file_range enqueued to scheduler"
                        );
                        // Return immediately - scheduler will reply asynchronously
                    }
                    Err(e) => {
                        // Enqueue failed - scheduler already replied with error.
                        // The reader is consumed, handle remains in ReaderLoaned state.
                        warn!(
                            error = %e,
                            fh_in,
                            fh_out,
                            "Failed to enqueue copy_file_range (scheduler replied with error)"
                        );
                    }
                }
                return;
            }
            FuseHandle::ReaderLoaned => {
                // Reader is busy with async operation - return EAGAIN
                trace!(fh_in, "copy_file_range while reader is loaned, returning EAGAIN");
                reply.error(libc::EAGAIN);
                return;
            }
            FuseHandle::ReadBuffer(content) => {
                // Synchronous path for in-memory buffers (fast)
                // FUSE guarantees offset_in is non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset = offset_in as usize;
                #[allow(clippy::cast_possible_truncation)]
                let end = std::cmp::min(offset + len as usize, content.len());
                let data = if offset < content.len() {
                    content[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                drop(handle_in);
                self.copy_file_range_write_dest(ino_out, fh_out, offset_out, &data, reply);
                return;
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Synchronous path for in-memory buffers (fast)
                // FUSE guarantees offset_in is non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let data = buffer.read(offset_in as u64, len as usize).to_vec();
                drop(handle_in);
                self.copy_file_range_write_dest(ino_out, fh_out, offset_out, &data, reply);
            }
        }
    }

    fn lseek(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        trace!(inode = ino, fh = fh, offset = offset, whence = whence, "lseek");

        // Get file size for SEEK_END calculations
        let file_size = {
            let Some(entry) = self.inodes.get(ino) else {
                reply.error(libc::ENOENT);
                return;
            };

            match &entry.kind {
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    // Check if we have an open buffer with the size
                    if let Some(mut handle) = self.handle_table.get_mut(&fh) {
                        if let Some(buffer) = handle.as_write_buffer_mut() {
                            buffer.len()
                        } else if let Some(reader) = handle.as_reader_mut() {
                            // Get size from reader
                            reader.plaintext_size()
                        } else {
                            0
                        }
                    } else {
                        // Fall back to O(1) find_file lookup
                        let ops = self.ops_clone();

                        match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                            Ok(Ok(Some(file_info))) => {
                                encrypted_to_plaintext_size_or_zero(file_info.encrypted_size)
                            }
                            Ok(Ok(None)) => 0,
                            Ok(Err(e)) => {
                                reply.error(crate::error::vault_error_to_errno(&e));
                                return;
                            }
                            Err(exec_err) => {
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        }
                    }
                }
                _ => {
                    reply.error(libc::EINVAL);
                    return;
                }
            }
        };

        // SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2, SEEK_DATA = 3, SEEK_HOLE = 4
        match whence {
            libc::SEEK_SET => {
                reply.offset(offset);
            }
            libc::SEEK_CUR => {
                // We don't track current position in FUSE - return offset as-is
                // (the kernel tracks the actual file position)
                reply.offset(offset);
            }
            libc::SEEK_END => {
                // File sizes in practice fit in i64; wrapping is extremely unlikely
                #[allow(clippy::cast_possible_wrap)]
                let new_offset = (file_size as i64) + offset;
                if new_offset < 0 {
                    reply.error(libc::EINVAL);
                } else {
                    reply.offset(new_offset);
                }
            }
            libc::SEEK_DATA => {
                // Cryptomator doesn't support sparse files - entire file is data
                // FUSE guarantees offset is non-negative
                #[allow(clippy::cast_sign_loss)]
                if offset as u64 >= file_size {
                    reply.error(libc::ENXIO);
                } else {
                    reply.offset(offset);
                }
            }
            libc::SEEK_HOLE => {
                // Cryptomator doesn't support sparse files - hole is at EOF
                // FUSE guarantees offset is non-negative
                #[allow(clippy::cast_sign_loss)]
                if offset as u64 >= file_size {
                    reply.error(libc::ENXIO);
                } else {
                    // File sizes in practice fit in i64; wrapping is extremely unlikely
                    #[allow(clippy::cast_possible_wrap)]
                    reply.offset(file_size as i64);
                }
            }
            _ => {
                reply.error(libc::EINVAL);
            }
        }
    }

    // ==================== Extended Attributes ====================
    //
    // Cryptomator vaults do not store extended attributes.
    // Return ENOTSUP for all xattr operations.

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &OsStr,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        // Extended attributes are not supported for Cryptomator vaults
        // Note: ENOTSUP (not ENODATA) indicates xattrs aren't supported at all,
        // rather than the specific attribute not existing.
        reply.error(libc::ENOTSUP);
    }

    fn setxattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(libc::ENOTSUP);
    }

    fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(libc::ENOTSUP);
    }

    fn removexattr(&mut self, _req: &Request<'_>, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(libc::ENOTSUP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notifier_cell_initially_empty() {
        // Create a test vault path (doesn't need to exist for this test)
        let _vault_path = Path::new("/tmp/test_vault");

        // We can't actually create a CryptomatorFS without a real vault,
        // but we can test that OnceLock starts empty
        let notifier: OnceLock<fuser::Notifier> = OnceLock::new();
        assert!(notifier.get().is_none());
    }

    #[test]
    fn test_block_size_constant() {
        assert_eq!(BLOCK_SIZE, 4096);
    }

    #[test]
    fn test_default_permissions() {
        assert_eq!(DEFAULT_FILE_PERM, 0o644);
        assert_eq!(DEFAULT_DIR_PERM, 0o755);
    }
}
