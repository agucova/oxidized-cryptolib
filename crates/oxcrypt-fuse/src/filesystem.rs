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
use crate::error::{FuseError, FuseResult};
use crate::handles::{FuseHandle, FuseHandleTable, WriteBuffer};
use crate::inode::{InodeKind, InodeTable};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen, ReplyWrite, Request,
};
use libc::c_int;
use oxcrypt_core::fs::encrypted_to_plaintext_size_or_zero;
use oxcrypt_core::vault::{DirId, VaultOperationsAsync};
use oxcrypt_mount::VaultStats;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, error, info, trace};

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
    /// Async vault operations (shared via Arc for thread safety).
    ops: Arc<VaultOperationsAsync>,
    /// Inode table for path/inode mapping.
    inodes: InodeTable,
    /// Attribute cache for file metadata.
    attr_cache: AttrCache,
    /// Directory listing cache.
    dir_cache: DirCache,
    /// File handle table for open files.
    handle_table: FuseHandleTable,
    /// Owned tokio runtime (when we create our own).
    /// Must be kept alive for the handle to remain valid.
    _owned_runtime: Option<Runtime>,
    /// Handle to tokio runtime for async operations.
    /// Points to either our owned runtime or an external one.
    handle: Handle,
    /// Async executor with dedicated thread pool for I/O operations.
    /// This prevents slow cloud storage from blocking the FUSE thread.
    executor: crate::executor::AsyncExecutor,
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
    /// Mount configuration (TTLs, concurrency, etc.).
    config: MountConfig,
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
        let runtime = Runtime::new().map_err(|e| {
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

        let stats = Arc::new(VaultStats::new());

        // Create attribute cache with configured TTLs
        let mut attr_cache = AttrCache::new(config.attr_ttl, config.negative_ttl);
        attr_cache.set_stats(stats.cache_stats());

        // Create async executor with dedicated thread pool
        // This prevents slow cloud storage from blocking the FUSE thread
        let executor = crate::executor::AsyncExecutor::new(
            handle.clone(),
            config.io_workers,
            config.io_timeout,
            config.saturation_policy,
        );

        info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
            attr_ttl_secs = config.attr_ttl.as_secs(),
            negative_ttl_ms = config.negative_ttl.as_millis(),
            io_timeout_secs = config.io_timeout.as_secs(),
            io_workers = config.io_workers,
            saturation_policy = ?config.saturation_policy,
            "CryptomatorFS initialized"
        );

        Ok(Self {
            ops,
            inodes: InodeTable::new(),
            attr_cache,
            dir_cache: DirCache::default(),
            handle_table: FuseHandleTable::new_auto_id(),
            _owned_runtime: owned_runtime,
            handle,
            executor,
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
            stats,
            config,
        })
    }

    /// Returns a clone of the stats Arc for external access.
    ///
    /// This allows the mount handle to expose stats to the GUI.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
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

    /// Executes an async operation using the dedicated I/O thread pool.
    ///
    /// This prevents slow cloud storage from blocking the FUSE thread.
    /// Operations that exceed the configured timeout will return ETIMEDOUT.
    fn exec<F, T>(&self, future: F) -> Result<T, crate::executor::ExecutorError>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.executor.execute(future)
    }

    /// Executes an async operation that returns a Result, flattening executor errors.
    ///
    /// This is a convenience wrapper for operations that already return Result.
    fn exec_result<F, T, E>(&self, future: F) -> Result<T, i32>
    where
        F: std::future::Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: crate::error::ToErrno + Send + 'static,
    {
        match self.executor.execute(future) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => Err(e.to_errno()),
            Err(exec_err) => Err(exec_err.to_errno()),
        }
    }

    /// Flush a write buffer to the vault without closing the handle.
    ///
    /// This is used by both `flush()` and `fsync()` FUSE operations.
    /// Returns Ok(()) if the handle is a reader or if the write succeeds.
    fn flush_handle(&self, ino: u64, fh: u64) -> Result<(), c_int> {
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

                // Write to vault using direct block_on (no timeout).
                // Data operations should not timeout - a slow write is better than data loss.
                let write_result = self.handle.block_on(async move {
                    ops.write_file(&dir_id, &filename, &content).await
                        .map(|_| content) // Return content back on success
                });

                // Handle the result
                match write_result {
                    Ok(returned_content) => {
                        // Success - restore the (now clean) content
                        if let Some(mut handle) = self.handle_table.get_mut(&fh)
                            && let Some(buffer) = handle.as_write_buffer_mut() {
                                buffer.restore_content(returned_content);
                            }
                        self.attr_cache.invalidate(ino);
                    }
                    Err(write_err) => {
                        // Write error - can't restore content (was consumed)
                        return Err(crate::error::write_error_to_errno(&write_err));
                    }
                }
            }
        // Readers don't need flushing
        Ok(())
    }

    /// Creates a FileAttr for a directory.
    fn make_dir_attr(&self, inode: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: inode,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
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
    fn make_file_attr(&self, inode: u64, size: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: inode,
            size,
            blocks: size.div_ceil(BLOCK_SIZE as u64),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
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

    /// Creates a FileAttr for a symlink.
    fn make_symlink_attr(&self, inode: u64, target_len: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: inode,
            size: target_len,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
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

    /// Looks up a child entry in a directory using O(1) path lookups.
    ///
    /// Uses `find_file`, `find_directory`, and `find_symlink` which calculate
    /// the expected encrypted path directly instead of listing all entries.
    /// All three lookups run in parallel to minimize latency on network filesystems.
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
        if let Some(existing_inode) = self.inodes.get_inode(&child_path) {
            if let Some(entry) = self.inodes.get(existing_inode) {
                let (attr, file_type) = match &entry.kind {
                    InodeKind::File { .. } => {
                        // Check attr cache first, otherwise use size 0 (file may be in WriteBuffer)
                        let attr = self.attr_cache.get(existing_inode)
                            .map(|cached| cached.value)
                            .unwrap_or_else(|| self.make_file_attr(existing_inode, 0));
                        (attr, FileType::RegularFile)
                    }
                    InodeKind::Directory { .. } => {
                        let attr = self.attr_cache.get(existing_inode)
                            .map(|cached| cached.value)
                            .unwrap_or_else(|| self.make_dir_attr(existing_inode));
                        (attr, FileType::Directory)
                    }
                    InodeKind::Symlink { .. } => {
                        // Use size 0 for symlink if not cached (rare case)
                        let attr = self.attr_cache.get(existing_inode)
                            .map(|cached| cached.value)
                            .unwrap_or_else(|| self.make_symlink_attr(existing_inode, 0));
                        (attr, FileType::Symlink)
                    }
                    InodeKind::Root => {
                        let attr = self.make_dir_attr(existing_inode);
                        (attr, FileType::Directory)
                    }
                };
                return Ok((existing_inode, attr, file_type));
            }
        }

        // Clone ops for async use
        let ops = self.ops_clone();
        let name_owned = name.to_string();

        // Run all three lookups in parallel - critical for high-latency backends like Google Drive
        // This reduces 3 sequential network round-trips to 1 parallel operation
        // Uses executor to prevent slow cloud storage from blocking FUSE thread
        let dir_id_for_lookup = dir_id.clone();
        let (file_result, dir_result, symlink_result) = self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_for_lookup, &name_owned),
                ops.find_directory(&dir_id_for_lookup, &name_owned),
                ops.find_symlink(&dir_id_for_lookup, &name_owned)
            )
        }).map_err(FuseError::Executor)?;

        // Check file result first (most common case)
        if let Ok(Some(file_info)) = file_result {
            let inode = self.inodes.get_or_insert(
                child_path,
                InodeKind::File {
                    dir_id,
                    name: name.to_string(),
                },
            );
            let attr = self.make_file_attr(inode, encrypted_to_plaintext_size_or_zero(file_info.encrypted_size));
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::RegularFile));
        }

        // Check directory result
        if let Ok(Some(dir_info)) = dir_result {
            let correct_kind = InodeKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let inode = self.inodes.get_or_insert(child_path, correct_kind.clone());
            // Always update the kind to ensure correct DirId (may have been placeholder)
            self.inodes.update_kind(inode, correct_kind);
            let attr = self.make_dir_attr(inode);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Directory));
        }

        // Check symlink result
        if let Ok(Some(symlink_info)) = symlink_result {
            let inode = self.inodes.get_or_insert(
                child_path,
                InodeKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let attr = self.make_symlink_attr(inode, symlink_info.target.len() as u64);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Symlink));
        }

        // Propagate any errors from the lookups
        file_result?;
        dir_result?;
        symlink_result?;

        // Not found
        Err(FuseError::PathResolution(format!("'{}' not found", name)))
    }

    /// Lists all entries in a directory.
    ///
    /// Uses `list_all` to fetch files, directories, and symlinks in a single
    /// operation with parallel I/O, replacing 3 sequential blocking calls.
    /// Uses the executor to prevent slow cloud storage from blocking the FUSE thread.
    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        let ops = self.ops_clone();
        let dir_id = dir_id.clone();

        // Execute with timeout to prevent slow cloud storage from blocking FUSE
        let (files, dirs, symlinks) = self.exec(async move {
            ops.list_all(&dir_id).await
        }).map_err(FuseError::Executor)??;

        // Build entries using iterator chain instead of three separate loops
        let entries: Vec<DirListingEntry> = dirs
            .into_iter()
            .map(|d| DirListingEntry {
                inode: 0, // Will be resolved on lookup
                file_type: FileType::Directory,
                name: d.name,
            })
            .chain(files.into_iter().map(|f| DirListingEntry {
                inode: 0,
                file_type: FileType::RegularFile,
                name: f.name,
            }))
            .chain(symlinks.into_iter().map(|s| DirListingEntry {
                inode: 0,
                file_type: FileType::Symlink,
                name: s.name,
            }))
            .collect();

        Ok(entries)
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
        // Enable async reads for better performance with concurrent readers
        config.add_capabilities(fuser::consts::FUSE_ASYNC_READ).ok();
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
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "lookup");

        // Check negative cache
        if self.attr_cache.is_negative(parent, name_str) {
            self.stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOENT);
            return;
        }

        match self.lookup_child(parent, name_str) {
            Ok((_inode, attr, _file_type)) => {
                // nlookup is incremented in lookup_child via get_or_insert (correct per spec)
                self.stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                // Add to negative cache
                self.attr_cache.insert_negative(parent, name_str.to_string());
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(e.to_errno());
            }
        }
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
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(inode = ino, "getattr");

        // Check cache first
        if let Some(cached) = self.attr_cache.get(ino) {
            self.stats.record_metadata_latency(start.elapsed());
            reply.attr(&cached.time_remaining(), &cached.value);
            return;
        }

        // Get inode entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let attr = match &entry.kind {
            InodeKind::Root => self.make_dir_attr(ino),
            InodeKind::Directory { .. } => self.make_dir_attr(ino),
            InodeKind::File { dir_id, name } => {
                // Get file size from vault using O(1) lookup instead of O(n) list+search
                let ops = self.ops_clone();
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                    Ok(Ok(Some(info))) => self.make_file_attr(ino, encrypted_to_plaintext_size_or_zero(info.encrypted_size)),
                    Ok(Ok(None)) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Ok(Err(e)) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                    Err(exec_err) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Get symlink target length
                let ops = self.ops_clone();
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.exec(async move { ops.read_symlink(&dir_id, &name).await }) {
                    Ok(Ok(target)) => self.make_symlink_attr(ino, target.len() as u64),
                    Ok(Err(e)) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                    Err(exec_err) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(exec_err.to_errno());
                        return;
                    }
                }
            }
        };

        self.attr_cache.insert(ino, attr);
        self.stats.record_metadata_latency(start.elapsed());
        reply.attr(&DEFAULT_ATTR_TTL, &attr);
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        trace!(inode = ino, "readlink");

        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
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

        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
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
                    Ok(Err(_)) => Vec::new(), // File doesn't exist, start empty
                    Err(_) => Vec::new(), // Timeout or error, start empty
                }
            };

            let buffer = WriteBuffer::new(dir_id, name, existing_content);
            let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));
            self.stats.record_file_open();
            reply.opened(fh, 0);
        } else {
            // Open for reading - open_file returns VaultFileReader (with timeout)
            match self.exec(async move { ops.open_file(&dir_id, &name).await }) {
                Ok(Ok(reader)) => {
                    // Store reader in handle table and return the handle ID
                    let fh = self.handle_table.insert_auto(FuseHandle::Reader(Box::new(reader)));
                    self.stats.record_file_open();
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
        let mut handle = match self.handle_table.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        match &mut *handle {
            FuseHandle::Reader(reader) => {
                // Read from streaming reader
                self.stats.start_read();
                let start = Instant::now();
                match self
                    .handle
                    .block_on(reader.read_range(offset as u64, size as usize))
                {
                    Ok(data) => {
                        let elapsed = start.elapsed();
                        let bytes_read = data.len() as u64;
                        self.stats.finish_read();
                        self.stats.record_read(bytes_read);
                        self.stats.record_read_latency(elapsed);
                        self.stats.record_decrypted(bytes_read);
                        reply.data(&data);
                    }
                    Err(e) => {
                        self.stats.finish_read();
                        self.stats.record_read_latency(start.elapsed());
                        error!(error = %e, "Read failed");
                        reply.error(libc::EIO);
                    }
                }
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Read from write buffer (for read-after-write in same handle)
                let data = buffer.read(offset as u64, size as usize);
                self.stats.record_read(data.len() as u64);
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
        let handle = match self.handle_table.remove(&fh) {
            Some(h) => h,
            None => {
                // Handle already released or never existed
                reply.ok();
                return;
            }
        };

        match handle {
            FuseHandle::Reader(_) => {
                // Reader just needs to be dropped
                self.stats.record_file_close();
                debug!(fh = fh, "Reader released");
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

                    // Use direct block_on (no timeout) for data operations.
                    // A slow write is better than data loss.
                    self.stats.start_write();
                    let start = Instant::now();
                    match self.handle.block_on(async move {
                        ops.write_file(&dir_id, &filename, &content).await
                    }) {
                        Ok(_) => {
                            let elapsed = start.elapsed();
                            self.stats.finish_write();
                            self.stats.record_write(content_len as u64);
                            self.stats.record_write_latency(elapsed);
                            self.stats.record_encrypted(content_len as u64);
                            debug!(fh = fh, filename = %filename_for_log, size = content_len, "WriteBuffer flushed");
                            // Invalidate attr cache since file changed
                            self.attr_cache.invalidate(ino);
                            self.stats.record_file_close();
                        }
                        Err(e) => {
                            self.stats.finish_write();
                            self.stats.record_write_latency(start.elapsed());
                            error!(error = %e, "Failed to write buffer back to vault");
                            self.stats.record_file_close();
                            reply.error(crate::error::write_error_to_errno(&e));
                            return;
                        }
                    }
                } else {
                    self.stats.record_file_close();
                    debug!(fh = fh, "WriteBuffer released (not dirty)");
                }
            }
        }

        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        trace!(inode = ino, "opendir");

        // Verify it's a directory
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => {
                self.stats.record_dir_open();
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
        self.stats.record_metadata_op();
        trace!(inode = ino, offset = offset, "readdir");

        // Get directory entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
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
            cached
        } else {
            // List directory contents
            match self.list_directory(&dir_id) {
                Ok(entries) => {
                    self.dir_cache.insert(ino, entries.clone());
                    entries
                }
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
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
                name: ".".to_string(),
            },
            DirListingEntry {
                inode: parent_inode,
                file_type: FileType::Directory,
                name: "..".to_string(),
            },
        ];
        all_entries.extend(entries);

        // Skip to offset and return entries
        for (i, entry) in all_entries.iter().enumerate().skip(offset as usize) {
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
                        dir_id: DirId::from_raw(""), // Placeholder, will be resolved on lookup
                    },
                    FileType::RegularFile => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: entry.name.clone(),
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
                self.inodes.get_or_insert_no_lookup_inc(child_path, kind)
            };

            // buffer.add returns true if buffer is full
            if reply.add(
                entry_inode,
                (i + 1) as i64,
                entry.file_type,
                &entry.name,
            ) {
                break;
            }
        }

        self.stats.record_metadata_latency(start.elapsed());
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
        self.stats.record_metadata_op();
        trace!(inode = ino, offset = offset, "readdirplus");

        // Get directory entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
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
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    reply.error(crate::error::vault_error_to_errno(&e));
                    return;
                }
                Err(exec_err) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    error!(error = %exec_err, "list_all timed out in readdirplus");
                    reply.error(exec_err.to_errno());
                    return;
                }
            };

        // Build entries with sizes using iterator chain instead of three separate loops
        let all_entries: Vec<(String, FileType, u64, Option<DirId>)> = [
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

        // Skip to offset and return entries with attributes
        for (i, (name, file_type, size, maybe_subdir_id)) in
            all_entries.iter().enumerate().skip(offset as usize)
        {
            // Allocate inode for entry if needed
            let (entry_inode, attr) = if name == "." {
                (ino, self.make_dir_attr(ino))
            } else if name == ".." {
                (parent_inode, self.make_dir_attr(parent_inode))
            } else {
                // Allocate a real inode for the entry
                let child_path = current_path.join(name);
                let kind = match file_type {
                    FileType::Directory => InodeKind::Directory {
                        dir_id: maybe_subdir_id.clone().unwrap_or_else(|| DirId::from_raw("")),
                    },
                    FileType::RegularFile => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: name.clone(),
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
                let entry_inode = self.inodes.get_or_insert(child_path, kind);

                let attr = match file_type {
                    FileType::Directory => self.make_dir_attr(entry_inode),
                    FileType::RegularFile => self.make_file_attr(entry_inode, *size),
                    FileType::Symlink => self.make_symlink_attr(entry_inode, *size),
                    _ => self.make_file_attr(entry_inode, *size),
                };

                // Cache the attribute
                self.attr_cache.insert(entry_inode, attr);

                (entry_inode, attr)
            };

            // buffer.add returns true if buffer is full
            if reply.add(entry_inode, (i + 1) as i64, name, &DEFAULT_ATTR_TTL, &attr, 0) {
                break;
            }
        }

        self.stats.record_metadata_latency(start.elapsed());
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        self.stats.record_dir_close();
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

        match self.flush_handle(ino, fh) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        trace!(inode = ino, fh = fh, "fsync");

        // For our implementation, fsync and flush are identical since we write
        // the entire file atomically. The datasync flag (sync data vs metadata)
        // doesn't matter because Cryptomator doesn't store metadata separately.
        match self.flush_handle(ino, fh) {
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
    /// - chmod/chown returns ENOTSUP (Cryptomator doesn't store Unix permissions)
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
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(
            inode = ino,
            mode = ?mode,
            uid = ?uid,
            gid = ?gid,
            size = ?size,
            "setattr"
        );

        // Cryptomator doesn't store Unix permissions or timestamps.
        // We support truncate (size change) and silently ignore atime/mtime for compatibility.
        // chmod/chown return ENOTSUP.

        if mode.is_some() || uid.is_some() || gid.is_some() {
            // chmod/chown not supported - Cryptomator doesn't store permissions
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            reply.error(libc::ENOTSUP);
            return;
        }

        // Get current inode info
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Handle size change (truncate)
        if let Some(new_size) = size {
            match &entry.kind {
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    // If we have an open file handle, truncate the buffer
                    if let Some(fh) = fh
                        && let Some(mut handle) = self.handle_table.get_mut(&fh)
                            && let Some(buffer) = handle.as_write_buffer_mut() {
                                buffer.truncate(new_size);
                                drop(handle);

                                let attr = self.make_file_attr(ino, new_size);
                                self.attr_cache.insert(ino, attr);
                                self.stats.record_metadata_latency(start.elapsed());
                                reply.attr(&DEFAULT_ATTR_TTL, &attr);
                                return;
                            }

                    // No open handle - read file, truncate, write back
                    let ops = self.ops_clone();
                    let dir_id_read = dir_id.clone();
                    let name_read = name.clone();

                    // Read existing content (or empty if file doesn't exist)
                    let mut content =
                        match self.exec(async move { ops.read_file(&dir_id_read, &name_read).await })
                        {
                            Ok(Ok(file)) => file.content,
                            Ok(Err(_)) => Vec::new(),
                            Err(_) => Vec::new(),
                        };

                    // Truncate or extend
                    content.resize(new_size as usize, 0);

                    // Write back
                    let ops = self.ops_clone();
                    let dir_id_write = dir_id.clone();
                    let name_write = name.clone();

                    match self.exec(async move {
                        ops.write_file(&dir_id_write, &name_write, &content).await
                    }) {
                        Ok(Ok(_)) => {
                            let attr = self.make_file_attr(ino, new_size);
                            self.attr_cache.insert(ino, attr);
                            self.stats.record_metadata_latency(start.elapsed());
                            reply.attr(&DEFAULT_ATTR_TTL, &attr);
                        }
                        Ok(Err(e)) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            reply.error(crate::error::write_error_to_errno(&e));
                        }
                        Err(exec_err) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                        }
                    }
                    return;
                }
                InodeKind::Directory { .. } | InodeKind::Root => {
                    // Can't truncate directories
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EISDIR);
                    return;
                }
                InodeKind::Symlink { .. } => {
                    // Can't truncate symlinks
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EINVAL);
                    return;
                }
            }
        }

        // Handle atime/mtime changes - silently succeed for compatibility
        // (touch, tar, rsync use these)
        if atime.is_some() || mtime.is_some() {
            // Get current attributes and return them unchanged
            // (Cryptomator doesn't store timestamps)
            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => self.make_dir_attr(ino),
                InodeKind::File { dir_id, name } => {
                    // First check attr cache - avoids I/O
                    if let Some(cached) = self.attr_cache.get(ino) {
                        drop(entry);
                        cached.value
                    } else {
                        let dir_id = dir_id.clone();
                        let name = name.clone();
                        drop(entry);

                        let ops = self.ops_clone();

                        // Cache miss - use O(1) find_file lookup
                        match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                            Ok(Ok(Some(file_info))) => {
                                let file_size =
                                    encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
                                self.make_file_attr(ino, file_size)
                            }
                            Ok(Ok(None)) => {
                                // File not found - use size 0
                                self.make_file_attr(ino, 0)
                            }
                            Ok(Err(e)) => {
                                self.stats.record_error();
                                self.stats.record_metadata_latency(start.elapsed());
                                reply.error(crate::error::vault_error_to_errno(&e));
                                return;
                            }
                            Err(exec_err) => {
                                self.stats.record_error();
                                self.stats.record_metadata_latency(start.elapsed());
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        }
                    }
                }
                InodeKind::Symlink { dir_id, name } => {
                    // First check attr cache - avoids read_symlink I/O
                    if let Some(cached) = self.attr_cache.get(ino) {
                        drop(entry);
                        cached.value
                    } else {
                        let dir_id = dir_id.clone();
                        let name = name.clone();
                        drop(entry);

                        let ops = self.ops_clone();

                        // Cache miss - fall back to read_symlink
                        match self.exec(async move { ops.read_symlink(&dir_id, &name).await }) {
                            Ok(Ok(target)) => self.make_symlink_attr(ino, target.len() as u64),
                            Ok(Err(e)) => {
                                self.stats.record_error();
                                self.stats.record_metadata_latency(start.elapsed());
                                reply.error(crate::error::vault_error_to_errno(&e));
                                return;
                            }
                            Err(exec_err) => {
                                self.stats.record_error();
                                self.stats.record_metadata_latency(start.elapsed());
                                reply.error(exec_err.to_errno());
                                return;
                            }
                        }
                    }
                }
            };

            self.attr_cache.insert(ino, attr);
            self.stats.record_metadata_latency(start.elapsed());
            reply.attr(&DEFAULT_ATTR_TTL, &attr);
            return;
        }

        // No changes requested - return current attributes
        if let Some(cached) = self.attr_cache.get(ino) {
            self.stats.record_metadata_latency(start.elapsed());
            reply.attr(&cached.time_remaining(), &cached.value);
        } else {
            // Fall back to getattr behavior
            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => self.make_dir_attr(ino),
                InodeKind::File { .. } | InodeKind::Symlink { .. } => {
                    // Need to get size, but we already have entry
                    drop(entry);
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EIO);
                    return;
                }
            };
            self.stats.record_metadata_latency(start.elapsed());
            reply.attr(&DEFAULT_ATTR_TTL, &attr);
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        // Query real filesystem statistics from underlying storage
        match nix::sys::statvfs::statvfs(&self.vault_path) {
            Ok(stat) => {
                reply.statfs(
                    stat.blocks() as u64,             // Total blocks
                    stat.blocks_free() as u64,        // Free blocks
                    stat.blocks_available() as u64,   // Available blocks (non-root)
                    stat.files() as u64,              // Total inodes
                    stat.files_free() as u64,         // Free inodes
                    stat.fragment_size() as u32,      // Block size
                    stat.name_max() as u32,           // Max filename length
                    stat.fragment_size() as u32,      // Fragment size
                );
            }
            Err(e) => {
                debug!(error = %e, "Failed to get statfs, using defaults");
                // Fallback to reasonable defaults
                reply.statfs(
                    1000000,    // blocks
                    500000,     // bfree
                    500000,     // bavail
                    1000000,    // files
                    500000,     // ffree
                    BLOCK_SIZE, // bsize
                    255,        // namelen
                    BLOCK_SIZE, // frsize
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
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "create");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before create
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
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
            Err(_) => false, // On executor error, proceed and let vault handle it
        };

        if exists {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            reply.error(libc::EEXIST);
            return;
        }

        // Create the file with a new WriteBuffer marked dirty
        // (File will be written to vault on release, even if empty)
        let buffer = WriteBuffer::new_for_create(dir_id.clone(), name_str.to_string());
        let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));

        // Allocate inode
        let inode = self.inodes.get_or_insert(
            child_path.clone(),
            InodeKind::File {
                dir_id: dir_id.clone(),
                name: name_str.to_string(),
            },
        );

        let attr = self.make_file_attr(inode, 0);
        self.attr_cache.insert(inode, attr);

        // Invalidate parent's negative cache and dir cache
        self.attr_cache.remove_negative(parent, name_str);
        self.dir_cache.invalidate(parent);

        self.stats.record_metadata_latency(start.elapsed());
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
        let mut handle = match self.handle_table.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        let buffer = match handle.as_write_buffer_mut() {
            Some(b) => b,
            None => {
                // Trying to write to a read-only handle
                reply.error(libc::EBADF);
                return;
            }
        };

        // Write data at offset (WriteBuffer handles buffer expansion)
        self.stats.start_write();
        let bytes_written = buffer.write(offset as u64, data);
        self.stats.finish_write();
        self.stats.record_write(bytes_written as u64);
        self.stats.record_encrypted(bytes_written as u64);

        // Invalidate attr cache for this inode
        self.attr_cache.invalidate(ino);
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
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "mkdir");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before mkdir
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
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
            Err(_) => false, // On executor error, proceed and let vault handle it
        };

        if exists {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
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
                    child_path,
                    InodeKind::Directory {
                        dir_id: new_dir_id,
                    },
                );

                let attr = self.make_dir_attr(inode);
                self.attr_cache.insert(inode, attr);

                // Invalidate parent caches
                self.attr_cache.remove_negative(parent, name_str);
                self.dir_cache.invalidate(parent);

                self.stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Ok(Err(e)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
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
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "unlink");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        let ops = self.ops_clone();
        let dir_id_file = dir_id.clone();
        let name_file = name_str.to_string();

        // Try to delete as file first
        match self.exec(async move { ops.delete_file(&dir_id_file, &name_file).await }) {
            Ok(Ok(())) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.stats.record_metadata_latency(start.elapsed());
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
                        let child_path = parent_path.join(name_str);
                        self.inodes.invalidate_path(&child_path);
                        self.dir_cache.invalidate(parent);
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::write_error_to_errno(&e));
                    }
                    Err(exec_err) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
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
    /// - Delegates to vault's `delete_directory` which checks for empty
    /// - Invalidates path mapping and parent's directory cache
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "rmdir");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

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
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.stats.record_metadata_latency(start.elapsed());
                reply.ok();
            }
            Ok(Err(e)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
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
        let name_str = match link_name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let target_str = match target.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, target = target_str, "symlink");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };
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
            Err(_) => false, // On executor error, proceed and let vault handle it
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
                    child_path,
                    InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: name_str.to_string(),
                    },
                );

                let attr = self.make_symlink_attr(inode, target_str.len() as u64);
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
        self.stats.record_metadata_op();

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        let newname_str = match newname.to_str() {
            Some(s) => s,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(
            parent = parent,
            name = name_str,
            newparent = newparent,
            newname = newname_str,
            "rename"
        );

        // Get source parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let src_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let src_parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Get destination parent directory
        let newparent_entry = match self.inodes.get(newparent) {
            Some(e) => e,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dest_dir_id = match newparent_entry.dir_id() {
            Some(id) => id,
            None => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(libc::ENOTDIR);
                return;
            }
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
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                let dest_inode = match self.inodes.get_inode(&dest_path) {
                    Some(inode) => inode,
                    None => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                // Get entry kinds
                let src_entry = match self.inodes.get(src_inode) {
                    Some(e) => e,
                    None => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
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
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
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
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
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
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
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

                        // Invalidate attribute caches for both inodes
                        self.attr_cache.invalidate(src_inode);
                        self.attr_cache.invalidate(dest_inode);

                        // Invalidate directory caches for both parents
                        self.dir_cache.invalidate(parent);
                        if parent != newparent {
                            self.dir_cache.invalidate(newparent);
                        }

                        self.stats.record_metadata_latency(start.elapsed());
                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        error!("rename: RENAME_EXCHANGE failed: {}", e);
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        reply.error(crate::error::write_error_to_errno(&e));
                    }
                    Err(exec_err) => {
                        error!("rename: RENAME_EXCHANGE exec error: {:?}", exec_err);
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
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
                                            self.stats.record_error();
                                            self.stats.record_metadata_latency(start.elapsed());
                                            reply.error(e.to_errno());
                                            return;
                                        }
                                        Err(exec_err) => {
                                            self.stats.record_error();
                                            self.stats.record_metadata_latency(start.elapsed());
                                            reply.error(exec_err.to_errno());
                                            return;
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    self.stats.record_error();
                                    self.stats.record_metadata_latency(start.elapsed());
                                    reply.error(e.to_errno());
                                    return;
                                }
                                Err(exec_err) => {
                                    self.stats.record_error();
                                    self.stats.record_metadata_latency(start.elapsed());
                                    reply.error(exec_err.to_errno());
                                    return;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            reply.error(e.to_errno());
                            return;
                        }
                        Err(exec_err) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            reply.error(exec_err.to_errno());
                            return;
                        }
                    };

                if target_exists {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    reply.error(libc::EEXIST);
                    return;
                }
            }
        }

        // Perform rename/move atomically
        let name_owned = name_str.to_string();
        let newname_owned = newname_str.to_string();

        let result = if parent == newparent {
            // Same directory - just rename
            let ops_rename = self.ops_clone();
            let src_dir_id_rename = src_dir_id.clone();
            self.exec(async move {
                ops_rename
                    .rename_file(&src_dir_id_rename, &name_owned, &newname_owned)
                    .await
            })
        } else if name_str == newname_str {
            // Different directories, same name - just move
            let ops_move = self.ops_clone();
            let src_dir_id_move = src_dir_id.clone();
            let dest_dir_id_move = dest_dir_id.clone();
            self.exec(async move {
                ops_move
                    .move_file(&src_dir_id_move, &name_owned, &dest_dir_id_move)
                    .await
            })
        } else {
            // Different directories, different name - atomic move+rename
            let ops_move_rename = self.ops_clone();
            let src_dir_id_mr = src_dir_id.clone();
            let dest_dir_id_mr = dest_dir_id.clone();
            self.exec(async move {
                ops_move_rename
                    .move_and_rename_file(&src_dir_id_mr, &name_owned, &dest_dir_id_mr, &newname_owned)
                    .await
            })
        };

        match result {
            Ok(Ok(())) => {
                // Update inode mapping
                let old_path = src_parent_path.join(name_str);
                let new_path = dest_parent_path.join(newname_str);

                if let Some(inode) = self.inodes.get_inode(&old_path) {
                    self.inodes.update_path(inode, &old_path, new_path);
                    self.attr_cache.invalidate(inode);
                }

                // Invalidate caches
                self.dir_cache.invalidate(parent);
                if parent != newparent {
                    self.dir_cache.invalidate(newparent);
                }

                // Invalidate negative cache for the new name (it now exists)
                self.attr_cache.remove_negative(newparent, newname_str);

                self.stats.record_metadata_latency(start.elapsed());
                reply.ok();
            }
            Ok(Err(e)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                reply.error(crate::error::write_error_to_errno(&e));
            }
            Err(exec_err) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
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
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
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

        let new_size = (offset + length) as u64;

        // If we have an open file handle, extend the buffer
        if let Some(mut handle) = self.handle_table.get_mut(&fh)
            && let Some(buffer) = handle.as_write_buffer_mut() {
                // Only extend, don't shrink
                if new_size > buffer.len() {
                    buffer.truncate(new_size);
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
                Ok(Err(_)) => Vec::new(),
                Err(_) => Vec::new(),
            };

        // Extend if needed (don't shrink)
        if new_size as usize > content.len() {
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

        // Read from source
        let data = {
            let mut handle = match self.handle_table.get_mut(&fh_in) {
                Some(h) => h,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            };

            match &mut *handle {
                FuseHandle::Reader(reader) => {
                    match self
                        .handle
                        .block_on(reader.read_range(offset_in as u64, len as usize))
                    {
                        Ok(data) => data,
                        Err(e) => {
                            error!(error = %e, "copy_file_range read failed");
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
                FuseHandle::WriteBuffer(buffer) => {
                    buffer.read(offset_in as u64, len as usize).to_vec()
                }
            }
        };

        // Write to destination
        let bytes_written = {
            let mut handle = match self.handle_table.get_mut(&fh_out) {
                Some(h) => h,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            };

            let buffer = match handle.as_write_buffer_mut() {
                Some(b) => b,
                None => {
                    // Destination must be opened for writing
                    reply.error(libc::EBADF);
                    return;
                }
            };

            buffer.write(offset_out as u64, &data)
        };

        // Invalidate attr cache for destination
        self.attr_cache.invalidate(ino_out);
        reply.written(bytes_written as u32);
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
            let entry = match self.inodes.get(ino) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
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
                let new_offset = (file_size as i64) + offset;
                if new_offset < 0 {
                    reply.error(libc::EINVAL);
                } else {
                    reply.offset(new_offset);
                }
            }
            libc::SEEK_DATA => {
                // Cryptomator doesn't support sparse files - entire file is data
                if offset as u64 >= file_size {
                    reply.error(libc::ENXIO);
                } else {
                    reply.offset(offset);
                }
            }
            libc::SEEK_HOLE => {
                // Cryptomator doesn't support sparse files - hole is at EOF
                if offset as u64 >= file_size {
                    reply.error(libc::ENXIO);
                } else {
                    reply.offset(file_size as i64);
                }
            }
            _ => {
                reply.error(libc::EINVAL);
            }
        }
    }
}
