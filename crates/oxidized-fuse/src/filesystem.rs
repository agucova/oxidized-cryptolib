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
//! | rename | **BUG** | Ignores RENAME_NOREPLACE/RENAME_EXCHANGE flags |
//! | access | OK | |
//! | statfs | OK | |
//! | fallocate | OK | Only mode=0 supported (correct for non-sparse FS) |
//! | copy_file_range | OK | |
//! | lseek | OK | SEEK_DATA/SEEK_HOLE handled correctly for non-sparse |
//!
//! ## Known Issues
//!
//! 1. **rename flags ignored**: The `flags` parameter supports `RENAME_NOREPLACE`
//!    (fail if target exists) and `RENAME_EXCHANGE` (atomically swap two files).
//!    Current implementation ignores these flags entirely.

use crate::attr::{AttrCache, DirCache, DirListingEntry, DEFAULT_ATTR_TTL};
use crate::error::{FuseError, FuseResult};
use crate::handles::{FuseHandle, FuseHandleTable, WriteBuffer};
use crate::inode::{InodeKind, InodeTable};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen, ReplyWrite, Request,
};
use libc::c_int;
use oxidized_cryptolib::fs::encrypted_to_plaintext_size_or_zero;
use oxidized_cryptolib::vault::{DirId, VaultOperationsAsync};
use oxidized_mount_common::VaultStats;
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
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl CryptomatorFS {
    /// Creates a new CryptomatorFS from a vault path and password.
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
        let runtime = Runtime::new().map_err(|e| {
            FuseError::Io(std::io::Error::other(format!(
                "Failed to create tokio runtime: {e}"
            )))
        })?;
        let handle = runtime.handle().clone();
        Self::with_runtime_internal(vault_path, password, Some(runtime), handle)
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
        Self::with_runtime_internal(vault_path, password, None, handle)
    }

    /// Internal constructor used by both `new()` and `with_runtime_handle()`.
    fn with_runtime_internal(
        vault_path: &Path,
        password: &str,
        owned_runtime: Option<Runtime>,
        handle: Handle,
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

        // Create attribute cache and connect it to stats for hit/miss tracking
        let mut attr_cache = AttrCache::with_defaults();
        attr_cache.set_stats(stats.cache_stats());

        info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
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
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
            stats,
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

                // Write to vault
                let write_result = self.handle
                    .block_on(ops.write_file(&dir_id, &filename, &content));

                // Re-acquire handle to restore content (whether success or failure)
                if let Some(mut handle) = self.handle_table.get_mut(&fh)
                    && let Some(buffer) = handle.as_write_buffer_mut() {
                        // restore_content marks clean, so re-mark dirty on failure
                        buffer.restore_content(content);
                        if write_result.is_err() {
                            buffer.mark_dirty();
                        }
                    }

                // Propagate error after restoring content
                write_result.map_err(|e| crate::error::write_error_to_errno(&e))?;

                self.attr_cache.invalidate(ino);
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

        // Clone ops for async use
        let ops = self.ops_clone();
        let child_path = parent_path.join(name);

        // Try O(1) lookup for file first (most common case)
        if let Some(file_info) = self.handle.block_on(ops.find_file(&dir_id, name))? {
            let inode = self.inodes.get_or_insert(
                child_path,
                InodeKind::File {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let attr = self.make_file_attr(inode, encrypted_to_plaintext_size_or_zero(file_info.encrypted_size));
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::RegularFile));
        }

        // Try O(1) lookup for directory
        if let Some(dir_info) = self.handle.block_on(ops.find_directory(&dir_id, name))? {
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

        // Try O(1) lookup for symlink
        if let Some(symlink_info) = self.handle.block_on(ops.find_symlink(&dir_id, name))? {
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

        // Not found
        Err(FuseError::PathResolution(format!("'{}' not found", name)))
    }

    /// Lists all entries in a directory.
    ///
    /// Uses `list_all` to fetch files, directories, and symlinks in a single
    /// operation with parallel I/O, replacing 3 sequential blocking calls.
    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        let ops = self.ops_clone();

        // Single blocking call with parallel I/O internally
        let (files, dirs, symlinks) = self.handle.block_on(ops.list_all(dir_id))?;

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
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "lookup");

        // Check negative cache
        if self.attr_cache.is_negative(parent, name_str) {
            reply.error(libc::ENOENT);
            return;
        }

        match self.lookup_child(parent, name_str) {
            Ok((_inode, attr, _file_type)) => {
                // nlookup is incremented in lookup_child via get_or_insert (correct per spec)
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                // Add to negative cache
                self.attr_cache.insert_negative(parent, name_str.to_string());
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
        trace!(inode = ino, "getattr");

        // Check cache first
        if let Some(cached) = self.attr_cache.get(ino) {
            reply.attr(&cached.time_remaining(), &cached.value);
            return;
        }

        // Get inode entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
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

                match self.handle.block_on(ops.find_file(&dir_id, &name)) {
                    Ok(Some(info)) => self.make_file_attr(ino, encrypted_to_plaintext_size_or_zero(info.encrypted_size)),
                    Ok(None) => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Err(e) => {
                        reply.error(crate::error::vault_error_to_errno(&e));
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

                match self.handle.block_on(ops.read_symlink(&dir_id, &name)) {
                    Ok(target) => self.make_symlink_attr(ino, target.len() as u64),
                    Err(e) => {
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                }
            }
        };

        self.attr_cache.insert(ino, attr);
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

        match self.handle.block_on(ops.read_symlink(&dir_id, &name)) {
            Ok(target) => {
                reply.data(target.as_bytes());
            }
            Err(e) => {
                reply.error(crate::error::vault_error_to_errno(&e));
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
                // Read existing content if file exists
                match self.handle.block_on(ops.read_file(&dir_id, &name)) {
                    Ok(file) => file.content,
                    Err(_) => Vec::new(), // File doesn't exist, start empty
                }
            };

            let buffer = WriteBuffer::new(dir_id, name, existing_content);
            let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));
            self.stats.record_file_open();
            reply.opened(fh, 0);
        } else {
            // Open for reading - open_file returns VaultFileReader
            match self.handle.block_on(ops.open_file(&dir_id, &name)) {
                Ok(reader) => {
                    // Store reader in handle table and return the handle ID
                    let fh = self.handle_table.insert_auto(FuseHandle::Reader(Box::new(reader)));
                    self.stats.record_file_open();
                    reply.opened(fh, 0);
                }
                Err(e) => {
                    reply.error(crate::error::vault_error_to_errno(&e));
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
                    let content = buffer.into_content();
                    let content_len = content.len();

                    self.stats.start_write();
                    let start = Instant::now();
                    match self.handle.block_on(ops.write_file(&dir_id, &filename, &content)) {
                        Ok(_) => {
                            let elapsed = start.elapsed();
                            self.stats.finish_write();
                            self.stats.record_write(content_len as u64);
                            self.stats.record_write_latency(elapsed);
                            self.stats.record_encrypted(content_len as u64);
                            debug!(fh = fh, filename = %filename, size = content_len, "WriteBuffer flushed");
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
        trace!(inode = ino, offset = offset, "readdir");

        // Get directory entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match entry.dir_id() {
            Some(id) => id,
            None => {
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
        trace!(inode = ino, offset = offset, "readdirplus");

        // Get directory entry
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_id = match entry.dir_id() {
            Some(id) => id,
            None => {
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

        // Single blocking call with parallel I/O internally
        let (files, dirs, symlinks) = match self.handle.block_on(ops.list_all(&dir_id)) {
            Ok(result) => result,
            Err(e) => {
                reply.error(crate::error::vault_error_to_errno(&e));
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
            reply.error(libc::ENOTSUP);
            return;
        }

        // Get current inode info
        let entry = match self.inodes.get(ino) {
            Some(e) => e,
            None => {
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
                                reply.attr(&DEFAULT_ATTR_TTL, &attr);
                                return;
                            }

                    // No open handle - read file, truncate, write back
                    let ops = self.ops_clone();

                    // Read existing content (or empty if file doesn't exist)
                    let mut content = match self.handle.block_on(ops.read_file(&dir_id, &name)) {
                        Ok(file) => file.content,
                        Err(_) => Vec::new(),
                    };

                    // Truncate or extend
                    content.resize(new_size as usize, 0);

                    // Write back
                    let ops = self.ops_clone();

                    match self.handle.block_on(ops.write_file(&dir_id, &name, &content)) {
                        Ok(_) => {
                            let attr = self.make_file_attr(ino, new_size);
                            self.attr_cache.insert(ino, attr);
                            reply.attr(&DEFAULT_ATTR_TTL, &attr);
                        }
                        Err(e) => {
                            reply.error(crate::error::write_error_to_errno(&e));
                        }
                    }
                    return;
                }
                InodeKind::Directory { .. } | InodeKind::Root => {
                    // Can't truncate directories
                    reply.error(libc::EISDIR);
                    return;
                }
                InodeKind::Symlink { .. } => {
                    // Can't truncate symlinks
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
                        match self.handle.block_on(ops.find_file(&dir_id, &name)) {
                            Ok(Some(file_info)) => {
                                let file_size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
                                self.make_file_attr(ino, file_size)
                            }
                            Ok(None) => {
                                // File not found - use size 0
                                self.make_file_attr(ino, 0)
                            }
                            Err(e) => {
                                reply.error(crate::error::vault_error_to_errno(&e));
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
                        match self.handle.block_on(ops.read_symlink(&dir_id, &name)) {
                            Ok(target) => self.make_symlink_attr(ino, target.len() as u64),
                            Err(e) => {
                                reply.error(crate::error::vault_error_to_errno(&e));
                                return;
                            }
                        }
                    }
                }
            };

            self.attr_cache.insert(ino, attr);
            reply.attr(&DEFAULT_ATTR_TTL, &attr);
            return;
        }

        // No changes requested - return current attributes
        if let Some(cached) = self.attr_cache.get(ino) {
            reply.attr(&cached.time_remaining(), &cached.value);
        } else {
            // Fall back to getattr behavior
            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => self.make_dir_attr(ino),
                InodeKind::File { .. } | InodeKind::Symlink { .. } => {
                    // Need to get size, but we already have entry
                    drop(entry);
                    reply.error(libc::EIO);
                    return;
                }
            };
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
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "create");

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

        // Create the file with a new WriteBuffer marked dirty
        // (File will be written to vault on release, even if empty)
        let buffer = WriteBuffer::new_for_create(dir_id.clone(), name_str.to_string());
        let fh = self.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));

        // Allocate inode
        let child_path = parent_path.join(name_str);
        let inode = self.inodes.get_or_insert(
            child_path,
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

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "mkdir");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        let ops = self.ops_clone();

        // Create directory
        match self
            .handle
            .block_on(ops.create_directory(&parent_dir_id, name_str))
        {
            Ok(new_dir_id) => {
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

                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                reply.error(crate::error::write_error_to_errno(&e));
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
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "unlink");

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

        let ops = self.ops_clone();

        // Try to delete as file first
        match self.handle.block_on(ops.delete_file(&dir_id, name_str)) {
            Ok(()) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                reply.ok();
            }
            Err(_) => {
                // Try as symlink
                let ops = self.ops_clone();

                match self.handle.block_on(ops.delete_symlink(&dir_id, name_str)) {
                    Ok(()) => {
                        let child_path = parent_path.join(name_str);
                        self.inodes.invalidate_path(&child_path);
                        self.dir_cache.invalidate(parent);
                        reply.ok();
                    }
                    Err(e) => {
                        reply.error(crate::error::write_error_to_errno(&e));
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
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        trace!(parent = parent, name = name_str, "rmdir");

        // Get parent directory
        let parent_entry = match self.inodes.get(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        let ops = self.ops_clone();

        // Delete directory
        match self
            .handle
            .block_on(ops.delete_directory(&parent_dir_id, name_str))
        {
            Ok(()) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                reply.ok();
            }
            Err(e) => {
                reply.error(crate::error::write_error_to_errno(&e));
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

        let ops = self.ops_clone();

        // Create symlink
        match self
            .handle
            .block_on(ops.create_symlink(&dir_id, name_str, target_str))
        {
            Ok(()) => {
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
            Err(e) => {
                reply.error(crate::error::write_error_to_errno(&e));
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
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let newname_str = match newname.to_str() {
            Some(s) => s,
            None => {
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
                reply.error(libc::ENOENT);
                return;
            }
        };

        let src_dir_id = match parent_entry.dir_id() {
            Some(id) => id,
            None => {
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
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dest_dir_id = match newparent_entry.dir_id() {
            Some(id) => id,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };
        let dest_parent_path = newparent_entry.path.clone();
        drop(newparent_entry);

        let ops = self.ops_clone();

        // Handle rename flags
        #[cfg(target_os = "linux")]
        {
            // RENAME_EXCHANGE: atomic swap of source and target
            // This is complex to implement atomically, return ENOTSUP
            if _flags & libc::RENAME_EXCHANGE != 0 {
                warn!("rename: RENAME_EXCHANGE not supported");
                reply.error(libc::ENOTSUP);
                return;
            }

            // RENAME_NOREPLACE: fail if target exists (check file, dir, and symlink)
            if _flags & libc::RENAME_NOREPLACE != 0 {
                // Use O(1) lookups to check if target exists as file, directory, or symlink
                let target_exists = match self.handle.block_on(ops.find_file(&dest_dir_id, newname_str)) {
                    Ok(Some(_)) => true,
                    Ok(None) => match self.handle.block_on(ops.find_directory(&dest_dir_id, newname_str)) {
                        Ok(Some(_)) => true,
                        Ok(None) => match self.handle.block_on(ops.find_symlink(&dest_dir_id, newname_str)) {
                            Ok(Some(_)) => true,
                            Ok(None) => false,
                            Err(e) => {
                                reply.error(e.to_errno());
                                return;
                            }
                        },
                        Err(e) => {
                            reply.error(e.to_errno());
                            return;
                        }
                    },
                    Err(e) => {
                        reply.error(e.to_errno());
                        return;
                    }
                };

                if target_exists {
                    reply.error(libc::EEXIST);
                    return;
                }
            }
        }

        // Perform rename/move atomically
        let result = if parent == newparent {
            // Same directory - just rename
            self.handle
                .block_on(ops.rename_file(&src_dir_id, name_str, newname_str))
        } else if name_str == newname_str {
            // Different directories, same name - just move
            self.handle
                .block_on(ops.move_file(&src_dir_id, name_str, &dest_dir_id))
        } else {
            // Different directories, different name - atomic move+rename
            self.handle
                .block_on(ops.move_and_rename_file(&src_dir_id, name_str, &dest_dir_id, newname_str))
        };

        match result {
            Ok(()) => {
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

                reply.ok();
            }
            Err(e) => {
                reply.error(crate::error::write_error_to_errno(&e));
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

        // Read existing content
        let mut content = match self.handle.block_on(ops.read_file(&dir_id, &name)) {
            Ok(file) => file.content,
            Err(_) => Vec::new(),
        };

        // Extend if needed (don't shrink)
        if new_size as usize > content.len() {
            content.resize(new_size as usize, 0);

            // Write back
            let ops = self.ops_clone();

            match self.handle.block_on(ops.write_file(&dir_id, &name, &content)) {
                Ok(_) => {
                    self.attr_cache.invalidate(ino);
                    reply.ok();
                }
                Err(e) => {
                    reply.error(crate::error::write_error_to_errno(&e));
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

                        match self.handle.block_on(ops.find_file(&dir_id, &name)) {
                            Ok(Some(file_info)) => {
                                encrypted_to_plaintext_size_or_zero(file_info.encrypted_size)
                            }
                            Ok(None) => 0,
                            Err(e) => {
                                reply.error(crate::error::vault_error_to_errno(&e));
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
