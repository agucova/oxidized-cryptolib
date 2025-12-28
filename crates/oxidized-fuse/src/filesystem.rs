//! FUSE filesystem implementation for Cryptomator vaults.
//!
//! This module implements the fuser `Filesystem` trait for mounting
//! Cryptomator vaults as native filesystems.

use crate::attr::{AttrCache, DirCache, DirListingEntry, DEFAULT_ATTR_TTL};
use crate::error::{FuseError, FuseResult};
use crate::handles::{FuseHandle, FuseHandleTable, WriteBuffer};
use crate::inode::{InodeKind, InodeTable};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::c_int;
use oxidized_cryptolib::fs::encrypted_to_plaintext_size_or_zero;
use oxidized_cryptolib::vault::{DirId, VaultOperationsAsync};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::runtime::Runtime;
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
    /// Async vault operations (cloned per operation for thread safety).
    ops: VaultOperationsAsync,
    /// Inode table for path/inode mapping.
    inodes: InodeTable,
    /// Attribute cache for file metadata.
    attr_cache: AttrCache,
    /// Directory listing cache.
    dir_cache: DirCache,
    /// File handle table for open files.
    handle_table: FuseHandleTable,
    /// Tokio runtime for async operations.
    runtime: Runtime,
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
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

        // Open vault - extracts key, reads config, configures cipher combo automatically
        let ops = VaultOperationsAsync::open(vault_path, password).map_err(|e| {
            FuseError::Io(std::io::Error::other(format!("Failed to open vault: {e}")))
        })?;

        // Get current user/group
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
            "CryptomatorFS initialized"
        );

        Ok(Self {
            ops,
            inodes: InodeTable::new(),
            attr_cache: AttrCache::with_defaults(),
            dir_cache: DirCache::default(),
            handle_table: FuseHandleTable::new(),
            runtime,
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
        })
    }

    /// Creates a new CryptomatorFS with custom UID/GID.
    pub fn with_ownership(vault_path: &Path, password: &str, uid: u32, gid: u32) -> Result<Self, FuseError> {
        let mut fs = Self::new(vault_path, password)?;
        fs.uid = uid;
        fs.gid = gid;
        Ok(fs)
    }

    /// Clones the vault operations for use in async context.
    fn ops_clone(&self) -> Result<VaultOperationsAsync, FuseError> {
        self.ops.clone_shared().map_err(|e| {
            FuseError::Io(std::io::Error::other(format!("Failed to clone ops: {e}")))
        })
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

    /// Looks up a child entry in a directory.
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
        let ops = self.ops_clone()?;

        // Try to find as a directory first
        let dirs = self.runtime.block_on(ops.list_directories(&dir_id))?;
        for dir_info in dirs {
            if dir_info.name == name {
                let child_path = parent_path.join(name);
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
        }

        // Try as a file
        let ops = self.ops_clone()?;
        let files = self.runtime.block_on(ops.list_files(&dir_id))?;
        for file_info in files {
            if file_info.name == name {
                let child_path = parent_path.join(name);
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
        }

        // Try as a symlink
        let ops = self.ops_clone()?;
        let symlinks = self.runtime.block_on(ops.list_symlinks(&dir_id))?;
        for symlink_info in symlinks {
            if symlink_info.name == name {
                let child_path = parent_path.join(name);
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
        }

        // Not found
        Err(FuseError::PathResolution(format!("'{}' not found", name)))
    }

    /// Lists all entries in a directory.
    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        let ops = self.ops_clone()?;
        let mut entries = Vec::new();

        // List directories
        let dirs = self.runtime.block_on(ops.list_directories(dir_id))?;
        for dir_info in dirs {
            entries.push(DirListingEntry {
                inode: 0, // Will be resolved on lookup
                file_type: FileType::Directory,
                name: dir_info.name,
            });
        }

        // List files
        let ops = self.ops_clone()?;
        let files = self.runtime.block_on(ops.list_files(dir_id))?;
        for file_info in files {
            entries.push(DirListingEntry {
                inode: 0,
                file_type: FileType::RegularFile,
                name: file_info.name,
            });
        }

        // List symlinks
        let ops = self.ops_clone()?;
        let symlinks = self.runtime.block_on(ops.list_symlinks(dir_id))?;
        for symlink_info in symlinks {
            entries.push(DirListingEntry {
                inode: 0,
                file_type: FileType::Symlink,
                name: symlink_info.name,
            });
        }

        Ok(entries)
    }
}

impl Filesystem for CryptomatorFS {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        info!("FUSE filesystem initialized");
        // Enable async reads
        config.add_capabilities(fuser::consts::FUSE_ASYNC_READ).ok();
        Ok(())
    }

    fn destroy(&mut self) {
        info!("FUSE filesystem destroyed");
    }

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
                reply.entry(&DEFAULT_ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                // Add to negative cache
                self.attr_cache.insert_negative(parent, name_str.to_string());
                reply.error(e.to_errno());
            }
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        trace!(inode = ino, nlookup = nlookup, "forget");
        self.inodes.forget(ino, nlookup);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        trace!(inode = ino, "getattr");

        // Check cache first
        if let Some(cached) = self.attr_cache.get(ino) {
            reply.attr(&cached.time_remaining(), &cached.attr);
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
                // Get file size from vault
                let ops = match self.ops_clone() {
                    Ok(ops) => ops,
                    Err(e) => {
                        reply.error(e.to_errno());
                        return;
                    }
                };
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.runtime.block_on(ops.list_files(&dir_id)) {
                    Ok(files) => {
                        let file_info = files.into_iter().find(|f| f.name == name);
                        match file_info {
                            Some(info) => self.make_file_attr(ino, encrypted_to_plaintext_size_or_zero(info.encrypted_size)),
                            None => {
                                reply.error(libc::ENOENT);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        reply.error(crate::error::vault_error_to_errno(&e));
                        return;
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Get symlink target length
                let ops = match self.ops_clone() {
                    Ok(ops) => ops,
                    Err(e) => {
                        reply.error(e.to_errno());
                        return;
                    }
                };
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                match self.runtime.block_on(ops.read_symlink(&dir_id, &name)) {
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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        match self.runtime.block_on(ops.read_symlink(&dir_id, &name)) {
            Ok(target) => {
                reply.data(target.as_bytes());
            }
            Err(e) => {
                reply.error(crate::error::vault_error_to_errno(&e));
            }
        }
    }

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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

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
                match self.runtime.block_on(ops.read_file(&dir_id, &name)) {
                    Ok(file) => file.content,
                    Err(_) => Vec::new(), // File doesn't exist, start empty
                }
            };

            let buffer = WriteBuffer::new(dir_id, name, existing_content);
            let fh = self.handle_table.insert(FuseHandle::WriteBuffer(buffer));
            reply.opened(fh, 0);
        } else {
            // Open for reading - open_file returns VaultFileReader
            match self.runtime.block_on(ops.open_file(&dir_id, &name)) {
                Ok(reader) => {
                    // Store reader in handle table and return the handle ID
                    let fh = self.handle_table.insert(FuseHandle::Reader(reader));
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
        let mut handle = match self.handle_table.get_mut(fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        match &mut *handle {
            FuseHandle::Reader(reader) => {
                // Read from streaming reader
                match self
                    .runtime
                    .block_on(reader.read_range(offset as u64, size as usize))
                {
                    Ok(data) => {
                        reply.data(&data);
                    }
                    Err(e) => {
                        error!(error = %e, "Read failed");
                        reply.error(libc::EIO);
                    }
                }
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Read from write buffer (for read-after-write in same handle)
                let data = buffer.read(offset as u64, size as usize);
                reply.data(data);
            }
        }
    }

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
        let handle = match self.handle_table.remove(fh) {
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
                debug!(fh = fh, "Reader released");
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Write buffer back to vault if dirty
                if buffer.is_dirty() {
                    let ops = match self.ops_clone() {
                        Ok(ops) => ops,
                        Err(e) => {
                            error!(error = %e, "Failed to clone ops for write-back");
                            reply.error(libc::EIO);
                            return;
                        }
                    };

                    let dir_id = buffer.dir_id().clone();
                    let filename = buffer.filename().to_string();
                    let content = buffer.into_content();

                    match self.runtime.block_on(ops.write_file(&dir_id, &filename, &content)) {
                        Ok(_) => {
                            debug!(fh = fh, filename = %filename, size = content.len(), "WriteBuffer flushed");
                            // Invalidate attr cache since file changed
                            self.attr_cache.invalidate(ino);
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to write buffer back to vault");
                            reply.error(crate::error::write_error_to_errno(&e));
                            return;
                        }
                    }
                } else {
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
                reply.opened(0, 0);
            }
            _ => {
                reply.error(libc::ENOTDIR);
            }
        }
    }

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
                self.inodes.get_or_insert(child_path, kind)
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

    fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        reply.ok();
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
        let fh = self.handle_table.insert(FuseHandle::WriteBuffer(buffer));

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
        let mut handle = match self.handle_table.get_mut(fh) {
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
        let bytes_written = buffer.write(offset as u64, data);

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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        // Create directory
        match self
            .runtime
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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        // Try to delete as file first
        match self.runtime.block_on(ops.delete_file(&dir_id, name_str)) {
            Ok(()) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                reply.ok();
            }
            Err(_) => {
                // Try as symlink
                let ops = match self.ops_clone() {
                    Ok(ops) => ops,
                    Err(e) => {
                        reply.error(e.to_errno());
                        return;
                    }
                };

                match self.runtime.block_on(ops.delete_symlink(&dir_id, name_str)) {
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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        // Delete directory
        match self
            .runtime
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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        // Create symlink
        match self
            .runtime
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

        let ops = match self.ops_clone() {
            Ok(ops) => ops,
            Err(e) => {
                reply.error(e.to_errno());
                return;
            }
        };

        // Perform rename/move atomically
        let result = if parent == newparent {
            // Same directory - just rename
            self.runtime
                .block_on(ops.rename_file(&src_dir_id, name_str, newname_str))
        } else if name_str == newname_str {
            // Different directories, same name - just move
            self.runtime
                .block_on(ops.move_file(&src_dir_id, name_str, &dest_dir_id))
        } else {
            // Different directories, different name - atomic move+rename
            self.runtime
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

                reply.ok();
            }
            Err(e) => {
                reply.error(crate::error::write_error_to_errno(&e));
            }
        }
    }
}
