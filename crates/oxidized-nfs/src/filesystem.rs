//! NFS filesystem implementation for Cryptomator vaults.
//!
//! This module implements the `NFSFileSystem` trait from `nfsserve` to provide
//! an NFS server backend for Cryptomator vaults.

use crate::error::vault_error_to_nfsstat;
use crate::inode::{InodeEntry, InodeKind, NfsInodeTable, ROOT_FILEID};
use async_trait::async_trait;
use dashmap::DashMap;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfsstring, nfstime3, sattr3, set_size3,
    specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use oxidized_cryptolib::fs::streaming::encrypted_to_plaintext_size_or_zero_for_cipher;
use oxidized_cryptolib::vault::operations_async::VaultOperationsAsync;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use oxidized_mount_common::moka_cache::SyncTtlCache;
use oxidized_mount_common::{VaultStats, WriteBuffer};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};

/// NFS filesystem implementation for Cryptomator vaults.
///
/// This implements the `NFSFileSystem` trait to provide NFS access to vault contents.
/// It uses shared utilities from `oxidized-mount-common`:
/// - `WriteBuffer` for buffering writes until flush/commit
/// - `VaultErrorCategory` for error mapping (via `vault_error_to_nfsstat`)
///
/// # Write Buffering
///
/// NFS clients may split large writes into multiple WRITE RPCs. To handle this correctly,
/// we buffer writes in memory per-file and only flush to the vault when:
/// - A read is requested (read-after-write consistency)
/// - setattr with truncate is called
/// - The file is removed
/// - A rename operation occurs
/// TTL for read cache entries.
/// Short TTL (5 seconds) allows consecutive reads to reuse decrypted content
/// while ensuring freshness for external modifications.
const READ_CACHE_TTL: Duration = Duration::from_secs(5);

pub struct CryptomatorNFS {
    /// Vault operations for reading/writing encrypted files.
    ops: Arc<VaultOperationsAsync>,
    /// Mapping between NFS file IDs and vault paths.
    inodes: NfsInodeTable,
    /// Write buffers for files with pending writes.
    /// Key: file ID, Value: WriteBuffer containing pending data.
    write_buffers: DashMap<fileid3, WriteBuffer>,
    /// Read cache for decrypted file contents.
    /// Key: file ID, Value: decrypted content.
    /// This prevents re-decrypting the entire file on each NFS READ RPC.
    read_cache: SyncTtlCache<fileid3, Vec<u8>>,
    /// Server generation number (for cookieverf3).
    generation: u64,
    /// UID for all files (from process).
    uid: u32,
    /// GID for all files (from process).
    gid: u32,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl CryptomatorNFS {
    /// Creates a new NFS filesystem for the given vault.
    pub fn new(ops: Arc<VaultOperationsAsync>) -> Self {
        let generation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ops,
            inodes: NfsInodeTable::new(),
            write_buffers: DashMap::new(),
            read_cache: SyncTtlCache::new(READ_CACHE_TTL),
            generation,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            stats: Arc::new(VaultStats::new()),
        }
    }

    /// Get the statistics for this filesystem.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
    }

    /// Flush a write buffer to the vault.
    ///
    /// This writes the buffered content to the vault and removes the buffer.
    /// Returns the final content length on success.
    async fn flush_buffer(&self, id: fileid3) -> Result<u64, nfsstat3> {
        if let Some((_, buffer)) = self.write_buffers.remove(&id) {
            let len = buffer.len();
            if buffer.is_dirty() {
                debug!(id, len, "Flushing write buffer to vault");
                self.stats.start_write();
                let result = self.ops
                    .write_file(buffer.dir_id(), buffer.filename(), buffer.content())
                    .await
                    .map_err(|e| vault_error_to_nfsstat(&e));
                self.stats.finish_write();
                result?;
                // Record encrypted bytes written to vault
                self.stats.record_encrypted(len);
            }
            Ok(len)
        } else {
            Ok(0)
        }
    }

    /// Get or create a write buffer for a file.
    ///
    /// If the file doesn't have a buffer yet, reads existing content from vault
    /// and creates a new buffer. Uses atomic entry API to prevent race conditions
    /// when multiple WRITE RPCs arrive concurrently.
    async fn get_or_create_buffer(
        &self,
        id: fileid3,
        dir_id: &DirId,
        name: &str,
    ) -> Result<dashmap::mapref::one::RefMut<'_, fileid3, WriteBuffer>, nfsstat3> {
        // Fast path: buffer already exists
        if let Some(buffer) = self.write_buffers.get_mut(&id) {
            debug!(id, "Using existing buffer");
            return Ok(buffer);
        }

        // Slow path: need to read existing content from vault
        let existing = match self.ops.read_file(dir_id, name).await {
            Ok(decrypted) => {
                debug!(id, existing_len = decrypted.content.len(), "Read existing content for buffer");
                decrypted.content
            }
            Err(_) => {
                debug!(id, "File doesn't exist yet, creating empty buffer");
                Vec::new()
            }
        };

        // Use entry API to atomically insert only if key doesn't exist.
        // This prevents race conditions where two concurrent WRITEs both read
        // existing content and then both try to insert, with the second overwriting
        // the first's buffer (losing data).
        let buffer = WriteBuffer::new(dir_id.clone(), name.to_string(), existing);
        self.write_buffers.entry(id).or_insert(buffer);

        self.write_buffers.get_mut(&id).ok_or(nfsstat3::NFS3ERR_IO)
    }

    /// Creates file attributes for a directory.
    fn dir_attr(&self, fileid: u64) -> fattr3 {
        let now = self.current_time();
        fattr3 {
            ftype: ftype3::NF3DIR,
            mode: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            size: 4096,
            used: 4096,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }

    /// Creates file attributes for a regular file.
    fn file_attr(&self, fileid: u64, size: u64) -> fattr3 {
        let now = self.current_time();
        fattr3 {
            ftype: ftype3::NF3REG,
            mode: 0o644,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            size,
            used: size,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }

    /// Creates file attributes for a symlink.
    fn symlink_attr(&self, fileid: u64, target_len: u64) -> fattr3 {
        let now = self.current_time();
        fattr3 {
            ftype: ftype3::NF3LNK,
            mode: 0o777,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            size: target_len,
            used: target_len,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }

    /// Gets the current time as NFS time.
    fn current_time(&self) -> nfstime3 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        nfstime3 {
            seconds: now.as_secs() as u32,
            nseconds: now.subsec_nanos(),
        }
    }

    /// Gets an inode entry or returns NFS3ERR_STALE.
    fn get_entry(&self, id: fileid3) -> Result<dashmap::mapref::one::Ref<'_, u64, InodeEntry>, nfsstat3> {
        self.inodes.get(id).ok_or(nfsstat3::NFS3ERR_STALE)
    }

    /// Gets a directory entry or returns NFS3ERR_NOTDIR/NFS3ERR_STALE.
    fn get_dir_entry(&self, id: fileid3) -> Result<DirId, nfsstat3> {
        let entry = self.get_entry(id)?;
        entry.dir_id().ok_or(nfsstat3::NFS3ERR_NOTDIR)
    }

    /// Converts a filename3 to a Rust string.
    fn filename_to_str(filename: &filename3) -> Result<&str, nfsstat3> {
        std::str::from_utf8(filename).map_err(|_| nfsstat3::NFS3ERR_INVAL)
    }

    /// Gets the parent path for a directory entry.
    fn get_parent_path(&self, dirid: fileid3) -> Result<VaultPath, nfsstat3> {
        let entry = self.get_entry(dirid)?;
        Ok(entry.path.clone())
    }
}

#[async_trait]
impl NFSFileSystem for CryptomatorNFS {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_FILEID
    }

    fn serverid(&self) -> [u8; 8] {
        self.generation.to_be_bytes()
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = Self::filename_to_str(filename)?;
        trace!(dirid, name, "lookup");

        // Handle special names
        if name == "." {
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(dirid);
        }

        let parent_path = self.get_parent_path(dirid)?;
        let dir_id = self.get_dir_entry(dirid)?;

        // Handle ".." - go to parent
        if name == ".." {
            if let Some(parent) = parent_path.parent()
                && let Some(id) = self.inodes.get_id(&parent)
            {
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(id);
            }
            // At root, ".." is root itself
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(ROOT_FILEID);
        }

        let child_path = parent_path.join(name);

        // Check if we already have this entry
        if let Some(id) = self.inodes.get_id(&child_path) {
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(id);
        }

        // Try to look up as directory first
        if let Ok(Some(dir_info)) = self.ops.find_directory(&dir_id, name).await {
            let kind = InodeKind::Directory {
                dir_id: dir_info.directory_id,
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(child_path, kind));
        }

        // Try as file
        if let Ok(Some(_file_info)) = self.ops.find_file(&dir_id, name).await {
            let kind = InodeKind::File {
                dir_id: dir_id.clone(),
                name: name.to_string(),
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(child_path, kind));
        }

        // Try as symlink - use O(1) lookup instead of reading the full target
        if self.ops.find_symlink(&dir_id, name).await.ok().flatten().is_some() {
            let kind = InodeKind::Symlink {
                dir_id: dir_id.clone(),
                name: name.to_string(),
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(child_path, kind));
        }

        self.stats.record_metadata_latency(start.elapsed());
        self.stats.record_error();
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, "getattr");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_metadata_latency(start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };

        let result = match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => Ok(self.dir_attr(id)),
            InodeKind::File { dir_id, name } => {
                // Check if we have a buffer with pending writes - use that size
                if let Some(buffer) = self.write_buffers.get(&id) {
                    return {
                        self.stats.record_metadata_latency(start.elapsed());
                        Ok(self.file_attr(id, buffer.len()))
                    };
                }

                // Get file info from vault
                match self.ops.find_file(dir_id, name).await {
                    Ok(Some(file_info)) => {
                        // Convert encrypted size to plaintext size
                        let cipher = self.ops.cipher_combo();
                        let size = encrypted_to_plaintext_size_or_zero_for_cipher(file_info.encrypted_size, cipher);
                        Ok(self.file_attr(id, size))
                    }
                    Ok(None) => {
                        self.stats.record_error();
                        Err(nfsstat3::NFS3ERR_NOENT)
                    }
                    Err(e) => {
                        self.stats.record_error();
                        Err(vault_error_to_nfsstat(&e))
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Get symlink target length using O(1) lookup
                match self.ops.find_symlink(dir_id, name).await {
                    Ok(Some(symlink_info)) => Ok(self.symlink_attr(id, symlink_info.target.len() as u64)),
                    Ok(None) => {
                        self.stats.record_error();
                        Err(nfsstat3::NFS3ERR_NOENT)
                    }
                    Err(e) => {
                        self.stats.record_error();
                        Err(vault_error_to_nfsstat(&e))
                    }
                }
            }
        };

        self.stats.record_metadata_latency(start.elapsed());
        result
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, ?setattr, "setattr");

        // We don't support changing attributes, but we can handle truncate
        if let set_size3::size(size) = setattr.size {
            let entry = match self.get_entry(id) {
                Ok(e) => e,
                Err(e) => {
                    self.stats.record_metadata_latency(start.elapsed());
                    self.stats.record_error();
                    return Err(e);
                }
            };
            if let Some((dir_id, name)) = entry.file_info() {
                let dir_id = dir_id.clone();
                let name = name.to_string();
                drop(entry); // Release the borrow before async operations

                // Discard any pending buffer - we're replacing content
                self.write_buffers.remove(&id);
                // Invalidate read cache since content is being truncated
                self.read_cache.invalidate(&id);

                if size == 0 {
                    // Truncate to empty - create empty file
                    debug!(id, "Truncating file to empty");
                    if let Err(e) = self.ops.write_file(&dir_id, &name, &[]).await {
                        self.stats.record_metadata_latency(start.elapsed());
                        self.stats.record_error();
                        return Err(vault_error_to_nfsstat(&e));
                    }
                } else {
                    // Partial truncate - read, truncate, write
                    debug!(id, size, "Truncating file to size");
                    let decrypted = match self.ops.read_file(&dir_id, &name).await {
                        Ok(d) => d,
                        Err(e) => {
                            self.stats.record_metadata_latency(start.elapsed());
                            self.stats.record_error();
                            return Err(vault_error_to_nfsstat(&e));
                        }
                    };
                    let truncated: Vec<u8> = decrypted.content.into_iter().take(size as usize).collect();
                    if let Err(e) = self.ops.write_file(&dir_id, &name, &truncated).await {
                        self.stats.record_metadata_latency(start.elapsed());
                        self.stats.record_error();
                        return Err(vault_error_to_nfsstat(&e));
                    }
                }
            }
        }

        self.stats.record_metadata_latency(start.elapsed());
        // Return current attributes (getattr records its own metadata op)
        self.getattr(id).await
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let op_start = Instant::now();
        trace!(id, offset, count, "read");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_read_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };
        let (dir_id, name) = match entry.file_info() {
            Some((d, n)) => (d.clone(), n.to_string()),
            None => {
                self.stats.record_read_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }
        };
        drop(entry); // Release the borrow before async operations

        // Check if we have buffered writes - if so, flush first for read-after-write consistency
        if self.write_buffers.contains_key(&id) {
            debug!(id, "Flushing buffer before read for consistency");
            // Invalidate read cache since we're about to write new content
            self.read_cache.invalidate(&id);
            if let Err(e) = self.flush_buffer(id).await {
                self.stats.record_read_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        }

        // Try to get content from cache first
        let content = if let Some(cached) = self.read_cache.get(&id) {
            trace!(id, "Read cache hit");
            cached.value
        } else {
            // Cache miss - decrypt the file and cache it
            trace!(id, "Read cache miss, decrypting file");
            self.stats.start_read();
            let result = self.ops.read_file(&dir_id, &name).await;
            self.stats.finish_read();

            let decrypted = match result {
                Ok(d) => d,
                Err(e) => {
                    self.stats.record_read_latency(op_start.elapsed());
                    self.stats.record_error();
                    return Err(vault_error_to_nfsstat(&e));
                }
            };

            // Cache the decrypted content for subsequent reads
            let content = decrypted.content;
            self.read_cache.insert(id, content.clone());
            self.stats.record_decrypted(content.len() as u64);
            content
        };

        let start = offset as usize;
        let end = (offset as usize + count as usize).min(content.len());

        if start >= content.len() {
            self.stats.record_read_latency(op_start.elapsed());
            return Ok((vec![], true)); // EOF
        }

        let data = content[start..end].to_vec();
        let eof = end >= content.len();

        // Record bytes read
        self.stats.record_read(data.len() as u64);
        self.stats.record_read_latency(op_start.elapsed());

        Ok((data, eof))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let op_start = Instant::now();
        debug!(id, offset, data_len = data.len(), "write");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_write_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };
        let (dir_id, name) = match entry.file_info() {
            Some((d, n)) => (d.clone(), n.to_string()),
            None => {
                self.stats.record_write_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }
        };
        drop(entry); // Release the borrow before async operations

        // Invalidate read cache since file content is changing
        self.read_cache.invalidate(&id);

        // Get or create write buffer for this file
        let mut buffer = match self.get_or_create_buffer(id, &dir_id, &name).await {
            Ok(b) => b,
            Err(e) => {
                self.stats.record_write_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };

        // Write to buffer
        buffer.write(offset, data);
        let new_size = buffer.len();

        // Record bytes written
        self.stats.record_write(data.len() as u64);
        self.stats.record_write_latency(op_start.elapsed());

        // Return attributes with updated size
        // Note: We don't flush here - let read() or setattr() handle that
        Ok(self.file_attr(id, new_size))
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "create");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create empty file
        if let Err(e) = self.ops.write_file(&dir_id, name, &[]).await {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(vault_error_to_nfsstat(&e));
        }

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::File {
            dir_id: dir_id.clone(),
            name: name.to_string(),
        };
        let id = self.inodes.get_or_insert(child_path, kind);

        let attr = self.file_attr(id, 0);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "create_exclusive");

        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Check if file already exists
        if let Ok(Some(_)) = self.ops.find_file(&dir_id, name).await {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(nfsstat3::NFS3ERR_EXIST);
        }

        // Create using regular create (which has its own stats recording)
        match self.create(dirid, filename, sattr3::default()).await {
            Ok((id, _)) => {
                self.stats.record_metadata_latency(start.elapsed());
                Ok(id)
            }
            Err(e) => {
                // Error already recorded in create()
                self.stats.record_metadata_latency(start.elapsed());
                Err(e)
            }
        }
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(dirname) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "mkdir");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let parent_dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create directory in vault
        let new_dir_id = match self.ops.create_directory(&parent_dir_id, name).await {
            Ok(id) => id,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::Directory {
            dir_id: new_dir_id,
        };
        let id = self.inodes.get_or_insert(child_path, kind);

        let attr = self.dir_attr(id);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "remove");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Get file ID to discard any pending write buffer and read cache
        let child_path = parent_path.join(name);
        if let Some(file_id) = self.inodes.get_id(&child_path) {
            // Discard pending writes - file is being deleted
            self.write_buffers.remove(&file_id);
            // Invalidate read cache for the deleted file
            self.read_cache.invalidate(&file_id);
        }

        // Try to remove as file first
        if let Ok(Some(_)) = self.ops.find_file(&dir_id, name).await {
            if let Err(e) = self.ops.delete_file(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else if self.ops.find_symlink(&dir_id, name).await.ok().flatten().is_some() {
            // It's a symlink - use O(1) lookup
            if let Err(e) = self.ops.delete_symlink(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else if let Ok(Some(_)) = self.ops.find_directory(&dir_id, name).await {
            // It's a directory
            if let Err(e) = self.ops.delete_directory(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        // Remove from inode table
        self.inodes.remove(&child_path);

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let from_name = match Self::filename_to_str(from_filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let to_name = match Self::filename_to_str(to_filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(from_dirid, from_name, to_dirid, to_name, "rename");

        let from_parent_path = match self.get_parent_path(from_dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let from_dir_id = match self.get_dir_entry(from_dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let to_dir_id = match self.get_dir_entry(to_dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Flush any pending writes for the source file before rename
        let from_path = from_parent_path.join(from_name);
        if let Some(file_id) = self.inodes.get_id(&from_path)
            && self.write_buffers.contains_key(&file_id)
        {
            debug!(file_id, "Flushing buffer before rename");
            // Invalidate read cache since we're writing new content
            self.read_cache.invalidate(&file_id);
            if let Err(e) = self.flush_buffer(file_id).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        }

        // Determine entry type and perform appropriate rename/move
        if let Ok(Some(_)) = self.ops.find_file(&from_dir_id, from_name).await {
            // It's a file
            if from_dir_id == to_dir_id && from_name != to_name {
                // Same directory, just rename
                if let Err(e) = self.ops.rename_file(&from_dir_id, from_name, to_name).await {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(vault_error_to_nfsstat(&e));
                }
            } else {
                // Cross-directory move (and optionally rename)
                if let Err(e) = self
                    .ops
                    .move_and_rename_file(&from_dir_id, from_name, &to_dir_id, to_name)
                    .await
                {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(vault_error_to_nfsstat(&e));
                }
            }
        } else if let Ok(Some(_)) = self.ops.find_directory(&from_dir_id, from_name).await {
            // It's a directory - only same-directory rename is supported
            if from_dir_id == to_dir_id {
                if let Err(e) = self
                    .ops
                    .rename_directory(&from_dir_id, from_name, to_name)
                    .await
                {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(vault_error_to_nfsstat(&e));
                }
            } else {
                // Cross-directory move of directories not supported
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(nfsstat3::NFS3ERR_NOTSUPP);
            }
        } else {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        // Update inode table
        let old_path = from_parent_path.join(from_name);
        let to_parent_path = match self.get_parent_path(to_dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let new_path = to_parent_path.join(to_name);

        if let Some(id) = self.inodes.get_id(&old_path) {
            self.inodes.update_path(id, &old_path, new_path);
        }

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(dirid, start_after, max_entries, "readdir");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let cipher = self.ops.cipher_combo();

        // Build entry list from vault
        let mut entries: Vec<DirEntry> = Vec::new();

        // List files
        let files = match self.ops.list_files(&dir_id).await {
            Ok(f) => f,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for file_info in files {
            let child_path = parent_path.join(&file_info.name);
            let kind = InodeKind::File {
                dir_id: dir_id.clone(),
                name: file_info.name.clone(),
            };
            let id = self.inodes.get_or_insert(child_path, kind);
            // Convert encrypted size to plaintext size
            let size = encrypted_to_plaintext_size_or_zero_for_cipher(file_info.encrypted_size, cipher);
            let attr = self.file_attr(id, size);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(file_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // List directories
        let dirs = match self.ops.list_directories(&dir_id).await {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for dir_info in dirs {
            let child_path = parent_path.join(&dir_info.name);
            let kind = InodeKind::Directory {
                dir_id: dir_info.directory_id,
            };
            let id = self.inodes.get_or_insert(child_path, kind);
            let attr = self.dir_attr(id);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(dir_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // List symlinks
        let symlinks = match self.ops.list_symlinks(&dir_id).await {
            Ok(s) => s,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for symlink_info in symlinks {
            let child_path = parent_path.join(&symlink_info.name);
            let kind = InodeKind::Symlink {
                dir_id: dir_id.clone(),
                name: symlink_info.name.clone(),
            };
            let id = self.inodes.get_or_insert(child_path, kind);
            let attr = self.symlink_attr(id, symlink_info.target.len() as u64);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(symlink_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // Sort entries by name for deterministic ordering
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Handle pagination
        let start_idx = if start_after == 0 {
            0
        } else {
            entries
                .iter()
                .position(|e| e.fileid == start_after)
                .map(|i| i + 1)
                .unwrap_or(0)
        };

        let result_entries: Vec<DirEntry> =
            entries.into_iter().skip(start_idx).take(max_entries).collect();

        let end = result_entries.len() < max_entries;

        self.stats.record_metadata_latency(start.elapsed());
        Ok(ReadDirResult {
            entries: result_entries,
            end,
        })
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink_target: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(linkname) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let target = match std::str::from_utf8(symlink_target) {
            Ok(t) => t,
            Err(_) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(nfsstat3::NFS3ERR_INVAL);
            }
        };
        debug!(dirid, name, target, "symlink");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create symlink in vault
        if let Err(e) = self.ops.create_symlink(&dir_id, name, target).await {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(vault_error_to_nfsstat(&e));
        }

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::Symlink {
            dir_id: dir_id.clone(),
            name: name.to_string(),
        };
        let id = self.inodes.get_or_insert(child_path, kind);

        let attr = self.symlink_attr(id, target.len() as u64);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, "readlink");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        match &entry.kind {
            InodeKind::Symlink { dir_id, name } => {
                let target = match self.ops.read_symlink(dir_id, name).await {
                    Ok(t) => t,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(vault_error_to_nfsstat(&e));
                    }
                };
                self.stats.record_metadata_latency(start.elapsed());
                Ok(nfsstring(target.into_bytes()))
            }
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                Err(nfsstat3::NFS3ERR_INVAL)
            }
        }
    }
}
