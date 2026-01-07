//! WebDAV filesystem implementation for Cryptomator vaults.
//!
//! This module provides the `DavFileSystem` trait implementation that wraps
//! `VaultOperationsAsync` to expose vault contents via WebDAV.

use crate::dir_entry::CryptomatorDirEntry;
use crate::error::{vault_error_to_fs_error, write_error_to_fs_error, WebDavError};
use crate::file::CryptomatorFile;
use crate::metadata::CryptomatorMetaData;
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsStream, OpenOptions,
    ReadDirMeta,
};
use futures::stream;
use oxcrypt_core::vault::operations_async::VaultOperationsAsync;
use oxcrypt_core::vault::DirId;
use oxcrypt_mount::moka_cache::SyncTtlCache;
use oxcrypt_mount::{HandleTable, VaultStats, WriteBuffer};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, trace};

/// Type alias for write buffer table (path -> WriteBuffer).
type WriteBufferTable = HandleTable<String, WriteBuffer>;

/// Type alias for metadata cache (path -> CryptomatorMetaData).
type MetadataCache = SyncTtlCache<String, CryptomatorMetaData>;

/// Type alias for path resolution cache (path -> DirId).
type PathResolutionCache = SyncTtlCache<String, DirId>;

/// TTL for path resolution cache entries (5 seconds - longer than metadata).
/// Path structure changes less frequently than file contents.
const PATH_CACHE_TTL: Duration = Duration::from_secs(5);

/// WebDAV filesystem backed by a Cryptomator vault.
///
/// Implements the `DavFileSystem` trait from dav-server to expose
/// an encrypted vault as a WebDAV resource.
///
/// # Performance Optimizations
///
/// This implementation includes several caches to reduce vault operations:
/// - **Path resolution cache**: Maps vault paths to directory IDs (5s TTL)
/// - **Metadata cache**: Caches file/directory metadata (1s TTL)
/// - **File info cache**: At VaultOperationsAsync level, caches encrypted paths
#[derive(Clone)]
pub struct CryptomatorWebDav {
    /// Shared vault operations (thread-safe via Arc).
    ops: Arc<VaultOperationsAsync>,
    /// Write buffer table for pending PUT operations.
    write_buffers: Arc<WriteBufferTable>,
    /// Metadata cache to reduce vault operations.
    metadata_cache: Arc<MetadataCache>,
    /// Path resolution cache (vault_path -> DirId).
    path_cache: Arc<PathResolutionCache>,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl CryptomatorWebDav {
    /// Create a new WebDAV filesystem from vault operations.
    pub fn new(ops: Arc<VaultOperationsAsync>) -> Self {
        // Create stats first so we can connect caches to it
        let stats = Arc::new(VaultStats::new());

        // Create metadata cache and connect it to stats for hit/miss tracking
        let mut metadata_cache = SyncTtlCache::with_defaults();
        metadata_cache.set_stats(stats.cache_stats());

        // Create path resolution cache with longer TTL (5s)
        // Path structure changes less frequently than file contents
        let path_cache = SyncTtlCache::new(PATH_CACHE_TTL);

        Self {
            ops,
            write_buffers: Arc::new(HandleTable::new()),
            metadata_cache: Arc::new(metadata_cache),
            path_cache: Arc::new(path_cache),
            stats,
        }
    }

    /// Open a vault and create a WebDAV filesystem.
    pub fn open(vault_path: &Path, password: &str) -> Result<Self, WebDavError> {
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| WebDavError::Server(e.to_string()))?
            .into_shared();

        Ok(Self::new(ops))
    }

    /// Get the statistics for this filesystem.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
    }

    /// Parse a WebDAV path to a vault path string.
    fn parse_path(path: &DavPath) -> String {
        let path_str = path.as_url_string();
        // Remove leading slash if present, then re-add it for consistency
        // Also remove trailing slash which would cause parsing issues
        let normalized = path_str.trim_start_matches('/').trim_end_matches('/');
        tracing::trace!(raw_path = %path_str, normalized = %normalized, "parse_path");
        if normalized.is_empty() {
            String::new()
        } else {
            format!("/{normalized}")
        }
    }

    /// Split a path into parent directory ID and filename.
    async fn resolve_path(&self, path: &str) -> Result<(DirId, String), FsError> {
        if path.is_empty() || path == "/" {
            return Err(FsError::GeneralFailure); // Can't split root
        }

        let path = path.trim_start_matches('/');
        let components: Vec<&str> = path.split('/').collect();

        if components.is_empty() {
            return Err(FsError::GeneralFailure);
        }

        let filename = components.last().unwrap().to_string();
        let parent_path = if components.len() == 1 {
            String::new() // Parent is root
        } else {
            format!("/{}", components[..components.len() - 1].join("/"))
        };

        let parent_dir_id = self.resolve_dir_path(&parent_path).await?;
        Ok((parent_dir_id, filename))
    }

    /// Resolve a path to a directory ID (cached).
    async fn resolve_dir_path(&self, path: &str) -> Result<DirId, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(DirId::root());
        }

        // Check path resolution cache first
        let path_key = path.to_string();
        if let Some(cached) = self.path_cache.get(&path_key) {
            trace!(path = %path, "path resolution cache hit");
            return Ok(cached.value);
        }

        // Cache miss - resolve path
        let (dir_id, _is_dir) = self.ops
            .resolve_path(path)
            .await
            .map_err(vault_error_to_fs_error)?;

        // Cache the resolved directory ID
        self.path_cache.insert(path_key, dir_id.clone());
        trace!(path = %path, dir_id = %dir_id.as_str(), "path resolution cache miss, cached");

        Ok(dir_id)
    }

    /// Find metadata for a path (file, directory, or symlink).
    ///
    /// Uses O(1) direct lookups (`find_directory`, `find_file`, `find_symlink`)
    /// instead of listing the entire parent directory. This is critical for
    /// performance when directories contain many files.
    async fn find_entry(&self, path: &str) -> Result<CryptomatorMetaData, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(CryptomatorMetaData::root());
        }

        // Check cache first
        let path_key = path.to_string();
        if let Some(cached) = self.metadata_cache.get(&path_key) {
            trace!(path = %path, "metadata cache hit");
            return Ok(cached.value);
        }

        let (parent_dir_id, name) = self.resolve_path(path).await?;

        // Try O(1) lookup for directories first (most common for path resolution)
        // Note: find_directory may return ENOTDIR if the encrypted file is a regular file
        // In that case, we treat it as "not a directory" and continue to file lookup
        match self.ops.find_directory(&parent_dir_id, &name).await {
            Ok(Some(dir_info)) => {
                let meta = CryptomatorMetaData::from_directory(&dir_info);
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found directory via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {}  // Not a directory, continue to file lookup
            Err(e) => {
                // ENOTDIR (error code 20) means we tried to open a file as a directory
                // This is expected when the path is a file, so we treat it as "not found"
                // and continue to the next lookup
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20)) {
                    // Not a directory - continue to file lookup
                } else {
                    // Other errors should be propagated
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        // Try O(1) lookup for files
        match self.ops.find_file(&parent_dir_id, &name).await {
            Ok(Some(file_info)) => {
                let meta = CryptomatorMetaData::from_file(&file_info);
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found file via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {}  // Not a file, continue to symlink lookup
            Err(e) => {
                // Similar to directories, ENOTDIR means we tried to read a directory as a file
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20)) {
                    // Not a file - continue to symlink lookup
                } else {
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        // Try O(1) lookup for symlinks
        match self.ops.find_symlink(&parent_dir_id, &name).await {
            Ok(Some(symlink_info)) => {
                let meta = CryptomatorMetaData::from_symlink(&symlink_info);
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found symlink via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {}  // Not a symlink
            Err(e) => {
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20)) {
                    // Not a symlink
                } else {
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        Err(FsError::NotFound)
    }

    /// Flush a write buffer to the vault.
    async fn flush_write_buffer(&self, path: &str) -> Result<(), FsError> {
        let path_key = path.to_string();
        if let Some(buffer) = self.write_buffers.remove(&path_key)
            && buffer.is_dirty() {
                let dir_id = buffer.dir_id().clone();
                let filename = buffer.filename().to_string();
                let content = buffer.into_content();

                debug!(path = %path, size = content.len(), "Flushing write buffer to vault");

                self.ops
                    .write_file(&dir_id, &filename, &content)
                    .await
                    .map_err(write_error_to_fs_error)?;

                // Invalidate cache since file size has changed
                self.metadata_cache.invalidate(&path_key);
            }
        Ok(())
    }

    fn join_path(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            format!("/{name}")
        } else {
            format!("{}/{}", parent.trim_end_matches('/'), name)
        }
    }

    async fn delete_directory_contents_recursive(
        &self,
        dir_id: &DirId,
        dir_path: &str,
    ) -> Result<(), FsError> {
        let mut stack: Vec<(DirId, String, DirId, String, bool)> = Vec::new();

        let (files, dirs, symlinks) = self
            .ops
            .list_all(dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;

        for file in files {
            let file_path = Self::join_path(dir_path, &file.name);
            self.flush_write_buffer(&file_path).await.ok();
            self.ops
                .delete_file(dir_id, &file.name)
                .await
                .map_err(write_error_to_fs_error)?;
            self.metadata_cache.invalidate(&file_path);
        }

        for symlink in symlinks {
            let symlink_path = Self::join_path(dir_path, &symlink.name);
            self.ops
                .delete_symlink(dir_id, &symlink.name)
                .await
                .map_err(write_error_to_fs_error)?;
            self.metadata_cache.invalidate(&symlink_path);
        }

        for dir in dirs {
            let child_path = Self::join_path(dir_path, &dir.name);
            stack.push((
                dir_id.clone(),
                dir.name,
                dir.directory_id,
                child_path,
                false,
            ));
        }

        while let Some((parent_dir_id, dir_name, current_dir_id, current_path, visited)) =
            stack.pop()
        {
            if visited {
                self.ops
                    .delete_directory(&parent_dir_id, &dir_name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate_prefix(&current_path);
                self.path_cache.invalidate_prefix(&current_path);
                continue;
            }

            stack.push((
                parent_dir_id.clone(),
                dir_name.clone(),
                current_dir_id.clone(),
                current_path.clone(),
                true,
            ));

            let (files, dirs, symlinks) = self
                .ops
                .list_all(&current_dir_id)
                .await
                .map_err(vault_error_to_fs_error)?;

            for file in files {
                let file_path = Self::join_path(&current_path, &file.name);
                self.flush_write_buffer(&file_path).await.ok();
                self.ops
                    .delete_file(&current_dir_id, &file.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&file_path);
            }

            for symlink in symlinks {
                let symlink_path = Self::join_path(&current_path, &symlink.name);
                self.ops
                    .delete_symlink(&current_dir_id, &symlink.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&symlink_path);
            }

            for dir in dirs {
                let child_path = Self::join_path(&current_path, &dir.name);
                stack.push((
                    current_dir_id.clone(),
                    dir.name,
                    dir.directory_id,
                    child_path,
                    false,
                ));
            }
        }

        Ok(())
    }

    async fn delete_directory_recursive(
        &self,
        parent_dir_id: &DirId,
        dir_name: &str,
        dir_path: &str,
    ) -> Result<(), FsError> {
        let dirs = self
            .ops
            .list_directories(parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;
        let dir_info = dirs
            .into_iter()
            .find(|dir| dir.name == dir_name)
            .ok_or(FsError::NotFound)?;

        self.delete_directory_contents_recursive(&dir_info.directory_id, dir_path)
            .await?;
        self.ops
            .delete_directory(parent_dir_id, dir_name)
            .await
            .map_err(write_error_to_fs_error)?;
        Ok(())
    }

    async fn copy_directory_recursive(
        &self,
        from_dir_id: &DirId,
        to_dir_id: &DirId,
        from_path: &str,
        to_path: &str,
    ) -> Result<(), FsError> {
        let mut stack: Vec<(DirId, DirId, String, String)> = Vec::new();
        stack.push((
            from_dir_id.clone(),
            to_dir_id.clone(),
            from_path.to_string(),
            to_path.to_string(),
        ));

        while let Some((current_from_id, current_to_id, current_from_path, current_to_path)) =
            stack.pop()
        {
            let (files, dirs, symlinks) = self
                .ops
                .list_all(&current_from_id)
                .await
                .map_err(vault_error_to_fs_error)?;

            for file in files {
                let source_path = Self::join_path(&current_from_path, &file.name);
                self.flush_write_buffer(&source_path).await.ok();
                let content = self
                    .ops
                    .read_file(&current_from_id, &file.name)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                self.ops
                    .write_file(&current_to_id, &file.name, &content.content)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let dest_path = Self::join_path(&current_to_path, &file.name);
                self.metadata_cache.invalidate(&dest_path);
            }

            for symlink in symlinks {
                let target = self
                    .ops
                    .read_symlink(&current_from_id, &symlink.name)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                self.ops
                    .create_symlink(&current_to_id, &symlink.name, &target)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let dest_path = Self::join_path(&current_to_path, &symlink.name);
                self.metadata_cache.invalidate(&dest_path);
            }

            for dir in dirs {
                let new_dir_id = self
                    .ops
                    .create_directory(&current_to_id, &dir.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let child_from_path = Self::join_path(&current_from_path, &dir.name);
                let child_to_path = Self::join_path(&current_to_path, &dir.name);
                stack.push((
                    dir.directory_id,
                    new_dir_id,
                    child_from_path,
                    child_to_path.clone(),
                ));
                self.metadata_cache.invalidate_prefix(&child_to_path);
                self.path_cache.invalidate_prefix(&child_to_path);
            }
        }

        Ok(())
    }
}

impl DavFileSystem for CryptomatorWebDav {
    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let open_start = Instant::now();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, options = ?options, "Opening file");

            if options.create_new && self.write_buffers.get_mut(&vault_path).is_some() {
                return Err(FsError::Exists);
            }

            // Check if we have an existing write buffer for this path
            if let Some(buf_ref) = self.write_buffers.get_mut(&vault_path) {
                let filename = buf_ref.filename().to_string();
                drop(buf_ref);
                // Return a file handle that references the existing buffer
                // For simplicity, we create a new buffer with the same content
                let buffer = self.write_buffers.remove(&vault_path).ok_or_else(|| {
                    tracing::error!(path = %vault_path, "Write buffer disappeared between check and remove");
                    FsError::GeneralFailure
                })?;
                let file = CryptomatorFile::writer(
                    buffer,
                    filename,
                    self.ops.clone(),
                    vault_path.clone(),
                    self.metadata_cache.clone(),
                    self.stats.clone(),
                );
                return Ok(Box::new(file) as Box<dyn DavFile>);
            }

            if options.write || options.create || options.create_new {
                // Write mode: create a write buffer
                let resolve_start = Instant::now();
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;
                let resolve_elapsed = resolve_start.elapsed();
                if resolve_elapsed.as_millis() > 10 {
                    tracing::warn!(path = %vault_path, elapsed_ms = resolve_elapsed.as_millis(), "Slow resolve_path");
                }

                if options.create_new {
                    match self.find_entry(&vault_path).await {
                        Ok(_) => return Err(FsError::Exists),
                        Err(FsError::NotFound) => {}
                        Err(e) => return Err(e),
                    }
                }

                let buffer = if options.create_new {
                    // New file, start empty
                    WriteBuffer::new_for_create(dir_id, filename.clone())
                } else if options.truncate {
                    // Truncate: file will be rewritten from scratch
                    // Use new_for_create to mark as dirty so empty files are created
                    WriteBuffer::new_for_create(dir_id, filename.clone())
                } else {
                    // Open existing file for append/modify
                    match self.ops.read_file(&dir_id, &filename).await {
                        Ok(content) => WriteBuffer::new(dir_id, filename.clone(), content.content),
                        Err(_) if options.create => {
                            // File doesn't exist, create new
                            WriteBuffer::new_for_create(dir_id, filename.clone())
                        }
                        Err(e) => return Err(vault_error_to_fs_error(e)),
                    }
                };

                self.write_buffers.insert(vault_path.clone(), buffer);
                let buffer = self.write_buffers.remove(&vault_path).ok_or_else(|| {
                    tracing::error!(path = %vault_path, "Write buffer disappeared immediately after insert");
                    FsError::GeneralFailure
                })?;
                let file = CryptomatorFile::writer(
                    buffer,
                    filename,
                    self.ops.clone(),
                    vault_path.clone(),
                    self.metadata_cache.clone(),
                    self.stats.clone(),
                );
                let open_elapsed = open_start.elapsed();
                if open_elapsed.as_millis() > 50 {
                    tracing::warn!(path = %vault_path, elapsed_ms = open_elapsed.as_millis(), "Slow write open");
                }
                Ok(Box::new(file) as Box<dyn DavFile>)
            } else {
                // Read mode: load file content into memory buffer
                // NOTE: We use read_file instead of open_file because open_file returns
                // a VaultFileReader that holds directory read locks for its lifetime.
                // This could block write operations (like delete) on the same directory.
                // By reading the entire file into memory at open time, we release locks
                // immediately and avoid contention.
                let resolve_start = Instant::now();
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;
                let resolve_elapsed = resolve_start.elapsed();
                if resolve_elapsed.as_millis() > 10 {
                    tracing::warn!(path = %vault_path, elapsed_ms = resolve_elapsed.as_millis(), "Slow resolve_path (read)");
                }
                let decrypted = self
                    .ops
                    .read_file(&dir_id, &filename)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                let file = CryptomatorFile::reader(decrypted.content, filename, self.stats.clone());
                let open_elapsed = open_start.elapsed();
                if open_elapsed.as_millis() > 50 {
                    tracing::warn!(path = %vault_path, elapsed_ms = open_elapsed.as_millis(), "Slow read open");
                }
                Ok(Box::new(file) as Box<dyn DavFile>)
            }
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Reading directory");

            let dir_id = match self.resolve_dir_path(&vault_path).await {
                Ok(id) => id,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Use list_all for efficiency (single lock, concurrent fetches)
            let (files, dirs, symlinks) = match self.ops.list_all(&dir_id).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(vault_error_to_fs_error(e));
                }
            };

            let mut entries: Vec<Box<dyn DavDirEntry>> = Vec::new();

            // Add directories
            for dir_info in dirs {
                entries.push(Box::new(CryptomatorDirEntry::directory(dir_info)));
            }

            // Add files
            for file_info in files {
                entries.push(Box::new(CryptomatorDirEntry::file(file_info)));
            }

            // Add symlinks (as files - WebDAV doesn't support symlinks)
            for symlink_info in symlinks {
                entries.push(Box::new(CryptomatorDirEntry::symlink(symlink_info)));
            }

            trace!(count = entries.len(), "Directory entries found");

            self.stats.record_metadata_latency(start.elapsed());
            Ok(Box::pin(stream::iter(entries.into_iter().map(Ok))) as FsStream<_>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let _meta_start = Instant::now();
            let vault_path = Self::parse_path(path);
            trace!(vault_path = %vault_path, "Getting metadata");

            let meta = self.find_entry(&vault_path).await?;
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Creating directory");

            // Check if the path already exists (RFC 4918: MKCOL on existing resource returns 405)
            if self.find_entry(&vault_path).await.is_ok() {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::Exists);
            }

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if let Err(e) = self.ops.create_directory(&parent_dir_id, &name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(write_error_to_fs_error(e));
            }

            // Invalidate caches for the new directory
            self.metadata_cache.invalidate(&vault_path);
            // Don't need to invalidate path_cache - new dir won't be in it yet

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Removing directory");

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if let Err(e) = self
                .delete_directory_recursive(&parent_dir_id, &name, &vault_path)
                .await
            {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }

            // Invalidate caches for the directory and all children
            self.metadata_cache.invalidate_prefix(&vault_path);
            self.path_cache.invalidate_prefix(&vault_path);

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Removing file");

            // First flush any pending writes
            self.flush_write_buffer(&vault_path).await.ok();

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Try to delete as file first
            if self.ops.delete_file(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            // Try as symlink
            if self.ops.delete_symlink(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            // Try as directory (WebDAV DELETE can target directories too)
            if self
                .delete_directory_recursive(&parent_dir_id, &name, &vault_path)
                .await
                .is_ok()
            {
                self.metadata_cache.invalidate_prefix(&vault_path);
                self.path_cache.invalidate_prefix(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            Err(FsError::NotFound)
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let from_path = Self::parse_path(from);
            let to_path = Self::parse_path(to);
            debug!(from = %from_path, to = %to_path, "Renaming/moving");

            // Flush any pending writes on source
            self.flush_write_buffer(&from_path).await.ok();

            let (from_dir_id, from_name) = match self.resolve_path(&from_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };
            let (to_dir_id, to_name) = match self.resolve_path(&to_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Determine if source is a directory or file
            let source_meta = match self.find_entry(&from_path).await {
                Ok(meta) => meta,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if source_meta.is_dir() {
                // Directory operations
                if from_dir_id != to_dir_id {
                    let dirs = match self.ops.list_directories(&from_dir_id).await {
                        Ok(dirs) => dirs,
                        Err(e) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            return Err(vault_error_to_fs_error(e));
                        }
                    };
                    let source_dir = dirs
                        .into_iter()
                        .find(|dir| dir.name == from_name)
                        .ok_or(FsError::NotFound)?;
                    let new_dir_id = match self.ops.create_directory(&to_dir_id, &to_name).await {
                        Ok(new_dir_id) => new_dir_id,
                        Err(e) => {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            return Err(write_error_to_fs_error(e));
                        }
                    };
                    if let Err(e) = self
                        .copy_directory_recursive(
                            &source_dir.directory_id,
                            &new_dir_id,
                            &from_path,
                            &to_path,
                        )
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(e);
                    }
                    if let Err(e) = self
                        .delete_directory_recursive(&from_dir_id, &from_name, &from_path)
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(e);
                    }
                } else {
                    // Same directory rename
                    if let Err(e) = self
                        .ops
                        .rename_directory(&from_dir_id, &from_name, &to_name)
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                }
            } else {
                // File operations
                // dav-server doesn't delete destination files for us when Overwrite: T is set,
                // so we need to delete the destination if it exists.
                // (dav-server only deletes destination directories, not files)
                if let Ok(dest_meta) = self.find_entry(&to_path).await
                    && dest_meta.is_file() {
                        debug!(dest = %to_path, "Deleting existing destination file for overwrite");
                        if let Err(e) = self.ops.delete_file(&to_dir_id, &to_name).await {
                            self.stats.record_error();
                            self.stats.record_metadata_latency(start.elapsed());
                            return Err(write_error_to_fs_error(e));
                        }
                    }

                if from_dir_id == to_dir_id && from_name != to_name {
                    // Same directory, just rename
                    if let Err(e) = self
                        .ops
                        .rename_file(&from_dir_id, &from_name, &to_name)
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                } else if from_name == to_name {
                    // Different directory, same name - move
                    if let Err(e) = self
                        .ops
                        .move_file(&from_dir_id, &from_name, &to_dir_id)
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                } else {
                    // Different directory and name - move and rename
                    if let Err(e) = self
                        .ops
                        .move_and_rename_file(&from_dir_id, &from_name, &to_dir_id, &to_name)
                        .await
                    {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                }
            }

            // Invalidate caches for both source and destination
            self.metadata_cache.invalidate(&from_path);
            self.metadata_cache.invalidate(&to_path);
            // For directory renames, also invalidate path cache
            if source_meta.is_dir() {
                self.path_cache.invalidate_prefix(&from_path);
                self.path_cache.invalidate_prefix(&to_path);
            }

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let from_path = Self::parse_path(from);
            let to_path = Self::parse_path(to);
            debug!(from = %from_path, to = %to_path, "Copying");

            let source_meta = match self.find_entry(&from_path).await {
                Ok(meta) => meta,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            let (from_dir_id, from_name) = match self.resolve_path(&from_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };
            let (to_dir_id, to_name) = match self.resolve_path(&to_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if source_meta.is_dir() {
                let dirs = match self.ops.list_directories(&from_dir_id).await {
                    Ok(dirs) => dirs,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(vault_error_to_fs_error(e));
                    }
                };
                let source_dir = dirs
                    .into_iter()
                    .find(|dir| dir.name == from_name)
                    .ok_or(FsError::NotFound)?;
                let new_dir_id = match self.ops.create_directory(&to_dir_id, &to_name).await {
                    Ok(new_dir_id) => new_dir_id,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                };
                if let Err(e) = self
                    .copy_directory_recursive(
                        &source_dir.directory_id,
                        &new_dir_id,
                        &from_path,
                        &to_path,
                    )
                    .await
                {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
                self.metadata_cache.invalidate_prefix(&to_path);
                self.path_cache.invalidate_prefix(&to_path);
            } else if source_meta.is_symlink() {
                let target = self
                    .ops
                    .read_symlink(&from_dir_id, &from_name)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                self.ops
                    .create_symlink(&to_dir_id, &to_name, &target)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&to_path);
            } else {
                self.flush_write_buffer(&from_path).await.ok();
                // Read source file
                let content = match self.ops.read_file(&from_dir_id, &from_name).await {
                    Ok(content) => content,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(vault_error_to_fs_error(e));
                    }
                };

                // Write to destination
                if let Err(e) = self
                    .ops
                    .write_file(&to_dir_id, &to_name, &content.content)
                    .await
                {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(write_error_to_fs_error(e));
                }

                // Invalidate cache for the destination
                self.metadata_cache.invalidate(&to_path);
            }

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // We don't support WebDAV properties beyond the basics
        Box::pin(async { false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path() {
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/").unwrap()),
            ""
        );
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/test.txt").unwrap()),
            "/test.txt"
        );
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/foo/bar/baz.txt").unwrap()),
            "/foo/bar/baz.txt"
        );
    }
}
