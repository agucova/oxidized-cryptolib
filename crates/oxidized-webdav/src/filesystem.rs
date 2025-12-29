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
use oxidized_cryptolib::vault::operations_async::VaultOperationsAsync;
use oxidized_cryptolib::vault::DirId;
use oxidized_mount_common::{HandleTable, TtlCache, VaultStats, WriteBuffer};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, instrument, trace};

/// Type alias for write buffer table (path -> WriteBuffer).
type WriteBufferTable = HandleTable<String, WriteBuffer>;

/// Type alias for metadata cache (path -> CryptomatorMetaData).
type MetadataCache = TtlCache<String, CryptomatorMetaData>;

/// Type alias for path resolution cache (path -> DirId).
type PathResolutionCache = TtlCache<String, DirId>;

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
        let mut metadata_cache = TtlCache::with_defaults();
        metadata_cache.set_stats(stats.cache_stats());

        // Create path resolution cache with longer TTL (5s)
        // Path structure changes less frequently than file contents
        let path_cache = TtlCache::new(PATH_CACHE_TTL);

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
            format!("/{}", normalized)
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
    /// Uses `list_all` for efficient single-call fetching of all directory entries
    /// instead of 3 separate calls for files, directories, and symlinks.
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

        // Use list_all for efficient single-call lookup (instead of 3 sequential calls)
        let (files, dirs, symlinks) = self
            .ops
            .list_all(&parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;

        // Search in directories first (most common for path resolution)
        if let Some(dir_info) = dirs.into_iter().find(|d| d.name == name) {
            let meta = CryptomatorMetaData::from_directory(&dir_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
        }

        // Search in files
        if let Some(file_info) = files.into_iter().find(|f| f.name == name) {
            let meta = CryptomatorMetaData::from_file(&file_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
        }

        // Search in symlinks
        if let Some(symlink_info) = symlinks.into_iter().find(|s| s.name == name) {
            let meta = CryptomatorMetaData::from_symlink(&symlink_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
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
}

impl DavFileSystem for CryptomatorWebDav {
    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let open_start = std::time::Instant::now();
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, options = ?options, "Opening file");

            // Check if we have an existing write buffer for this path
            if let Some(buf_ref) = self.write_buffers.get_mut(&vault_path) {
                let filename = buf_ref.filename().to_string();
                drop(buf_ref);
                // Return a file handle that references the existing buffer
                // For simplicity, we create a new buffer with the same content
                let buffer = self.write_buffers.remove(&vault_path).unwrap();
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
                let resolve_start = std::time::Instant::now();
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;
                let resolve_elapsed = resolve_start.elapsed();
                if resolve_elapsed.as_millis() > 10 {
                    tracing::warn!(path = %vault_path, elapsed_ms = resolve_elapsed.as_millis(), "Slow resolve_path")
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
                let buffer = self.write_buffers.remove(&vault_path).unwrap();
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
                // Read mode: open streaming reader
                let resolve_start = std::time::Instant::now();
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;
                let resolve_elapsed = resolve_start.elapsed();
                if resolve_elapsed.as_millis() > 10 {
                    tracing::warn!(path = %vault_path, elapsed_ms = resolve_elapsed.as_millis(), "Slow resolve_path (read)");
                }
                let reader = self
                    .ops
                    .open_file(&dir_id, &filename)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                let file = CryptomatorFile::reader(reader, filename, self.stats.clone());
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
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Reading directory");

            let dir_id = self.resolve_dir_path(&vault_path).await?;

            // Use list_all for efficiency (single lock, concurrent fetches)
            let (files, dirs, symlinks) = self
                .ops
                .list_all(&dir_id)
                .await
                .map_err(vault_error_to_fs_error)?;

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

            Ok(Box::pin(stream::iter(entries.into_iter().map(Ok))) as FsStream<_>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let meta_start = std::time::Instant::now();
            let vault_path = Self::parse_path(path);
            trace!(vault_path = %vault_path, "Getting metadata");

            let meta = self.find_entry(&vault_path).await?;
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Creating directory");

            // Check if the path already exists (RFC 4918: MKCOL on existing resource returns 405)
            if self.find_entry(&vault_path).await.is_ok() {
                return Err(FsError::Exists);
            }

            let (parent_dir_id, name) = self.resolve_path(&vault_path).await?;

            self.ops
                .create_directory(&parent_dir_id, &name)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate caches for the new directory
            self.metadata_cache.invalidate(&vault_path);
            // Don't need to invalidate path_cache - new dir won't be in it yet

            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Removing directory");

            let (parent_dir_id, name) = self.resolve_path(&vault_path).await?;

            self.ops
                .delete_directory(&parent_dir_id, &name)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate caches for the directory and all children
            self.metadata_cache.invalidate_prefix(&vault_path);
            self.path_cache.invalidate_prefix(&vault_path);

            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, "Removing file");

            // First flush any pending writes
            self.flush_write_buffer(&vault_path).await.ok();

            let (parent_dir_id, name) = self.resolve_path(&vault_path).await?;

            // Try to delete as file first
            if self.ops.delete_file(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                return Ok(());
            }

            // Try as symlink
            if self.ops.delete_symlink(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                return Ok(());
            }

            // Try as directory (WebDAV DELETE can target directories too)
            if self.ops.delete_directory(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate_prefix(&vault_path);
                self.path_cache.invalidate_prefix(&vault_path);
                return Ok(());
            }

            Err(FsError::NotFound)
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_path = Self::parse_path(from);
            let to_path = Self::parse_path(to);
            debug!(from = %from_path, to = %to_path, "Renaming/moving");

            // Flush any pending writes on source
            self.flush_write_buffer(&from_path).await.ok();

            let (from_dir_id, from_name) = self.resolve_path(&from_path).await?;
            let (to_dir_id, to_name) = self.resolve_path(&to_path).await?;

            // Determine if source is a directory or file
            let source_meta = self.find_entry(&from_path).await?;

            if source_meta.is_dir() {
                // Directory operations
                if from_dir_id != to_dir_id {
                    // Cross-directory move not supported for directories
                    debug!("Cross-directory move not supported for directories");
                    return Err(FsError::NotImplemented);
                }
                // Same directory rename
                self.ops
                    .rename_directory(&from_dir_id, &from_name, &to_name)
                    .await
                    .map_err(write_error_to_fs_error)?;
            } else {
                // File operations
                // dav-server doesn't delete destination files for us when Overwrite: T is set,
                // so we need to delete the destination if it exists.
                // (dav-server only deletes destination directories, not files)
                if let Ok(dest_meta) = self.find_entry(&to_path).await {
                    if dest_meta.is_file() {
                        debug!(dest = %to_path, "Deleting existing destination file for overwrite");
                        self.ops
                            .delete_file(&to_dir_id, &to_name)
                            .await
                            .map_err(write_error_to_fs_error)?;
                    }
                }

                if from_dir_id == to_dir_id && from_name != to_name {
                    // Same directory, just rename
                    self.ops
                        .rename_file(&from_dir_id, &from_name, &to_name)
                        .await
                        .map_err(write_error_to_fs_error)?;
                } else if from_name == to_name {
                    // Different directory, same name - move
                    self.ops
                        .move_file(&from_dir_id, &from_name, &to_dir_id)
                        .await
                        .map_err(write_error_to_fs_error)?;
                } else {
                    // Different directory and name - move and rename
                    self.ops
                        .move_and_rename_file(&from_dir_id, &from_name, &to_dir_id, &to_name)
                        .await
                        .map_err(write_error_to_fs_error)?;
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

            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_path = Self::parse_path(from);
            let to_path = Self::parse_path(to);
            debug!(from = %from_path, to = %to_path, "Copying");

            let (from_dir_id, from_name) = self.resolve_path(&from_path).await?;
            let (to_dir_id, to_name) = self.resolve_path(&to_path).await?;

            // Read source file
            let content = self
                .ops
                .read_file(&from_dir_id, &from_name)
                .await
                .map_err(vault_error_to_fs_error)?;

            // Write to destination
            self.ops
                .write_file(&to_dir_id, &to_name, &content.content)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate cache for the destination
            self.metadata_cache.invalidate(&to_path);

            Ok(())
        })
    }

    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
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
