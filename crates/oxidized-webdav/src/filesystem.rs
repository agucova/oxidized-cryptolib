//! WebDAV filesystem implementation for Cryptomator vaults.
//!
//! This module provides the `DavFileSystem` trait implementation that wraps
//! `VaultOperationsAsync` to expose vault contents via WebDAV.

use crate::cache::MetadataCache;
use crate::dir_entry::CryptomatorDirEntry;
use crate::error::{vault_error_to_fs_error, write_error_to_fs_error, WebDavError};
use crate::file::CryptomatorFile;
use crate::metadata::CryptomatorMetaData;
use crate::write_buffer::{WriteBuffer, WriteBufferTable};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsStream, OpenOptions,
    ReadDirMeta,
};
use futures::stream;
use oxidized_cryptolib::vault::operations_async::VaultOperationsAsync;
use oxidized_cryptolib::vault::DirId;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, instrument, trace, warn};

/// WebDAV filesystem backed by a Cryptomator vault.
///
/// Implements the `DavFileSystem` trait from dav-server to expose
/// an encrypted vault as a WebDAV resource.
#[derive(Clone)]
pub struct CryptomatorWebDav {
    /// Shared vault operations (thread-safe via Arc).
    ops: Arc<VaultOperationsAsync>,
    /// Write buffer table for pending PUT operations.
    write_buffers: Arc<WriteBufferTable>,
    /// Metadata cache to reduce vault operations.
    metadata_cache: Arc<MetadataCache>,
}

impl CryptomatorWebDav {
    /// Create a new WebDAV filesystem from vault operations.
    pub fn new(ops: Arc<VaultOperationsAsync>) -> Self {
        Self {
            ops,
            write_buffers: Arc::new(WriteBufferTable::new()),
            metadata_cache: Arc::new(MetadataCache::with_defaults()),
        }
    }

    /// Open a vault and create a WebDAV filesystem.
    pub fn open(vault_path: &Path, password: &str) -> Result<Self, WebDavError> {
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| WebDavError::Server(e.to_string()))?
            .into_shared();

        Ok(Self::new(ops))
    }

    /// Parse a WebDAV path to a vault path string.
    fn parse_path(path: &DavPath) -> String {
        let path_str = path.as_url_string();
        // Remove leading slash if present, then re-add it for consistency
        let normalized = path_str.trim_start_matches('/');
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

    /// Resolve a path to a directory ID.
    async fn resolve_dir_path(&self, path: &str) -> Result<DirId, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(DirId::root());
        }

        self.ops
            .resolve_path(path)
            .await
            .map(|(dir_id, _is_root)| dir_id)
            .map_err(vault_error_to_fs_error)
    }

    /// Find metadata for a path (file, directory, or symlink).
    async fn find_entry(&self, path: &str) -> Result<CryptomatorMetaData, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(CryptomatorMetaData::root());
        }

        // Check cache first
        if let Some(cached) = self.metadata_cache.get(path) {
            trace!(path = %path, "metadata cache hit");
            return Ok(cached.metadata);
        }

        let (parent_dir_id, name) = self.resolve_path(path).await?;

        // Try to find as directory first
        let dirs = self
            .ops
            .list_directories(&parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;
        if let Some(dir_info) = dirs.into_iter().find(|d| d.name == name) {
            let meta = CryptomatorMetaData::from_directory(&dir_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
        }

        // Try to find as file
        let files = self
            .ops
            .list_files(&parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;
        if let Some(file_info) = files.into_iter().find(|f| f.name == name) {
            let meta = CryptomatorMetaData::from_file(&file_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
        }

        // Try symlinks
        let symlinks = self
            .ops
            .list_symlinks(&parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;
        if let Some(symlink_info) = symlinks.into_iter().find(|s| s.name == name) {
            let meta = CryptomatorMetaData::from_symlink(&symlink_info);
            self.metadata_cache.insert(path.to_string(), meta.clone());
            return Ok(meta);
        }

        Err(FsError::NotFound)
    }

    /// Flush a write buffer to the vault.
    async fn flush_write_buffer(&self, path: &str) -> Result<(), FsError> {
        if let Some(buffer) = self.write_buffers.remove(path) && buffer.is_dirty() {
            let dir_id = buffer.dir_id().clone();
            let filename = buffer.filename().to_string();
            let content = buffer.into_content();

            debug!(path = %path, size = content.len(), "Flushing write buffer to vault");

            self.ops
                .write_file(&dir_id, &filename, &content)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate cache since file size has changed
            self.metadata_cache.invalidate(path);
        }
        Ok(())
    }
}

impl DavFileSystem for CryptomatorWebDav {
    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path);
            debug!(vault_path = %vault_path, options = ?options, "Opening file");

            // Check if we have an existing write buffer for this path
            if let Some(mut buf_ref) = self.write_buffers.get_mut(&vault_path) {
                let size = buf_ref.len();
                let filename = buf_ref.filename().to_string();
                drop(buf_ref);
                // Return a file handle that references the existing buffer
                // For simplicity, we create a new buffer with the same content
                let buffer = self.write_buffers.remove(&vault_path).unwrap();
                let file = CryptomatorFile::writer(buffer, filename);
                return Ok(Box::new(file) as Box<dyn DavFile>);
            }

            if options.write || options.create || options.create_new {
                // Write mode: create a write buffer
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;

                let buffer = if options.create_new {
                    // New file, start empty
                    WriteBuffer::new_for_create(dir_id, filename.clone())
                } else if options.truncate {
                    // Truncate existing file
                    WriteBuffer::new_empty(dir_id, filename.clone())
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
                let file = CryptomatorFile::writer(buffer, filename);
                Ok(Box::new(file) as Box<dyn DavFile>)
            } else {
                // Read mode: open streaming reader
                let (dir_id, filename) = self.resolve_path(&vault_path).await?;
                let reader = self
                    .ops
                    .open_file(&dir_id, &filename)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                let file = CryptomatorFile::reader(reader, filename);
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

            let (parent_dir_id, name) = self.resolve_path(&vault_path).await?;

            self.ops
                .create_directory(&parent_dir_id, &name)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate cache for the new directory
            self.metadata_cache.invalidate(&vault_path);

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

            // Invalidate cache for the directory and all children
            self.metadata_cache.invalidate_prefix(&vault_path);

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
            let result = match self.ops.delete_file(&parent_dir_id, &name).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Try as symlink
                    self.ops
                        .delete_symlink(&parent_dir_id, &name)
                        .await
                        .map_err(write_error_to_fs_error)
                }
            };

            // Invalidate cache for the removed file
            self.metadata_cache.invalidate(&vault_path);

            result
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

            // Invalidate cache for both source and destination
            self.metadata_cache.invalidate(&from_path);
            self.metadata_cache.invalidate(&to_path);

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
