//! WebDAV file handle implementation.
//!
//! This module provides the `DavFile` trait implementation for vault files,
//! supporting both streaming reads and buffered writes.

#![allow(dead_code)] // APIs used by DavFile trait

use crate::error::write_error_to_fs_error;
use crate::metadata::CryptomatorMetaData;
use bytes::Bytes;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use oxcrypt_core::vault::VaultOperationsAsync;
use oxcrypt_mount::moka_cache::SyncTtlCache;
use oxcrypt_mount::{VaultStats, WriteBuffer};
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::debug;

/// Type alias for the metadata cache.
type MetadataCache = SyncTtlCache<String, CryptomatorMetaData>;

/// A file handle for WebDAV operations.
///
/// Supports two modes:
/// - **Reader**: In-memory buffered read-only access
/// - **WriteBuffer**: Buffered write access with read-modify-write pattern
///
/// Both modes use in-memory buffers to avoid holding vault locks for the
/// duration of the HTTP request. This prevents lock contention when multiple
/// operations target the same directory.
pub enum CryptomatorFile {
    /// Read-only in-memory buffer for GET requests.
    Reader(ReaderHandle),
    /// Write buffer for PUT requests.
    Writer(WriterHandle),
}

impl std::fmt::Debug for CryptomatorFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptomatorFile::Reader(h) => f
                .debug_struct("CryptomatorFile::Reader")
                .field("filename", &h.filename)
                .field("position", &h.position)
                .field("size", &h.size)
                .finish(),
            CryptomatorFile::Writer(h) => f
                .debug_struct("CryptomatorFile::Writer")
                .field("filename", &h.filename)
                .field("position", &h.position)
                .finish(),
        }
    }
}

/// Handle for read-only file access.
///
/// Uses an in-memory buffer that is populated at open time using `read_file`.
/// This avoids holding vault locks for the lifetime of the HTTP request,
/// preventing lock contention with concurrent write operations.
pub struct ReaderHandle {
    /// In-memory file content buffer.
    content: Vec<u8>,
    /// Current read position.
    position: u64,
    /// File size (plaintext).
    size: u64,
    /// Filename for metadata.
    filename: String,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

/// Handle for write access.
pub struct WriterHandle {
    /// The write buffer (wrapped in Mutex for interior mutability).
    buffer: Arc<Mutex<WriteBuffer>>,
    /// Vault operations for flushing.
    ops: Arc<VaultOperationsAsync>,
    /// Current write position.
    position: u64,
    /// Filename for metadata.
    filename: String,
    /// Vault path for cache invalidation.
    vault_path: String,
    /// Metadata cache reference for invalidation after flush.
    cache: Arc<MetadataCache>,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl CryptomatorFile {
    /// Create a new reader handle from file content.
    ///
    /// The content should be obtained via `read_file` which reads the entire
    /// file into memory at open time. This avoids holding vault locks for the
    /// duration of the HTTP request.
    pub fn reader(content: Vec<u8>, filename: String, stats: Arc<VaultStats>) -> Self {
        let size = content.len() as u64;
        stats.record_file_open();
        CryptomatorFile::Reader(ReaderHandle {
            content,
            position: 0,
            size,
            filename,
            stats,
        })
    }

    /// Create a new writer handle from a WriteBuffer.
    pub fn writer(
        buffer: WriteBuffer,
        filename: String,
        ops: Arc<VaultOperationsAsync>,
        vault_path: String,
        cache: Arc<MetadataCache>,
        stats: Arc<VaultStats>,
    ) -> Self {
        stats.record_file_open();
        CryptomatorFile::Writer(WriterHandle {
            buffer: Arc::new(Mutex::new(buffer)),
            ops,
            position: 0,
            filename,
            vault_path,
            cache,
            stats,
        })
    }

    /// Get the filename.
    pub fn filename(&self) -> &str {
        match self {
            CryptomatorFile::Reader(h) => &h.filename,
            CryptomatorFile::Writer(h) => &h.filename,
        }
    }

    /// Get the current size.
    pub fn size(&self) -> u64 {
        match self {
            CryptomatorFile::Reader(h) => h.size,
            CryptomatorFile::Writer(_) => 0, // Will be computed from buffer
        }
    }
}

impl DavFile for CryptomatorFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let (name, size) = match self {
                CryptomatorFile::Reader(h) => (h.filename.clone(), h.size),
                CryptomatorFile::Writer(h) => {
                    let buf = h.buffer.lock().await;
                    (h.filename.clone(), buf.len())
                }
            };
            Ok(Box::new(CryptomatorMetaData::file_with_size(name, size)) as Box<dyn DavMetaData>)
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        Box::pin(async move {
            match self {
                CryptomatorFile::Reader(h) => {
                    h.stats.start_read();
                    let start = Instant::now();

                    // Read from in-memory buffer (no locks held)
                    // Safe cast: position is tracked file offset, fits in usize
                    #[allow(clippy::cast_possible_truncation)]
                    let offset = h.position as usize;
                    let end = std::cmp::min(offset + count, h.content.len());
                    let data = if offset < h.content.len() {
                        h.content[offset..end].to_vec()
                    } else {
                        Vec::new()
                    };

                    let elapsed = start.elapsed();
                    h.stats.finish_read();
                    h.stats.record_read_latency(elapsed);

                    let len = data.len() as u64;
                    h.position += len;
                    h.stats.record_read(len);
                    h.stats.record_decrypted(len);
                    Ok(Bytes::from(data))
                }
                CryptomatorFile::Writer(h) => {
                    let buf = h.buffer.lock().await;
                    let data = buf.read(h.position, count).to_vec();
                    let len = data.len() as u64;
                    h.position += len;
                    h.stats.record_read(len);
                    Ok(Bytes::from(data))
                }
            }
        })
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<'_, ()> {
        Box::pin(async move {
            match self {
                CryptomatorFile::Reader(_) => Err(FsError::Forbidden),
                CryptomatorFile::Writer(h) => {
                    let len = buf.len() as u64;
                    let mut buffer = h.buffer.lock().await;
                    buffer.write(h.position, &buf);
                    h.position += len;
                    h.stats.record_write(len);
                    Ok(())
                }
            }
        })
    }

    fn write_buf(&mut self, mut buf: Box<dyn bytes::Buf + Send>) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let bytes = buf.copy_to_bytes(buf.remaining());
            self.write_bytes(bytes).await
        })
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        Box::pin(async move {
            let (base, offset) = match pos {
                SeekFrom::Start(n) => (0i64, i64::try_from(n).unwrap_or(0)),
                SeekFrom::End(n) => {
                    let size = match self {
                        // Safe cast: file sizes from dav_server API are always positive and within i64 range
                        #[allow(clippy::cast_possible_wrap)]
                        CryptomatorFile::Reader(h) => h.size as i64,
                        CryptomatorFile::Writer(h) => {
                            let buf = h.buffer.lock().await;
                            // Safe cast: buffer lengths are always positive and within i64 range
                            #[allow(clippy::cast_possible_wrap)]
                            let len = buf.len() as i64;
                            len
                        }
                    };
                    (size, n)
                }
                SeekFrom::Current(n) => {
                    let pos = match self {
                        // Safe cast: file positions are always positive and within i64 range
                        #[allow(clippy::cast_possible_wrap)]
                        CryptomatorFile::Reader(h) => h.position as i64,
                        // Safe cast: file positions are always positive and within i64 range
                        #[allow(clippy::cast_possible_wrap)]
                        CryptomatorFile::Writer(h) => h.position as i64,
                    };
                    (pos, n)
                }
            };

            let new_pos = u64::try_from((base + offset).max(0)).unwrap_or(0);
            match self {
                CryptomatorFile::Reader(h) => h.position = new_pos,
                CryptomatorFile::Writer(h) => h.position = new_pos,
            }
            Ok(new_pos)
        })
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        Box::pin(async move {
            match self {
                CryptomatorFile::Reader(_) => Ok(()), // Nothing to flush for readers
                CryptomatorFile::Writer(h) => {
                    let mut buffer = h.buffer.lock().await;

                    if buffer.is_dirty() {
                        let dir_id = buffer.dir_id().clone();
                        let filename = buffer.filename().to_string();
                        let content = buffer.content().to_vec();
                        let content_len = content.len() as u64;

                        debug!(
                            filename = %filename,
                            size = content.len(),
                            "Flushing write buffer to vault"
                        );

                        h.stats.start_write();
                        let start = Instant::now();
                        let result = h.ops
                            .write_file(&dir_id, &filename, &content)
                            .await
                            .map_err(write_error_to_fs_error);
                        let elapsed = start.elapsed();
                        h.stats.finish_write();
                        h.stats.record_write_latency(elapsed);

                        result?;

                        // Record encrypted bytes written to vault
                        h.stats.record_encrypted(content_len);

                        // Invalidate metadata cache so PROPFIND returns updated size
                        h.cache.invalidate(&h.vault_path);

                        buffer.mark_clean();
                    }
                    Ok(())
                }
            }
        })
    }
}

impl Drop for CryptomatorFile {
    fn drop(&mut self) {
        match self {
            CryptomatorFile::Reader(h) => h.stats.record_file_close(),
            CryptomatorFile::Writer(h) => h.stats.record_file_close(),
        }
    }
}

// Note: Unit tests for CryptomatorFile::writer have been moved to integration tests
// since they require VaultOperationsAsync which needs a real vault.
// See tests/crud_tests.rs for full write/read cycle tests.

#[cfg(test)]
mod tests {
    // Unit tests for CryptomatorFile require a real vault.
    // See tests/crud_tests.rs for integration tests covering:
    // - Write/read roundtrip
    // - Seek operations
    // - Metadata
    // - Flush behavior
}
