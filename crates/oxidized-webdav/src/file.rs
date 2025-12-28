//! WebDAV file handle implementation.
//!
//! This module provides the `DavFile` trait implementation for vault files,
//! supporting both streaming reads and buffered writes.

#![allow(dead_code)] // APIs used by DavFile trait

use crate::error::write_error_to_fs_error;
use crate::metadata::CryptomatorMetaData;
use bytes::Bytes;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use oxidized_cryptolib::fs::streaming::VaultFileReader;
use oxidized_cryptolib::vault::VaultOperationsAsync;
use oxidized_mount_common::{TtlCache, WriteBuffer};
use std::io::SeekFrom;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

/// Type alias for the metadata cache.
type MetadataCache = TtlCache<String, CryptomatorMetaData>;

/// A file handle for WebDAV operations.
///
/// Supports two modes:
/// - **Reader**: Streaming read-only access using `VaultFileReader`
/// - **WriteBuffer**: Buffered write access with read-modify-write pattern
pub enum CryptomatorFile {
    /// Read-only streaming reader for GET requests.
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
pub struct ReaderHandle {
    /// The streaming reader (wrapped in Mutex for interior mutability).
    reader: Arc<Mutex<VaultFileReader>>,
    /// Current read position.
    position: u64,
    /// File size (plaintext).
    size: u64,
    /// Filename for metadata.
    filename: String,
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
}

impl CryptomatorFile {
    /// Create a new reader handle from a VaultFileReader.
    pub fn reader(reader: VaultFileReader, filename: String) -> Self {
        let size = reader.plaintext_size();
        CryptomatorFile::Reader(ReaderHandle {
            reader: Arc::new(Mutex::new(reader)),
            position: 0,
            size,
            filename,
        })
    }

    /// Create a new writer handle from a WriteBuffer.
    pub fn writer(
        buffer: WriteBuffer,
        filename: String,
        ops: Arc<VaultOperationsAsync>,
        vault_path: String,
        cache: Arc<MetadataCache>,
    ) -> Self {
        CryptomatorFile::Writer(WriterHandle {
            buffer: Arc::new(Mutex::new(buffer)),
            ops,
            position: 0,
            filename,
            vault_path,
            cache,
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
                    let mut reader = h.reader.lock().await;
                    let data = reader
                        .read_range(h.position, count)
                        .await
                        .map_err(|_| FsError::GeneralFailure)?;
                    h.position += data.len() as u64;
                    Ok(Bytes::from(data))
                }
                CryptomatorFile::Writer(h) => {
                    let buf = h.buffer.lock().await;
                    let data = buf.read(h.position, count).to_vec();
                    h.position += data.len() as u64;
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
                    let mut buffer = h.buffer.lock().await;
                    buffer.write(h.position, &buf);
                    h.position += buf.len() as u64;
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
                SeekFrom::Start(n) => (0i64, n as i64),
                SeekFrom::End(n) => {
                    let size = match self {
                        CryptomatorFile::Reader(h) => h.size as i64,
                        CryptomatorFile::Writer(h) => {
                            let buf = h.buffer.lock().await;
                            buf.len() as i64
                        }
                    };
                    (size, n)
                }
                SeekFrom::Current(n) => {
                    let pos = match self {
                        CryptomatorFile::Reader(h) => h.position as i64,
                        CryptomatorFile::Writer(h) => h.position as i64,
                    };
                    (pos, n)
                }
            };

            let new_pos = (base + offset).max(0) as u64;
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

                        debug!(
                            filename = %filename,
                            size = content.len(),
                            "Flushing write buffer to vault"
                        );

                        h.ops
                            .write_file(&dir_id, &filename, &content)
                            .await
                            .map_err(write_error_to_fs_error)?;

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
