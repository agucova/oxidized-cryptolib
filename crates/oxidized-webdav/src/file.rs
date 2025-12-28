//! WebDAV file handle implementation.
//!
//! This module provides the `DavFile` trait implementation for vault files,
//! supporting both streaming reads and buffered writes.

use crate::metadata::CryptomatorMetaData;
use crate::write_buffer::WriteBuffer;
use bytes::Bytes;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use oxidized_cryptolib::fs::streaming::VaultFileReader;
use std::io::SeekFrom;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    /// Current write position.
    position: u64,
    /// Filename for metadata.
    filename: String,
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
    pub fn writer(buffer: WriteBuffer, filename: String) -> Self {
        CryptomatorFile::Writer(WriterHandle {
            buffer: Arc::new(Mutex::new(buffer)),
            position: 0,
            filename,
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
            // For readers, nothing to flush
            // For writers, the actual flush happens when the file is closed
            // via the filesystem's close handler
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::vault::DirId;

    fn test_dir_id() -> DirId {
        DirId::from_raw("test-dir-id")
    }

    #[tokio::test]
    async fn test_writer_handle_write_and_read() {
        let buffer = WriteBuffer::new_for_create(test_dir_id(), "test.txt".to_string());
        let mut file = CryptomatorFile::writer(buffer, "test.txt".to_string());

        // Write some data
        file.write_bytes(Bytes::from("hello")).await.unwrap();

        // Seek to start
        file.seek(SeekFrom::Start(0)).await.unwrap();

        // Read it back
        let data = file.read_bytes(5).await.unwrap();
        assert_eq!(&data[..], b"hello");
    }

    #[tokio::test]
    async fn test_writer_handle_seek() {
        let buffer = WriteBuffer::new_for_create(test_dir_id(), "test.txt".to_string());
        let mut file = CryptomatorFile::writer(buffer, "test.txt".to_string());

        // Write some data
        file.write_bytes(Bytes::from("hello world")).await.unwrap();

        // Seek to middle
        let pos = file.seek(SeekFrom::Start(6)).await.unwrap();
        assert_eq!(pos, 6);

        // Read from middle
        let data = file.read_bytes(5).await.unwrap();
        assert_eq!(&data[..], b"world");

        // Seek from end
        let pos = file.seek(SeekFrom::End(-5)).await.unwrap();
        assert_eq!(pos, 6);
    }

    #[tokio::test]
    async fn test_writer_metadata() {
        let buffer = WriteBuffer::new_for_create(test_dir_id(), "test.txt".to_string());
        let mut file = CryptomatorFile::writer(buffer, "test.txt".to_string());

        file.write_bytes(Bytes::from("hello")).await.unwrap();

        let meta = file.metadata().await.unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.len(), 5);
    }
}
