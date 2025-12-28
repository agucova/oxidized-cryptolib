//! Streaming file I/O for FUSE compatibility.
//!
//! Provides [`VaultFileReader`] for random-access reads and [`VaultFileWriter`] for
//! streaming writes without loading entire files into memory.
//!
//! # File Format Reference
//!
//! Cryptomator encrypted files consist of:
//! - **Header (68 bytes)**: 12-byte nonce + 40-byte encrypted payload + 16-byte tag
//! - **Content chunks (up to 32,796 bytes each)**: 12-byte nonce + ≤32KB ciphertext + 16-byte tag
//!
//! Each chunk is independently encrypted with AES-GCM, using the chunk number and
//! header nonce as additional authenticated data (AAD).

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};

use aead::Payload;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard};
use tracing::{debug, instrument, trace, warn};
use zeroize::Zeroizing;

use crate::crypto::keys::MasterKey;
use super::file::{FileContext, FileDecryptionError, FileEncryptionError};

// ============================================================================
// Constants
// ============================================================================

/// Size of the file header in bytes (nonce + encrypted payload + tag).
pub const HEADER_SIZE: usize = 68;

/// Size of the header nonce in bytes.
pub const HEADER_NONCE_SIZE: usize = 12;

/// Size of the chunk nonce in bytes.
pub const CHUNK_NONCE_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Maximum plaintext size per chunk (32 KB).
pub const CHUNK_PLAINTEXT_SIZE: usize = 32768;

/// Maximum encrypted chunk size (nonce + ciphertext + tag).
pub const CHUNK_ENCRYPTED_SIZE: usize = CHUNK_PLAINTEXT_SIZE + CHUNK_OVERHEAD;

/// Overhead per chunk (nonce + tag).
pub const CHUNK_OVERHEAD: usize = CHUNK_NONCE_SIZE + TAG_SIZE;

// ============================================================================
// Chunk Math Helpers
// ============================================================================

/// Calculate which chunk contains the given plaintext byte offset.
#[inline]
pub fn plaintext_to_chunk_number(offset: u64) -> u64 {
    offset / CHUNK_PLAINTEXT_SIZE as u64
}

/// Calculate the byte offset within a chunk for a given plaintext offset.
#[inline]
pub fn plaintext_to_chunk_offset(offset: u64) -> usize {
    (offset % CHUNK_PLAINTEXT_SIZE as u64) as usize
}

/// Calculate the encrypted file offset for the start of a chunk.
#[inline]
pub fn chunk_to_encrypted_offset(chunk_num: u64) -> u64 {
    HEADER_SIZE as u64 + chunk_num * CHUNK_ENCRYPTED_SIZE as u64
}

/// Calculate plaintext file size from encrypted file size.
///
/// Returns `None` if the encrypted size is too small to be valid.
pub fn encrypted_to_plaintext_size(encrypted_size: u64) -> Option<u64> {
    if encrypted_size < HEADER_SIZE as u64 {
        return None;
    }

    let content_size = encrypted_size - HEADER_SIZE as u64;
    if content_size == 0 {
        // File with header but no content chunks - invalid
        return None;
    }

    let full_chunks = content_size / CHUNK_ENCRYPTED_SIZE as u64;
    let remainder = content_size % CHUNK_ENCRYPTED_SIZE as u64;

    // Calculate plaintext from full chunks
    let mut plaintext_size = full_chunks * CHUNK_PLAINTEXT_SIZE as u64;

    // Handle partial final chunk
    if remainder > 0 {
        if remainder < CHUNK_OVERHEAD as u64 {
            // Partial chunk too small to be valid
            return None;
        }
        plaintext_size += remainder - CHUNK_OVERHEAD as u64;
    }

    Some(plaintext_size)
}

/// Calculate plaintext file size, returning 0 for edge cases.
///
/// This is a convenience wrapper around [`encrypted_to_plaintext_size`] that
/// returns 0 for empty files (single empty chunk) and invalid sizes.
pub fn encrypted_to_plaintext_size_or_zero(encrypted_size: u64) -> u64 {
    // Special case: header + single empty chunk (empty file)
    // Empty chunk is CHUNK_OVERHEAD bytes (nonce + tag with no ciphertext)
    if encrypted_size == HEADER_SIZE as u64 + CHUNK_OVERHEAD as u64 {
        return 0;
    }

    encrypted_to_plaintext_size(encrypted_size).unwrap_or(0)
}

// ============================================================================
// Streaming Error Types
// ============================================================================

/// Context for streaming operations.
#[derive(Debug, Clone, Default)]
pub struct StreamingContext {
    /// Path to the encrypted file
    pub path: Option<PathBuf>,
    /// Current chunk being processed
    pub chunk_number: Option<u64>,
    /// Operation being performed
    pub operation: Option<&'static str>,
}

impl StreamingContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_chunk(mut self, chunk_number: u64) -> Self {
        self.chunk_number = Some(chunk_number);
        self
    }

    pub fn with_operation(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
        self
    }
}

impl std::fmt::Display for StreamingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(ref op) = self.operation {
            parts.push(op.to_string());
        }
        if let Some(ref path) = self.path {
            parts.push(format!("at {:?}", path.display()));
        }
        if let Some(chunk) = self.chunk_number {
            parts.push(format!("chunk {}", chunk));
        }

        if parts.is_empty() {
            write!(f, "(no context)")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

/// Errors that can occur during streaming operations.
#[derive(Error, Debug)]
pub enum StreamingError {
    /// IO error during streaming operation
    #[error("IO error during {context}: {source}")]
    Io {
        #[source]
        source: io::Error,
        context: StreamingContext,
    },

    /// File is too small to contain valid encrypted data
    #[error("File too small for {context}: expected at least {expected} bytes, got {actual}")]
    FileTooSmall {
        expected: usize,
        actual: usize,
        context: StreamingContext,
    },

    /// Incomplete chunk encountered during read
    #[error("Incomplete chunk for {context}: expected at least {expected} bytes, got {actual}")]
    IncompleteChunk {
        chunk_number: u64,
        expected: usize,
        actual: usize,
        context: StreamingContext,
    },

    /// Chunk decryption failed (authentication tag mismatch)
    #[error("Chunk decryption failed for {context}: authentication tag mismatch")]
    ChunkDecryptionFailed {
        chunk_number: u64,
        context: StreamingContext,
    },

    /// Chunk encryption failed
    #[error("Chunk encryption failed for {context}: {reason}")]
    ChunkEncryptionFailed {
        chunk_number: u64,
        reason: String,
        context: StreamingContext,
    },

    /// Header decryption failed
    #[error("Header decryption failed: {0}")]
    HeaderDecryption(#[from] FileDecryptionError),

    /// Header encryption failed
    #[error("Header encryption failed: {0}")]
    HeaderEncryption(#[from] FileEncryptionError),

    /// Temporary file operation failed
    #[error("Temporary file error for {context}: {reason}")]
    TempFile {
        reason: String,
        context: StreamingContext,
    },

    /// Invalid path provided
    #[error("Invalid path: {reason}")]
    InvalidPath { reason: String },
}

impl StreamingError {
    /// Create an IO error with context
    pub fn io_with_context(source: io::Error, context: StreamingContext) -> Self {
        StreamingError::Io { source, context }
    }
}

// ============================================================================
// VaultFileReader
// ============================================================================

/// Random-access reader for encrypted vault files.
///
/// Enables efficient FUSE `read(offset, size)` operations by decrypting only
/// the necessary chunks. Maintains a small cache of recently accessed chunks
/// to optimize sequential reads.
///
/// # Lock Retention
///
/// When created through `VaultOperationsAsync::open_file()`, this reader holds
/// directory and file read locks for its entire lifetime, preventing concurrent
/// modifications to the file.
///
/// # Example
///
/// ```ignore
/// let mut reader = VaultFileReader::open(&encrypted_path, &master_key).await?;
///
/// // Read bytes 1000-2000 (only decrypts the relevant chunk)
/// let data = reader.read_range(1000, 1000).await?;
///
/// // Get total plaintext size
/// let size = reader.plaintext_size();
/// ```
pub struct VaultFileReader {
    /// Handle to the encrypted file
    file: File,
    /// The decrypted content key from the file header
    content_key: Zeroizing<[u8; 32]>,
    /// Header nonce, used as part of chunk AAD
    header_nonce: [u8; HEADER_NONCE_SIZE],
    /// Total plaintext size of the file
    plaintext_size: u64,
    /// Path to the file (for error context)
    path: PathBuf,
    /// Cached chunk: (chunk_number, decrypted_data)
    cached_chunk: Option<(u64, Zeroizing<Vec<u8>>)>,
    /// Directory read lock guard (held for lifetime if set).
    /// This prevents the directory from being modified while reading.
    #[allow(dead_code)]
    dir_lock_guard: Option<OwnedRwLockReadGuard<()>>,
    /// File read lock guard (held for lifetime if set).
    /// This prevents the file from being modified while reading.
    #[allow(dead_code)]
    file_lock_guard: Option<OwnedRwLockReadGuard<()>>,
}

impl std::fmt::Debug for VaultFileReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultFileReader")
            .field("path", &self.path)
            .field("plaintext_size", &self.plaintext_size)
            .field("cached_chunk", &self.cached_chunk.as_ref().map(|(n, _)| n))
            .finish_non_exhaustive()
    }
}

impl VaultFileReader {
    /// Open an encrypted file for streaming reads.
    ///
    /// Reads and decrypts the file header to extract the content key.
    /// The file handle is kept open for subsequent read operations.
    #[instrument(level = "debug", skip(master_key), fields(path = %path.as_ref().display()))]
    pub async fn open(path: impl AsRef<Path>, master_key: &MasterKey) -> Result<Self, StreamingError> {
        let path = path.as_ref();
        let context = StreamingContext::new()
            .with_path(path)
            .with_operation("open");

        debug!("Opening encrypted file for streaming read");

        let mut file = File::open(path).await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;

        // Get file size
        let metadata = file.metadata().await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;
        let encrypted_size = metadata.len();

        if encrypted_size < HEADER_SIZE as u64 {
            return Err(StreamingError::FileTooSmall {
                expected: HEADER_SIZE,
                actual: encrypted_size as usize,
                context,
            });
        }

        // Read header
        let mut header_bytes = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes).await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;

        // Extract header nonce before decryption
        let mut header_nonce = [0u8; HEADER_NONCE_SIZE];
        header_nonce.copy_from_slice(&header_bytes[..HEADER_NONCE_SIZE]);

        // Decrypt header to get content key
        let file_context = FileContext::new().with_path(path);
        let header = super::file::decrypt_file_header_with_context(
            &header_bytes,
            master_key,
            file_context,
        )?;

        // Calculate plaintext size
        let plaintext_size = encrypted_to_plaintext_size_or_zero(encrypted_size);

        debug!(
            encrypted_size = encrypted_size,
            plaintext_size = plaintext_size,
            "File opened for streaming read"
        );

        Ok(Self {
            file,
            content_key: header.content_key,
            header_nonce,
            plaintext_size,
            path: path.to_path_buf(),
            cached_chunk: None,
            dir_lock_guard: None,
            file_lock_guard: None,
        })
    }

    /// Set the lock guards to hold for the lifetime of this reader.
    ///
    /// This is called by `VaultOperationsAsync::open_file()` to ensure the
    /// file cannot be modified while this reader exists.
    ///
    /// # Arguments
    ///
    /// * `dir_guard` - Directory read lock guard
    /// * `file_guard` - File read lock guard
    pub fn with_locks(
        mut self,
        dir_guard: OwnedRwLockReadGuard<()>,
        file_guard: OwnedRwLockReadGuard<()>,
    ) -> Self {
        self.dir_lock_guard = Some(dir_guard);
        self.file_lock_guard = Some(file_guard);
        self
    }

    /// Check if this reader is holding lock guards.
    pub fn has_locks(&self) -> bool {
        self.dir_lock_guard.is_some() && self.file_lock_guard.is_some()
    }

    /// Get the total plaintext size of the file.
    #[inline]
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    /// Read a range of bytes from the file.
    ///
    /// Calculates which chunks are needed, seeks to their positions, decrypts
    /// them, and returns the requested byte range. Uses a simple cache to
    /// avoid re-decrypting the same chunk on sequential reads.
    ///
    /// Returns fewer bytes than requested if reading past EOF.
    #[instrument(level = "debug", skip(self), fields(path = %self.path.display()))]
    pub async fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, StreamingError> {
        // Handle read past EOF
        if offset >= self.plaintext_size {
            trace!(offset = offset, size = self.plaintext_size, "Read past EOF");
            return Ok(Vec::new());
        }

        // Clamp length to available data
        let available = (self.plaintext_size - offset) as usize;
        let actual_len = len.min(available);

        if actual_len == 0 {
            return Ok(Vec::new());
        }

        trace!(offset = offset, requested = len, actual = actual_len, "Reading range");

        // Calculate chunk range
        let start_chunk = plaintext_to_chunk_number(offset);
        let end_offset = offset + actual_len as u64 - 1;
        let end_chunk = plaintext_to_chunk_number(end_offset);

        let mut result = Vec::with_capacity(actual_len);
        let start_within_chunk = plaintext_to_chunk_offset(offset);

        for chunk_num in start_chunk..=end_chunk {
            let chunk_data = self.read_chunk(chunk_num).await?;

            // Calculate slice within this chunk
            let chunk_start = if chunk_num == start_chunk {
                start_within_chunk
            } else {
                0
            };

            let chunk_end = if chunk_num == end_chunk {
                let remaining = actual_len - result.len();
                (chunk_start + remaining).min(chunk_data.len())
            } else {
                chunk_data.len()
            };

            if chunk_start < chunk_data.len() {
                let end = chunk_end.min(chunk_data.len());
                result.extend_from_slice(&chunk_data[chunk_start..end]);
            }

            // Stop if we have enough data
            if result.len() >= actual_len {
                break;
            }
        }

        // Trim to exact requested length
        result.truncate(actual_len);

        trace!(read_bytes = result.len(), "Range read complete");
        Ok(result)
    }

    /// Read and decrypt a single chunk.
    ///
    /// Uses the cache if the chunk was recently read.
    async fn read_chunk(&mut self, chunk_num: u64) -> Result<Zeroizing<Vec<u8>>, StreamingError> {
        // Check cache
        if let Some((cached_num, ref data)) = self.cached_chunk
            && cached_num == chunk_num
        {
            trace!(chunk = chunk_num, "Cache hit");
            return Ok(data.clone());
        }

        trace!(chunk = chunk_num, "Cache miss, reading from disk");

        let context = StreamingContext::new()
            .with_path(&self.path)
            .with_chunk(chunk_num)
            .with_operation("read_chunk");

        // Seek to chunk position
        let encrypted_offset = chunk_to_encrypted_offset(chunk_num);
        self.file
            .seek(SeekFrom::Start(encrypted_offset))
            .await
            .map_err(|e| StreamingError::io_with_context(e, context.clone()))?;

        // Read encrypted chunk (may be smaller for last chunk)
        let mut encrypted_chunk = vec![0u8; CHUNK_ENCRYPTED_SIZE];
        let bytes_read = self.file.read(&mut encrypted_chunk).await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;

        if bytes_read == 0 {
            // No data at this position - shouldn't happen for valid chunk numbers
            return Err(StreamingError::IncompleteChunk {
                chunk_number: chunk_num,
                expected: CHUNK_OVERHEAD,
                actual: 0,
                context,
            });
        }

        encrypted_chunk.truncate(bytes_read);

        if encrypted_chunk.len() < CHUNK_OVERHEAD {
            return Err(StreamingError::IncompleteChunk {
                chunk_number: chunk_num,
                expected: CHUNK_OVERHEAD,
                actual: encrypted_chunk.len(),
                context,
            });
        }

        // Decrypt chunk
        let decrypted = self.decrypt_chunk(chunk_num, &encrypted_chunk)?;
        let decrypted = Zeroizing::new(decrypted);

        // Update cache
        self.cached_chunk = Some((chunk_num, decrypted.clone()));

        Ok(decrypted)
    }

    /// Decrypt a single chunk using AES-GCM.
    fn decrypt_chunk(&self, chunk_num: u64, encrypted: &[u8]) -> Result<Vec<u8>, StreamingError> {
        let context = StreamingContext::new()
            .with_path(&self.path)
            .with_chunk(chunk_num)
            .with_operation("decrypt_chunk");

        let nonce = Nonce::from_slice(&encrypted[..CHUNK_NONCE_SIZE]);
        let ciphertext = &encrypted[CHUNK_NONCE_SIZE..];

        // Build AAD: chunk_number (8 bytes BE) || header_nonce (12 bytes)
        let mut aad = Vec::with_capacity(8 + HEADER_NONCE_SIZE);
        aad.extend_from_slice(&chunk_num.to_be_bytes());
        aad.extend_from_slice(&self.header_nonce);

        let key = Key::<Aes256Gcm>::from_slice(&*self.content_key);
        let cipher = Aes256Gcm::new(key);

        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        cipher.decrypt(nonce, payload).map_err(|_| {
            warn!(chunk = chunk_num, "Chunk decryption failed - authentication tag mismatch");
            StreamingError::ChunkDecryptionFailed {
                chunk_number: chunk_num,
                context,
            }
        })
    }
}

impl Drop for VaultFileReader {
    fn drop(&mut self) {
        // Zeroizing handles content_key cleanup automatically
        // Clear the cache
        self.cached_chunk = None;
        trace!(path = %self.path.display(), "VaultFileReader dropped");
    }
}

// ============================================================================
// VaultFileWriter
// ============================================================================

/// Streaming writer for encrypted vault files.
///
/// Writes data to a temporary file and atomically renames on `finish()`.
/// Buffers up to 32KB before encrypting and flushing each chunk.
///
/// # Lock Retention
///
/// When created through `VaultOperationsAsync::create_file()`, this writer holds
/// directory and file write locks for its entire lifetime, preventing concurrent
/// access to the file until `finish()` or `abort()` is called.
///
/// # Example
///
/// ```ignore
/// let mut writer = VaultFileWriter::create(&dest_path, &master_key).await?;
///
/// writer.write(b"Hello, ").await?;
/// writer.write(b"World!").await?;
///
/// // Atomically rename temp file to destination
/// let final_path = writer.finish().await?;
/// ```
pub struct VaultFileWriter {
    /// Handle to the temporary file
    temp_file: File,
    /// Path to the temporary file
    temp_path: PathBuf,
    /// Final destination path
    dest_path: PathBuf,
    /// Content encryption key for this file
    content_key: Zeroizing<[u8; 32]>,
    /// Header nonce, used as part of chunk AAD
    header_nonce: [u8; HEADER_NONCE_SIZE],
    /// Buffer for accumulating data before chunk encryption
    buffer: Zeroizing<Vec<u8>>,
    /// Number of chunks written so far
    chunks_written: u64,
    /// Whether the header has been written
    header_written: bool,
    /// Whether finish() or abort() has been called
    finished: bool,
    /// Directory write lock guard (held for lifetime if set).
    /// This prevents the directory from being modified while writing.
    #[allow(dead_code)]
    dir_lock_guard: Option<OwnedRwLockWriteGuard<()>>,
    /// File write lock guard (held for lifetime if set).
    /// This prevents the file from being accessed while writing.
    #[allow(dead_code)]
    file_lock_guard: Option<OwnedRwLockWriteGuard<()>>,
}

impl std::fmt::Debug for VaultFileWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultFileWriter")
            .field("temp_path", &self.temp_path)
            .field("dest_path", &self.dest_path)
            .field("chunks_written", &self.chunks_written)
            .field("buffer_len", &self.buffer.len())
            .field("header_written", &self.header_written)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl VaultFileWriter {
    /// Create a new encrypted file for streaming writes.
    ///
    /// Generates a random content key and header nonce. The file header is
    /// written on the first `write()` call.
    #[instrument(level = "debug", skip(master_key), fields(dest = %dest.as_ref().display()))]
    pub async fn create(
        dest: impl AsRef<Path>,
        master_key: &MasterKey,
    ) -> Result<Self, StreamingError> {
        let dest = dest.as_ref();
        let context = StreamingContext::new()
            .with_path(dest)
            .with_operation("create");

        debug!("Creating encrypted file for streaming write");

        // Generate random content key and header nonce
        let mut content_key = Zeroizing::new([0u8; 32]);
        let mut header_nonce = [0u8; HEADER_NONCE_SIZE];
        rand::rng().fill_bytes(&mut *content_key);
        rand::rng().fill_bytes(&mut header_nonce);

        // Create temp file in same directory for atomic rename
        let parent = dest.parent().ok_or_else(|| StreamingError::InvalidPath {
            reason: "destination has no parent directory".to_string(),
        })?;

        // Generate temp filename
        let mut temp_suffix = [0u8; 8];
        rand::rng().fill_bytes(&mut temp_suffix);
        let temp_name = format!(".tmp_{}", hex::encode(temp_suffix));
        let temp_path = parent.join(&temp_name);

        let temp_file = File::create(&temp_path).await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;

        // Encrypt and write header
        let file_context = FileContext::new().with_path(dest);
        let encrypted_header = super::file::encrypt_file_header_with_context(
            &content_key,
            master_key,
            file_context,
        )?;

        // Update header_nonce from the actual encrypted header
        let mut actual_header_nonce = [0u8; HEADER_NONCE_SIZE];
        actual_header_nonce.copy_from_slice(&encrypted_header[..HEADER_NONCE_SIZE]);

        let mut writer = Self {
            temp_file,
            temp_path,
            dest_path: dest.to_path_buf(),
            content_key,
            header_nonce: actual_header_nonce,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_PLAINTEXT_SIZE)),
            chunks_written: 0,
            header_written: false,
            finished: false,
            dir_lock_guard: None,
            file_lock_guard: None,
        };

        // Write header immediately
        writer.temp_file.write_all(&encrypted_header).await.map_err(|e| {
            StreamingError::io_with_context(e, context)
        })?;
        writer.header_written = true;

        debug!(temp_path = %writer.temp_path.display(), "Writer created with temp file");

        Ok(writer)
    }

    /// Set the lock guards to hold for the lifetime of this writer.
    ///
    /// This is called by `VaultOperationsAsync::create_file()` to ensure the
    /// file cannot be accessed by other operations while this writer exists.
    ///
    /// # Arguments
    ///
    /// * `dir_guard` - Directory write lock guard
    /// * `file_guard` - File write lock guard
    pub fn with_locks(
        mut self,
        dir_guard: OwnedRwLockWriteGuard<()>,
        file_guard: OwnedRwLockWriteGuard<()>,
    ) -> Self {
        self.dir_lock_guard = Some(dir_guard);
        self.file_lock_guard = Some(file_guard);
        self
    }

    /// Check if this writer is holding lock guards.
    pub fn has_locks(&self) -> bool {
        self.dir_lock_guard.is_some() && self.file_lock_guard.is_some()
    }

    /// Write data to the file.
    ///
    /// Data is buffered until 32KB is accumulated, then encrypted and written
    /// as a chunk. Returns the number of bytes accepted.
    #[instrument(level = "trace", skip(self, data), fields(dest = %self.dest_path.display(), data_len = data.len()))]
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, StreamingError> {
        if self.finished {
            return Err(StreamingError::TempFile {
                reason: "writer already finished".to_string(),
                context: StreamingContext::new()
                    .with_path(&self.dest_path)
                    .with_operation("write"),
            });
        }

        self.buffer.extend_from_slice(data);

        // Flush complete chunks
        while self.buffer.len() >= CHUNK_PLAINTEXT_SIZE {
            let chunk_data: Vec<u8> = self.buffer.drain(..CHUNK_PLAINTEXT_SIZE).collect();
            self.write_chunk(&chunk_data).await?;
        }

        Ok(data.len())
    }

    /// Encrypt and write a single chunk.
    async fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), StreamingError> {
        let chunk_num = self.chunks_written;
        let context = StreamingContext::new()
            .with_path(&self.dest_path)
            .with_chunk(chunk_num)
            .with_operation("write_chunk");

        // Generate random chunk nonce
        let mut chunk_nonce = [0u8; CHUNK_NONCE_SIZE];
        rand::rng().fill_bytes(&mut chunk_nonce);

        // Build AAD: chunk_number (8 bytes BE) || header_nonce (12 bytes)
        let mut aad = Vec::with_capacity(8 + HEADER_NONCE_SIZE);
        aad.extend_from_slice(&chunk_num.to_be_bytes());
        aad.extend_from_slice(&self.header_nonce);

        let key = Key::<Aes256Gcm>::from_slice(&*self.content_key);
        let cipher = Aes256Gcm::new(key);

        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext = cipher.encrypt(Nonce::from_slice(&chunk_nonce), payload).map_err(|e| {
            StreamingError::ChunkEncryptionFailed {
                chunk_number: chunk_num,
                reason: e.to_string(),
                context: context.clone(),
            }
        })?;

        // Write nonce + ciphertext (ciphertext includes tag)
        self.temp_file.write_all(&chunk_nonce).await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;
        self.temp_file.write_all(&ciphertext).await.map_err(|e| {
            StreamingError::io_with_context(e, context)
        })?;

        self.chunks_written += 1;
        trace!(chunk = chunk_num, plaintext_size = plaintext.len(), "Chunk written");

        Ok(())
    }

    /// Finish writing and atomically rename to the destination.
    ///
    /// Flushes any remaining buffered data, writes a final chunk (even if
    /// empty for authentication), and renames the temp file to the destination.
    #[instrument(level = "debug", skip(self), fields(dest = %self.dest_path.display()))]
    pub async fn finish(mut self) -> Result<PathBuf, StreamingError> {
        let context = StreamingContext::new()
            .with_path(&self.dest_path)
            .with_operation("finish");

        if self.finished {
            return Err(StreamingError::TempFile {
                reason: "writer already finished".to_string(),
                context,
            });
        }

        self.finished = true;

        // Flush remaining buffer (may be empty)
        if !self.buffer.is_empty() || self.chunks_written == 0 {
            // Always write at least one chunk for authentication
            let remaining: Vec<u8> = self.buffer.drain(..).collect();
            self.write_chunk(&remaining).await?;
        }

        // Flush and sync to disk
        self.temp_file.flush().await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;
        self.temp_file.sync_all().await.map_err(|e| {
            StreamingError::io_with_context(e, context.clone())
        })?;

        // Atomic rename
        tokio::fs::rename(&self.temp_path, &self.dest_path).await.map_err(|e| {
            StreamingError::io_with_context(e, context)
        })?;

        debug!(
            chunks = self.chunks_written,
            dest = %self.dest_path.display(),
            "File finished and renamed"
        );

        Ok(self.dest_path.clone())
    }

    /// Abort the write and clean up the temporary file.
    #[instrument(level = "debug", skip(self), fields(dest = %self.dest_path.display()))]
    pub async fn abort(mut self) -> Result<(), StreamingError> {
        self.finished = true;

        // Remove temp file
        if let Err(e) = tokio::fs::remove_file(&self.temp_path).await {
            // Log but don't fail - temp file might already be gone
            warn!(
                temp_path = %self.temp_path.display(),
                error = %e,
                "Failed to remove temp file during abort"
            );
        }

        debug!("Write aborted, temp file cleaned up");
        Ok(())
    }
}

impl Drop for VaultFileWriter {
    fn drop(&mut self) {
        // If finish() or abort() wasn't called, try to clean up
        if !self.finished {
            warn!(
                temp_path = %self.temp_path.display(),
                "VaultFileWriter dropped without finish() or abort()"
            );
            // Best-effort synchronous cleanup
            let _ = std::fs::remove_file(&self.temp_path);
        }
        // Zeroizing handles content_key and buffer cleanup automatically
        trace!(dest = %self.dest_path.display(), "VaultFileWriter dropped");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_to_chunk_number() {
        assert_eq!(plaintext_to_chunk_number(0), 0);
        assert_eq!(plaintext_to_chunk_number(32767), 0);
        assert_eq!(plaintext_to_chunk_number(32768), 1);
        assert_eq!(plaintext_to_chunk_number(32769), 1);
        assert_eq!(plaintext_to_chunk_number(65535), 1);
        assert_eq!(plaintext_to_chunk_number(65536), 2);
        assert_eq!(plaintext_to_chunk_number(100_000), 3);
    }

    #[test]
    fn test_plaintext_to_chunk_offset() {
        assert_eq!(plaintext_to_chunk_offset(0), 0);
        assert_eq!(plaintext_to_chunk_offset(1000), 1000);
        assert_eq!(plaintext_to_chunk_offset(32767), 32767);
        assert_eq!(plaintext_to_chunk_offset(32768), 0);
        assert_eq!(plaintext_to_chunk_offset(32769), 1);
        assert_eq!(plaintext_to_chunk_offset(65536), 0);
    }

    #[test]
    fn test_chunk_to_encrypted_offset() {
        assert_eq!(chunk_to_encrypted_offset(0), 68);
        assert_eq!(chunk_to_encrypted_offset(1), 68 + 32796);
        assert_eq!(chunk_to_encrypted_offset(2), 68 + 2 * 32796);
    }

    #[test]
    fn test_encrypted_to_plaintext_size() {
        // File too small
        assert_eq!(encrypted_to_plaintext_size(0), None);
        assert_eq!(encrypted_to_plaintext_size(67), None);

        // Header only (no content) - invalid
        assert_eq!(encrypted_to_plaintext_size(68), None);

        // Single empty chunk (empty file)
        assert_eq!(encrypted_to_plaintext_size(68 + 28), Some(0));

        // Single chunk with 1 byte plaintext
        assert_eq!(encrypted_to_plaintext_size(68 + 29), Some(1));

        // Full single chunk (32KB plaintext)
        assert_eq!(encrypted_to_plaintext_size(68 + 32796), Some(32768));

        // Two full chunks
        assert_eq!(encrypted_to_plaintext_size(68 + 2 * 32796), Some(65536));

        // One full + one partial chunk (100 bytes in second)
        assert_eq!(encrypted_to_plaintext_size(68 + 32796 + 28 + 100), Some(32768 + 100));
    }

    #[test]
    fn test_encrypted_to_plaintext_size_or_zero() {
        // Empty file (single empty chunk)
        assert_eq!(encrypted_to_plaintext_size_or_zero(68 + 28), 0);

        // Invalid size returns 0
        assert_eq!(encrypted_to_plaintext_size_or_zero(10), 0);

        // Valid file
        assert_eq!(encrypted_to_plaintext_size_or_zero(68 + 32796), 32768);
    }
}
