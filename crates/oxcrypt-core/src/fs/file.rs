use std::{ffi::OsStr, fmt, fs, io, path::Path};

use aead::Payload;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use thiserror::Error;
use tracing::{debug, instrument, trace, warn};
use zeroize::Zeroizing;

use crate::crypto::keys::{KeyAccessError, MasterKey};

/// Context for file operations, providing debugging information.
#[derive(Debug, Clone, Default)]
pub struct FileContext {
    /// The cleartext filename (if known)
    pub filename: Option<String>,
    /// The encrypted path on disk
    pub encrypted_path: Option<std::path::PathBuf>,
    /// The parent directory ID
    pub dir_id: Option<String>,
    /// The chunk number (for content errors)
    pub chunk_number: Option<usize>,
}

impl FileContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.encrypted_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_dir_id(mut self, dir_id: impl Into<String>) -> Self {
        self.dir_id = Some(dir_id.into());
        self
    }

    #[must_use]
    pub fn with_chunk(mut self, chunk_number: usize) -> Self {
        self.chunk_number = Some(chunk_number);
        self
    }
}

impl fmt::Display for FileContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(ref filename) = self.filename {
            parts.push(format!("file '{filename}'"));
        }
        if let Some(ref dir_id) = self.dir_id {
            let display_id = if dir_id.is_empty() {
                "<root>".to_string()
            } else if dir_id.len() > 8 {
                format!("{}...", &dir_id[..8])
            } else {
                dir_id.clone()
            };
            parts.push(format!("in directory {display_id}"));
        }
        if let Some(chunk) = self.chunk_number {
            parts.push(format!("chunk {chunk}"));
        }
        if let Some(ref path) = self.encrypted_path {
            parts.push(format!("at {:?}", path.display()));
        }

        if parts.is_empty() {
            write!(f, "(no context)")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[derive(Error, Debug)]
pub enum FileError {
    #[error("File decryption error: {0}")]
    Decryption(#[from] FileDecryptionError),
    #[error("File encryption error: {0}")]
    Encryption(#[from] FileEncryptionError),
    #[error("IO error reading {context}: {source}")]
    Io {
        #[source]
        source: io::Error,
        context: FileContext,
    },
}

impl From<io::Error> for FileError {
    fn from(source: io::Error) -> Self {
        FileError::Io {
            source,
            context: FileContext::new(),
        }
    }
}

impl FileError {
    /// Create an IO error with context
    #[must_use]
    pub fn io_with_context(source: io::Error, context: FileContext) -> Self {
        FileError::Io { source, context }
    }
}

#[derive(Error, Debug)]
pub enum FileDecryptionError {
    /// File header decryption failed - authentication tag verification failed.
    ///
    /// **[INTEGRITY VIOLATION]** The header ciphertext is invalid or has been tampered with.
    #[error(
        "Failed to decrypt header for {context}: invalid authentication tag - possible tampering or wrong key"
    )]
    HeaderDecryption { context: FileContext },

    /// File content chunk decryption failed - authentication tag verification failed.
    ///
    /// **[INTEGRITY VIOLATION]** A content chunk's ciphertext is invalid or has been tampered with.
    #[error(
        "Failed to decrypt content for {context}: invalid authentication tag - possible tampering or wrong key"
    )]
    ContentDecryption { context: FileContext },

    /// File header has invalid structure (wrong length, missing magic bytes, etc.)
    #[error("Invalid file header for {context}: {reason}")]
    InvalidHeader {
        reason: String,
        context: FileContext,
    },

    /// Incomplete chunk encountered during decryption
    #[error("Incomplete chunk for {context}: expected at least 28 bytes, got {actual_size}")]
    IncompleteChunk {
        context: FileContext,
        actual_size: usize,
    },

    /// IO error during file decryption
    #[error("IO error reading {context}: {source}")]
    Io {
        #[source]
        source: io::Error,
        context: FileContext,
    },

    /// Key access failed due to memory protection error or borrow conflict
    #[error("Key access failed: {0}")]
    KeyAccess(#[from] KeyAccessError),
}

impl From<io::Error> for FileDecryptionError {
    fn from(source: io::Error) -> Self {
        FileDecryptionError::Io {
            source,
            context: FileContext::new(),
        }
    }
}

impl FileDecryptionError {
    /// Create an IO error with context
    #[must_use]
    pub fn io_with_context(source: io::Error, context: FileContext) -> Self {
        FileDecryptionError::Io { source, context }
    }

    /// Add or update context on an existing error
    #[must_use]
    pub fn with_context(self, context: FileContext) -> Self {
        match self {
            FileDecryptionError::HeaderDecryption { .. } => {
                FileDecryptionError::HeaderDecryption { context }
            }
            FileDecryptionError::ContentDecryption { .. } => {
                FileDecryptionError::ContentDecryption { context }
            }
            FileDecryptionError::InvalidHeader { reason, .. } => {
                FileDecryptionError::InvalidHeader { reason, context }
            }
            FileDecryptionError::IncompleteChunk { actual_size, .. } => {
                FileDecryptionError::IncompleteChunk {
                    context,
                    actual_size,
                }
            }
            FileDecryptionError::Io { source, .. } => FileDecryptionError::Io { source, context },
            FileDecryptionError::KeyAccess(e) => FileDecryptionError::KeyAccess(e),
        }
    }
}

#[derive(Error, Debug)]
pub enum FileEncryptionError {
    /// File header encryption failed unexpectedly
    #[error("Failed to encrypt header for {context}: {reason}")]
    HeaderEncryption {
        reason: String,
        context: FileContext,
    },

    /// File content chunk encryption failed unexpectedly
    #[error("Failed to encrypt content for {context}: {reason}")]
    ContentEncryption {
        reason: String,
        context: FileContext,
    },

    /// IO error during file encryption
    #[error("IO error writing {context}: {source}")]
    Io {
        #[source]
        source: io::Error,
        context: FileContext,
    },

    /// Key access failed due to memory protection error or borrow conflict
    #[error("Key access failed: {0}")]
    KeyAccess(#[from] KeyAccessError),
}

impl From<io::Error> for FileEncryptionError {
    fn from(source: io::Error) -> Self {
        FileEncryptionError::Io {
            source,
            context: FileContext::new(),
        }
    }
}

impl FileEncryptionError {
    /// Create an IO error with context
    #[must_use]
    pub fn io_with_context(source: io::Error, context: FileContext) -> Self {
        FileEncryptionError::Io { source, context }
    }
}

/// File header containing the content encryption key.
///
/// The header is 68 bytes: 12-byte nonce + 40-byte encrypted payload (8 reserved + 32-byte
/// content key) + 16-byte GCM authentication tag.
///
/// # Reference Implementation
/// - Java: [`FileHeaderImpl`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderImpl.java)
/// - Java: [`FileHeaderCryptorImpl`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java) (encryption/decryption)
///
/// # Security
///
/// The `content_key` is wrapped in `Zeroizing` to ensure it is securely
/// erased from memory when the header is dropped. The `Debug` implementation
/// intentionally redacts the key to prevent accidental logging.
pub struct FileHeader {
    pub content_key: Zeroizing<[u8; 32]>,
    pub tag: [u8; 16],
}

impl fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileHeader")
            .field("content_key", &"[REDACTED]")
            .field("tag", &hex::encode(self.tag))
            .finish()
    }
}

/// Decrypt a file header to extract the content encryption key.
///
/// # Reference Implementation
/// - Java: [`FileHeaderCryptorImpl.decryptHeader()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java)
pub fn decrypt_file_header(
    encrypted_header: &[u8],
    master_key: &MasterKey,
) -> Result<FileHeader, FileDecryptionError> {
    decrypt_file_header_with_context(encrypted_header, master_key, &FileContext::new())
}

/// Decrypt a file header with contextual error information.
///
/// # Reference Implementation
/// - Java: [`FileHeaderCryptorImpl.decryptHeader()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java)
#[instrument(level = "debug", skip(encrypted_header, master_key), fields(header_size = encrypted_header.len()))]
pub fn decrypt_file_header_with_context(
    encrypted_header: &[u8],
    master_key: &MasterKey,
    context: &FileContext,
) -> Result<FileHeader, FileDecryptionError> {
    trace!("Decrypting file header");

    if encrypted_header.len() != 68 {
        warn!(actual_size = encrypted_header.len(), "Invalid header size");
        return Err(FileDecryptionError::InvalidHeader {
            reason: format!("expected 68 bytes, got {} bytes", encrypted_header.len()),
            context: context.clone(),
        });
    }

    let nonce = Nonce::from_slice(&encrypted_header[0..12]);
    let ciphertext = &encrypted_header[12..52];
    let tag: [u8; 16] = encrypted_header[52..68].try_into().unwrap();

    master_key.with_aes_key(|aes_key| {
        let key: &Key<Aes256Gcm> = aes_key.into();
        let cipher = Aes256Gcm::new(key);

        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(&tag);

        let decrypted = cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| {
                warn!("Header decryption failed - authentication tag mismatch");
                FileDecryptionError::HeaderDecryption {
                    context: context.clone(),
                }
            })?;

        if decrypted.len() != 40 {
            warn!("Invalid header format after decryption");
            return Err(FileDecryptionError::InvalidHeader {
                reason: format!("decrypted header has incorrect size: expected 40 bytes, got {}", decrypted.len()),
                context: context.clone(),
            });
        }

        // Note: The first 8 bytes are reserved for future use. Java's implementation
        // does not validate these bytes, so we don't either - for forward compatibility.
        // We only log if they differ from the expected 0xFF pattern.
        if decrypted[0..8] != [0xFF; 8] {
            debug!(
                reserved_bytes = ?hex::encode(&decrypted[0..8]),
                "Header has non-standard reserved bytes (expected 0xFF padding). This is accepted for forward compatibility."
            );
        }

        let mut content_key = Zeroizing::new([0u8; 32]);
        content_key.copy_from_slice(&decrypted[8..40]);

        debug!("File header decrypted successfully");
        Ok(FileHeader { content_key, tag })
    })?
}

/// Decrypt file content using the content key from the file header.
///
/// Content is processed in 32KB chunks, each with its own nonce and authentication.
///
/// # Reference Implementation
/// - Java: [`FileContentCryptorImpl.decryptChunk()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileContentCryptorImpl.java)
pub fn decrypt_file_content(
    encrypted_content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8],
) -> Result<Vec<u8>, FileDecryptionError> {
    decrypt_file_content_with_context(
        encrypted_content,
        content_key,
        header_nonce,
        &FileContext::new(),
    )
}

/// Decrypt file content with contextual error information.
///
/// # Reference Implementation
/// - Java: [`FileContentCryptorImpl.decryptChunk()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileContentCryptorImpl.java)
#[instrument(level = "debug", skip(encrypted_content, content_key, header_nonce), fields(encrypted_size = encrypted_content.len()))]
pub fn decrypt_file_content_with_context(
    encrypted_content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8],
    base_context: &FileContext,
) -> Result<Vec<u8>, FileDecryptionError> {
    let key = Key::<Aes256Gcm>::from_slice(content_key);
    let cipher = Aes256Gcm::new(key);

    let chunk_count = encrypted_content.chunks(32768 + 28).len();
    debug!(chunk_count = chunk_count, "Decrypting file content");

    let mut decrypted_content = Vec::new();
    for (chunk_number, chunk) in encrypted_content.chunks(32768 + 28).enumerate() {
        let chunk_context = FileContext {
            chunk_number: Some(chunk_number),
            ..base_context.clone()
        };

        trace!(
            chunk = chunk_number,
            chunk_size = chunk.len(),
            "Decrypting chunk"
        );

        if chunk.len() < 28 {
            warn!(
                chunk = chunk_number,
                actual_size = chunk.len(),
                "Incomplete chunk"
            );
            return Err(FileDecryptionError::IncompleteChunk {
                context: chunk_context,
                actual_size: chunk.len(),
            });
        }

        let chunk_nonce = Nonce::from_slice(&chunk[0..12]);
        let ciphertext = &chunk[12..];

        // Build AAD: chunk_number (8 bytes BE) || header_nonce (12 bytes)
        // Use stack array to avoid heap allocation per chunk
        let mut aad = [0u8; 20];
        aad[..8].copy_from_slice(&(chunk_number as u64).to_be_bytes());
        aad[8..].copy_from_slice(header_nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let decrypted_chunk = cipher.decrypt(chunk_nonce, payload).map_err(|_| {
            warn!(
                chunk = chunk_number,
                "Chunk decryption failed - authentication tag mismatch"
            );
            FileDecryptionError::ContentDecryption {
                context: chunk_context.clone(),
            }
        })?;

        trace!(
            chunk = chunk_number,
            decrypted_size = decrypted_chunk.len(),
            "Chunk decrypted successfully"
        );
        decrypted_content.extend_from_slice(&decrypted_chunk);
    }

    debug!(
        decrypted_size = decrypted_content.len(),
        "File content decrypted successfully"
    );
    Ok(decrypted_content)
}

/// Encrypt a file header containing the content encryption key.
///
/// # Reference Implementation
/// - Java: [`FileHeaderCryptorImpl.encryptHeader()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java)
/// - Java: [`FileHeaderCryptorImpl.create()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java) (header creation)
pub fn encrypt_file_header(
    content_key: &[u8; 32],
    master_key: &MasterKey,
) -> Result<Vec<u8>, FileEncryptionError> {
    encrypt_file_header_with_context(content_key, master_key, &FileContext::new())
}

/// Encrypt a file header with contextual error information.
pub fn encrypt_file_header_with_context(
    content_key: &[u8; 32],
    master_key: &MasterKey,
    context: &FileContext,
) -> Result<Vec<u8>, FileEncryptionError> {
    let mut header_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut header_nonce);

    master_key.with_aes_key(|aes_key| {
        let key: &Key<Aes256Gcm> = aes_key.into();
        let cipher = Aes256Gcm::new(key);

        let mut plaintext = vec![0xFF; 8];
        plaintext.extend_from_slice(content_key);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&header_nonce), plaintext.as_ref())
            .map_err(|e| FileEncryptionError::HeaderEncryption {
                reason: e.to_string(),
                context: context.clone(),
            })?;

        let mut encrypted_header = Vec::with_capacity(68);
        encrypted_header.extend_from_slice(&header_nonce);
        encrypted_header.extend_from_slice(&ciphertext);

        Ok(encrypted_header)
    })?
}

/// Encrypt file content using AES-GCM with 32KB chunks.
///
/// # Reference Implementation
/// - Java: [`FileContentCryptorImpl.encryptChunk()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileContentCryptorImpl.java)
pub fn encrypt_file_content(
    content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8; 12],
) -> Result<Vec<u8>, FileEncryptionError> {
    encrypt_file_content_with_context(content, content_key, header_nonce, &FileContext::new())
}

/// Encrypt file content with contextual error information.
pub fn encrypt_file_content_with_context(
    content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8; 12],
    base_context: &FileContext,
) -> Result<Vec<u8>, FileEncryptionError> {
    let key = Key::<Aes256Gcm>::from_slice(content_key);
    let cipher = Aes256Gcm::new(key);

    let mut encrypted_content = Vec::new();
    let chunk_size = 32 * 1024; // 32 KiB

    // Always process at least one chunk, even for empty content
    // This ensures proper authentication for empty files
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![&[]] // One empty chunk
    } else {
        content.chunks(chunk_size).collect()
    };

    for (chunk_number, chunk) in chunks.iter().enumerate() {
        let chunk_context = FileContext {
            chunk_number: Some(chunk_number),
            ..base_context.clone()
        };

        let mut chunk_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut chunk_nonce);

        // Build AAD: chunk_number (8 bytes BE) || header_nonce (12 bytes)
        // Use stack array to avoid heap allocation per chunk
        let mut aad = [0u8; 20];
        aad[..8].copy_from_slice(&(chunk_number as u64).to_be_bytes());
        aad[8..].copy_from_slice(header_nonce);

        let payload = Payload {
            msg: chunk,
            aad: &aad,
        };

        let encrypted_chunk = cipher
            .encrypt(Nonce::from_slice(&chunk_nonce), payload)
            .map_err(|e| FileEncryptionError::ContentEncryption {
                reason: e.to_string(),
                context: chunk_context,
            })?;

        encrypted_content.extend_from_slice(&chunk_nonce);
        encrypted_content.extend_from_slice(&encrypted_chunk);
    }

    Ok(encrypted_content)
}

pub struct DecryptedFile {
    pub header: FileHeader,
    pub content: Vec<u8>,
}

impl fmt::Debug for DecryptedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snippet_len = self.content.len().min(100);
        let content = format!(
            "{:?}",
            String::from_utf8_lossy(&self.content[0..snippet_len])
        );
        let content_str = if snippet_len < self.content.len() {
            format!("{content}...")
        } else {
            content
        };
        f.debug_struct("DecryptedFile")
            .field("header", &self.header)
            .field("content", &content_str)
            .finish()
    }
}

#[instrument(level = "info", skip(master_key), fields(path = %path.display()))]
pub fn decrypt_file(path: &Path, master_key: &MasterKey) -> Result<DecryptedFile, FileError> {
    debug!("Decrypting file");
    let context = FileContext::new().with_path(path);

    if path.file_name() == Some(OsStr::new("dir.c9r")) {
        warn!("Attempted to decrypt directory marker file");
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: "cannot decrypt directory marker files (dir.c9r) as regular files".to_string(),
            context,
        }));
    }

    let encrypted = fs::read(path).map_err(|e| FileError::io_with_context(e, context.clone()))?;
    trace!(encrypted_size = encrypted.len(), "Read encrypted file");

    if encrypted.len() < 68 {
        warn!(
            actual_size = encrypted.len(),
            "File too small for valid encrypted file"
        );
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: format!(
                "file too small: expected at least 68 bytes, got {}",
                encrypted.len()
            ),
            context,
        }));
    }

    debug!("Decrypting header");
    let header = decrypt_file_header_with_context(&encrypted[0..68], master_key, &context)?;

    debug!("Decrypting content");
    let content = decrypt_file_content_with_context(
        &encrypted[68..],
        &header.content_key,
        &encrypted[0..12],
        &context,
    )?;

    Ok(DecryptedFile { header, content })
}

/// Decrypt a file with full context for error messages.
pub fn decrypt_file_with_context(
    path: &Path,
    master_key: &MasterKey,
    filename: Option<&str>,
    dir_id: Option<&str>,
) -> Result<DecryptedFile, FileError> {
    let mut context = FileContext::new().with_path(path);
    if let Some(name) = filename {
        context = context.with_filename(name);
    }
    if let Some(id) = dir_id {
        context = context.with_dir_id(id);
    }

    if path.file_name() == Some(OsStr::new("dir.c9r")) {
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: "cannot decrypt directory marker files (dir.c9r) as regular files".to_string(),
            context,
        }));
    }

    let encrypted = fs::read(path).map_err(|e| FileError::io_with_context(e, context.clone()))?;

    if encrypted.len() < 68 {
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader {
            reason: format!(
                "file too small: expected at least 68 bytes, got {}",
                encrypted.len()
            ),
            context,
        }));
    }

    let header = decrypt_file_header_with_context(&encrypted[0..68], master_key, &context)?;
    let content = decrypt_file_content_with_context(
        &encrypted[68..],
        &header.content_key,
        &encrypted[0..12],
        &context,
    )?;

    Ok(DecryptedFile { header, content })
}

/// Encrypt a directory ID for backup storage in dirid.c9r files.
///
/// The dirid.c9r file stores the **directory's own ID** (not the parent's) using
/// standard AES-GCM file content encryption. This matches the Java Cryptomator
/// reference implementation.
///
/// # Format
///
/// The encrypted data uses the same format as regular encrypted files:
/// - 68-byte header (12-byte nonce + 40-byte encrypted payload + 16-byte tag)
/// - AES-GCM encrypted content chunks (for directory IDs, just one small chunk)
///
/// # Reference Implementation
/// - Java: [`DirectoryIdBackup.write()`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/DirectoryIdBackup.java)
/// - Uses `EncryptedChannels.wrapEncryptionAround()` which applies file content encryption
///
/// # Arguments
///
/// * `dir_id` - The directory's own ID (empty string for root, UUID for subdirectories)
/// * `master_key` - The vault's master key
///
/// # Returns
///
/// The encrypted data suitable for writing to a `dirid.c9r` file.
pub fn encrypt_dir_id_backup(
    dir_id: &str,
    master_key: &MasterKey,
) -> Result<Vec<u8>, FileEncryptionError> {
    // Generate a random content key for this backup file
    let mut content_key = [0u8; 32];
    rand::rng().fill_bytes(&mut content_key);

    // Encrypt the header
    let encrypted_header = encrypt_file_header(&content_key, master_key)?;

    // Extract the header nonce for AAD
    let header_nonce: [u8; 12] = encrypted_header[..12].try_into().unwrap();

    // Encrypt the directory ID as content
    let encrypted_content = encrypt_file_content(dir_id.as_bytes(), &content_key, &header_nonce)?;

    // Combine header and content
    let mut result = encrypted_header;
    result.extend_from_slice(&encrypted_content);

    Ok(result)
}

/// Decrypt a directory ID from a dirid.c9r backup file.
///
/// The dirid.c9r file stores the **directory's own ID** (not the parent's) using
/// standard AES-GCM file content encryption.
///
/// # Reference Implementation
/// - Java: [`DirectoryIdBackup.read()`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/DirectoryIdBackup.java)
///
/// # Arguments
///
/// * `encrypted_data` - The raw bytes from the dirid.c9r file
/// * `master_key` - The vault's master key
///
/// # Returns
///
/// The decrypted directory ID string.
pub fn decrypt_dir_id_backup(
    encrypted_data: &[u8],
    master_key: &MasterKey,
) -> Result<String, FileDecryptionError> {
    let context = FileContext::new().with_filename("dirid.c9r");

    if encrypted_data.len() < 68 {
        return Err(FileDecryptionError::InvalidHeader {
            reason: format!(
                "dirid.c9r too small: expected at least 68 bytes, got {}",
                encrypted_data.len()
            ),
            context,
        });
    }

    // Decrypt the header to get the content key
    let header = decrypt_file_header_with_context(&encrypted_data[..68], master_key, &context)?;

    // Decrypt the content (if any - empty for root directory)
    let content = if encrypted_data.len() > 68 {
        decrypt_file_content_with_context(
            &encrypted_data[68..],
            &header.content_key,
            &encrypted_data[..12],
            &context,
        )?
    } else {
        Vec::new()
    };

    // Convert to string (directory IDs are US-ASCII in Java, valid UTF-8)
    String::from_utf8(content).map_err(|e| FileDecryptionError::InvalidHeader {
        reason: format!("dirid.c9r contains invalid UTF-8: {e}"),
        context,
    })
}
