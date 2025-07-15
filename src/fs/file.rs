use std::{ffi::OsStr, fmt, fs, io, path::Path};

use aead::Payload;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

use crate::crypto::keys::MasterKey;

#[derive(Error, Debug)]
pub enum FileError {
    #[error("File decryption error: {0}")]
    Decryption(#[from] FileDecryptionError),
    #[error("File encryption error: {0}")]
    Encryption(#[from] FileEncryptionError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum FileDecryptionError {
    #[error("Failed to decrypt file header: {0}")]
    HeaderDecryption(String),
    #[error("Failed to decrypt file content: {0}")]
    ContentDecryption(String),
    #[error("Invalid file header: {0}")]
    InvalidHeader(String),
    #[error("IO error during decryption: {0}")]
    Io(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum FileEncryptionError {
    #[error("Failed to encrypt file header: {0}")]
    HeaderEncryption(String),
    #[error("Failed to encrypt file content: {0}")]
    ContentEncryption(String),
    #[error("IO error during encryption: {0}")]
    Io(#[from] io::Error),
}

pub struct FileHeader {
    pub content_key: [u8; 32],
    pub tag: [u8; 16],
}

impl fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileHeader")
            .field("content_key", &hex::encode(self.content_key))
            .field("tag", &hex::encode(self.tag))
            .finish()
    }
}

pub fn decrypt_file_header(
    encrypted_header: &[u8],
    master_key: &MasterKey,
) -> Result<FileHeader, FileDecryptionError> {
    if encrypted_header.len() != 68 {
        return Err(FileDecryptionError::InvalidHeader(
            "Incorrect header length".to_string(),
        ));
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
            .map_err(|e| FileDecryptionError::HeaderDecryption(e.to_string()))?;

        if decrypted.len() != 40 || decrypted[0..8] != [0xFF; 8] {
            return Err(FileDecryptionError::InvalidHeader(
                "Decrypted header has incorrect format".to_string(),
            ));
        }

        let mut content_key = [0u8; 32];
        content_key.copy_from_slice(&decrypted[8..40]);

        Ok(FileHeader { content_key, tag })
    })
}

pub fn decrypt_file_content(
    encrypted_content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8],
) -> Result<Vec<u8>, FileDecryptionError> {
    let key = Key::<Aes256Gcm>::from_slice(content_key);
    let cipher = Aes256Gcm::new(key);

    let mut decrypted_content = Vec::new();
    for (chunk_number, chunk) in encrypted_content.chunks(32768 + 28).enumerate() {
        if chunk.len() < 28 {
            return Err(FileDecryptionError::ContentDecryption(
                "Incomplete chunk".to_string(),
            ));
        }

        let chunk_nonce = Nonce::from_slice(&chunk[0..12]);
        let ciphertext = &chunk[12..];

        let mut aad = Vec::new();
        aad.extend_from_slice(&(chunk_number as u64).to_be_bytes());
        aad.extend_from_slice(header_nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let decrypted_chunk = cipher
            .decrypt(chunk_nonce, payload)
            .map_err(|e| FileDecryptionError::ContentDecryption(e.to_string()))?;

        decrypted_content.extend_from_slice(&decrypted_chunk);
    }

    Ok(decrypted_content)
}

pub fn encrypt_file_header(
    content_key: &[u8; 32],
    master_key: &MasterKey,
) -> Result<Vec<u8>, FileEncryptionError> {
    let mut header_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut header_nonce);

    master_key.with_aes_key(|aes_key| {
        let key: &Key<Aes256Gcm> = aes_key.into();
        let cipher = Aes256Gcm::new(key);

        let mut plaintext = vec![0xFF; 8];
        plaintext.extend_from_slice(content_key);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&header_nonce), plaintext.as_ref())
            .map_err(|e| FileEncryptionError::HeaderEncryption(e.to_string()))?;

        let mut encrypted_header = Vec::with_capacity(68);
        encrypted_header.extend_from_slice(&header_nonce);
        encrypted_header.extend_from_slice(&ciphertext);

        Ok(encrypted_header)
    })
}

pub fn encrypt_file_content(
    content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8; 12],
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
        let mut chunk_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut chunk_nonce);

        let mut aad = Vec::new();
        aad.extend_from_slice(&(chunk_number as u64).to_be_bytes());
        aad.extend_from_slice(header_nonce);

        let payload = Payload {
            msg: chunk,
            aad: &aad,
        };

        let encrypted_chunk = cipher
            .encrypt(Nonce::from_slice(&chunk_nonce), payload)
            .map_err(|e| FileEncryptionError::ContentEncryption(e.to_string()))?;

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

pub fn decrypt_file(path: &Path, master_key: &MasterKey) -> Result<DecryptedFile, FileError> {
    if path.file_name() == Some(OsStr::new("dir.c9r")) {
        return Err(FileError::Decryption(FileDecryptionError::InvalidHeader(
            "This function cannot be used on directory files".to_string(),
        )));
    }

    let encrypted = fs::read(path).map_err(FileError::Io)?;
    let header = decrypt_file_header(&encrypted[0..68], master_key)?;
    let content = decrypt_file_content(&encrypted[68..], &header.content_key, &encrypted[0..12])?;

    Ok(DecryptedFile { header, content })
}
