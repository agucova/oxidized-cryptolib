//! AES-CTR + HMAC-SHA256 file encryption for the SIV_CTRMAC cipher combo.
//!
//! This module implements the v1 Cryptomator file format which uses:
//! - AES-CTR for encryption (with 16-byte nonces)
//! - HMAC-SHA256 for authentication (32-byte MACs)
//!
//! # File Header Format (88 bytes)
//!
//! | Offset | Size | Description |
//! |--------|------|-------------|
//! | 0      | 16   | Nonce (IV for AES-CTR) |
//! | 16     | 40   | Encrypted payload (8-byte reserved + 32-byte content key) |
//! | 56     | 32   | HMAC-SHA256 over nonce + encrypted payload |
//!
//! # Content Chunk Format (up to 32816 bytes)
//!
//! | Offset | Size | Description |
//! |--------|------|-------------|
//! | 0      | 16   | Chunk nonce |
//! | 16     | n    | AES-CTR encrypted payload (up to 32768 bytes) |
//! | 16+n   | 32   | HMAC-SHA256 over (header_nonce + chunk_number + nonce + ciphertext) |
//!
//! # Reference Implementation
//! - Java: [`org.cryptomator.cryptolib.v1`](https://github.com/cryptomator/cryptolib/tree/develop/src/main/java/org/cryptomator/cryptolib/v1)

use std::fmt;

use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use ring::hmac;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::{debug, instrument, trace, warn};
use zeroize::Zeroizing;

use crate::crypto::keys::{KeyAccessError, MasterKey};

use super::file::FileContext;

// ============================================================================
// Constants
// ============================================================================

/// Nonce size for AES-CTR in v1 format (16 bytes)
pub const NONCE_SIZE: usize = 16;

/// HMAC-SHA256 output size (32 bytes)
pub const MAC_SIZE: usize = 32;

/// Cleartext payload size per chunk (32 KB)
pub const PAYLOAD_SIZE: usize = 32 * 1024;

/// Total encrypted chunk size: nonce + payload + MAC
pub const CHUNK_SIZE: usize = NONCE_SIZE + PAYLOAD_SIZE + MAC_SIZE;

/// File header size: nonce + encrypted payload + MAC
pub const HEADER_SIZE: usize = NONCE_SIZE + 40 + MAC_SIZE; // 88 bytes

/// Header payload size (8-byte reserved + 32-byte content key)
const HEADER_PAYLOAD_SIZE: usize = 40;

// ============================================================================
// Type Aliases
// ============================================================================

/// AES-256-CTR with big-endian 128-bit counter (matches Java implementation)
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum CtrMacError {
    /// HMAC verification failed - possible tampering
    #[error("HMAC verification failed for {context}: possible tampering or wrong key")]
    HmacVerification { context: FileContext },

    /// Invalid header structure
    #[error("Invalid header for {context}: {reason}")]
    InvalidHeader { reason: String, context: FileContext },

    /// Invalid chunk structure
    #[error("Invalid chunk for {context}: {reason}")]
    InvalidChunk { reason: String, context: FileContext },

    /// Key access failed
    #[error("Key access failed: {0}")]
    KeyAccess(#[from] KeyAccessError),
}

// ============================================================================
// File Header
// ============================================================================

/// Decrypted file header containing the content encryption key.
pub struct CtrMacFileHeader {
    /// The original nonce from the header (needed for chunk MAC calculation)
    pub nonce: [u8; NONCE_SIZE],
    /// The decrypted content encryption key
    pub content_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for CtrMacFileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtrMacFileHeader")
            .field("nonce", &hex::encode(self.nonce))
            .field("content_key", &"[REDACTED]")
            .finish()
    }
}

/// Decrypt a file header using AES-CTR + HMAC-SHA256.
///
/// # Reference Implementation
/// - Java: [`FileHeaderCryptorImpl.decryptHeader()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v1/FileHeaderCryptorImpl.java)
#[instrument(level = "debug", skip(encrypted_header, master_key), fields(header_size = encrypted_header.len()))]
pub fn decrypt_header(
    encrypted_header: &[u8],
    master_key: &MasterKey,
    context: &FileContext,
) -> Result<CtrMacFileHeader, CtrMacError> {
    trace!("Decrypting CTRMAC file header");

    if encrypted_header.len() != HEADER_SIZE {
        warn!(
            actual_size = encrypted_header.len(),
            expected_size = HEADER_SIZE,
            "Invalid header size"
        );
        return Err(CtrMacError::InvalidHeader {
            reason: format!(
                "expected {} bytes, got {} bytes",
                HEADER_SIZE,
                encrypted_header.len()
            ),
            context: context.clone(),
        });
    }

    // Parse header components
    let nonce: [u8; NONCE_SIZE] = encrypted_header[..NONCE_SIZE].try_into().unwrap();
    let ciphertext = &encrypted_header[NONCE_SIZE..NONCE_SIZE + HEADER_PAYLOAD_SIZE];
    let expected_mac = &encrypted_header[NONCE_SIZE + HEADER_PAYLOAD_SIZE..];

    // Verify HMAC first (authenticate-then-decrypt)
    master_key.with_mac_key(|mac_key| {
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        let data_to_verify = &encrypted_header[..NONCE_SIZE + HEADER_PAYLOAD_SIZE];

        // Compute expected MAC
        let computed_mac = hmac::sign(&key, data_to_verify);

        // Constant-time comparison
        if computed_mac.as_ref().ct_eq(expected_mac).into() {
            Ok(())
        } else {
            warn!("Header HMAC verification failed");
            Err(CtrMacError::HmacVerification {
                context: context.clone(),
            })
        }
    })??;

    // Decrypt payload with AES-CTR
    let content_key = master_key.with_aes_key(|aes_key| {
        let mut cipher = Aes256Ctr::new(aes_key.into(), (&nonce).into());

        // Use Zeroizing to ensure plaintext (containing content key) is securely erased
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        cipher.apply_keystream(&mut plaintext);

        // plaintext is now: 8-byte reserved + 32-byte content key
        if plaintext.len() != HEADER_PAYLOAD_SIZE {
            return Err(CtrMacError::InvalidHeader {
                reason: format!(
                    "decrypted payload has wrong size: expected {}, got {}",
                    HEADER_PAYLOAD_SIZE,
                    plaintext.len()
                ),
                context: context.clone(),
            });
        }

        // Check reserved bytes (should be -1 as signed long, i.e., 0xFFFFFFFFFFFFFFFF)
        // Java uses -1L which is all 1s in two's complement
        let reserved = &plaintext[..8];
        if reserved != [0xFF; 8] {
            debug!(
                reserved_bytes = ?hex::encode(reserved),
                "Header has non-standard reserved bytes (expected 0xFF padding)"
            );
        }

        let mut content_key = Zeroizing::new([0u8; 32]);
        content_key.copy_from_slice(&plaintext[8..40]);

        Ok(content_key)
    })??;

    debug!("CTRMAC file header decrypted successfully");
    Ok(CtrMacFileHeader { nonce, content_key })
}

// ============================================================================
// File Content
// ============================================================================

/// Decrypt file content using AES-CTR + HMAC-SHA256.
///
/// # Reference Implementation
/// - Java: [`FileContentCryptorImpl.decryptChunk()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v1/FileContentCryptorImpl.java)
#[instrument(level = "debug", skip(encrypted_content, content_key, header_nonce, mac_key), fields(encrypted_size = encrypted_content.len()))]
pub fn decrypt_content(
    encrypted_content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8; NONCE_SIZE],
    mac_key: &[u8],
    base_context: &FileContext,
) -> Result<Vec<u8>, CtrMacError> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);

    // Calculate number of chunks
    // Minimum chunk size is NONCE_SIZE + MAC_SIZE (empty payload)
    let min_chunk_size = NONCE_SIZE + MAC_SIZE;
    let chunk_count = if encrypted_content.is_empty() {
        0
    } else {
        // Ceiling division to handle partial chunks
        encrypted_content.len().div_ceil(CHUNK_SIZE)
    };

    debug!(chunk_count = chunk_count, "Decrypting CTRMAC file content");

    let mut decrypted_content = Vec::new();
    let mut offset = 0;
    let mut chunk_number: u64 = 0;

    while offset < encrypted_content.len() {
        let chunk_end = (offset + CHUNK_SIZE).min(encrypted_content.len());
        let chunk = &encrypted_content[offset..chunk_end];

        let chunk_context = FileContext {
            // chunk_number is u64 but FileContext expects usize - safe cast since chunk numbers
            // are always small (file would need to be 32 exabytes to exceed u32::MAX chunks)
            #[allow(clippy::cast_possible_truncation)]
            chunk_number: Some(chunk_number as usize),
            ..base_context.clone()
        };

        trace!(
            chunk = chunk_number,
            chunk_size = chunk.len(),
            "Decrypting chunk"
        );

        if chunk.len() < min_chunk_size {
            warn!(
                chunk = chunk_number,
                actual_size = chunk.len(),
                min_size = min_chunk_size,
                "Incomplete chunk"
            );
            return Err(CtrMacError::InvalidChunk {
                reason: format!(
                    "chunk too small: expected at least {} bytes, got {}",
                    min_chunk_size,
                    chunk.len()
                ),
                context: chunk_context,
            });
        }

        // Parse chunk components
        let chunk_nonce: [u8; NONCE_SIZE] = chunk[..NONCE_SIZE].try_into().unwrap();
        let ciphertext = &chunk[NONCE_SIZE..chunk.len() - MAC_SIZE];
        let expected_mac = &chunk[chunk.len() - MAC_SIZE..];

        // Verify HMAC: MAC(header_nonce || chunk_number_be || chunk_nonce || ciphertext)
        let mut mac_context = hmac::Context::with_key(&hmac_key);
        mac_context.update(header_nonce);
        mac_context.update(&chunk_number.to_be_bytes());
        mac_context.update(&chunk_nonce);
        mac_context.update(ciphertext);
        let computed_mac = mac_context.sign();

        // Constant-time comparison
        if !bool::from(computed_mac.as_ref().ct_eq(expected_mac)) {
            warn!(chunk = chunk_number, "Chunk HMAC verification failed");
            return Err(CtrMacError::HmacVerification {
                context: chunk_context,
            });
        }

        // Decrypt with AES-CTR
        let mut cipher = Aes256Ctr::new(content_key.into(), (&chunk_nonce).into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        trace!(
            chunk = chunk_number,
            decrypted_size = plaintext.len(),
            "Chunk decrypted successfully"
        );
        decrypted_content.extend_from_slice(&plaintext);

        offset = chunk_end;
        chunk_number += 1;
    }

    debug!(
        decrypted_size = decrypted_content.len(),
        "CTRMAC file content decrypted successfully"
    );
    Ok(decrypted_content)
}

// ============================================================================
// Encryption (for write support)
// ============================================================================

/// Encrypt a file header using AES-CTR + HMAC-SHA256.
///
/// # Reference Implementation
/// - Java: [`FileHeaderCryptorImpl.encryptHeader()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v1/FileHeaderCryptorImpl.java)
pub fn encrypt_header(
    content_key: &[u8; 32],
    master_key: &MasterKey,
) -> Result<Vec<u8>, CtrMacError> {
    // Generate random nonce
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);

    // Build plaintext: reserved (8 bytes of 0xFF) + content key
    // Use Zeroizing to ensure plaintext (containing content key) is securely erased
    let mut plaintext = Zeroizing::new(vec![0xFF; 8]);
    plaintext.extend_from_slice(content_key);

    // Encrypt with AES-CTR
    let ciphertext = master_key.with_aes_key(|aes_key| {
        let mut cipher = Aes256Ctr::new(aes_key.into(), (&nonce).into());
        // Use Zeroizing for encrypted buffer (also contains content key material)
        let mut encrypted = Zeroizing::new(plaintext.to_vec());
        cipher.apply_keystream(&mut encrypted);
        // Return the inner Vec - the Zeroizing wrapper gets dropped here, zeroing the buffer
        Ok::<_, CtrMacError>(encrypted.to_vec())
    })??;

    // Compute HMAC over nonce + ciphertext
    let mac = master_key.with_mac_key(|mac_key| {
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        let mut data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        Ok::<_, CtrMacError>(hmac::sign(&key, &data))
    })??;

    // Build header: nonce + ciphertext + MAC
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ciphertext);
    header.extend_from_slice(mac.as_ref());

    Ok(header)
}

/// Encrypt file content using AES-CTR + HMAC-SHA256.
///
/// # Reference Implementation
/// - Java: [`FileContentCryptorImpl.encryptChunk()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v1/FileContentCryptorImpl.java)
pub fn encrypt_content(
    content: &[u8],
    content_key: &[u8; 32],
    header_nonce: &[u8; NONCE_SIZE],
    mac_key: &[u8],
) -> Result<Vec<u8>, CtrMacError> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);

    let mut encrypted_content = Vec::new();

    // Always process at least one chunk (even for empty content)
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![&[]]
    } else {
        content.chunks(PAYLOAD_SIZE).collect()
    };

    for (chunk_number, chunk) in chunks.iter().enumerate() {
        // Generate random nonce for this chunk
        let mut chunk_nonce = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut chunk_nonce);

        // Encrypt with AES-CTR
        let mut cipher = Aes256Ctr::new(content_key.into(), (&chunk_nonce).into());
        let mut ciphertext = chunk.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Compute HMAC: MAC(header_nonce || chunk_number_be || chunk_nonce || ciphertext)
        let mut mac_context = hmac::Context::with_key(&hmac_key);
        mac_context.update(header_nonce);
        mac_context.update(&(chunk_number as u64).to_be_bytes());
        mac_context.update(&chunk_nonce);
        mac_context.update(&ciphertext);
        let mac = mac_context.sign();

        // Append: nonce + ciphertext + MAC
        encrypted_content.extend_from_slice(&chunk_nonce);
        encrypted_content.extend_from_slice(&ciphertext);
        encrypted_content.extend_from_slice(mac.as_ref());
    }

    Ok(encrypted_content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let master_key = MasterKey::random().unwrap();
        let mut content_key = [0u8; 32];
        rand::rng().fill_bytes(&mut content_key);

        let encrypted = encrypt_header(&content_key, &master_key).unwrap();
        assert_eq!(encrypted.len(), HEADER_SIZE);

        let header = decrypt_header(&encrypted, &master_key, &FileContext::new()).unwrap();
        assert_eq!(header.content_key.as_ref(), &content_key);
    }

    #[test]
    fn test_content_roundtrip() {
        let mut content_key = [0u8; 32];
        let mut header_nonce = [0u8; NONCE_SIZE];
        let mut mac_key = [0u8; 32];

        rand::rng().fill_bytes(&mut content_key);
        rand::rng().fill_bytes(&mut header_nonce);
        rand::rng().fill_bytes(&mut mac_key);

        let plaintext = b"Hello, Cryptomator!";
        let encrypted = encrypt_content(plaintext, &content_key, &header_nonce, &mac_key).unwrap();

        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, &FileContext::new())
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_content_multi_chunk() {
        let mut content_key = [0u8; 32];
        let mut header_nonce = [0u8; NONCE_SIZE];
        let mut mac_key = [0u8; 32];

        rand::rng().fill_bytes(&mut content_key);
        rand::rng().fill_bytes(&mut header_nonce);
        rand::rng().fill_bytes(&mut mac_key);

        // Create content larger than one chunk
        // Safe cast: (i % 256) always produces values 0-255, fits safely in u8
        let plaintext: Vec<u8> = (0..PAYLOAD_SIZE + 1000).map(|i| (i % 256) as u8).collect();

        let encrypted =
            encrypt_content(&plaintext, &content_key, &header_nonce, &mac_key).unwrap();

        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, &FileContext::new())
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_header_mac() {
        let master_key = MasterKey::random().unwrap();
        let mut content_key = [0u8; 32];
        rand::rng().fill_bytes(&mut content_key);

        let mut encrypted = encrypt_header(&content_key, &master_key).unwrap();

        // Tamper with the MAC
        encrypted[HEADER_SIZE - 1] ^= 0xFF;

        let result = decrypt_header(&encrypted, &master_key, &FileContext::new());
        assert!(matches!(result, Err(CtrMacError::HmacVerification { .. })));
    }

    #[test]
    fn test_tampered_content_mac() {
        let mut content_key = [0u8; 32];
        let mut header_nonce = [0u8; NONCE_SIZE];
        let mut mac_key = [0u8; 32];

        rand::rng().fill_bytes(&mut content_key);
        rand::rng().fill_bytes(&mut header_nonce);
        rand::rng().fill_bytes(&mut mac_key);

        let plaintext = b"Hello, Cryptomator!";
        let mut encrypted =
            encrypt_content(plaintext, &content_key, &header_nonce, &mac_key).unwrap();

        // Tamper with the MAC
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        let result =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, &FileContext::new());
        assert!(matches!(result, Err(CtrMacError::HmacVerification { .. })));
    }
}
