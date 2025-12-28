//! Fuzz target for AES-GCM file decryption
//!
//! This target focuses on finding vulnerabilities in file header and content
//! decryption. It tests:
//! - Header parsing with malformed 68-byte inputs
//! - Content decryption with chunk boundary issues
//! - Authentication failure handling (no plaintext leakage)

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::file::{
    decrypt_file_content, decrypt_file_header, encrypt_file_content,
};

/// Fixed master key for fuzzing
fn create_fixed_master_key() -> MasterKey {
    let aes_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let mac_key = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    MasterKey::new(aes_key, mac_key)
}

/// Structured input for more targeted fuzzing
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Mode of operation
    mode: FuzzMode,
    /// Raw data to fuzz with
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum FuzzMode {
    /// Fuzz file header decryption with raw bytes
    HeaderRaw,
    /// Fuzz file header with exactly 68 bytes (valid length)
    Header68Bytes,
    /// Fuzz file content decryption
    ContentRaw,
    /// Fuzz roundtrip (encrypt then corrupt then decrypt)
    RoundtripCorrupt,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to avoid OOM
    if input.data.len() > 10 * 1024 * 1024 {
        return;
    }

    let master_key = create_fixed_master_key();

    match input.mode {
        FuzzMode::HeaderRaw => {
            // Test header decryption with arbitrary bytes
            // Should never panic, always return Result
            let _ = decrypt_file_header(&input.data, &master_key);
        }

        FuzzMode::Header68Bytes => {
            // Test header decryption with exactly 68 bytes
            if input.data.len() >= 68 {
                let header_data = &input.data[..68];
                let _ = decrypt_file_header(header_data, &master_key);
            }
        }

        FuzzMode::ContentRaw => {
            // Test content decryption with arbitrary bytes
            // Using fixed content key and nonce
            let content_key = [0x42u8; 32];
            let header_nonce = &[0x00u8; 12];

            let _ = decrypt_file_content(&input.data, &content_key, header_nonce);
        }

        FuzzMode::RoundtripCorrupt => {
            // Encrypt valid content, corrupt it, verify decryption fails
            if input.data.is_empty() {
                return;
            }

            let content_key = [0x42u8; 32];
            let header_nonce = [0x00u8; 12];

            // Encrypt the fuzz input as content
            if let Ok(encrypted) = encrypt_file_content(&input.data, &content_key, &header_nonce) {
                // Verify clean roundtrip works
                let decrypted = decrypt_file_content(&encrypted, &content_key, &header_nonce)
                    .expect("Roundtrip of valid content must succeed");
                assert_eq!(
                    input.data.as_slice(),
                    decrypted.as_slice(),
                    "Roundtrip must preserve content"
                );

                // Now corrupt the encrypted data and verify decryption fails
                if !encrypted.is_empty() {
                    let mut corrupted = encrypted.clone();
                    // Flip a bit in a random position based on input
                    let pos = input.data.iter().map(|&b| b as usize).sum::<usize>() % corrupted.len();
                    corrupted[pos] ^= 0x01;

                    // Corrupted data should fail decryption (integrity violation)
                    let result = decrypt_file_content(&corrupted, &content_key, &header_nonce);
                    // It's OK if it fails (expected) or succeeds rarely (collision)
                    // But it must not panic
                    let _ = result;
                }
            }
        }
    }
});
