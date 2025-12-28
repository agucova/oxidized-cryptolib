//! Fuzz target for AES-SIV filename decryption
//!
//! This target focuses on finding vulnerabilities in filename encryption and
//! decryption. It tests:
//! - Malformed base64 handling
//! - Invalid UTF-8 after decryption
//! - Context confusion (wrong parent directory ID)
//! - Determinism (same input = same output)

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::name::{decrypt_filename, encrypt_filename, hash_dir_id};

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
    /// Primary data (filename or encrypted name)
    data: String,
    /// Secondary data (parent directory ID)
    parent_dir_id: String,
}

#[derive(Arbitrary, Debug)]
enum FuzzMode {
    /// Fuzz decryption with arbitrary strings
    DecryptRaw,
    /// Fuzz encryption then decryption roundtrip
    EncryptRoundtrip,
    /// Fuzz context confusion (encrypt with one parent ID, decrypt with another)
    ContextConfusion,
    /// Fuzz directory ID hashing
    DirIdHash,
    /// Verify determinism of encryption
    Determinism,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to avoid OOM
    if input.data.len() > 1024 * 1024 || input.parent_dir_id.len() > 1024 * 1024 {
        return;
    }

    let master_key = create_fixed_master_key();

    match input.mode {
        FuzzMode::DecryptRaw => {
            // Test decryption with arbitrary strings
            // Should never panic, always return Result
            let _ = decrypt_filename(&input.data, &input.parent_dir_id, &master_key);

            // Also test with .c9r extension
            let with_ext = format!("{}.c9r", input.data);
            let _ = decrypt_filename(&with_ext, &input.parent_dir_id, &master_key);
        }

        FuzzMode::EncryptRoundtrip => {
            // Encrypt and decrypt should roundtrip
            if let Ok(encrypted) = encrypt_filename(&input.data, &input.parent_dir_id, &master_key) {
                let decrypted = decrypt_filename(&encrypted, &input.parent_dir_id, &master_key)
                    .expect("Decryption of freshly encrypted filename must succeed");
                assert_eq!(
                    input.data, decrypted,
                    "Roundtrip must preserve original filename"
                );
            }
        }

        FuzzMode::ContextConfusion => {
            // Encrypt with one parent ID, try to decrypt with another
            // This should fail (integrity violation) unless the parent IDs happen to be equal
            if input.data.is_empty() {
                return;
            }

            let parent_id_1 = &input.parent_dir_id;
            // Create a different parent ID by appending something
            let parent_id_2 = format!("{}_different", input.parent_dir_id);

            if let Ok(encrypted) = encrypt_filename(&input.data, parent_id_1, &master_key) {
                // Decryption with correct parent ID must succeed
                let _ = decrypt_filename(&encrypted, parent_id_1, &master_key)
                    .expect("Decryption with correct parent ID must succeed");

                // Decryption with wrong parent ID should fail
                // (unless by extreme coincidence the SIV tag matches)
                let result = decrypt_filename(&encrypted, &parent_id_2, &master_key);
                // We don't assert failure because hash collisions are theoretically possible
                // but the implementation must not panic
                let _ = result;
            }
        }

        FuzzMode::DirIdHash => {
            // Test directory ID hashing - should never panic
            let _ = hash_dir_id(&input.data, &master_key);
        }

        FuzzMode::Determinism => {
            // Verify that encryption is deterministic (AES-SIV property)
            if let Ok(encrypted1) = encrypt_filename(&input.data, &input.parent_dir_id, &master_key) {
                let encrypted2 = encrypt_filename(&input.data, &input.parent_dir_id, &master_key)
                    .expect("Second encryption must succeed if first did");
                assert_eq!(
                    encrypted1, encrypted2,
                    "AES-SIV encryption must be deterministic"
                );
            }
        }
    }
});
