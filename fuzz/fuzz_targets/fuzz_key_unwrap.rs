//! Fuzz target for RFC 3394 AES Key Unwrap
//!
//! This target focuses on finding authentication bypass vulnerabilities in the
//! key unwrapping implementation. It uses a fixed KEK and fuzzes the ciphertext
//! input to explore error handling paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidized_cryptolib::crypto::key_wrap::{unwrap_key, wrap_key};
use secrecy::SecretBox;

/// Fixed Key Encryption Key for fuzzing
/// Using a deterministic key so we focus on parsing/validation bugs, not key material
const FIXED_KEK: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fuzz_target!(|data: &[u8]| {
    // Limit input size to avoid OOM
    if data.len() > 1024 * 1024 {
        return;
    }

    let kek = SecretBox::new(Box::new(FIXED_KEK));

    // Test 1: Fuzz unwrap with arbitrary ciphertext
    // This should never panic - it should return an error for invalid inputs
    let _ = unwrap_key(data, &kek);

    // Test 2: If the data is a valid multiple of 8, also test roundtrip
    if !data.is_empty() && data.len() % 8 == 0 {
        // Try to wrap the data as a plaintext key
        if let Ok(wrapped) = wrap_key(data, &kek) {
            // If wrap succeeded, unwrap must succeed and return original
            let unwrapped = unwrap_key(&wrapped, &kek)
                .expect("Unwrap of freshly wrapped key must succeed");
            assert_eq!(
                data,
                unwrapped.as_slice(),
                "Roundtrip must preserve original data"
            );
        }
    }
});
