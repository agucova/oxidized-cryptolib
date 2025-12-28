//! Timing leak detection tests using the dudect methodology.
//!
//! These tests verify that security-critical operations run in constant time
//! by statistically comparing execution times between different input classes.
//!
//! # Methodology
//!
//! Using the dudect statistical framework, we test whether operations like
//! key verification and decryption take the same amount of time regardless
//! of whether the input is valid or invalid. A timing difference would
//! indicate a potential side-channel that could leak information.
//!
//! # Interpretation
//!
//! - t-value < 4.5: No statistically significant timing difference (PASS)
//! - t-value > 4.5: Strong evidence of timing difference (FAIL)
//!
//! # Running the tests
//!
//! ```bash
//! # Quick test (fast, lower confidence)
//! cargo bench --release --bench timing_leaks -- --quick
//!
//! # Full test (slower, higher confidence)
//! cargo bench --release --bench timing_leaks
//! ```

use dudect_bencher::rand::{Rng, RngCore};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::file::{
    decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
};
use oxidized_cryptolib::fs::name::{decrypt_filename, encrypt_filename};
use ring::hmac;
use subtle::ConstantTimeEq;

/// Helper to generate random bytes using BenchRng
fn rand_bytes<const N: usize>(rng: &mut BenchRng) -> [u8; N] {
    let mut arr = [0u8; N];
    rng.fill_bytes(&mut arr);
    arr
}

/// RFC 3394 integrity check IV (from RFC 3394 Section 2.2.3.1)
const IV_3394: [u8; 8] = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];

/// Test that the RFC 3394 integrity check comparison runs in constant time.
///
/// This tests ONLY the `ct_eq` comparison used in key unwrap, isolating it
/// from the different success/failure code paths (zeroize, allocation, etc.).
///
/// The security property we care about is that the comparison doesn't leak
/// which bytes differ between the computed integrity check and the expected IV.
///
/// We compare:
/// - Left: Integrity check matches IV (what happens with correct KEK)
/// - Right: Integrity check doesn't match IV (what happens with wrong KEK)
fn timing_key_unwrap(runner: &mut CtRunner, rng: &mut BenchRng) {
    let expected = IV_3394;

    // Generate a "wrong" integrity check value (simulates wrong KEK result)
    let wrong_integrity: [u8; 8] = rand_bytes::<8>(rng);

    // Generate batch of inputs with random class assignments
    let mut classes = Vec::with_capacity(1000);
    let mut integrity_checks = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            integrity_checks.push(expected); // Matching (correct KEK scenario)
        } else {
            classes.push(Class::Right);
            integrity_checks.push(wrong_integrity); // Non-matching (wrong KEK scenario)
        }
    }

    // Run timing measurements - ONLY the ct_eq comparison
    for (class, integrity_check) in classes.into_iter().zip(integrity_checks.into_iter()) {
        runner.run_one(class, || {
            // This is exactly what key_wrap.rs does at line 178
            let result = integrity_check.ct_eq(&expected);
            std::hint::black_box(result);
        });
    }
}

/// Test that HMAC verification runs in constant time.
///
/// ring::hmac::verify() should be constant-time by design, but we verify
/// this property to catch any regressions or unexpected behavior.
///
/// We compare:
/// - Left: Verify correct MAC
/// - Right: Verify incorrect MAC (one byte flipped)
fn timing_hmac_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Generate a random key and message
    let key_bytes = rand_bytes::<32>(rng);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let message = rand_bytes::<64>(rng);

    // Generate the correct MAC
    let correct_tag = hmac::sign(&key, &message);
    let correct_tag_bytes: Vec<u8> = correct_tag.as_ref().to_vec();

    // Create an incorrect MAC (flip one byte)
    let mut wrong_tag_bytes = correct_tag_bytes.clone();
    wrong_tag_bytes[0] ^= 0xFF;

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut tags = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            tags.push(correct_tag_bytes.clone());
        } else {
            classes.push(Class::Right);
            tags.push(wrong_tag_bytes.clone());
        }
    }

    // Run timing measurements
    for (class, tag) in classes.into_iter().zip(tags.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(hmac::verify(&key, &message, &tag));
        });
    }
}

/// Test that AES-GCM file header decryption runs in constant time.
///
/// This tests that the authenticated decryption doesn't leak timing
/// information about whether the authentication tag is valid.
///
/// We compare:
/// - Left: Decrypt valid header (correct tag)
/// - Right: Decrypt tampered header (corrupted tag)
fn timing_aes_gcm_header(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let content_key = rand_bytes::<32>(rng);

    // Encrypt a header
    let valid_header = encrypt_file_header(&content_key, &master_key).expect("encrypt should work");

    // Create an invalid header by corrupting the authentication tag
    // The tag is in the last 16 bytes of the 68-byte header
    let mut invalid_header = valid_header.clone();
    invalid_header[52] ^= 0xFF; // Corrupt the first byte of the tag

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut headers = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            headers.push(valid_header.clone());
        } else {
            classes.push(Class::Right);
            headers.push(invalid_header.clone());
        }
    }

    // Run timing measurements
    for (class, header) in classes.into_iter().zip(headers.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_file_header(&header, &master_key));
        });
    }
}

/// Test that AES-GCM file content decryption runs in constant time.
///
/// We compare:
/// - Left: Decrypt valid content (correct tag)
/// - Right: Decrypt tampered content (corrupted tag)
fn timing_aes_gcm_content(runner: &mut CtRunner, rng: &mut BenchRng) {
    let content_key = rand_bytes::<32>(rng);
    let header_nonce = rand_bytes::<12>(rng);

    // Use a small content size to keep the test fast
    let plaintext = rand_bytes::<256>(rng);

    // Encrypt the content
    let valid_ciphertext =
        encrypt_file_content(&plaintext, &content_key, &header_nonce).expect("encrypt should work");

    // Create invalid ciphertext by corrupting the authentication tag
    let mut invalid_ciphertext = valid_ciphertext.clone();
    if invalid_ciphertext.len() > 16 {
        // Corrupt somewhere in the tag region (last 16 bytes of first chunk)
        let tag_offset = invalid_ciphertext.len() - 16;
        invalid_ciphertext[tag_offset] ^= 0xFF;
    }

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut ciphertexts = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            ciphertexts.push(valid_ciphertext.clone());
        } else {
            classes.push(Class::Right);
            ciphertexts.push(invalid_ciphertext.clone());
        }
    }

    // Run timing measurements
    for (class, ct) in classes.into_iter().zip(ciphertexts.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_file_content(&ct, &content_key, &header_nonce));
        });
    }
}

/// Test that AES-SIV filename decryption runs in constant time.
///
/// We compare:
/// - Left: Decrypt valid encrypted filename
/// - Right: Decrypt corrupted encrypted filename (authentication fails)
fn timing_aes_siv_filename(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let filename = "test_file.txt";
    let parent_dir_id = "";

    // Encrypt the filename
    let valid_encrypted =
        encrypt_filename(filename, parent_dir_id, &master_key).expect("encrypt should work");

    // Create an invalid encrypted filename by corrupting it
    let mut chars: Vec<char> = valid_encrypted.chars().collect();
    if !chars.is_empty() {
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    }
    let invalid_encrypted: String = chars.into_iter().collect();

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut encrypted_names = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            encrypted_names.push(valid_encrypted.clone());
        } else {
            classes.push(Class::Right);
            encrypted_names.push(invalid_encrypted.clone());
        }
    }

    // Run timing measurements
    for (class, name) in classes.into_iter().zip(encrypted_names.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_filename(&name, parent_dir_id, &master_key));
        });
    }
}

/// Test that AES-SIV decryption with wrong parent directory ID runs in constant time.
///
/// This tests the scenario where an attacker tries to decrypt a filename
/// that was encrypted with a different parent directory ID.
///
/// We compare:
/// - Left: Decrypt with correct parent directory ID
/// - Right: Decrypt with wrong parent directory ID (authentication fails)
fn timing_aes_siv_wrong_context(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let filename = "test_file.txt";
    let correct_parent_id = "correct-parent-uuid";
    let wrong_parent_id = "wrong-parent-uuid";

    // Encrypt the filename with the correct parent ID
    let encrypted =
        encrypt_filename(filename, correct_parent_id, &master_key).expect("encrypt should work");

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut parent_ids = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            parent_ids.push(correct_parent_id);
        } else {
            classes.push(Class::Right);
            parent_ids.push(wrong_parent_id);
        }
    }

    // Run timing measurements
    for (class, parent_id) in classes.into_iter().zip(parent_ids.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_filename(&encrypted, parent_id, &master_key));
        });
    }
}

// Register all timing tests
ctbench_main!(
    timing_key_unwrap,
    timing_hmac_verify,
    timing_aes_gcm_header,
    timing_aes_gcm_content,
    timing_aes_siv_filename,
    timing_aes_siv_wrong_context
);
