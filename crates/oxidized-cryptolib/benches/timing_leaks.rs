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

use base64::{engine::general_purpose::URL_SAFE, Engine};
use dudect_bencher::rand::{Rng, RngCore};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::file::{
    decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
    FileContext,
};
use oxidized_cryptolib::fs::file_ctrmac::{
    decrypt_content as ctrmac_decrypt_content, decrypt_header as ctrmac_decrypt_header,
    encrypt_content as ctrmac_encrypt_content, encrypt_header as ctrmac_encrypt_header,
    NONCE_SIZE as CTRMAC_NONCE_SIZE,
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

/// Test that AES-GCM file header tag comparison runs in constant time.
///
/// This tests that the tag comparison doesn't leak timing information about
/// WHERE the tag differs. A non-constant-time comparison (e.g., early exit on
/// first differing byte) would show different timing based on corruption position.
///
/// We compare:
/// - Left: Tag corrupted at first byte (position 52)
/// - Right: Tag corrupted at last byte (position 67)
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_aes_gcm_header(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let content_key = rand_bytes::<32>(rng);

    // Encrypt a header (68 bytes: 12 nonce + 40 payload + 16 tag)
    let valid_header = encrypt_file_header(&content_key, &master_key).expect("encrypt should work");

    // Create two invalid headers with tag corrupted at different positions
    // Tag starts at byte 52 (12 + 40), ends at byte 67
    let mut invalid_first_byte = valid_header.clone();
    invalid_first_byte[52] ^= 0xFF; // Corrupt FIRST byte of tag

    let mut invalid_last_byte = valid_header.clone();
    invalid_last_byte[67] ^= 0xFF; // Corrupt LAST byte of tag

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut headers = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            headers.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            headers.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements
    for (class, header) in classes.into_iter().zip(headers.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_file_header(&header, &master_key));
        });
    }
}

/// Test that AES-GCM file content tag comparison runs in constant time.
///
/// This tests that the chunk tag comparison doesn't leak timing information about
/// WHERE the tag differs. A non-constant-time comparison would show different
/// timing based on corruption position.
///
/// We compare:
/// - Left: Tag corrupted at first byte
/// - Right: Tag corrupted at last byte
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_aes_gcm_content(runner: &mut CtRunner, rng: &mut BenchRng) {
    let content_key = rand_bytes::<32>(rng);
    let header_nonce = rand_bytes::<12>(rng);

    // Use a small content size to keep the test fast
    let plaintext = rand_bytes::<256>(rng);

    // Encrypt the content
    // Chunk format: 12-byte nonce + ciphertext + 16-byte tag
    let valid_ciphertext =
        encrypt_file_content(&plaintext, &content_key, &header_nonce).expect("encrypt should work");

    // Create two invalid ciphertexts with tag corrupted at different positions
    // Tag is in the last 16 bytes of the chunk
    let tag_start = valid_ciphertext.len() - 16;
    let tag_end = valid_ciphertext.len() - 1;

    let mut invalid_first_byte = valid_ciphertext.clone();
    invalid_first_byte[tag_start] ^= 0xFF; // Corrupt FIRST byte of tag

    let mut invalid_last_byte = valid_ciphertext.clone();
    invalid_last_byte[tag_end] ^= 0xFF; // Corrupt LAST byte of tag

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut ciphertexts = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            ciphertexts.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            ciphertexts.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements
    for (class, ct) in classes.into_iter().zip(ciphertexts.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_file_content(&ct, &content_key, &header_nonce));
        });
    }
}

/// Test that AES-SIV filename SIV comparison runs in constant time.
///
/// This tests that the SIV (synthetic IV / authentication tag) comparison doesn't
/// leak timing information about WHERE the tag differs. AES-SIV prepends a 16-byte
/// SIV to the ciphertext, which is verified during decryption.
///
/// We compare:
/// - Left: SIV corrupted at first byte (position 0 of raw ciphertext)
/// - Right: SIV corrupted at last byte (position 15 of raw ciphertext)
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_aes_siv_filename(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let filename = "test_file.txt";
    let parent_dir_id = "";

    // Encrypt the filename (result is base64url encoded)
    let valid_encrypted =
        encrypt_filename(filename, parent_dir_id, &master_key).expect("encrypt should work");

    // Decode to get raw bytes (16-byte SIV + ciphertext)
    let raw_bytes = URL_SAFE
        .decode(valid_encrypted.as_bytes())
        .expect("valid base64");

    // Create two invalid versions with SIV corrupted at different positions
    // SIV is bytes 0-15
    let mut raw_first_byte = raw_bytes.clone();
    raw_first_byte[0] ^= 0xFF; // Corrupt FIRST byte of SIV

    let mut raw_last_byte = raw_bytes;
    raw_last_byte[15] ^= 0xFF; // Corrupt LAST byte of SIV

    // Re-encode to base64url
    let invalid_first_byte = URL_SAFE.encode(&raw_first_byte);
    let invalid_last_byte = URL_SAFE.encode(&raw_last_byte);

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut encrypted_names = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            encrypted_names.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            encrypted_names.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements
    for (class, name) in classes.into_iter().zip(encrypted_names.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_filename(&name, parent_dir_id, &master_key));
        });
    }
}

/// Test that AES-SIV SIV comparison runs in constant time with wrong AAD.
///
/// This tests the same property as timing_aes_siv_filename but with a different
/// (wrong) parent directory ID. This verifies that the SIV comparison is constant-time
/// even when the AAD doesn't match what was used during encryption.
///
/// We compare:
/// - Left: SIV corrupted at first byte, decrypted with wrong parent ID
/// - Right: SIV corrupted at last byte, decrypted with wrong parent ID
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_aes_siv_wrong_context(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let filename = "test_file.txt";
    let encryption_parent_id = "encryption-parent-uuid";
    let wrong_parent_id = "wrong-parent-uuid";

    // Encrypt the filename with one parent ID
    let valid_encrypted =
        encrypt_filename(filename, encryption_parent_id, &master_key).expect("encrypt should work");

    // Decode to get raw bytes (16-byte SIV + ciphertext)
    let raw_bytes = URL_SAFE
        .decode(valid_encrypted.as_bytes())
        .expect("valid base64");

    // Create two invalid versions with SIV corrupted at different positions
    let mut raw_first_byte = raw_bytes.clone();
    raw_first_byte[0] ^= 0xFF; // Corrupt FIRST byte of SIV

    let mut raw_last_byte = raw_bytes;
    raw_last_byte[15] ^= 0xFF; // Corrupt LAST byte of SIV

    // Re-encode to base64url
    let invalid_first_byte = URL_SAFE.encode(&raw_first_byte);
    let invalid_last_byte = URL_SAFE.encode(&raw_last_byte);

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut encrypted_names = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            encrypted_names.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            encrypted_names.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements - decrypt with WRONG parent ID
    for (class, name) in classes.into_iter().zip(encrypted_names.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decrypt_filename(&name, wrong_parent_id, &master_key));
        });
    }
}

/// Test that CTR-MAC file header HMAC comparison runs in constant time.
///
/// This tests that the HMAC comparison doesn't leak timing information about
/// WHERE the MAC differs. A non-constant-time comparison (e.g., early exit on
/// first differing byte) would show different timing based on corruption position.
///
/// We compare:
/// - Left: MAC corrupted at first byte (position 56)
/// - Right: MAC corrupted at last byte (position 87)
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_ctrmac_header(runner: &mut CtRunner, rng: &mut BenchRng) {
    let master_key = MasterKey::random().unwrap();
    let content_key = rand_bytes::<32>(rng);

    // Encrypt a header (88 bytes: 16 nonce + 40 payload + 32 MAC)
    let valid_header =
        ctrmac_encrypt_header(&content_key, &master_key).expect("encrypt should work");

    // Create two invalid headers with MAC corrupted at different positions
    // MAC starts at byte 56 (16 + 40), ends at byte 87
    let mut invalid_first_byte = valid_header.clone();
    invalid_first_byte[56] ^= 0xFF; // Corrupt FIRST byte of MAC

    let mut invalid_last_byte = valid_header.clone();
    invalid_last_byte[87] ^= 0xFF; // Corrupt LAST byte of MAC

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut headers = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            headers.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            headers.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements
    for (class, header) in classes.into_iter().zip(headers.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(ctrmac_decrypt_header(
                &header,
                &master_key,
                FileContext::new(),
            ));
        });
    }
}

/// Test that CTR-MAC file content HMAC comparison runs in constant time.
///
/// This tests that chunk HMAC comparison doesn't leak timing information about
/// WHERE the MAC differs. A non-constant-time comparison would show different
/// timing based on corruption position.
///
/// We compare:
/// - Left: MAC corrupted at first byte
/// - Right: MAC corrupted at last byte
///
/// If constant-time: both should take the same time
/// If early-exit: first-byte corruption detected faster than last-byte
fn timing_ctrmac_content(runner: &mut CtRunner, rng: &mut BenchRng) {
    let content_key = rand_bytes::<32>(rng);
    let header_nonce = rand_bytes::<CTRMAC_NONCE_SIZE>(rng);
    let mac_key = rand_bytes::<32>(rng);

    // Use a small content size to keep the test fast
    // Chunk format: 16-byte nonce + ciphertext + 32-byte MAC
    let plaintext = rand_bytes::<256>(rng);

    // Encrypt the content
    let valid_ciphertext =
        ctrmac_encrypt_content(&plaintext, &content_key, &header_nonce, &mac_key)
            .expect("encrypt should work");

    // Create two invalid ciphertexts with MAC corrupted at different positions
    // MAC is in the last 32 bytes of the chunk
    let mac_start = valid_ciphertext.len() - 32;
    let mac_end = valid_ciphertext.len() - 1;

    let mut invalid_first_byte = valid_ciphertext.clone();
    invalid_first_byte[mac_start] ^= 0xFF; // Corrupt FIRST byte of MAC

    let mut invalid_last_byte = valid_ciphertext.clone();
    invalid_last_byte[mac_end] ^= 0xFF; // Corrupt LAST byte of MAC

    // Generate batch of inputs
    let mut classes = Vec::with_capacity(1000);
    let mut ciphertexts = Vec::with_capacity(1000);

    for _ in 0..1000 {
        if rng.gen_bool(0.5) {
            classes.push(Class::Left);
            ciphertexts.push(invalid_first_byte.clone());
        } else {
            classes.push(Class::Right);
            ciphertexts.push(invalid_last_byte.clone());
        }
    }

    // Run timing measurements
    for (class, ct) in classes.into_iter().zip(ciphertexts.into_iter()) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(ctrmac_decrypt_content(
                &ct,
                &content_key,
                &header_nonce,
                &mac_key,
                FileContext::new(),
            ));
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
    timing_aes_siv_wrong_context,
    timing_ctrmac_header,
    timing_ctrmac_content
);
