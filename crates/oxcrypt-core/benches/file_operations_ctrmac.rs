//! Benchmarks for CTR-MAC file encryption/decryption operations.
//!
//! This benchmarks the SIV_CTRMAC cipher combo which uses:
//! - AES-CTR for encryption (with 16-byte nonces)
//! - HMAC-SHA256 for authentication (32-byte MACs)
//!
//! These benchmarks mirror `file_operations.rs` (which benchmarks AES-GCM)
//! for easy comparison between the two cipher combos.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxcrypt_core::crypto::keys::MasterKey;
use oxcrypt_core::fs::file::FileContext;
use oxcrypt_core::fs::file_ctrmac::{
    decrypt_content, decrypt_header, encrypt_content, encrypt_header, HEADER_SIZE, NONCE_SIZE,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::hint::black_box;

fn setup_master_key() -> MasterKey {
    MasterKey::random().unwrap()
}

fn generate_test_file(size: usize) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(12345);
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

fn generate_content_key() -> [u8; 32] {
    let mut rng = ChaCha8Rng::seed_from_u64(54321);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    key
}

fn generate_header_nonce() -> [u8; NONCE_SIZE] {
    let mut rng = ChaCha8Rng::seed_from_u64(11111);
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce);
    nonce
}

fn generate_mac_key() -> [u8; 32] {
    let mut rng = ChaCha8Rng::seed_from_u64(99999);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    key
}

fn bench_ctrmac_file_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctrmac_file_decryption");
    let master_key = setup_master_key();

    // Test various file sizes that are realistic for a Cryptomator vault
    let test_sizes = [
        ("empty", 0),
        ("1KB", 1024),
        ("32KB", 32 * 1024),       // One chunk exactly
        ("100KB", 100 * 1024),     // Multiple chunks
        ("1MB", 1024 * 1024),      // Large file
        ("10MB", 10 * 1024 * 1024), // Very large file
    ];

    for (name, size) in test_sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            // Setup: encrypt a file first
            let plaintext = generate_test_file(size);
            let content_key = generate_content_key();

            // Encrypt header to get header nonce
            let encrypted_header = encrypt_header(&content_key, &master_key).unwrap();
            let header_nonce: [u8; NONCE_SIZE] = encrypted_header[..NONCE_SIZE].try_into().unwrap();

            // Get MAC key from master key for content encryption
            let mac_key = generate_mac_key();
            let ciphertext = encrypt_content(&plaintext, &content_key, &header_nonce, &mac_key).unwrap();

            b.iter(|| {
                // Realistic workflow: decrypt header first, then content
                let header = decrypt_header(&encrypted_header, &master_key, &FileContext::new()).unwrap();
                let decrypted_content = decrypt_content(
                    &ciphertext,
                    &header.content_key,
                    &header_nonce,
                    &mac_key,
                    &FileContext::new(),
                )
                .unwrap();
                black_box(decrypted_content);
            });
        });
    }
    group.finish();
}

fn bench_ctrmac_file_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctrmac_file_encryption");
    let master_key = setup_master_key();

    let test_sizes = [
        ("1KB", 1024),
        ("32KB", 32 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];

    for (name, size) in test_sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            let plaintext = generate_test_file(size);
            let content_key = generate_content_key();
            let mac_key = generate_mac_key();

            b.iter(|| {
                // Realistic workflow: encrypt header and content together
                let encrypted_header = encrypt_header(&content_key, &master_key).unwrap();
                let header_nonce: [u8; NONCE_SIZE] = encrypted_header[..NONCE_SIZE].try_into().unwrap();
                let ciphertext = encrypt_content(&plaintext, &content_key, &header_nonce, &mac_key).unwrap();
                black_box((encrypted_header, ciphertext));
            });
        });
    }
    group.finish();
}

fn bench_ctrmac_chunked_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctrmac_chunked_operations");

    // Test files around chunk boundaries to understand overhead
    // CTR-MAC uses 32KB chunks like GCM
    let chunk_size = 32 * 1024;
    let test_sizes = [
        ("just_under_1_chunk", chunk_size - 100),
        ("exactly_1_chunk", chunk_size),
        ("just_over_1_chunk", chunk_size + 100),
        ("exactly_2_chunks", chunk_size * 2),
        ("2.5_chunks", chunk_size * 2 + chunk_size / 2),
        ("10_chunks", chunk_size * 10),
    ];

    for (name, size) in test_sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            let plaintext = generate_test_file(size);
            let content_key = generate_content_key();
            let header_nonce = generate_header_nonce();
            let mac_key = generate_mac_key();

            let ciphertext = encrypt_content(&plaintext, &content_key, &header_nonce, &mac_key).unwrap();

            b.iter(|| {
                let decrypted = decrypt_content(
                    &ciphertext,
                    &content_key,
                    &header_nonce,
                    &mac_key,
                    &FileContext::new(),
                )
                .unwrap();
                black_box(decrypted);
            });
        });
    }
    group.finish();
}

fn bench_ctrmac_header_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctrmac_header_operations");
    let master_key = setup_master_key();

    // Generate multiple content keys to simulate batch operations
    let content_keys: Vec<[u8; 32]> = (0..100).map(|_| generate_content_key()).collect();

    let encrypted_headers: Vec<Vec<u8>> = content_keys
        .iter()
        .map(|key| encrypt_header(key, &master_key).unwrap())
        .collect();

    group.throughput(Throughput::Elements(content_keys.len() as u64));
    group.bench_function("batch_header_decryption", |b| {
        b.iter(|| {
            // Simulate opening multiple files (e.g., for directory stats)
            for encrypted_header in &encrypted_headers {
                let header = decrypt_header(encrypted_header, &master_key, &FileContext::new()).unwrap();
                black_box(header);
            }
        });
    });

    group.finish();
}

/// Compare CTR-MAC vs GCM header sizes and overhead
fn bench_ctrmac_vs_gcm_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctrmac_header_size_comparison");
    let master_key = setup_master_key();
    let content_key = generate_content_key();

    // Document the size difference
    // CTR-MAC header: 88 bytes (16 nonce + 40 payload + 32 MAC)
    // GCM header: 68 bytes (12 nonce + 40 payload + 16 tag)
    group.bench_function("ctrmac_header_encrypt", |b| {
        b.iter(|| {
            let header = encrypt_header(&content_key, &master_key).unwrap();
            assert_eq!(header.len(), HEADER_SIZE); // 88 bytes
            black_box(header);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ctrmac_file_decryption,
    bench_ctrmac_file_encryption,
    bench_ctrmac_chunked_operations,
    bench_ctrmac_header_operations,
    bench_ctrmac_vs_gcm_header
);
criterion_main!(benches);
