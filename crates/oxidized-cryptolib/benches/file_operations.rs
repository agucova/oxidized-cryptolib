use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::file::{
    decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
};
use oxidized_cryptolib::fs::symlink::{decrypt_symlink_target, encrypt_symlink_target};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

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

fn generate_nonce() -> [u8; 12] {
    let mut rng = ChaCha8Rng::seed_from_u64(11111);
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    nonce
}

fn bench_file_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_decryption");
    let master_key = setup_master_key();
    
    // Test various file sizes that are realistic for a Cryptomator vault
    let test_sizes = [
        ("empty", 0),
        ("1KB", 1024),
        ("32KB", 32 * 1024),      // One chunk exactly
        ("100KB", 100 * 1024),    // Multiple chunks
        ("1MB", 1024 * 1024),     // Large file
        ("10MB", 10 * 1024 * 1024), // Very large file
    ];
    
    for (name, size) in test_sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &size, |b, &size| {
            // Setup: encrypt a file first
            let plaintext = generate_test_file(size);
            let content_key = generate_content_key();
            let header_nonce = generate_nonce();
            
            let ciphertext = encrypt_file_content(&plaintext, &content_key, &header_nonce).unwrap();
            let encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();
            
            b.iter(|| {
                // Realistic workflow: decrypt header first, then content
                let decrypted_header = decrypt_file_header(&encrypted_header, &master_key).unwrap();
                let decrypted_content = decrypt_file_content(
                    &ciphertext,
                    &decrypted_header.content_key,
                    &header_nonce,
                ).unwrap();
                black_box(decrypted_content);
            });
        });
    }
    group.finish();
}

fn bench_file_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_encryption");
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
            let header_nonce = generate_nonce();
            
            b.iter(|| {
                // Realistic workflow: encrypt content and header together
                let ciphertext = encrypt_file_content(&plaintext, &content_key, &header_nonce).unwrap();
                let encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();
                black_box((encrypted_header, ciphertext));
            });
        });
    }
    group.finish();
}

fn bench_chunked_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunked_operations");
    let _master_key = setup_master_key();
    
    // Test files around chunk boundaries to understand overhead
    let chunk_size = 32 * 1024; // 32KB chunks
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
            let header_nonce = generate_nonce();
            
            let ciphertext = encrypt_file_content(&plaintext, &content_key, &header_nonce).unwrap();
            
            b.iter(|| {
                let decrypted = decrypt_file_content(
                    &ciphertext,
                    &content_key,
                    &header_nonce,
                ).unwrap();
                black_box(decrypted);
            });
        });
    }
    group.finish();
}

fn bench_header_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_operations");
    let master_key = setup_master_key();
    
    // Generate multiple content keys to simulate batch operations
    let content_keys: Vec<[u8; 32]> = (0..100)
        .map(|_| generate_content_key())
        .collect();
    
    let encrypted_headers: Vec<Vec<u8>> = content_keys
        .iter()
        .map(|key| encrypt_file_header(key, &master_key).unwrap())
        .collect();
    
    group.throughput(Throughput::Elements(content_keys.len() as u64));
    group.bench_function("batch_header_decryption", |b| {
        b.iter(|| {
            // Simulate opening multiple files (e.g., for directory stats)
            for encrypted_header in &encrypted_headers {
                let header = decrypt_file_header(encrypted_header, &master_key).unwrap();
                black_box(header);
            }
        });
    });
    
    group.finish();
}

fn bench_streaming_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_decryption");
    let _master_key = setup_master_key();
    
    // Simulate streaming a large file in chunks (like video playback)
    let read_size = 1024 * 1024; // Read 1MB at a time
    
    // For benchmark purposes, we'll simulate with a smaller representative portion
    let sample_size = 10 * 1024 * 1024; // 10MB sample
    let plaintext = generate_test_file(sample_size);
    let content_key = generate_content_key();
    let header_nonce = generate_nonce();
    
    let ciphertext = encrypt_file_content(&plaintext, &content_key, &header_nonce).unwrap();
    
    group.throughput(Throughput::Bytes(read_size as u64));
    group.bench_function("streaming_1MB_reads", |b| {
        b.iter(|| {
            // Simulate reading 1MB portions of the file
            let start_offset = 0;
            let end_offset = std::cmp::min(start_offset + read_size, ciphertext.len());
            
            if end_offset > start_offset {
                let partial_ciphertext = &ciphertext[start_offset..end_offset];
                // In a real implementation, we'd decrypt only the needed chunks
                // For now, we'll decrypt the portion we have
                let decrypted = decrypt_file_content(
                    partial_ciphertext,
                    &content_key,
                    &header_nonce,
                ).unwrap_or_else(|_| vec![]);
                black_box(decrypted);
            }
        });
    });
    
    group.finish();
}

/// Benchmark symlink target encryption and decryption.
///
/// Symlinks store their target path as encrypted file content (header + AES-GCM chunks).
/// This is relevant for vaults containing symlinks, especially with long target paths.
fn bench_symlink_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("symlink_operations");
    let master_key = setup_master_key();

    // Test various symlink target lengths
    let test_targets = [
        ("short_relative", "../file.txt"),
        ("medium_relative", "../some/nested/directory/structure/file.txt"),
        ("long_absolute", &format!("/home/user/documents/{}/file.txt", "a".repeat(200))),
        ("very_long", &format!("/path/to/{}/deeply/nested/target.txt", "x".repeat(500))),
    ];

    // Benchmark decryption (more common - reading symlinks)
    for (name, target) in &test_targets {
        group.throughput(Throughput::Bytes(target.len() as u64));

        // Pre-encrypt for decryption benchmark
        let encrypted = encrypt_symlink_target(target, &master_key).unwrap();

        group.bench_with_input(
            BenchmarkId::new("decrypt", *name),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    let decrypted = decrypt_symlink_target(encrypted, &master_key).unwrap();
                    black_box(decrypted);
                });
            },
        );
    }

    // Benchmark encryption (less common - creating symlinks)
    for (name, target) in &test_targets {
        group.throughput(Throughput::Bytes(target.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt", *name),
            target,
            |b, target| {
                b.iter(|| {
                    let encrypted = encrypt_symlink_target(target, &master_key).unwrap();
                    black_box(encrypted);
                });
            },
        );
    }

    // Batch symlink resolution (directory with many symlinks)
    let batch_targets: Vec<String> = (0..50)
        .map(|i| format!("../targets/file_{i:03}.txt"))
        .collect();
    let encrypted_targets: Vec<Vec<u8>> = batch_targets
        .iter()
        .map(|t| encrypt_symlink_target(t, &master_key).unwrap())
        .collect();

    group.throughput(Throughput::Elements(50));
    group.bench_function("batch_decrypt_50_symlinks", |b| {
        b.iter(|| {
            for encrypted in &encrypted_targets {
                let target = decrypt_symlink_target(encrypted, &master_key).unwrap();
                black_box(target);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_file_decryption,
    bench_file_encryption,
    bench_chunked_operations,
    bench_header_operations,
    bench_streaming_decryption,
    bench_symlink_operations
);
criterion_main!(benches);