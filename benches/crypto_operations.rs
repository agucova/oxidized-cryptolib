use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;
use oxidized_cryptolib::{
    crypto::keys::MasterKey,
    fs::{
        file::{encrypt_file_content, decrypt_file_content, decrypt_file_header},
        name::{encrypt_filename, decrypt_filename},
    },
    vault::master_key::{MasterKeyFile, create_masterkey_file},
};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use secrecy::Secret;

/// Create a deterministic MasterKey for benchmarking
fn create_bench_master_key() -> MasterKey {
    MasterKey {
        aes_master_key: Secret::new([0x01; 32]),
        mac_master_key: Secret::new([0x02; 32]),
    }
}

/// Generate test data of specified size
fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

/// Benchmark filename encryption and decryption
fn bench_filename_operations(c: &mut Criterion) {
    let master_key = create_bench_master_key();
    let directory_id = "benchmark-dir";
    let filenames = vec![
        "config.json",
        "document.pdf", 
        "image.jpg",
        "very_long_filename_that_might_be_common_in_real_world_usage_scenarios.txt",
        "script.py",
        "data.csv",
        "archive.zip",
        "readme.md",
    ];
    
    let mut group = c.benchmark_group("filename_operations");
    // Configure for stable benchmarks - keep default sample size
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    
    // Benchmark encryption
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            for filename in &filenames {
                black_box(encrypt_filename(
                    black_box(filename), 
                    black_box(directory_id), 
                    black_box(&master_key)
                ));
            }
        })
    });
    
    // Pre-encrypt for decryption benchmark
    let encrypted_names: Vec<_> = filenames.iter()
        .map(|name| encrypt_filename(name, directory_id, &master_key))
        .collect();
    
    // Benchmark decryption
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            for encrypted_name in &encrypted_names {
                black_box(decrypt_filename(
                    black_box(encrypted_name), 
                    black_box(directory_id), 
                    black_box(&master_key)
                ).unwrap());
            }
        })
    });
    
    group.finish();
}

/// Create a deterministic file header for benchmarking (bypasses random nonce generation)
fn create_deterministic_header(content_key: &[u8; 32], master_key: &MasterKey, seed: u8) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    
    // Use deterministic nonce based on seed
    let header_nonce = [seed; 12];

    master_key.with_aes_key(|aes_key| {
        let key: &Key<Aes256Gcm> = aes_key.into();
        let cipher = Aes256Gcm::new(key);

        let mut plaintext = vec![0xFF; 8];
        plaintext.extend_from_slice(content_key);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&header_nonce), plaintext.as_ref())
            .expect("Encryption failed");

        let mut encrypted_header = Vec::with_capacity(68);
        encrypted_header.extend_from_slice(&header_nonce);
        encrypted_header.extend_from_slice(&ciphertext);

        encrypted_header
    })
}

/// Benchmark file header operations
fn bench_file_header_operations(c: &mut Criterion) {
    let master_key = create_bench_master_key();
    
    // Use deterministic content keys
    let mut content_keys = Vec::new();
    for i in 0..20 {
        let mut key = [0u8; 32];
        // Fill with deterministic pattern based on index
        for j in 0..32 {
            key[j] = ((i * 32 + j) % 256) as u8;
        }
        content_keys.push(key);
    }
    
    let mut group = c.benchmark_group("file_header_operations");
    // Configure for stable benchmarks - keep default sample size
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    
    // Benchmark header encryption (deterministic)
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            for (i, content_key) in content_keys.iter().enumerate() {
                black_box(create_deterministic_header(
                    black_box(content_key), 
                    black_box(&master_key),
                    black_box(i as u8)
                ));
            }
        })
    });
    
    // Pre-encrypt headers for decryption benchmark (deterministic)
    let encrypted_headers: Vec<_> = content_keys.iter().enumerate()
        .map(|(i, key)| create_deterministic_header(key, &master_key, i as u8))
        .collect();
    
    // Benchmark header decryption
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            for header in &encrypted_headers {
                black_box(decrypt_file_header(
                    black_box(header), 
                    black_box(&master_key)
                ).unwrap());
            }
        })
    });
    
    group.finish();
}

/// Benchmark file content operations across different sizes
fn bench_file_content_operations(c: &mut Criterion) {
    let test_sizes = vec![
        ("empty", 0),
        ("tiny", 256),
        ("small", 4096),
        ("medium", 32768),     // 32KB - one chunk
        ("large", 131072),     // 128KB - multiple chunks
    ];
    
    // Use deterministic content key and nonce
    let content_key = [0x05; 32]; // Deterministic key
    let nonce = [0x06; 12]; // Deterministic nonce
    
    let mut group = c.benchmark_group("file_content_operations");
    // Configure for more stable benchmarks  
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));
    
    for (name, size) in test_sizes {
        let data = generate_test_data(size, 42);
        
        // Set throughput for better metrics
        group.throughput(Throughput::Bytes(size as u64));
        
        // Benchmark encryption
        group.bench_with_input(
            BenchmarkId::new("encrypt", name), 
            &data, 
            |b, data| {
                b.iter(|| {
                    black_box(encrypt_file_content(
                        black_box(data), 
                        black_box(&content_key), 
                        black_box(&nonce)
                    ).unwrap());
                })
            }
        );
        
        // Pre-encrypt for decryption benchmark
        let encrypted_data = encrypt_file_content(&data, &content_key, &nonce).unwrap();
        
        // Benchmark decryption
        group.bench_with_input(
            BenchmarkId::new("decrypt", name), 
            &encrypted_data, 
            |b, encrypted_data| {
                b.iter(|| {
                    black_box(decrypt_file_content(
                        black_box(encrypted_data), 
                        black_box(&content_key), 
                        black_box(&nonce)
                    ).unwrap());
                })
            }
        );
    }
    
    group.finish();
}

/// Benchmark masterkey operations (vault unlock)
fn bench_masterkey_operations(c: &mut Criterion) {
    let master_key = create_bench_master_key();
    let passphrase = "benchmark-passphrase-for-testing";
    
    let mut group = c.benchmark_group("masterkey_operations");
    // Configure for stable benchmarks - keep default sample size
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    
    // Create masterkey data once in setup (random salt doesn't affect timing of unlock operation)
    let masterkey_data = create_masterkey_file(&master_key, passphrase).unwrap();
    let masterkey_file: MasterKeyFile = serde_json::from_str(&masterkey_data).unwrap();
    
    // Benchmark masterkey file reading (unlocking) - most relevant operation
    // The unlock operation itself is deterministic given the same input
    group.bench_function("unlock", |b| {
        b.iter(|| {
            black_box(masterkey_file.unlock(black_box(passphrase)));
        })
    });
    
    group.finish();
}

/// Benchmark chunk boundary performance
fn bench_chunk_boundaries(c: &mut Criterion) {
    let chunk_size = 32768; // 32KB
    let test_cases = vec![
        ("chunk_minus_one", chunk_size - 1),
        ("chunk_exact", chunk_size),
        ("chunk_plus_one", chunk_size + 1),
        ("two_chunks", chunk_size * 2),
    ];
    
    // Use deterministic content key and nonce
    let content_key = [0x03; 32]; // Deterministic key
    let nonce = [0x04; 12]; // Deterministic nonce
    
    let mut group = c.benchmark_group("chunk_boundaries");
    // Configure for stable benchmarks - keep default sample size
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    
    for (name, size) in test_cases {
        let data = generate_test_data(size, 123);
        
        group.throughput(Throughput::Bytes(size as u64));
        
        // Benchmark encryption at chunk boundaries
        group.bench_with_input(
            BenchmarkId::new("encrypt", name), 
            &data, 
            |b, data| {
                b.iter(|| {
                    black_box(encrypt_file_content(
                        black_box(data), 
                        black_box(&content_key), 
                        black_box(&nonce)
                    ).unwrap());
                })
            }
        );
        
        // Pre-encrypt for decryption benchmark
        let encrypted_data = encrypt_file_content(&data, &content_key, &nonce).unwrap();
        
        // Benchmark decryption at chunk boundaries
        group.bench_with_input(
            BenchmarkId::new("decrypt", name), 
            &encrypted_data, 
            |b, encrypted_data| {
                b.iter(|| {
                    black_box(decrypt_file_content(
                        black_box(encrypted_data), 
                        black_box(&content_key), 
                        black_box(&nonce)
                    ).unwrap());
                })
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    benches, 
    bench_filename_operations,
    bench_file_header_operations,
    bench_file_content_operations,
    bench_masterkey_operations,
    bench_chunk_boundaries
);
criterion_main!(benches);