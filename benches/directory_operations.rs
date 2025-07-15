use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::name::{decrypt_filename, encrypt_filename, hash_dir_id};
use std::collections::HashMap;

fn setup_master_key() -> MasterKey {
    MasterKey::random()
}

fn generate_directory_with_files(n_files: usize) -> (Vec<String>, Vec<String>, String) {
    let master_key = setup_master_key();
    let dir_id = "test-directory-id";
    
    let mut encrypted_names = Vec::with_capacity(n_files);
    let mut original_names = Vec::with_capacity(n_files);
    
    for i in 0..n_files {
        let filename = format!("document_{i:04}.pdf");
        original_names.push(filename.clone());
        let encrypted = encrypt_filename(&filename, dir_id, &master_key);
        encrypted_names.push(encrypted);
    }
    
    (encrypted_names, original_names, dir_id.to_string())
}

fn bench_directory_listing(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_listing");
    
    for size in [10, 100, 1000] {
        let (encrypted_names, _, dir_id) = generate_directory_with_files(size);
        let master_key = setup_master_key();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    // Realistic scenario: decrypt all filenames when listing a directory
                    for encrypted_name in &encrypted_names {
                        let decrypted = decrypt_filename(
                            encrypted_name,
                            &dir_id,
                            &master_key,
                        );
                        let _ = black_box(decrypted);
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_directory_path_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_path_computation");
    let master_key = setup_master_key();
    
    // Test different path depths
    let test_cases = [
        ("root", ""),
        ("shallow", "Documents"),
        ("medium", "Documents/Projects/2024"),
        ("deep", "Documents/Projects/2024/ClientA/src/components/ui/buttons"),
    ];
    
    for (name, path) in test_cases {
        group.bench_function(name, |b| {
            b.iter(|| {
                // Compute directory ID from path components
                if path.is_empty() {
                    black_box(String::new());
                } else {
                    let components: Vec<&str> = path.split('/').collect();
                    let mut current_id = String::new();
                    for _component in components {
                        current_id = hash_dir_id(&current_id, &master_key);
                    }
                    black_box(current_id);
                }
            });
        });
    }
    group.finish();
}

fn bench_path_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_resolution");
    let master_key = setup_master_key();
    
    // Build a directory tree structure
    let mut dir_map: HashMap<String, String> = HashMap::new();
    dir_map.insert("".to_string(), String::new()); // root
    
    // Add some nested directories
    let paths = [
        "Documents",
        "Documents/Work",
        "Documents/Work/Reports",
        "Documents/Work/Reports/2024",
        "Documents/Personal",
        "Documents/Personal/Photos",
        "Pictures",
        "Pictures/Vacation",
        "Pictures/Vacation/2023",
        "Pictures/Vacation/2024",
    ];
    
    for path in paths {
        let components: Vec<&str> = path.split('/').collect();
        let mut current_id = String::new();
        let mut current_path = String::new();
        
        for component in components {
            if !current_path.is_empty() {
                current_path.push('/');
            }
            current_path.push_str(component);
            current_id = hash_dir_id(&current_id, &master_key);
            dir_map.insert(current_path.clone(), current_id.clone());
        }
    }
    
    // Benchmark path resolution
    group.bench_function("resolve_shallow_path", |b| {
        b.iter(|| {
            // Simulate resolving a path by walking the tree
            let target = "Documents/Work";
            let components: Vec<&str> = target.split('/').collect();
            let mut current_id = String::new();
            
            for _component in components {
                current_id = hash_dir_id(&current_id, &master_key);
            }
            black_box(current_id);
        });
    });
    
    group.bench_function("resolve_deep_path", |b| {
        b.iter(|| {
            let target = "Documents/Work/Reports/2024";
            let components: Vec<&str> = target.split('/').collect();
            let mut current_id = String::new();
            
            for _component in components {
                current_id = hash_dir_id(&current_id, &master_key);
            }
            black_box(current_id);
        });
    });
    
    group.finish();
}

fn bench_bulk_filename_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_filename_operations");
    
    // Simulate renaming operations (encrypt old + decrypt new)
    let master_key = setup_master_key();
    let dir_id = "parent-directory-id";
    
    let file_pairs: Vec<(String, String)> = (0..100)
        .map(|i| {
            (
                format!("old_document_{i:03}.txt"),
                format!("new_document_{i:03}.txt"),
            )
        })
        .collect();
    
    group.throughput(Throughput::Elements(file_pairs.len() as u64));
    group.bench_function("bulk_rename_simulation", |b| {
        b.iter(|| {
            for (old_name, new_name) in &file_pairs {
                // Encrypt the new name
                let encrypted_new = encrypt_filename(new_name, dir_id, &master_key);
                
                // In a real scenario, we'd also decrypt the old name to verify
                let encrypted_old = encrypt_filename(old_name, dir_id, &master_key);
                let decrypted_verify = decrypt_filename(
                    &encrypted_old,
                    dir_id,
                    &master_key,
                );
                
                black_box(encrypted_new);
                let _ = black_box(decrypted_verify);
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_directory_listing,
    bench_directory_path_computation,
    bench_path_resolution,
    bench_bulk_filename_operations
);
criterion_main!(benches);