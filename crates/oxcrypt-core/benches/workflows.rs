#![allow(clippy::cast_possible_truncation)] // Benchmark code with safe type conversions
#![allow(clippy::cast_sign_loss)] // Benchmark uses modulo to ensure safe u8 conversion

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use oxcrypt_core::crypto::keys::MasterKey;
use oxcrypt_core::fs::file::{
    decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
};
use oxcrypt_core::fs::name::{decrypt_filename, encrypt_filename, hash_dir_id};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::hint::black_box;

fn setup_master_key() -> MasterKey {
    MasterKey::random().unwrap()
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

struct MockVault {
    master_key: MasterKey,
    directory_structure: HashMap<String, String>, // path -> directory_id
    files: HashMap<String, Vec<u8>>,              // path -> encrypted content
}

impl MockVault {
    fn new() -> Self {
        let master_key = setup_master_key();
        let mut vault = MockVault {
            master_key,
            directory_structure: HashMap::new(),
            files: HashMap::new(),
        };

        // Setup directory structure
        vault
            .directory_structure
            .insert(String::new(), String::new()); // root
        vault.add_directory("Documents");
        vault.add_directory("Documents/Work");
        vault.add_directory("Documents/Personal");
        vault.add_directory("Pictures");
        vault.add_directory("Pictures/Vacation");

        vault
    }

    fn add_directory(&mut self, path: &str) {
        let components: Vec<&str> = path.split('/').collect();
        let mut current_id = String::new();

        for _component in components {
            current_id = hash_dir_id(&current_id, &self.master_key).unwrap();
        }

        self.directory_structure
            .insert(path.to_string(), current_id);
    }

    fn add_file(&mut self, path: &str, content: &[u8]) {
        let content_key = generate_content_key();
        let header_nonce = generate_nonce();

        let ciphertext = encrypt_file_content(content, &content_key, &header_nonce).unwrap();
        let encrypted_header = encrypt_file_header(&content_key, &self.master_key).unwrap();

        // Store as encrypted_header + ciphertext
        let mut file_data = encrypted_header;
        file_data.extend_from_slice(&ciphertext);

        self.files.insert(path.to_string(), file_data);
    }

    fn open_file(&self, path: &str) -> Option<Vec<u8>> {
        // Get encrypted file data
        let file_data = self.files.get(path)?;

        // Split header and content
        let (encrypted_header, ciphertext) = file_data.split_at(68); // 68 bytes for header

        // Decrypt header
        let header = decrypt_file_header(encrypted_header, &self.master_key).ok()?;

        // For this benchmark, we'll use a fixed nonce
        let header_nonce = generate_nonce();

        // Decrypt content
        let content = decrypt_file_content(ciphertext, &header.content_key, &header_nonce).ok()?;

        Some(content)
    }
}

fn bench_open_and_read_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("complete_workflows");

    let mut vault = MockVault::new();

    // Add some test files
    let small_content = b"This is a small text file with some content.";
    let medium_content = vec![0u8; 100 * 1024]; // 100KB
    let large_content = vec![0u8; 1024 * 1024]; // 1MB

    vault.add_file("Documents/readme.txt", small_content);
    vault.add_file("Documents/Work/report.pdf", &medium_content);
    vault.add_file("Pictures/Vacation/photo.jpg", &large_content);

    group.bench_function("open_small_file", |b| {
        b.iter(|| {
            let content = vault.open_file("Documents/readme.txt").unwrap();
            black_box(content);
        });
    });

    group.bench_function("open_medium_file", |b| {
        b.iter(|| {
            let content = vault.open_file("Documents/Work/report.pdf").unwrap();
            black_box(content);
        });
    });

    group.bench_function("open_large_file", |b| {
        b.iter(|| {
            let content = vault.open_file("Pictures/Vacation/photo.jpg").unwrap();
            black_box(content);
        });
    });

    group.finish();
}

fn bench_directory_browsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_browsing");

    let master_key = setup_master_key();

    // Simulate different directory sizes
    for size in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}_files")),
            &size,
            |b, &size| {
                // Setup: create encrypted filenames
                let dir_id = hash_dir_id("", &master_key).unwrap(); // Documents directory
                let mut encrypted_names = Vec::with_capacity(size);

                for i in 0..size {
                    let filename = format!("document_{i:04}.pdf");
                    let encrypted = encrypt_filename(&filename, &dir_id, &master_key).unwrap();
                    encrypted_names.push(encrypted);
                }

                b.iter(|| {
                    // Complete directory browsing: decrypt all names and "stat" them
                    let mut entries = Vec::with_capacity(size);

                    for encrypted_name in &encrypted_names {
                        // Decrypt filename
                        let name = decrypt_filename(encrypted_name, &dir_id, &master_key).unwrap();

                        // In a real implementation, we'd also:
                        // - Check if it's a file or directory
                        // - Get file size from encrypted file
                        // - Get modification time
                        entries.push(name);
                    }

                    black_box(entries);
                });
            },
        );
    }

    group.finish();
}

fn bench_find_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_files");

    let master_key = setup_master_key();

    // Build a directory tree with files
    struct DirNode {
        id: String,
        files: Vec<String>, // encrypted names
        subdirs: Vec<(String, DirNode)>,
    }

    fn build_tree(_name: &str, parent_id: &str, depth: usize, master_key: &MasterKey) -> DirNode {
        let id = hash_dir_id(parent_id, master_key).unwrap();
        let mut node = DirNode {
            id: id.clone(),
            files: Vec::new(),
            subdirs: Vec::new(),
        };

        // Add some files
        for i in 0..10 {
            let filename = format!("file_{}.{}", i, if i % 3 == 0 { "pdf" } else { "txt" });
            let encrypted = encrypt_filename(&filename, &id, master_key).unwrap();
            node.files.push(encrypted);
        }

        // Add subdirectories
        if depth > 0 {
            for i in 0..3 {
                let subdir_name = format!("subdir_{i}");
                let subdir = build_tree(&subdir_name, &id, depth - 1, master_key);
                node.subdirs.push((subdir_name, subdir));
            }
        }

        node
    }

    let root = build_tree("root", "", 3, &master_key); // 3 levels deep

    group.bench_function("find_pdf_files", |b| {
        b.iter(|| {
            let mut pdf_count = 0;
            let mut stack = vec![&root];

            // Traverse directory tree looking for PDFs
            while let Some(node) = stack.pop() {
                // Check all files in this directory
                for encrypted_name in &node.files {
                    let name = decrypt_filename(encrypted_name, &node.id, &master_key).unwrap();
                    // Benchmark code: case-sensitive check is intentional for performance
                    #[allow(clippy::case_sensitive_file_extension_comparisons)]
                    if name.ends_with(".pdf") {
                        pdf_count += 1;
                    }
                }

                // Add subdirectories to stack
                for (_, subdir) in &node.subdirs {
                    stack.push(subdir);
                }
            }

            black_box(pdf_count);
        });
    });

    group.finish();
}

fn bench_bulk_file_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_operations");

    let master_key = setup_master_key();
    let source_dir_id = hash_dir_id("", &master_key).unwrap(); // source directory
    let dest_dir_id = hash_dir_id("destination", &master_key).unwrap();

    // Setup source files
    let files: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| {
            let filename = format!("file_{i:03}.dat");
            let size = 10 * 1024; // 10KB each
            let mut content = vec![0u8; size];
            rand::rng().fill(&mut content[..]);
            (filename, content)
        })
        .collect();

    group.bench_function("copy_50_files", |b| {
        b.iter(|| {
            // Simulate copying files from one directory to another
            for (filename, content) in &files {
                // Encrypt filename for source directory
                let src_encrypted_name =
                    encrypt_filename(filename, &source_dir_id, &master_key).unwrap();

                // Encrypt file content
                let content_key = generate_content_key();
                let header_nonce = generate_nonce();
                let ciphertext =
                    encrypt_file_content(content, &content_key, &header_nonce).unwrap();
                let encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();

                // "Copy" to destination (re-encrypt filename with new directory ID)
                let dst_encrypted_name =
                    encrypt_filename(filename, &dest_dir_id, &master_key).unwrap();

                black_box((
                    src_encrypted_name,
                    dst_encrypted_name,
                    encrypted_header,
                    ciphertext,
                ));
            }
        });
    });

    group.finish();
}

/// Benchmark file write operations (encryption path).
///
/// This measures the full write workflow: encrypt filename + header + content.
/// These are the operations that block the user when saving files.
fn bench_write_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_operations");
    let master_key = setup_master_key();
    let dir_id = hash_dir_id("", &master_key).unwrap();

    // Test files of different sizes (realistic for document editing)
    let test_cases = [
        ("small_config", 256),           // Config file, JSON, etc.
        ("text_document", 10 * 1024),    // 10KB text file
        ("medium_document", 100 * 1024), // 100KB document
        ("large_file", 1024 * 1024),     // 1MB file
    ];

    for (name, size) in test_cases {
        let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.bench_function(format!("write_{name}"), |b| {
            b.iter(|| {
                // Full write workflow
                let filename = format!("{name}.txt");

                // 1. Encrypt filename
                let encrypted_name = encrypt_filename(&filename, &dir_id, &master_key).unwrap();

                // 2. Generate content key
                let mut content_key = [0u8; 32];
                rand::rng().fill(&mut content_key);

                // 3. Encrypt header
                let encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();

                // 4. Extract nonce from header
                let header_nonce: [u8; 12] = encrypted_header[0..12].try_into().unwrap();

                // 5. Encrypt content
                let encrypted_content =
                    encrypt_file_content(&content, &content_key, &header_nonce).unwrap();

                black_box((encrypted_name, encrypted_header, encrypted_content));
            });
        });
    }

    group.finish();
}

/// Benchmark directory creation workflow.
///
/// Creating a directory involves:
/// - Generating a new directory ID (UUID)
/// - Encrypting the directory name
/// - Computing the storage path hash
fn bench_directory_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_creation");
    let master_key = setup_master_key();
    let parent_dir_id = hash_dir_id("", &master_key).unwrap();

    group.bench_function("create_single_directory", |b| {
        b.iter(|| {
            // Full directory creation workflow
            let dir_name = "NewDirectory";

            // 1. Generate new directory ID
            let new_dir_id = uuid::Uuid::new_v4().to_string();

            // 2. Encrypt directory name
            let encrypted_name = encrypt_filename(dir_name, &parent_dir_id, &master_key).unwrap();

            // 3. Compute storage path for new directory
            let storage_hash = hash_dir_id(&new_dir_id, &master_key).unwrap();

            black_box((new_dir_id, encrypted_name, storage_hash));
        });
    });

    // Batch directory creation (like unpacking an archive)
    group.bench_function("create_10_nested_directories", |b| {
        b.iter(|| {
            let mut current_dir_id = parent_dir_id.clone();

            for i in 0..10 {
                let dir_name = format!("level_{i}");
                let new_dir_id = uuid::Uuid::new_v4().to_string();

                let encrypted_name =
                    encrypt_filename(&dir_name, &current_dir_id, &master_key).unwrap();
                let storage_hash = hash_dir_id(&new_dir_id, &master_key).unwrap();

                black_box((&encrypted_name, &storage_hash));
                current_dir_id = new_dir_id;
            }
        });
    });

    group.finish();
}

/// Benchmark file rename and move operations.
///
/// Rename: Same directory, new encrypted filename
/// Move: Different directory, re-encrypt filename with new parent ID
fn bench_rename_and_move(c: &mut Criterion) {
    let mut group = c.benchmark_group("rename_and_move");
    let master_key = setup_master_key();
    let source_dir_id = hash_dir_id("", &master_key).unwrap();
    let dest_dir_id = hash_dir_id("destination", &master_key).unwrap();

    // Prepare some encrypted filenames
    let old_name = "original_document.txt";
    let new_name = "renamed_document.txt";

    // Pre-encrypt the old name
    let old_encrypted = encrypt_filename(old_name, &source_dir_id, &master_key).unwrap();

    group.bench_function("rename_file", |b| {
        b.iter(|| {
            // Rename: decrypt old name (verify), encrypt new name
            let decrypted = decrypt_filename(&old_encrypted, &source_dir_id, &master_key).unwrap();
            black_box(&decrypted); // Verify it matches

            let new_encrypted = encrypt_filename(new_name, &source_dir_id, &master_key).unwrap();
            black_box(new_encrypted);
        });
    });

    group.bench_function("move_file_between_directories", |b| {
        b.iter(|| {
            // Move: decrypt from source, encrypt to destination
            let decrypted = decrypt_filename(&old_encrypted, &source_dir_id, &master_key).unwrap();

            // Re-encrypt with new directory ID
            let dest_encrypted = encrypt_filename(&decrypted, &dest_dir_id, &master_key).unwrap();
            black_box(dest_encrypted);
        });
    });

    // Batch move (like moving a folder's contents)
    let filenames: Vec<String> = (0..20).map(|i| format!("file_{i:03}.txt")).collect();
    let encrypted_names: Vec<String> = filenames
        .iter()
        .map(|f| encrypt_filename(f, &source_dir_id, &master_key).unwrap())
        .collect();

    group.bench_function("move_20_files", |b| {
        b.iter(|| {
            for encrypted in &encrypted_names {
                let decrypted = decrypt_filename(encrypted, &source_dir_id, &master_key).unwrap();
                let new_encrypted =
                    encrypt_filename(&decrypted, &dest_dir_id, &master_key).unwrap();
                black_box(new_encrypted);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_open_and_read_file,
    bench_directory_browsing,
    bench_find_files,
    bench_bulk_file_copy,
    bench_write_operations,
    bench_directory_creation,
    bench_rename_and_move
);
criterion_main!(benches);
