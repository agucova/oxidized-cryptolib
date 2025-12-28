use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use oxidized_cryptolib::crypto::keys::MasterKey;
use oxidized_cryptolib::fs::file::{decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header};
use oxidized_cryptolib::fs::name::{decrypt_filename, encrypt_filename, hash_dir_id};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

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
    files: HashMap<String, Vec<u8>>, // path -> encrypted content
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
        vault.directory_structure.insert("".to_string(), String::new()); // root
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
            current_id = hash_dir_id(&current_id, &self.master_key);
        }
        
        self.directory_structure.insert(path.to_string(), current_id);
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
                let dir_id = hash_dir_id("", &master_key); // Documents directory
                let mut encrypted_names = Vec::with_capacity(size);
                
                for i in 0..size {
                    let filename = format!("document_{i:04}.pdf");
                    let encrypted = encrypt_filename(&filename, &dir_id, &master_key);
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
        let id = hash_dir_id(parent_id, master_key);
        let mut node = DirNode {
            id: id.clone(),
            files: Vec::new(),
            subdirs: Vec::new(),
        };
        
        // Add some files
        for i in 0..10 {
            let filename = format!("file_{}.{}", i, if i % 3 == 0 { "pdf" } else { "txt" });
            let encrypted = encrypt_filename(&filename, &id, master_key);
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
    let source_dir_id = hash_dir_id("", &master_key); // source directory
    let dest_dir_id = hash_dir_id("destination", &master_key);
    
    // Setup source files
    let files: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| {
            let filename = format!("file_{i:03}.dat");
            let size = 10 * 1024; // 10KB each
            let mut content = vec![0u8; size];
            rand::thread_rng().fill(&mut content[..]);
            (filename, content)
        })
        .collect();
    
    group.bench_function("copy_50_files", |b| {
        b.iter(|| {
            // Simulate copying files from one directory to another
            for (filename, content) in &files {
                // Encrypt filename for source directory
                let src_encrypted_name = encrypt_filename(filename, &source_dir_id, &master_key);
                
                // Encrypt file content
                let content_key = generate_content_key();
                let header_nonce = generate_nonce();
                let ciphertext = encrypt_file_content(content, &content_key, &header_nonce).unwrap();
                let encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();
                
                // "Copy" to destination (re-encrypt filename with new directory ID)
                let dst_encrypted_name = encrypt_filename(filename, &dest_dir_id, &master_key);
                
                black_box((src_encrypted_name, dst_encrypted_name, encrypted_header, ciphertext));
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
    bench_bulk_file_copy
);
criterion_main!(benches);