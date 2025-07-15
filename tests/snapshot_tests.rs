mod common;

use insta::assert_debug_snapshot;
use oxidized_cryptolib::vault::operations::VaultOperations;
use common::{
    vault_builder::VaultBuilder,
    test_structures::{nested_structure, edge_case_structure},
    test_data::patterns,
};

#[test]
fn test_vault_structure_snapshot() {
    let (vault_path, master_key) = VaultBuilder::new()
        .with_rng_seed(42) // Deterministic for snapshots
        .add_file_structure(nested_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Capture the complete structure of the vault for regression testing
    let mut vault_structure = VaultStructure::default();
    
    // Recursively collect all files and directories
    collect_directory_structure(&vault_ops, "", &mut vault_structure);
    
    assert_debug_snapshot!(vault_structure);
}

#[test]
fn test_edge_case_vault_snapshot() {
    let (vault_path, master_key) = VaultBuilder::new()
        .with_rng_seed(123) // Different seed for different test
        .add_file_structure(edge_case_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    let mut vault_structure = VaultStructure::default();
    
    collect_directory_structure(&vault_ops, "", &mut vault_structure);
    
    assert_debug_snapshot!(vault_structure);
}

#[test]
fn test_file_content_patterns_snapshot() {
    use common::test_data::sizes::*;
    
    // Test various content patterns for regression
    let patterns_data = vec![
        ("all_bytes", patterns::all_bytes_pattern()),
        ("repeating", patterns::repeating_pattern(b"ABCD", 100)),
        ("compressible", patterns::compressible_data(100)),
        ("incompressible", patterns::incompressible_data(100)),
        ("chunk_size", patterns::pseudo_random_data(CHUNK_SIZE, 42)),
        ("chunk_plus_one", patterns::pseudo_random_data(CHUNK_PLUS_ONE, 42)),
    ];
    
    let mut builder = VaultBuilder::new().with_rng_seed(456);
    for (name, content) in &patterns_data {
        builder = builder.add_file(format!("{}.bin", name), content.clone());
    }
    let (vault_path, master_key) = builder.build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Create a summary of file sizes and checksums for snapshot testing
    let mut file_summary = Vec::new();
    for (name, _) in patterns_data {
        let filename = format!("{}.bin", name);
        let decrypted = vault_ops.read_file("", &filename).unwrap();
        
        file_summary.push(FileSummary {
            name: filename,
            size: decrypted.content.len(),
            checksum: format!("{:x}", md5::compute(&decrypted.content)),
            first_16_bytes: if decrypted.content.len() >= 16 {
                Some(format!("{:02x?}", &decrypted.content[..16]))
            } else {
                Some(format!("{:02x?}", &decrypted.content))
            },
        });
    }
    
    assert_debug_snapshot!(file_summary);
}

#[test]
fn test_filename_encryption_snapshot() {
    use common::test_filenames::*;
    
    let mut files = Vec::new();
    
    // Add various filename types
    for &filename in NORMAL_FILES {
        files.push((filename, b"normal content" as &[u8]));
    }
    
    for &filename in SPECIAL_CHAR_FILES {
        files.push((filename, b"special char content" as &[u8]));
    }
    
    for &filename in HIDDEN_FILES {
        files.push((filename, b"hidden content" as &[u8]));
    }
    
    let mut builder = VaultBuilder::new().with_rng_seed(789);
    for (name, content) in files {
        builder = builder.add_file(name, content);
    }
    let (vault_path, master_key) = builder.build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Collect file metadata for snapshot
    let files = vault_ops.list_files("").unwrap();
    let file_metadata: Vec<FileMetadata> = files.into_iter().map(|f| FileMetadata {
        decrypted_name: f.name,
        encrypted_name: f.encrypted_name,
        size: f.encrypted_size,
        is_shortened: f.is_shortened,
    }).collect();
    
    assert_debug_snapshot!(file_metadata);
}

// Helper structures for snapshot testing
#[derive(Debug, Default)]
struct VaultStructure {
    directories: Vec<DirectoryInfo>,
    files: Vec<FileInfo>,
}

#[derive(Debug)]
struct DirectoryInfo {
    path: String,
    name: String,
    children_count: usize,
}

#[derive(Debug)]
struct FileInfo {
    path: String,
    name: String,
    size: u64,
    content_hash: String,
}

#[derive(Debug)]
struct FileSummary {
    name: String,
    size: usize,
    checksum: String,
    first_16_bytes: Option<String>,
}

#[derive(Debug)]
struct FileMetadata {
    decrypted_name: String,
    encrypted_name: String,
    size: u64,
    is_shortened: bool,
}

fn collect_directory_structure(
    vault_ops: &VaultOperations,
    dir_path: &str,
    structure: &mut VaultStructure,
) {
    let dir_id = if dir_path.is_empty() {
        "".to_string()
    } else {
        vault_ops.resolve_path(dir_path).unwrap().0
    };
    
    // Collect files in this directory
    if let Ok(files) = vault_ops.list_files(&dir_id) {
        for file in files {
            let full_path = if dir_path.is_empty() {
                file.name.clone()
            } else {
                format!("{}/{}", dir_path, file.name)
            };
            
            // Read file to compute hash
            let content_hash = if let Ok(decrypted) = vault_ops.read_file(&dir_id, &file.name) {
                format!("{:x}", md5::compute(&decrypted.content))
            } else {
                "error".to_string()
            };
            
            structure.files.push(FileInfo {
                path: full_path,
                name: file.name,
                size: file.encrypted_size,
                content_hash,
            });
        }
    }
    
    // Collect subdirectories
    if let Ok(dirs) = vault_ops.list_directories(&dir_id) {
        for dir in dirs {
            let full_path = if dir_path.is_empty() {
                dir.name.clone()
            } else {
                format!("{}/{}", dir_path, dir.name)
            };
            
            // Count children
            let children_files = vault_ops.list_files(&dir.directory_id).unwrap_or_default().len();
            let children_dirs = vault_ops.list_directories(&dir.directory_id).unwrap_or_default().len();
            
            structure.directories.push(DirectoryInfo {
                path: full_path.clone(),
                name: dir.name,
                children_count: children_files + children_dirs,
            });
            
            // Recurse into subdirectory
            collect_directory_structure(vault_ops, &full_path, structure);
        }
    }
}