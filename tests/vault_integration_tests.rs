mod common;

use oxidized_cryptolib::{
    vault::operations::VaultOperations,
};
use common::{
    vault_builder::{VaultBuilder, create_test_vault_with_files},
    test_files, test_structures,
    assertions::*,
};

#[test]
fn test_empty_file_handling() {
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("empty.txt", b""),
        ("dir/empty.dat", b""),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key.clone());
    
    // Test root directory empty file
    let decrypted = vault_ops.read_file("", "empty.txt").unwrap();
    assert_eq!(decrypted.content.len(), 0);
    
    // Test subdirectory empty file  
    let (dir_id, _) = vault_ops.resolve_path("dir").unwrap();
    let decrypted = vault_ops.read_file(&dir_id, "empty.dat").unwrap();
    assert_eq!(decrypted.content.len(), 0);
}

#[test]
fn test_small_text_files() {
    let test_content = b"Hello, World! This is a test file.";
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("hello.txt", test_content),
        ("subdir/world.txt", b"World file content"),
        ("deep/nested/path/file.txt", b"Deeply nested content"),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Read from root
    let decrypted = vault_ops.read_file("", "hello.txt").unwrap();
    assert_file_content(&decrypted, test_content);
    
    // Read from subdirectory
    let (subdir_id, _) = vault_ops.resolve_path("subdir").unwrap();
    let decrypted = vault_ops.read_file(&subdir_id, "world.txt").unwrap();
    assert_file_content(&decrypted, b"World file content");
    
    // Read from deeply nested path
    let (dir_id, _) = vault_ops.resolve_path("deep/nested/path").unwrap();
    let decrypted = vault_ops.read_file(&dir_id, "file.txt").unwrap();
    assert_file_content(&decrypted, b"Deeply nested content");
}

#[test]
fn test_special_characters_in_filenames() {
    let files = vec![
        ("file with spaces.txt", b"Content 1" as &[u8]),
        ("special@#$%chars.doc", b"Content 2" as &[u8]),
        ("émojis-🚀.txt", b"Content 3" as &[u8]),
        ("mixed 特殊文字 chars.txt", b"Content 4" as &[u8]),
    ];
    
    let (vault_path, master_key) = create_test_vault_with_files(files.clone());
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Verify all files can be listed and read
    let file_list = vault_ops.list_files("").unwrap();
    assert_eq!(file_list.len(), files.len());
    
    for (filename, expected_content) in files {
        let decrypted = vault_ops.read_file("", filename).unwrap();
        assert_file_content(&decrypted, expected_content);
    }
}

#[test]
fn test_special_characters_in_content() {
    let special_content = test_files::create_special_char_content();
    let binary_content = vec![0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF];
    
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("special_text.txt", special_content.as_slice()),
        ("binary.bin", binary_content.as_slice()),
        ("null_bytes.dat", b"Before\x00\x00\x00After"),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test special character text
    let decrypted = vault_ops.read_file("", "special_text.txt").unwrap();
    assert_file_content(&decrypted, &special_content);
    
    // Test binary content
    let decrypted = vault_ops.read_file("", "binary.bin").unwrap();
    assert_file_content(&decrypted, &binary_content);
    
    // Test null bytes
    let decrypted = vault_ops.read_file("", "null_bytes.dat").unwrap();
    assert_file_content(&decrypted, b"Before\x00\x00\x00After");
}

#[test]
fn test_chunk_boundary_files() {
    use common::test_data::sizes::*;
    
    let test_cases = vec![
        ("chunk_minus_one.bin", test_files::create_sized_content(CHUNK_MINUS_ONE)),
        ("chunk_exact.bin", test_files::create_sized_content(CHUNK_SIZE)),
        ("chunk_plus_one.bin", test_files::create_sized_content(CHUNK_PLUS_ONE)),
        ("two_chunks.bin", test_files::create_sized_content(TWO_CHUNKS)),
        ("two_chunks_plus.bin", test_files::create_sized_content(TWO_CHUNKS_PLUS_ONE)),
    ];
    
    let mut builder = VaultBuilder::new();
    for (name, content) in &test_cases {
        builder = builder.add_file(*name, content.clone());
    }
    let (vault_path, master_key) = builder.build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Verify each file
    for (name, expected_content) in test_cases {
        let decrypted = vault_ops.read_file("", name).unwrap();
        assert_eq!(
            decrypted.content.len(),
            expected_content.len(),
            "Size mismatch for {name}"
        );
        assert_file_content(&decrypted, &expected_content);
    }
}

#[test]
fn test_very_long_filenames() {
    let long_name = "a".repeat(200) + ".txt";
    let very_long_name = "b".repeat(300) + ".txt";
    
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        (&long_name, b"Long filename content"),
        (&very_long_name, b"Very long filename content"),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    
    // Both files should be readable despite filename length
    let decrypted = vault_ops.read_file("", &long_name).unwrap();
    assert_file_content(&decrypted, b"Long filename content");
    
    let decrypted = vault_ops.read_file("", &very_long_name).unwrap();
    assert_file_content(&decrypted, b"Very long filename content");
}

#[test]
fn test_nested_directory_structure() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(test_structures::nested_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test root file
    let decrypted = vault_ops.read_file("", "root.txt").unwrap();
    assert_file_content(&decrypted, b"Root file");
    
    // Test files in docs/
    let (docs_id, _) = vault_ops.resolve_path("docs").unwrap();
    let docs = vault_ops.list_files(&docs_id).unwrap();
    assert_eq!(docs.len(), 2);
    
    let decrypted = vault_ops.read_file(&docs_id, "readme.md").unwrap();
    assert_file_content(&decrypted, b"# Documentation");
    
    // Test deeply nested file
    let (dir_id, _) = vault_ops.resolve_path("assets/images").unwrap();
    let decrypted = vault_ops.read_file(&dir_id, "logo.png").unwrap();
    assert_eq!(decrypted.content.len(), 1024);
}

#[test]
fn test_directory_listing() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("root1.txt", b"Root 1")
        .add_file("root2.txt", b"Root 2")
        .add_directory("empty_dir")
        .add_file("dir_a/file1.txt", b"A1")
        .add_file("dir_a/file2.txt", b"A2")
        .add_file("dir_b/file1.txt", b"B1")
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // List root directory
    let root_files = vault_ops.list_files("").unwrap();
    assert_eq!(root_files.len(), 2);
    assert!(root_files.iter().any(|f| f.name == "root1.txt"));
    assert!(root_files.iter().any(|f| f.name == "root2.txt"));
    
    let root_dirs = vault_ops.list_directories("").unwrap();
    assert_eq!(root_dirs.len(), 3);
    assert!(root_dirs.iter().any(|d| d.name == "empty_dir"));
    assert!(root_dirs.iter().any(|d| d.name == "dir_a"));
    assert!(root_dirs.iter().any(|d| d.name == "dir_b"));
    
    // List subdirectory
    let (dir_a_id, _) = vault_ops.resolve_path("dir_a").unwrap();
    let dir_a_files = vault_ops.list_files(&dir_a_id).unwrap();
    assert_eq!(dir_a_files.len(), 2);
}

#[test]
fn test_large_files() {
    use common::test_data::{sizes, patterns};
    
    let large_content = patterns::pseudo_random_data(sizes::LARGE, 42);
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("large.bin", &large_content),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    let decrypted = vault_ops.read_file("", "large.bin").unwrap();
    assert_eq!(decrypted.content.len(), sizes::LARGE);
    assert_file_content(&decrypted, &large_content);
}

#[test]
fn test_binary_file_patterns() {
    use common::test_data::patterns;
    
    let all_bytes = patterns::all_bytes_pattern();
    let repeating = patterns::repeating_pattern(b"DEADBEEF", 1024);
    let compressible = patterns::compressible_data(1024);
    let incompressible = patterns::incompressible_data(1024);
    
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("all_bytes.bin", &all_bytes),
        ("repeating.bin", &repeating),
        ("compressible.bin", &compressible),
        ("incompressible.bin", &incompressible),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Verify all patterns decrypt correctly
    let test_cases = vec![
        ("all_bytes.bin", &all_bytes),
        ("repeating.bin", &repeating),
        ("compressible.bin", &compressible),
        ("incompressible.bin", &incompressible),
    ];
    
    for (filename, expected) in test_cases {
        let decrypted = vault_ops.read_file("", filename).unwrap();
        assert_file_content(&decrypted, expected);
    }
}

#[test]
fn test_deterministic_vault_creation() {
    // Create two vaults with same seed - they should produce identical encrypted content
    let (vault1_path, key1) = VaultBuilder::new()
        .with_rng_seed(12345)
        .add_file("test1.txt", b"Content 1")
        .add_file("test2.txt", b"Content 2")
        .build();
    
    let (vault2_path, key2) = VaultBuilder::new()
        .with_rng_seed(12345)
        .add_file("test1.txt", b"Content 1")
        .add_file("test2.txt", b"Content 2")
        .build();
    
    // Master keys should be identical
    key1.with_raw_key(|k1| {
        key2.with_raw_key(|k2| {
            assert_eq!(k1, k2);
        })
    });
    
    // Files should decrypt to same content
    let vault_ops1 = VaultOperations::new(&vault1_path, key1);
    let vault_ops2 = VaultOperations::new(&vault2_path, key2);
    
    let file1_v1 = vault_ops1.read_file("", "test1.txt").unwrap();
    let file1_v2 = vault_ops2.read_file("", "test1.txt").unwrap();
    assert_eq!(file1_v1.content, file1_v2.content);
}

#[test]
fn test_edge_case_vault() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(test_structures::edge_case_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test empty file
    let empty = vault_ops.read_file("", "empty.txt").unwrap();
    assert_eq!(empty.content.len(), 0);
    
    // Test chunk boundary file
    let chunk_file = vault_ops.read_file("", "chunk_boundary.bin").unwrap();
    assert_eq!(chunk_file.content, test_files::create_chunk_boundary_content());
    
    // Test special characters
    let special = vault_ops.read_file("", "special_chars.txt").unwrap();
    assert_eq!(special.content, test_files::create_special_char_content());
    
    // Test deeply nested file
    let (dir_id, _) = vault_ops.resolve_path("nested/deeply/nested/structure").unwrap();
    let nested = vault_ops.read_file(&dir_id, "file.txt").unwrap();
    assert_file_content(&nested, b"Deeply nested file");
}