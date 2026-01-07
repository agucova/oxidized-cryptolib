mod common;

use oxcrypt_core::{
    vault::{operations::VaultOperations, DirId},
};
use common::{
    vault_builder::{VaultBuilder, create_test_vault_with_files},
    test_files, test_structures,
    assertions::assert_file_content,
    test_data::{sizes::{CHUNK_SIZE, CHUNK_MINUS_ONE, CHUNK_PLUS_ONE, TWO_CHUNKS, TWO_CHUNKS_PLUS_ONE, LARGE}, patterns},
};

#[test]
fn test_empty_file_handling() {
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("empty.txt", b""),
        ("dir/empty.dat", b""),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key.clone());
    
    // Test root directory empty file
    let decrypted = vault_ops.read_file(&DirId::root(), "empty.txt").unwrap();
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
    let decrypted = vault_ops.read_file(&DirId::root(), "hello.txt").unwrap();
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
    let file_list = vault_ops.list_files(&DirId::root()).unwrap();
    assert_eq!(file_list.len(), files.len());

    for (filename, expected_content) in files {
        let decrypted = vault_ops.read_file(&DirId::root(), filename).unwrap();
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
    let decrypted = vault_ops.read_file(&DirId::root(), "special_text.txt").unwrap();
    assert_file_content(&decrypted, &special_content);

    // Test binary content
    let decrypted = vault_ops.read_file(&DirId::root(), "binary.bin").unwrap();
    assert_file_content(&decrypted, &binary_content);

    // Test null bytes
    let decrypted = vault_ops.read_file(&DirId::root(), "null_bytes.dat").unwrap();
    assert_file_content(&decrypted, b"Before\x00\x00\x00After");
}

#[test]
fn test_chunk_boundary_files() {
    
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
        let decrypted = vault_ops.read_file(&DirId::root(), name).unwrap();
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
    let decrypted = vault_ops.read_file(&DirId::root(), &long_name).unwrap();
    assert_file_content(&decrypted, b"Long filename content");

    let decrypted = vault_ops.read_file(&DirId::root(), &very_long_name).unwrap();
    assert_file_content(&decrypted, b"Very long filename content");
}

#[test]
fn test_nested_directory_structure() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(test_structures::nested_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test root file
    let decrypted = vault_ops.read_file(&DirId::root(), "root.txt").unwrap();
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
    let root_files = vault_ops.list_files(&DirId::root()).unwrap();
    assert_eq!(root_files.len(), 2);
    assert!(root_files.iter().any(|f| f.name == "root1.txt"));
    assert!(root_files.iter().any(|f| f.name == "root2.txt"));

    let root_dirs = vault_ops.list_directories(&DirId::root()).unwrap();
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
    
    let large_content = patterns::pseudo_random_data(LARGE, 42);
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("large.bin", &large_content),
    ]);
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    let decrypted = vault_ops.read_file(&DirId::root(), "large.bin").unwrap();
    assert_eq!(decrypted.content.len(), LARGE);
    assert_file_content(&decrypted, &large_content);
}

#[test]
fn test_binary_file_patterns() {
    
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
        let decrypted = vault_ops.read_file(&DirId::root(), filename).unwrap();
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
    })
    .expect("Failed to access key1")
    .expect("Failed to access key2");
    
    // Files should decrypt to same content
    let vault_ops1 = VaultOperations::new(&vault1_path, key1);
    let vault_ops2 = VaultOperations::new(&vault2_path, key2);
    
    let file1_v1 = vault_ops1.read_file(&DirId::root(), "test1.txt").unwrap();
    let file1_v2 = vault_ops2.read_file(&DirId::root(), "test1.txt").unwrap();
    assert_eq!(file1_v1.content, file1_v2.content);
}

#[test]
fn test_edge_case_vault() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(test_structures::edge_case_structure())
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test empty file
    let empty = vault_ops.read_file(&DirId::root(), "empty.txt").unwrap();
    assert_eq!(empty.content.len(), 0);

    // Test chunk boundary file
    let chunk_file = vault_ops.read_file(&DirId::root(), "chunk_boundary.bin").unwrap();
    assert_eq!(chunk_file.content, test_files::create_chunk_boundary_content());

    // Test special characters
    let special = vault_ops.read_file(&DirId::root(), "special_chars.txt").unwrap();
    assert_eq!(special.content, test_files::create_special_char_content());
    
    // Test deeply nested file
    let (dir_id, _) = vault_ops.resolve_path("nested/deeply/nested/structure").unwrap();
    let nested = vault_ops.read_file(&dir_id, "file.txt").unwrap();
    assert_file_content(&nested, b"Deeply nested file");
}

// ==================== EntryType Tests ====================

#[test]
fn test_entry_type_root() {
    use oxcrypt_core::vault::path::EntryType;

    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("file.txt", b"content"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Root is always a directory
    assert_eq!(vault_ops.entry_type(""), Some(EntryType::Directory));
    assert_eq!(vault_ops.entry_type("/"), Some(EntryType::Directory));
}

#[test]
fn test_entry_type_file() {
    use oxcrypt_core::vault::path::EntryType;

    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("file.txt", b"content"),
        ("docs/readme.md", b"readme"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Files at root
    assert_eq!(vault_ops.entry_type("file.txt"), Some(EntryType::File));

    // Files in subdirectories
    assert_eq!(vault_ops.entry_type("docs/readme.md"), Some(EntryType::File));
}

#[test]
fn test_entry_type_directory() {
    use oxcrypt_core::vault::path::EntryType;

    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("docs/readme.md", b"content"),
        ("docs/nested/file.txt", b"nested"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Directory at root
    assert_eq!(vault_ops.entry_type("docs"), Some(EntryType::Directory));

    // Nested directory
    assert_eq!(vault_ops.entry_type("docs/nested"), Some(EntryType::Directory));
}

#[test]
fn test_entry_type_symlink() {
    use oxcrypt_core::vault::path::EntryType;

    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops.create_symlink(&DirId::root(), "link.txt", "file.txt").unwrap();

    // Verify the symlink is detected
    assert_eq!(vault_ops.entry_type("link.txt"), Some(EntryType::Symlink));

    // Original file is still a file
    assert_eq!(vault_ops.entry_type("file.txt"), Some(EntryType::File));
}

#[test]
fn test_entry_type_nonexistent() {
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("file.txt", b"content"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Non-existent paths
    assert_eq!(vault_ops.entry_type("nonexistent.txt"), None);
    assert_eq!(vault_ops.entry_type("nonexistent/path/file.txt"), None);
    assert_eq!(vault_ops.entry_type("file.txt/invalid"), None); // file is not a dir
}

#[test]
fn test_entry_type_convenience_methods() {
    use oxcrypt_core::vault::path::EntryType;

    // Test EntryType helper methods
    assert!(EntryType::File.is_file());
    assert!(!EntryType::File.is_directory());
    assert!(!EntryType::File.is_symlink());

    assert!(!EntryType::Directory.is_file());
    assert!(EntryType::Directory.is_directory());
    assert!(!EntryType::Directory.is_symlink());

    assert!(!EntryType::Symlink.is_file());
    assert!(!EntryType::Symlink.is_directory());
    assert!(EntryType::Symlink.is_symlink());
}

#[test]
fn test_entry_type_display() {
    use oxcrypt_core::vault::path::EntryType;

    assert_eq!(format!("{}", EntryType::File), "file");
    assert_eq!(format!("{}", EntryType::Directory), "directory");
    assert_eq!(format!("{}", EntryType::Symlink), "symlink");
}

// ==================== DirEntry and list() Tests ====================

#[test]
fn test_list_unified_entries() {
    use oxcrypt_core::vault::path::EntryType;

    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file1.txt", b"content 1")
        .add_file("file2.txt", b"content 2")
        .add_file("subdir/nested.txt", b"nested")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops.create_symlink(&DirId::root(), "link.txt", "file1.txt").unwrap();

    // List root directory - should have 2 files, 1 dir, 1 symlink
    let entries = vault_ops.list(&DirId::root()).unwrap();
    assert_eq!(entries.len(), 4);

    // Count by type
    let files: Vec<_> = entries.iter().filter(|e| e.is_file()).collect();
    let dirs: Vec<_> = entries.iter().filter(|e| e.is_directory()).collect();
    let symlinks: Vec<_> = entries.iter().filter(|e| e.is_symlink()).collect();

    assert_eq!(files.len(), 2);
    assert_eq!(dirs.len(), 1);
    assert_eq!(symlinks.len(), 1);

    // Verify names
    let file_names: Vec<_> = files.iter().map(|e| e.name()).collect();
    assert!(file_names.contains(&"file1.txt"));
    assert!(file_names.contains(&"file2.txt"));

    assert_eq!(dirs[0].name(), "subdir");
    assert_eq!(symlinks[0].name(), "link.txt");

    // Verify entry_type() method
    assert_eq!(files[0].entry_type(), EntryType::File);
    assert_eq!(dirs[0].entry_type(), EntryType::Directory);
    assert_eq!(symlinks[0].entry_type(), EntryType::Symlink);
}

#[test]
fn test_list_by_path() {
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("docs/readme.md", b"readme"),
        ("docs/notes/todo.txt", b"todo"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // List root by path
    let root_entries = vault_ops.list_by_path("").unwrap();
    assert_eq!(root_entries.len(), 1); // Just "docs"
    assert!(root_entries[0].is_directory());
    assert_eq!(root_entries[0].name(), "docs");

    // List "docs" directory by path
    let docs_entries = vault_ops.list_by_path("docs").unwrap();
    assert_eq!(docs_entries.len(), 2); // "readme.md" and "notes"

    let file_names: Vec<_> = docs_entries.iter()
        .filter(|e| e.is_file())
        .map(oxcrypt_core::vault::DirEntry::name)
        .collect();
    let dir_names: Vec<_> = docs_entries.iter()
        .filter(|e| e.is_directory())
        .map(oxcrypt_core::vault::DirEntry::name)
        .collect();

    assert_eq!(file_names, vec!["readme.md"]);
    assert_eq!(dir_names, vec!["notes"]);

    // List nested directory
    let notes_entries = vault_ops.list_by_path("docs/notes").unwrap();
    assert_eq!(notes_entries.len(), 1);
    assert!(notes_entries[0].is_file());
    assert_eq!(notes_entries[0].name(), "todo.txt");
}

#[test]
fn test_list_by_path_errors() {
    let (vault_path, master_key) = create_test_vault_with_files(vec![
        ("file.txt", b"content"),
    ]);
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Trying to list a file as a directory should fail
    let result = vault_ops.list_by_path("file.txt");
    assert!(result.is_err());

    // Trying to list non-existent path should fail
    let result = vault_ops.list_by_path("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_dir_entry_accessors() {
    use oxcrypt_core::vault::DirEntry;

    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .add_file("dir/nested.txt", b"nested")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops.create_symlink(&DirId::root(), "link.txt", "file.txt").unwrap();

    let entries = vault_ops.list(&DirId::root()).unwrap();

    for entry in &entries {
        match entry {
            DirEntry::File(info) => {
                assert_eq!(entry.as_file().unwrap().name, info.name);
                assert!(entry.as_directory().is_none());
                assert!(entry.as_symlink().is_none());
            }
            DirEntry::Directory(info) => {
                assert!(entry.as_file().is_none());
                assert_eq!(entry.as_directory().unwrap().name, info.name);
                assert!(entry.as_symlink().is_none());
            }
            DirEntry::Symlink(info) => {
                assert!(entry.as_file().is_none());
                assert!(entry.as_directory().is_none());
                assert_eq!(entry.as_symlink().unwrap().name, info.name);
            }
        }
    }
}

// ==================== High-Level Operations Tests ====================

#[test]
fn test_create_directory_all() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create nested directories in one call
    let dir_id = vault_ops.create_directory_all("a/b/c/d").unwrap();
    assert!(!dir_id.is_root());

    // Verify all directories were created
    assert_eq!(vault_ops.entry_type("a"), Some(oxcrypt_core::vault::path::EntryType::Directory));
    assert_eq!(vault_ops.entry_type("a/b"), Some(oxcrypt_core::vault::path::EntryType::Directory));
    assert_eq!(vault_ops.entry_type("a/b/c"), Some(oxcrypt_core::vault::path::EntryType::Directory));
    assert_eq!(vault_ops.entry_type("a/b/c/d"), Some(oxcrypt_core::vault::path::EntryType::Directory));

    // Creating same path again should be no-op
    let dir_id2 = vault_ops.create_directory_all("a/b/c/d").unwrap();
    assert_eq!(dir_id.as_str(), dir_id2.as_str());

    // Creating partial path should work
    vault_ops.create_directory_all("a/b/e").unwrap();
    assert_eq!(vault_ops.entry_type("a/b/e"), Some(oxcrypt_core::vault::path::EntryType::Directory));
}

#[test]
fn test_touch() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Touch new file
    vault_ops.touch("newfile.txt").unwrap();
    assert_eq!(vault_ops.entry_type("newfile.txt"), Some(oxcrypt_core::vault::path::EntryType::File));

    // Verify it's empty
    let content = vault_ops.read_file(&DirId::root(), "newfile.txt").unwrap();
    assert_eq!(content.content.len(), 0);

    // Touch existing file should be no-op
    vault_ops.touch("existing.txt").unwrap();
    let content = vault_ops.read_file(&DirId::root(), "existing.txt").unwrap();
    assert_eq!(&content.content, b"content");

    // Touch on existing directory should fail
    vault_ops.create_directory_by_path("mydir").unwrap();
    let result = vault_ops.touch("mydir");
    assert!(result.is_err());
}

#[test]
fn test_append() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("log.txt", b"Line 1\n")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Append to existing file
    vault_ops.append("log.txt", b"Line 2\n").unwrap();
    vault_ops.append("log.txt", b"Line 3\n").unwrap();

    let content = vault_ops.read_file(&DirId::root(), "log.txt").unwrap();
    assert_eq!(&content.content, b"Line 1\nLine 2\nLine 3\n");

    // Append to new file (creates it)
    vault_ops.append("newlog.txt", b"First entry\n").unwrap();
    let content = vault_ops.read_file(&DirId::root(), "newlog.txt").unwrap();
    assert_eq!(&content.content, b"First entry\n");
}

#[test]
fn test_create_directory_all_with_existing_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("a/file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to create directory through a file path - should fail
    let result = vault_ops.create_directory_all("a/file.txt/b");
    assert!(result.is_err());
}

// ==================== Phase 6: Path-first API Tests ====================

#[test]
fn test_rename_directory_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("projects/old_name")
        .add_file("projects/old_name/readme.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename directory
    vault_ops.rename_directory_by_path("projects/old_name", "new_name").unwrap();

    // Verify old path doesn't exist
    assert!(vault_ops.entry_type("projects/old_name").is_none());

    // Verify new path exists and is a directory
    assert_eq!(
        vault_ops.entry_type("projects/new_name"),
        Some(oxcrypt_core::vault::path::EntryType::Directory)
    );

    // Verify contents were preserved
    let content = vault_ops.read_by_path("projects/new_name/readme.txt").unwrap();
    assert_eq!(&content.content, b"content");
}

#[test]
fn test_symlink_by_path_operations() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("target.txt", b"target content")
        .add_directory("links")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create symlink by path
    vault_ops.create_symlink_by_path("links/mylink", "../target.txt").unwrap();

    // Verify entry type
    assert_eq!(
        vault_ops.entry_type("links/mylink"),
        Some(oxcrypt_core::vault::path::EntryType::Symlink)
    );

    // Read symlink target by path
    let target = vault_ops.read_symlink_by_path("links/mylink").unwrap();
    assert_eq!(target, "../target.txt");

    // Delete symlink by path
    vault_ops.delete_symlink_by_path("links/mylink").unwrap();
    assert!(vault_ops.entry_type("links/mylink").is_none());
}

#[test]
fn test_get_entry_returns_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("docs/readme.txt", b"readme content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let entry = vault_ops.get_entry("docs/readme.txt");
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert!(entry.is_file());
    assert_eq!(entry.name(), "readme.txt");

    // Access file-specific info
    let file_info = entry.as_file().unwrap();
    assert!(!file_info.is_shortened);
}

#[test]
fn test_get_entry_returns_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("projects/web")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let entry = vault_ops.get_entry("projects/web");
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert!(entry.is_directory());
    assert_eq!(entry.name(), "web");

    // Access directory-specific info
    let dir_info = entry.as_directory().unwrap();
    assert!(!dir_info.directory_id.is_root());
}

#[test]
fn test_get_entry_returns_symlink() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("links")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create symlink
    vault_ops.create_symlink_by_path("links/mylink", "/etc/hosts").unwrap();

    let entry = vault_ops.get_entry("links/mylink");
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert!(entry.is_symlink());
    assert_eq!(entry.name(), "mylink");

    // Access symlink-specific info
    let symlink_info = entry.as_symlink().unwrap();
    assert_eq!(symlink_info.target, "/etc/hosts");
}

#[test]
fn test_get_entry_root() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let entry = vault_ops.get_entry("");
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert!(entry.is_directory());

    let dir_info = entry.as_directory().unwrap();
    assert!(dir_info.directory_id.is_root());
}

#[test]
fn test_get_entry_nonexistent() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    assert!(vault_ops.get_entry("nonexistent").is_none());
    assert!(vault_ops.get_entry("a/b/c").is_none());
}