mod common;

use oxidized_cryptolib::vault::operations::VaultOperations;
use common::{
    create_seeded_master_key,
    test_data::{structures, test_vectors, performance},
    vault_builder::{VaultBuilder, create_standard_test_vault, create_edge_case_vault},
    assertions::*,
};

/// Test that seeded master key generation is deterministic and produces different keys for different seeds.
/// This is critical for reproducible testing - we need the same seed to always produce the same key,
/// but different seeds must produce different keys to avoid accidental key reuse in tests.
#[test]
fn test_seeded_master_keys_are_deterministic() {
    let key1 = create_seeded_master_key(42);
    let key2 = create_seeded_master_key(42);
    let key3 = create_seeded_master_key(43);
    
    // Same seed should produce identical keys
    key1.with_raw_key(|k1| {
        key2.with_raw_key(|k2| {
            assert_eq!(k1, k2, "Same seed should produce identical master keys");
        })
    });
    
    // Different seed should produce different keys
    key1.with_raw_key(|k1| {
        key3.with_raw_key(|k3| {
            assert_ne!(k1, k3, "Different seeds should produce different master keys");
        })
    });
}

#[test]
fn test_standard_vault_structure() {
    let (vault_path, master_key) = create_standard_test_vault();
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Standard vault should have the nested structure
    let root_files = vault_ops.list_files("").unwrap();
    assert!(root_files.iter().any(|f| f.name == "root.txt"));
    
    let root_dirs = vault_ops.list_directories("").unwrap();
    assert!(root_dirs.iter().any(|d| d.name == "docs"));
    assert!(root_dirs.iter().any(|d| d.name == "src"));
    assert!(root_dirs.iter().any(|d| d.name == "assets"));
    
    // Check nested content
    let (docs_id, _) = vault_ops.resolve_path("docs").unwrap();
    let docs_files = vault_ops.list_files(&docs_id).unwrap();
    assert_eq!(docs_files.len(), 2);
    assert!(docs_files.iter().any(|f| f.name == "readme.md"));
    assert!(docs_files.iter().any(|f| f.name == "guide.md"));
}

#[test]
fn test_edge_case_vault_structure() {
    let (vault_path, master_key) = create_edge_case_vault();
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test empty file
    let empty = vault_ops.read_file("", "empty.txt").unwrap();
    assert_eq!(empty.content.len(), 0);
    
    // Test chunk boundary file
    let chunk_file = vault_ops.read_file("", "chunk_boundary.bin").unwrap();
    assert!(chunk_file.content.len() > 32768); // Should be larger than one chunk
    
    // Test special characters
    let special = vault_ops.read_file("", "special_chars.txt").unwrap();
    assert!(special.content.len() > 0);
    
    // Test deeply nested file
    let (dir_id, _) = vault_ops.resolve_path("nested/deeply/nested/structure").unwrap();
    let nested = vault_ops.read_file(&dir_id, "file.txt").unwrap();
    assert_file_content(&nested, b"Deeply nested file");
}

/// Test deeply nested directory structures to ensure the vault can handle long directory paths.
/// This tests filesystem limits and path resolution in deeply nested hierarchies,
/// which can reveal issues with directory ID tracking and path resolution algorithms.
#[test]
fn test_deep_nesting_structure() {
    let structure = structures::deep_nesting(5);
    assert_eq!(structure.len(), 5);
    
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(structure)
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Test that we can read from the deepest level
    let (deep_id, _) = vault_ops.resolve_path("level0/level1/level2/level3/level4").unwrap();
    let deep_file = vault_ops.read_file(&deep_id, "file4.txt").unwrap();
    assert_file_content(&deep_file, b"Content at level 4");
}

/// Test directories with many files to stress-test file listing and directory operations.
/// This tests performance and correctness when dealing with directories containing many files,
/// which can reveal issues with directory scanning, memory usage, and filename collision handling.
#[test]
fn test_wide_structure() {
    let structure = structures::wide_structure(50);
    assert_eq!(structure.len(), 50);
    
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(structure)
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Should have 50 files in root directory
    let files = vault_ops.list_files("").unwrap();
    assert_eq!(files.len(), 50);
    
    // Check a few specific files
    let file0 = vault_ops.read_file("", "file0000.txt").unwrap();
    assert_file_content(&file0, b"File 0 content");
    
    let file25 = vault_ops.read_file("", "file0025.txt").unwrap();
    assert_file_content(&file25, b"File 25 content");
    
    let file49 = vault_ops.read_file("", "file0049.txt").unwrap();
    assert_file_content(&file49, b"File 49 content");
}

/// Test balanced tree structures that combine both depth and breadth to test realistic directory layouts.
/// This tests the interaction between nested directories and multiple files per directory,
/// simulating typical project structures and ensuring correct directory ID management in complex hierarchies.
#[test]
fn test_balanced_tree_structure() {
    let structure = structures::balanced_tree(3, 2);
    
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file_structure(structure)
        .build();
    
    let vault_ops = VaultOperations::new(&vault_path, master_key);
    
    // Root should have 2 directories (branching factor = 2)
    let root_dirs = vault_ops.list_directories("").unwrap();
    assert_eq!(root_dirs.len(), 2);
    assert!(root_dirs.iter().any(|d| d.name == "dir0"));
    assert!(root_dirs.iter().any(|d| d.name == "dir1"));
    
    // Each directory should have a file and subdirectories
    let (dir0_id, _) = vault_ops.resolve_path("dir0").unwrap();
    let dir0_files = vault_ops.list_files(&dir0_id).unwrap();
    assert_eq!(dir0_files.len(), 1);
    assert_eq!(dir0_files[0].name, "file.txt");
    
    let dir0_dirs = vault_ops.list_directories(&dir0_id).unwrap();
    assert_eq!(dir0_dirs.len(), 2); // Should have 2 subdirectories
    
    // Test nested content
    let (nested_id, _) = vault_ops.resolve_path("dir0/dir1").unwrap();
    let nested_file = vault_ops.read_file(&nested_id, "file.txt").unwrap();
    assert_file_content(&nested_file, b"File in dir0/dir1");
}

/// Test that the known master key for test vectors is consistent and different from other test keys.
/// This ensures test vector validation will work reliably and that we're not accidentally
/// using the same key across different test scenarios, which could mask bugs.
#[test]
fn test_known_master_key_consistency() {
    let key1 = test_vectors::known_master_key();
    let key2 = test_vectors::known_master_key();
    
    // Known master key should be consistent
    key1.with_raw_key(|k1| {
        key2.with_raw_key(|k2| {
            assert_eq!(k1, k2, "Known master key should be consistent across calls");
        })
    });
    
    // Should be different from test master key
    let test_key = common::create_test_master_key();
    key1.with_raw_key(|k1| {
        test_key.with_raw_key(|kt| {
            assert_ne!(k1, kt, "Known master key should differ from test master key");
        })
    });
}

/// Test the performance measurement utilities to ensure they work correctly.
/// While not directly related to vault operations, these utilities are important for
/// performance testing and benchmarking of cryptographic operations.
#[test]
fn test_performance_measurement() {
    let (result, duration) = performance::measure_time(|| {
        // Simulate some work
        let mut sum = 0;
        for i in 0..1000 {
            sum += i;
        }
        sum
    });
    
    assert_eq!(result, 499500); // Sum of 0..1000
    assert!(duration.as_nanos() > 0, "Should measure some time");
}

/// Test the benchmark statistics utilities to ensure they produce sensible results.
/// This validates that our benchmarking infrastructure works correctly for measuring
/// the performance characteristics of cryptographic operations.
#[test]
fn test_benchmark_statistics() {
    let benchmark_result = performance::benchmark(10, || {
        // Simple operation
        let _sum: i32 = (0..100).sum();
    });
    
    assert_eq!(benchmark_result.iterations, 10);
    assert!(benchmark_result.min <= benchmark_result.mean);
    assert!(benchmark_result.mean <= benchmark_result.max);
    assert!(benchmark_result.min.as_nanos() > 0);
}

/// Test that VaultBuilder's with_master_key method works correctly with seeded keys.
/// This ensures that the vault builder can accept custom master keys, which is important
/// for testing scenarios where we need specific keys rather than the default test key.
#[test]
fn test_seeded_keys_in_vault_creation() {
    // Use seeded master keys for deterministic vault testing
    let key1 = create_seeded_master_key(100);
    let key2 = create_seeded_master_key(101);
    
    let (vault1_path, _) = VaultBuilder::new()
        .with_master_key(key1.clone())
        .add_file("test.txt", b"Test content")
        .build();
    
    let (vault2_path, _) = VaultBuilder::new()
        .with_master_key(key2.clone())
        .add_file("test.txt", b"Test content")
        .build();
    
    let vault_ops1 = VaultOperations::new(&vault1_path, key1);
    let vault_ops2 = VaultOperations::new(&vault2_path, key2);
    
    // Both should decrypt to same content but with different encryption
    let file1 = vault_ops1.read_file("", "test.txt").unwrap();
    let file2 = vault_ops2.read_file("", "test.txt").unwrap();
    
    assert_eq!(file1.content, file2.content);
    assert_eq!(file1.content, b"Test content");
}