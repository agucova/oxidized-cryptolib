//! Concurrency tests for FSKit filesystem.
//!
//! Tests parallel filesystem operations to ensure thread safety and
//! proper locking. These tests help catch race conditions and cache
//! invalidation bugs.
//!
//! Run: `cargo nextest run -p oxidized-fskit --features fskit-tests concurrency_tests`

#![cfg(all(target_os = "macos", feature = "fskit-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

// Helper to read file directly via std::fs
fn read_file(path: &PathBuf) -> Vec<u8> {
    let mut content = Vec::new();
    File::open(path).unwrap().read_to_end(&mut content).unwrap();
    content
}

// Helper to write file directly via std::fs
fn write_file(path: &PathBuf, content: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(content).unwrap();
    file.sync_all().unwrap();
}

// =============================================================================
// Parallel File Creation
// =============================================================================

#[test]
fn test_parallel_file_creation() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());
    let mount_path = Arc::new(mount.mount_path.clone());

    let num_files = 10;
    let mut handles = vec![];

    for i in 0..num_files {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            let filename = format!("file_{}.txt", i);
            let content = format!("Content for file {}", i);
            write_file(&base_path.join(&filename), content.as_bytes());
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Verify all files were created
    for i in 0..num_files {
        let filename = format!("file_{}.txt", i);
        let expected = format!("Content for file {}", i);
        assert_file_content(&mount, &filename, expected.as_bytes());
    }
}

#[test]
fn test_parallel_directory_creation() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());
    let mount_path = Arc::new(mount.mount_path.clone());

    let num_dirs = 10;
    let mut handles = vec![];

    for i in 0..num_dirs {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            let dirname = format!("dir_{}", i);
            fs::create_dir(base_path.join(&dirname)).expect("parallel mkdir failed");
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Verify all directories were created
    for i in 0..num_dirs {
        let dirname = format!("dir_{}", i);
        assert_is_directory(&mount, &dirname);
    }
}

// =============================================================================
// Parallel Read/Write
// =============================================================================

#[test]
fn test_parallel_reads_same_file() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a larger file to increase chance of race conditions
    let content = multi_chunk_content(3);
    mount.write("shared.bin", &content).expect("write failed");

    let mount_path = Arc::new(mount.mount_path.clone());
    let expected_hash = sha256(&content);
    let mut handles = vec![];

    // Multiple threads reading the same file simultaneously
    for _ in 0..5 {
        let base_path = Arc::clone(&mount_path);
        let expected = expected_hash;
        handles.push(thread::spawn(move || {
            let data = read_file(&base_path.join("shared.bin"));
            let hash = sha256(&data);
            assert_eq!(hash, expected, "Data corruption during parallel read");
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }
}

#[test]
fn test_parallel_writes_different_files() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());
    let mount_path = Arc::new(mount.mount_path.clone());

    let num_files = 5;
    let mut handles = vec![];

    // Each thread writes to its own file
    for i in 0..num_files {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            let filename = format!("parallel_{}.bin", i);
            // Each file gets unique content
            let content = random_bytes(CHUNK_SIZE + i * 1000);
            let hash = sha256(&content);
            write_file(&base_path.join(&filename), &content);
            (filename, hash)
        }));
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    // Verify all files have correct content
    for (filename, expected_hash) in results {
        assert_file_hash(&mount, &filename, &expected_hash);
    }
}

// =============================================================================
// Mixed Operations
// =============================================================================

#[test]
fn test_parallel_mixed_operations() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Setup: create some initial files
    for i in 0..5 {
        mount
            .write(&format!("initial_{}.txt", i), format!("initial {}", i).as_bytes())
            .expect("setup write failed");
    }

    let mount_path = Arc::new(mount.mount_path.clone());
    let mut handles = vec![];

    // Thread 1: Create new files
    {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            for i in 0..5 {
                let path = base_path.join(format!("new_{}.txt", i));
                write_file(&path, format!("new {}", i).as_bytes());
            }
        }));
    }

    // Thread 2: Read existing files
    {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            for i in 0..5 {
                let path = base_path.join(format!("initial_{}.txt", i));
                let _ = read_file(&path);
            }
        }));
    }

    // Thread 3: List directories
    {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let _ = fs::read_dir(&*base_path);
            }
        }));
    }

    // Thread 4: Check metadata
    {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            for i in 0..5 {
                let path = base_path.join(format!("initial_{}.txt", i));
                let _ = fs::metadata(&path);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Verify final state is consistent
    for i in 0..5 {
        assert_exists(&mount, &format!("initial_{}.txt", i));
        assert_exists(&mount, &format!("new_{}.txt", i));
    }
}

// =============================================================================
// Stress Tests
// =============================================================================

#[test]
fn test_rapid_create_delete_cycle() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());
    let mount_path = Arc::new(mount.mount_path.clone());

    let num_threads = 4;
    let operations_per_thread = 10;
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            for op in 0..operations_per_thread {
                let filename = format!("rapid_{}_{}.txt", thread_id, op);
                let path = base_path.join(&filename);
                write_file(&path, b"temporary content");
                fs::remove_file(&path).expect("rapid delete failed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // All temporary files should be gone
    let entries = mount.list("/").expect("list failed");
    let rapid_files: Vec<_> = entries.iter().filter(|e| e.starts_with("rapid_")).collect();
    assert!(
        rapid_files.is_empty(),
        "Leftover files from rapid cycle: {:?}",
        rapid_files
    );
}

#[test]
fn test_parallel_directory_traversal() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a directory structure
    mount.mkdir_all("a/b/c").expect("mkdir_all failed");
    mount.write("a/file1.txt", b"1").expect("write failed");
    mount.write("a/b/file2.txt", b"2").expect("write failed");
    mount.write("a/b/c/file3.txt", b"3").expect("write failed");

    let mount_path = Arc::new(mount.mount_path.clone());
    let mut handles = vec![];

    // Multiple threads traversing the same directory structure
    for _ in 0..5 {
        let base_path = Arc::clone(&mount_path);
        handles.push(thread::spawn(move || {
            assert!(base_path.join("a").is_dir());
            assert!(base_path.join("a/b").is_dir());
            assert!(base_path.join("a/b/c").is_dir());
            assert_eq!(read_file(&base_path.join("a/file1.txt")), b"1");
            assert_eq!(read_file(&base_path.join("a/b/file2.txt")), b"2");
            assert_eq!(read_file(&base_path.join("a/b/c/file3.txt")), b"3");
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }
}

// =============================================================================
// Cache Consistency
// =============================================================================

#[test]
fn test_cache_invalidation_on_write() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Initial write
    mount.write("cached.txt", b"version 1").expect("write 1 failed");

    // Read to populate any caches
    let _ = mount.read("cached.txt").expect("read 1 failed");

    // Overwrite
    mount.write("cached.txt", b"version 2").expect("write 2 failed");

    // Read should see new content (cache invalidated)
    assert_file_content(&mount, "cached.txt", b"version 2");
}

#[test]
fn test_cache_invalidation_on_delete() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("to_delete.txt", b"content").expect("write failed");

    // Read to populate caches
    let _ = mount.read("to_delete.txt").expect("read failed");
    let _ = mount.metadata("to_delete.txt").expect("metadata failed");

    // Delete
    mount.remove("to_delete.txt").expect("delete failed");

    // Should immediately see file as gone
    assert_not_found(&mount, "to_delete.txt");
}

#[test]
fn test_listing_cache_invalidation() {
    skip_if_no_fskit!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Initial listing
    let before = mount.list("/").expect("list before failed");
    let before_count = before.len();

    // Create a file
    mount.write("new_file.txt", b"content").expect("write failed");

    // Listing should immediately reflect the change
    let after = mount.list("/").expect("list after failed");
    assert_eq!(after.len(), before_count + 1);
    assert!(after.contains(&"new_file.txt".to_string()));
}
