//! Concurrency tests for NFS backend.
//!
//! Tests parallel operations and race conditions:
//! - Parallel reads of same file
//! - Parallel writes to different files
//! - Concurrent create/delete
//! - Rapid read/write cycles
//!
//! Run: `cargo nextest run -p oxcrypt-nfs --features nfs-tests`

#![cfg(all(unix, feature = "nfs-tests"))]

mod common;

use common::{
    assert_file_content, assert_file_hash, multi_chunk_content, random_bytes, sha256, TestMount,
};
use std::sync::Arc;
use std::thread;

// ============================================================================
// Parallel Reads
// ============================================================================

#[test]
fn test_parallel_reads_same_file() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    let content = random_bytes(50000);
    let expected_hash = sha256(&content);
    mount.write("/shared.bin", &content).expect("write failed");

    let mut handles = vec![];

    for _ in 0..4 {
        let mount_clone = Arc::clone(&mount);
        let expected = expected_hash.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..5 {
                let read_content = mount_clone.read("/shared.bin").expect("read failed");
                let actual_hash = sha256(&read_content);
                assert_eq!(actual_hash, expected, "Content mismatch during parallel read");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_parallel_reads_different_files() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    // Create multiple files
    let mut expected_hashes = vec![];
    for i in 0..4 {
        let content = random_bytes(10000 + i * 1000);
        let hash = sha256(&content);
        mount.write(&format!("/file{}.bin", i), &content).expect("write failed");
        expected_hashes.push(hash);
    }

    let hashes = Arc::new(expected_hashes);
    let mut handles = vec![];

    for i in 0..4 {
        let mount_clone = Arc::clone(&mount);
        let hashes_clone = Arc::clone(&hashes);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let path = format!("/file{}.bin", i);
                let read_content = mount_clone.read(&path).expect("read failed");
                let actual_hash = sha256(&read_content);
                assert_eq!(actual_hash, hashes_clone[i], "Content mismatch for {}", path);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

// ============================================================================
// Parallel Writes
// ============================================================================

#[test]
fn test_parallel_writes_different_files() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    let mut handles = vec![];

    for i in 0..4 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for j in 0..5 {
                let path = format!("/thread{}_{}.txt", i, j);
                let content = format!("Thread {} iteration {}", i, j);
                mount_clone.write(&path, content.as_bytes()).expect("write failed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all files exist with correct content
    for i in 0..4 {
        for j in 0..5 {
            let path = format!("/thread{}_{}.txt", i, j);
            let expected = format!("Thread {} iteration {}", i, j);
            assert_file_content(&mount, &path, expected.as_bytes());
        }
    }
}

#[test]
fn test_parallel_writes_to_directories() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    // Create directories first
    for i in 0..4 {
        mount.mkdir(&format!("/dir{}", i)).expect("mkdir failed");
    }

    let mut handles = vec![];

    for i in 0..4 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for j in 0..5 {
                let path = format!("/dir{}/file{}.txt", i, j);
                let content = format!("Dir {} file {}", i, j);
                mount_clone.write(&path, content.as_bytes()).expect("write failed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify
    for i in 0..4 {
        for j in 0..5 {
            let path = format!("/dir{}/file{}.txt", i, j);
            let expected = format!("Dir {} file {}", i, j);
            assert_file_content(&mount, &path, expected.as_bytes());
        }
    }
}

// ============================================================================
// Concurrent Create/Delete
// ============================================================================

#[test]
fn test_concurrent_create_delete() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    let mut handles = vec![];

    // Creator threads
    for i in 0..2 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for j in 0..20 {
                let path = format!("/temp_c{}_{}.txt", i, j);
                let _ = mount_clone.write(&path, b"temp content");
                thread::sleep(std::time::Duration::from_millis(5));
            }
        }));
    }

    // Deleter threads (will delete their own files)
    for i in 0..2 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for j in 0..20 {
                thread::sleep(std::time::Duration::from_millis(10));
                let path = format!("/temp_c{}_{}.txt", i, j);
                let _ = mount_clone.delete(&path); // May fail if not yet created
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Cleanup any remaining files
    for i in 0..2 {
        for j in 0..20 {
            let path = format!("/temp_c{}_{}.txt", i, j);
            let _ = mount.delete(&path);
        }
    }
}

#[test]
fn test_create_delete_same_file() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    for iteration in 0..20 {
        let content = format!("Iteration {}", iteration);
        mount.write("/toggle.txt", content.as_bytes()).expect("write failed");

        // Verify it exists
        let read = mount.read("/toggle.txt");
        assert!(read.is_ok(), "File should exist after write");

        mount.delete("/toggle.txt").expect("delete failed");

        // Verify it's gone
        let read = mount.read("/toggle.txt");
        assert!(read.is_err(), "File should not exist after delete");
    }
}

// ============================================================================
// Rapid Read/Write Cycles
// ============================================================================

#[test]
fn test_rapid_read_write_cycle() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    mount.write("/rapid.txt", b"initial").expect("write failed");

    for i in 0..50 {
        // Read
        let content = mount.read("/rapid.txt").expect("read failed");
        let expected = if i == 0 {
            b"initial".to_vec()
        } else {
            format!("version {}", i - 1).into_bytes()
        };
        assert_eq!(content, expected);

        // Write new version
        let new_content = format!("version {}", i);
        mount.write("/rapid.txt", new_content.as_bytes()).expect("write failed");
    }
}

#[test]
fn test_interleaved_reads_writes() {
    let mount = TestMount::with_temp_vault().expect("Failed to create test mount");

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    mount.write("/file_a.txt", b"initial A").expect("write failed");
    mount.write("/file_b.txt", b"initial B").expect("write failed");

    // Interleave operations
    assert_file_content(&mount, "/file_a.txt", b"initial A");
    mount.write("/file_b.txt", b"updated B").expect("write failed");
    assert_file_content(&mount, "/file_b.txt", b"updated B");
    mount.write("/file_a.txt", b"updated A").expect("write failed");
    assert_file_content(&mount, "/file_a.txt", b"updated A");
    assert_file_content(&mount, "/file_b.txt", b"updated B");
}

// ============================================================================
// Parallel Directory Operations
// ============================================================================

/// Stress test: parallel directory creation.
///
/// This test is ignored by default because parallel mkdir over NFS
/// can be very slow due to metadata contention and may timeout in CI.
#[test]
#[ignore]
fn test_parallel_mkdir() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    let mut handles = vec![];

    for i in 0..4 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for j in 0..5 {
                let path = format!("/pdir_{}_{}", i, j);
                mount_clone.mkdir(&path).expect("mkdir failed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all directories exist
    for i in 0..4 {
        for j in 0..5 {
            let path = format!("/pdir_{}_{}", i, j);
            assert!(mount.exists(&path), "Directory {} should exist", path);
        }
    }
}

#[test]
fn test_parallel_list_dir() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    // Create some files
    for i in 0..10 {
        mount.write(&format!("/list_file{}.txt", i), b"content").expect("write failed");
    }

    let mut handles = vec![];

    for _ in 0..4 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let entries = mount_clone.list_dir("/").expect("list_dir failed");
                assert!(entries.len() >= 10, "Should have at least 10 files");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

// ============================================================================
// Large File Concurrent Access
// ============================================================================

#[test]
fn test_parallel_reads_large_file() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    // Create a multi-chunk file
    let content = multi_chunk_content(5); // 160KB
    let expected_hash = sha256(&content);
    mount.write("/large_shared.bin", &content).expect("write failed");

    let mut handles = vec![];

    for _ in 0..4 {
        let mount_clone = Arc::clone(&mount);
        let expected = expected_hash.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..3 {
                let read_content = mount_clone.read("/large_shared.bin").expect("read failed");
                let actual_hash = sha256(&read_content);
                assert_eq!(actual_hash, expected, "Large file content mismatch");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

// ============================================================================
// Sequential vs Concurrent Verification
// ============================================================================

#[test]
fn test_sequential_then_concurrent() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    // Sequential writes
    for i in 0..10 {
        let content = format!("Sequential {}", i);
        mount.write(&format!("/seq{}.txt", i), content.as_bytes()).expect("write failed");
    }

    // Concurrent reads
    let mut handles = vec![];

    for i in 0..10 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            let path = format!("/seq{}.txt", i);
            let expected = format!("Sequential {}", i);
            let content = mount_clone.read(&path).expect("read failed");
            assert_eq!(content, expected.as_bytes());
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_stress_many_small_operations() {
    let mount = Arc::new(TestMount::with_temp_vault().expect("Failed to create test mount"));

    if !mount.is_mounted() {
        eprintln!("Skipping test: NFS mount not available");
        return;
    }

    let mut handles = vec![];

    for thread_id in 0..4 {
        let mount_clone = Arc::clone(&mount);
        handles.push(thread::spawn(move || {
            for i in 0..25 {
                let path = format!("/stress_{}_{}.txt", thread_id, i);
                let content = format!("T{}I{}", thread_id, i);

                // Write
                mount_clone.write(&path, content.as_bytes()).expect("write failed");

                // Read and verify
                let read = mount_clone.read(&path).expect("read failed");
                assert_eq!(read, content.as_bytes());

                // Delete
                mount_clone.delete(&path).expect("delete failed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}
