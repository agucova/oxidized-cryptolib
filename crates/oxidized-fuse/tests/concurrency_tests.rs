//! Concurrency tests for FUSE filesystem.
//!
//! Tests thread safety and race condition handling. Verifies that
//! parallel operations don't corrupt data or cause deadlocks.
//!
//! Run: `cargo nextest run -p oxidized-fuse --features fuse-tests concurrency_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Parallel Reads
// =============================================================================

#[test]
fn test_parallel_reads_same_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file with known content
    let content = multi_chunk_content(3);
    let expected_hash = sha256(&content);
    mount.write("shared.bin", &content).expect("write failed");

    // Spawn multiple threads reading the same file
    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let path = mount_path.clone();
            let expected = expected_hash;
            let success = Arc::clone(&success);

            thread::spawn(move || {
                for j in 0..5 {
                    match std::fs::read(path.join("shared.bin")) {
                        Ok(data) => {
                            let actual = sha256(&data);
                            if actual != expected {
                                eprintln!("Thread {} iter {}: hash mismatch!", i, j);
                                success.store(false, Ordering::SeqCst);
                            }
                        }
                        Err(e) => {
                            eprintln!("Thread {} iter {}: read failed: {}", i, j, e);
                            success.store(false, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(success.load(Ordering::SeqCst), "Some parallel reads failed");
}

#[test]
fn test_parallel_reads_different_files() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create multiple files
    let mut expected_hashes = Vec::new();
    for i in 0..5 {
        let content = random_bytes(10000);
        expected_hashes.push(sha256(&content));
        mount
            .write(&format!("file_{}.bin", i), &content)
            .expect("write failed");
    }

    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let path = mount_path.clone();
            let expected = expected_hashes[i];
            let success = Arc::clone(&success);

            thread::spawn(move || {
                for _ in 0..10 {
                    match std::fs::read(path.join(format!("file_{}.bin", i))) {
                        Ok(data) => {
                            let actual = sha256(&data);
                            if actual != expected {
                                success.store(false, Ordering::SeqCst);
                            }
                        }
                        Err(e) => {
                            eprintln!("Thread {}: read failed: {}", i, e);
                            success.store(false, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(success.load(Ordering::SeqCst), "Some parallel reads failed");
}

// =============================================================================
// Parallel Writes
// =============================================================================

#[test]
fn test_parallel_writes_different_files() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let path = mount_path.clone();
            let success = Arc::clone(&success);

            thread::spawn(move || {
                let content = random_bytes(10000);
                let expected = sha256(&content);
                let filename = format!("parallel_{}.bin", i);

                // Write
                if std::fs::write(path.join(&filename), &content).is_err() {
                    success.store(false, Ordering::SeqCst);
                    return;
                }

                // Read back and verify
                match std::fs::read(path.join(&filename)) {
                    Ok(data) => {
                        if sha256(&data) != expected {
                            success.store(false, Ordering::SeqCst);
                        }
                    }
                    Err(_) => success.store(false, Ordering::SeqCst),
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(success.load(Ordering::SeqCst), "Some parallel writes failed");
}

#[test]
fn test_sequential_writes_same_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Last writer wins semantics
    let mount_path = mount.mount_path.clone();

    // Write from main thread first
    mount.write("contested.txt", b"initial").expect("write failed");

    // Sequential writes from different threads
    for i in 0..5 {
        let path = mount_path.clone();
        let content = format!("content from iteration {}", i);

        let handle = thread::spawn(move || {
            std::fs::write(path.join("contested.txt"), content.as_bytes()).expect("write failed");
        });
        handle.join().expect("thread panicked");
    }

    // File should exist and have content from one of the writes
    let content = mount.read("contested.txt").expect("read failed");
    assert!(!content.is_empty());
}

// =============================================================================
// Create/Delete Cycles
// =============================================================================

#[test]
fn test_rapid_create_delete_cycle() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    for i in 0..20 {
        let filename = format!("cycle_{}.txt", i);
        let content = format!("content {}", i);

        mount.write(&filename, content.as_bytes()).expect("write failed");
        assert_exists(&mount, &filename);

        mount.remove(&filename).expect("delete failed");
        assert_not_found(&mount, &filename);
    }
}

#[test]
fn test_parallel_create_delete_different_files() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let path = mount_path.clone();
            let success = Arc::clone(&success);

            thread::spawn(move || {
                let filename = format!("thread_{}.txt", i);
                let file_path = path.join(&filename);

                for j in 0..5 {
                    let content = format!("iter {}", j);

                    if std::fs::write(&file_path, content.as_bytes()).is_err() {
                        success.store(false, Ordering::SeqCst);
                        return;
                    }

                    if std::fs::remove_file(&file_path).is_err() {
                        success.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(
        success.load(Ordering::SeqCst),
        "Some create/delete cycles failed"
    );
}

// =============================================================================
// Concurrent Directory Operations
// =============================================================================

#[test]
fn test_parallel_mkdir() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let mount_path = mount.mount_path.clone();
    let successes = Arc::new(AtomicUsize::new(0));

    // Multiple threads try to create the same directory
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let path = mount_path.clone();
            let successes = Arc::clone(&successes);

            thread::spawn(move || {
                if std::fs::create_dir(path.join("contested_dir")).is_ok() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Exactly one should succeed
    assert_eq!(
        successes.load(Ordering::SeqCst),
        1,
        "Exactly one mkdir should succeed"
    );
    assert_is_directory(&mount, "contested_dir");
}

#[test]
fn test_parallel_list_directory() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create some files
    for i in 0..10 {
        mount
            .write(&format!("file_{}.txt", i), b"content")
            .expect("write failed");
    }

    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    let handles: Vec<_> = (0..5)
        .map(|_| {
            let path = mount_path.clone();
            let success = Arc::clone(&success);

            thread::spawn(move || {
                for _ in 0..10 {
                    match std::fs::read_dir(&path) {
                        Ok(entries) => {
                            let count = entries.count();
                            if count < 10 {
                                // Should have at least 10 files
                                success.store(false, Ordering::SeqCst);
                            }
                        }
                        Err(_) => success.store(false, Ordering::SeqCst),
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(
        success.load(Ordering::SeqCst),
        "Some directory listings failed"
    );
}

// =============================================================================
// Reader/Writer Concurrency
// =============================================================================

#[test]
fn test_reader_writer_same_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Initial content
    mount.write("rw.txt", b"initial").expect("write failed");

    let mount_path = mount.mount_path.clone();
    let done = Arc::new(AtomicBool::new(false));

    // Writer thread
    let writer_path = mount_path.clone();
    let writer_done = Arc::clone(&done);
    let writer = thread::spawn(move || {
        for i in 0..20 {
            let content = format!("update {}", i);
            std::fs::write(writer_path.join("rw.txt"), content.as_bytes()).ok();
            thread::sleep(Duration::from_millis(5));
        }
        writer_done.store(true, Ordering::SeqCst);
    });

    // Reader thread
    let reader_path = mount_path.clone();
    let reader_done = Arc::clone(&done);
    let success = Arc::new(AtomicBool::new(true));
    let reader_success = Arc::clone(&success);
    let reader = thread::spawn(move || {
        while !reader_done.load(Ordering::SeqCst) {
            match std::fs::read(reader_path.join("rw.txt")) {
                Ok(data) => {
                    // Should always get valid UTF-8 content
                    if String::from_utf8(data).is_err() {
                        reader_success.store(false, Ordering::SeqCst);
                    }
                }
                Err(_) => {
                    // Reads might occasionally fail during writes - that's ok
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    writer.join().expect("writer panicked");
    reader.join().expect("reader panicked");

    assert!(success.load(Ordering::SeqCst), "Reader got corrupt data");

    // Final state should be valid
    let final_content = mount.read("rw.txt").expect("final read failed");
    assert!(String::from_utf8(final_content).is_ok());
}

// =============================================================================
// Stress Tests
// =============================================================================

/// Concurrent file creation stress test.
///
/// Note: This test is sensitive to system load and stale FUSE mounts.
/// If it times out frequently, check for zombie mounts with:
///   `mount | grep cryptomator-test`
/// Unmount stale mounts with:
///   `diskutil unmount force <mountpoint>`
#[test]
fn test_many_small_files_concurrent() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let mount_path = mount.mount_path.clone();
    let success = Arc::new(AtomicBool::new(true));

    // 3 threads, each creates 2 files = 6 files total
    // Keep this small to avoid CI timeouts with FUSE overhead
    let handles: Vec<_> = (0..3)
        .map(|t| {
            let path = mount_path.clone();
            let success = Arc::clone(&success);

            thread::spawn(move || {
                for f in 0..2 {
                    let filename = format!("t{}_f{}.txt", t, f);
                    let content = format!("thread {} file {}", t, f);

                    if std::fs::write(path.join(&filename), content.as_bytes()).is_err() {
                        success.store(false, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    assert!(success.load(Ordering::SeqCst), "Some file creations failed");

    // Verify all 6 files exist
    let entries = mount.list("/").expect("list failed");
    let file_count = entries.iter().filter(|e| e.starts_with("t")).count();
    assert_eq!(file_count, 6, "Expected 6 files, found {}", file_count);
}
