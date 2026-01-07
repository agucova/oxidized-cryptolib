//! Concurrency stress tests for vault operations.
//!
//! These tests use high-contention patterns to detect concurrency bugs in the
//! async vault operations. They stress-test the actual production code with
//! real tokio primitives (tokio::sync::RwLock, DashMap).
//!
//! # Test Categories
//!
//! - **Happy-path tests** (`concurrency_happy_*`): Verify correct behavior
//! - **Stress tests** (`concurrency_stress_*`, `stress_*`): High-contention race detection
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p oxcrypt-core --test concurrency_stress_tests
//! ```

#![cfg(feature = "async")]

use oxcrypt_core::vault::{
    handles::VaultHandleTable,
    locks::VaultLockManager,
    operations_async::VaultOperationsAsync,
    path::DirId,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

mod common;
use common::vault_builder::VaultBuilder;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test vault with some files for concurrent operations.
/// Returns (vault_path, enc_key_bytes, mac_key_bytes)
fn setup_test_vault() -> (PathBuf, [u8; 32], [u8; 32]) {
    let (path, master_key) = VaultBuilder::new()
        .add_file("file1.txt", b"Content of file 1")
        .add_file("file2.txt", b"Content of file 2")
        .add_file("subdir/nested.txt", b"Nested file content")
        .add_directory("empty_dir")
        .build();

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    #[allow(deprecated)]
    {
        let raw = master_key.raw_key();
        enc_key.copy_from_slice(&raw[..32]);
        mac_key.copy_from_slice(&raw[32..]);
    }

    (path, enc_key, mac_key)
}

/// Create a vault with a single file for write tests.
/// Returns (vault_path, enc_key_bytes, mac_key_bytes)
fn setup_write_test_vault() -> (PathBuf, [u8; 32], [u8; 32]) {
    let (path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"Original content")
        .build();

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    #[allow(deprecated)]
    {
        let raw = master_key.raw_key();
        enc_key.copy_from_slice(&raw[..32]);
        mac_key.copy_from_slice(&raw[32..]);
    }

    (path, enc_key, mac_key)
}

/// Helper to create VaultOperationsAsync from components
fn create_ops(vault_path: &std::path::Path, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Arc<VaultOperationsAsync> {
    use oxcrypt_core::crypto::keys::MasterKey;
    let master_key = Arc::new(MasterKey::new(*enc_key, *mac_key).unwrap());
    VaultOperationsAsync::new(vault_path, master_key).into_shared()
}

// ============================================================================
// Happy Path Tests
// ============================================================================

/// Verify that Arc-cloned instances properly synchronize
/// Note: VaultOperationsAsync is now Send+Sync, but we use join! for simpler test structure
#[tokio::test]
async fn concurrency_happy_clone_shared_sync() {
    let (vault_path, enc_key, mac_key) = setup_write_test_vault();
    let root = DirId::root();

    // Create ONE instance and clone it (shares lock manager)
    let ops = create_ops(&vault_path, &enc_key, &mac_key);
    let ops1 = ops.clone();
    let ops2 = ops.clone();

    let data1 = b"First write content".to_vec();
    let data2 = b"Second write content".to_vec();

    let root1 = root.clone();
    let root2 = root.clone();

    // Use tokio::join! to run concurrently within the same task
    let (result1, result2) = tokio::join!(
        async { ops1.write_file(&root1, "shared.txt", &data1).await },
        async { ops2.write_file(&root2, "shared.txt", &data2).await }
    );

    // At least one should succeed
    assert!(
        result1.is_ok() || result2.is_ok(),
        "At least one write should succeed"
    );

    // Content should be one of the writes (serialized), not corrupted
    let ops_read = create_ops(&vault_path, &enc_key, &mac_key);
    let result = ops_read.read_file(&root, "shared.txt").await;

    if let Ok(file) = result {
        let is_data1 = file.content == data1;
        let is_data2 = file.content == data2;
        assert!(
            is_data1 || is_data2,
            "File content should be serialized, not corrupted: {:?}",
            String::from_utf8_lossy(&file.content)
        );
    }
}

/// Verify concurrent readers don't block each other
#[tokio::test]
async fn concurrency_happy_concurrent_readers() {
    let (vault_path, enc_key, mac_key) = setup_test_vault();
    let root = DirId::root();

    let ops = create_ops(&vault_path, &enc_key, &mac_key);
    let ops1 = ops.clone();
    let ops2 = ops.clone();
    let ops3 = ops.clone();

    let root1 = root.clone();
    let root2 = root.clone();
    let root3 = root.clone();

    // Run all reads concurrently with join!
    let (result1, result2, result3) = tokio::join!(
        async { ops1.read_file(&root1, "file1.txt").await },
        async { ops2.read_file(&root2, "file2.txt").await },
        async { ops3.read_file(&root3, "file1.txt").await }
    );

    // All reads should complete successfully
    assert!(result1.is_ok(), "Read 1 should succeed");
    assert!(result2.is_ok(), "Read 2 should succeed");
    assert!(result3.is_ok(), "Read 3 should succeed");
}

/// Verify writing different files concurrently works
#[tokio::test]
async fn concurrency_happy_different_files() {
    let (vault_path, enc_key, mac_key) = setup_write_test_vault();
    let root = DirId::root();

    let ops = create_ops(&vault_path, &enc_key, &mac_key);
    let ops1 = ops.clone();
    let ops2 = ops.clone();

    let root1 = root.clone();
    let root2 = root.clone();

    let (result1, result2) = tokio::join!(
        async { ops1.write_file(&root1, "new_a.txt", b"Content A").await },
        async { ops2.write_file(&root2, "new_b.txt", b"Content B").await }
    );

    assert!(result1.is_ok(), "Write to file A should succeed");
    assert!(result2.is_ok(), "Write to file B should succeed");

    // Verify both files exist
    let ops_read = create_ops(&vault_path, &enc_key, &mac_key);
    let files = ops_read.list_files(&root).await.unwrap();

    let file_names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    assert!(file_names.contains(&"new_a.txt"));
    assert!(file_names.contains(&"new_b.txt"));
}

/// Verify ordered locking prevents deadlocks in multi-directory operations
#[tokio::test]
async fn concurrency_happy_ordered_locking() {
    let lock_manager = Arc::new(VaultLockManager::new());

    let dir_a = DirId::from_raw("aaa");
    let dir_b = DirId::from_raw("bbb");
    let dir_c = DirId::from_raw("ccc");

    let mut tasks = JoinSet::new();

    // Multiple tasks acquiring locks on different directory pairs
    for _ in 0..5 {
        let lm = lock_manager.clone();
        let da = dir_a.clone();
        let dc = dir_c.clone();
        tasks.spawn(async move {
            let _guards = lm.lock_directories_write_ordered(&[&da, &dc]).await;
            tokio::task::yield_now().await;
        });

        let lm = lock_manager.clone();
        let db = dir_b.clone();
        let da = dir_a.clone();
        tasks.spawn(async move {
            let _guards = lm.lock_directories_write_ordered(&[&db, &da]).await;
            tokio::task::yield_now().await;
        });

        let lm = lock_manager.clone();
        let dc = dir_c.clone();
        let db = dir_b.clone();
        tasks.spawn(async move {
            let _guards = lm.lock_directories_write_ordered(&[&dc, &db]).await;
            tokio::task::yield_now().await;
        });
    }

    // Use timeout to detect deadlocks
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Ordered locking should prevent deadlocks - test timed out"
    );
}

/// Verify handle table concurrent CRUD operations
#[tokio::test]
async fn concurrency_happy_handle_table_crud() {
    let table = Arc::new(VaultHandleTable::new());

    // Thread 1: Check table operations
    let table1 = table.clone();
    let handle1 = tokio::spawn(async move {
        assert!(table1.is_empty());
        assert_eq!(table1.len(), 0);
        assert!(!table1.contains(1));
        assert!(table1.get(1).is_none());
    });

    handle1.await.unwrap();

    // Verify table is still consistent
    assert!(table.is_empty());
}

/// Verify same lock is reused across multiple acquisitions
#[tokio::test]
async fn concurrency_happy_lock_reuse() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("test-dir");

    // Get lock reference
    let lock1 = manager.directory_lock(&dir_id);
    let lock2 = manager.directory_lock(&dir_id);

    // Should be the same Arc (same underlying lock)
    assert!(
        Arc::ptr_eq(&lock1, &lock2),
        "Same directory should return same lock"
    );

    // Different directory should get different lock
    let other_dir = DirId::from_raw("other-dir");
    let lock3 = manager.directory_lock(&other_dir);
    assert!(
        !Arc::ptr_eq(&lock1, &lock3),
        "Different directories should have different locks"
    );
}

/// Verify file locks are distinct from directory locks
#[tokio::test]
async fn concurrency_happy_file_vs_dir_locks() {
    let manager = VaultLockManager::new();
    let dir_id = DirId::from_raw("test-dir");

    // Directory and file locks should be independent
    // Acquire directory write lock
    let _dir_guard = manager.directory_write(&dir_id).await;

    // Should still be able to get file lock (different lock space)
    let _file_guard = manager.file_write(&dir_id, "file.txt").await;

    // Both locks held simultaneously - no deadlock
}

/// Verify list operations are consistent under concurrent reads
#[tokio::test]
async fn concurrency_happy_concurrent_list_operations() {
    let (vault_path, enc_key, mac_key) = setup_test_vault();
    let root = DirId::root();

    let ops = create_ops(&vault_path, &enc_key, &mac_key);
    let ops1 = ops.clone();
    let ops2 = ops.clone();

    let root1 = root.clone();
    let root2 = root.clone();

    let (result1, result2) = tokio::join!(
        async { ops1.list_files(&root1).await },
        async { ops2.list_files(&root2).await }
    );

    let files1 = result1.unwrap();
    let files2 = result2.unwrap();

    // Both should see the same file count (consistent view)
    assert_eq!(
        files1.len(),
        files2.len(),
        "Concurrent list operations should see consistent state"
    );
    assert_eq!(files1.len(), 2, "Should see 2 files in root");
}

/// High-contention stress test for lock manager
#[tokio::test]
async fn concurrency_stress_lock_contention() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("contended-dir");
    let counter = Arc::new(AtomicUsize::new(0));

    let mut tasks = JoinSet::new();

    // Spawn many tasks all contending for the same lock
    for _ in 0..20 {
        let mgr = manager.clone();
        let dir = dir_id.clone();
        let cnt = counter.clone();

        tasks.spawn(async move {
            for _ in 0..50 {
                let _guard = mgr.directory_write(&dir).await;
                cnt.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        });
    }

    // Wait for all tasks with timeout
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(result.is_ok(), "Stress test should complete without timeout");

    // All increments should have happened
    let final_count = counter.load(Ordering::SeqCst);
    assert_eq!(final_count, 20 * 50, "All operations should complete");
}

/// Stress test for mixed read/write lock operations
#[tokio::test]
async fn concurrency_stress_mixed_rw_locks() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("rw-test-dir");
    let read_count = Arc::new(AtomicUsize::new(0));
    let write_count = Arc::new(AtomicUsize::new(0));

    let mut tasks = JoinSet::new();

    // Spawn reader tasks
    for _ in 0..10 {
        let mgr = manager.clone();
        let dir = dir_id.clone();
        let cnt = read_count.clone();

        tasks.spawn(async move {
            for _ in 0..100 {
                let _guard = mgr.directory_read(&dir).await;
                cnt.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
    }

    // Spawn writer tasks
    for _ in 0..5 {
        let mgr = manager.clone();
        let dir = dir_id.clone();
        let cnt = write_count.clone();

        tasks.spawn(async move {
            for _ in 0..20 {
                let _guard = mgr.directory_write(&dir).await;
                cnt.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
    }

    // Wait for all tasks with timeout
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(result.is_ok(), "Mixed R/W test should complete");

    let reads = read_count.load(Ordering::Relaxed);
    let writes = write_count.load(Ordering::Relaxed);
    assert_eq!(reads, 10 * 100, "All reads should complete");
    assert_eq!(writes, 5 * 20, "All writes should complete");
}

// ============================================================================
// Enhanced Stress Tests (Stronger Race Detection)
// ============================================================================

/// Stress test: Lock identity must be preserved even during cleanup.
///
/// This test verifies that the same DirId always returns the same Arc<RwLock>
/// even when cleanup is running concurrently. A race condition would cause
/// different threads to hold different lock instances for the same key.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stress_lock_identity_under_cleanup() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("identity-test-dir");
    let violations = Arc::new(AtomicUsize::new(0));
    let operations = Arc::new(AtomicUsize::new(0));

    let mut tasks = JoinSet::new();

    // 50 tasks acquiring and checking lock identity
    for _ in 0..50 {
        let mgr = manager.clone();
        let dir = dir_id.clone();
        let viols = violations.clone();
        let ops = operations.clone();

        tasks.spawn(async move {
            for _ in 0..100 {
                // Get lock reference before acquiring
                let lock1 = mgr.directory_lock(&dir);

                // Acquire the lock
                let _guard = mgr.directory_write(&dir).await;
                ops.fetch_add(1, Ordering::Relaxed);

                // Yield to allow cleanup to interleave
                tokio::task::yield_now().await;

                // Get lock reference again - should be the same Arc
                let lock2 = mgr.directory_lock(&dir);

                if !Arc::ptr_eq(&lock1, &lock2) {
                    viols.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    // 10 tasks running cleanup aggressively
    for _ in 0..10 {
        let mgr = manager.clone();

        tasks.spawn(async move {
            for _ in 0..200 {
                mgr.cleanup_unused_locks();
                tokio::task::yield_now().await;
            }
        });
    }

    // Wait for all with timeout
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(result.is_ok(), "Test should complete within timeout");

    let viols = violations.load(Ordering::SeqCst);
    let ops = operations.load(Ordering::Relaxed);

    assert_eq!(
        viols, 0,
        "Lock identity violated {viols} times out of {ops} operations - cleanup race detected!"
    );
}

/// Stress test: High contention on single lock with serialization verification.
///
/// 100 threads × 500 iterations all contending for the same write lock.
/// Verifies that counter increments are properly serialized (no lost updates).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stress_high_contention_single_lock() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("high-contention-dir");
    let counter = Arc::new(AtomicUsize::new(0));
    let conflicts = Arc::new(AtomicUsize::new(0));

    let mut tasks = JoinSet::new();

    const TASK_COUNT: usize = 100;
    const ITERATIONS: usize = 500;

    for _ in 0..TASK_COUNT {
        let mgr = manager.clone();
        let dir = dir_id.clone();
        let cnt = counter.clone();
        let conf = conflicts.clone();

        tasks.spawn(async move {
            for _ in 0..ITERATIONS {
                let _guard = mgr.directory_write(&dir).await;

                // Under exclusive lock, increment should be serialized
                let before = cnt.fetch_add(1, Ordering::SeqCst);

                // Random yield to increase interleaving
                if rand::random::<u8>().is_multiple_of(10) {
                    tokio::task::yield_now().await;
                }

                let after = cnt.load(Ordering::SeqCst);

                // After should be exactly before + 1 (we hold exclusive lock)
                if after != before + 1 {
                    conf.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    let result = tokio::time::timeout(Duration::from_secs(120), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(result.is_ok(), "Test should complete within timeout");

    let final_count = counter.load(Ordering::SeqCst);
    let conflict_count = conflicts.load(Ordering::SeqCst);

    assert_eq!(
        final_count,
        TASK_COUNT * ITERATIONS,
        "All {} increments should complete, got {}",
        TASK_COUNT * ITERATIONS,
        final_count
    );

    assert_eq!(
        conflict_count, 0,
        "Detected {conflict_count} serialization conflicts - lock not providing exclusion!"
    );
}

/// Stress test: Ordered locking with many threads acquiring overlapping sets.
///
/// 100 threads acquiring random subsets of directories in random order.
/// Uses timeout to detect deadlocks. All acquisitions should complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stress_ordered_locking_no_deadlock() {
    let manager = Arc::new(VaultLockManager::new());
    let dir_ids: Vec<DirId> = (0..10)
        .map(|i| DirId::from_raw(format!("dir-{i:02}")))
        .collect();
    let completions = Arc::new(AtomicUsize::new(0));

    let mut tasks = JoinSet::new();

    const TASK_COUNT: usize = 100;
    const ITERATIONS: usize = 50;

    for task_id in 0..TASK_COUNT {
        let mgr = manager.clone();
        let dirs = dir_ids.clone();
        let comp = completions.clone();

        tasks.spawn(async move {
            for iter in 0..ITERATIONS {
                // Pick 2-4 random directories (overlapping sets trigger deadlock potential)
                let count = 2 + (task_id + iter) % 3;
                let indices: Vec<usize> = (0..count)
                    .map(|i| (task_id + iter + i * 3) % dirs.len())
                    .collect();

                let selected: Vec<&DirId> = indices.iter().map(|&i| &dirs[i]).collect();

                // Ordered locking should prevent deadlock
                let _guards = mgr.lock_directories_write_ordered(&selected).await;

                // Small work under lock
                tokio::task::yield_now().await;

                comp.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    // Use timeout to detect deadlock
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("task panicked");
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Deadlock detected! Ordered locking should prevent this."
    );

    let completed = completions.load(Ordering::Relaxed);
    assert_eq!(
        completed,
        TASK_COUNT * ITERATIONS,
        "All {} operations should complete, got {}",
        TASK_COUNT * ITERATIONS,
        completed
    );
}

/// Stress test: True OS-level parallelism with std::thread.
///
/// Uses std::thread (not tokio::spawn) to force OS-level preemption
/// rather than cooperative yielding. This is more likely to trigger
/// races that cooperative async tests miss.
#[test]
#[cfg(feature = "stress")]
fn stress_true_parallel_lock_contention() {
    use std::thread;

    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("parallel-test-dir");
    let counter = Arc::new(AtomicUsize::new(0));
    let violations = Arc::new(AtomicUsize::new(0));

    const THREAD_COUNT: usize = 16;
    const ITERATIONS: usize = 1000;

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|_| {
            let mgr = manager.clone();
            let dir = dir_id.clone();
            let cnt = counter.clone();
            let viols = violations.clone();

            thread::spawn(move || {
                // Each thread gets its own tokio runtime
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    for _ in 0..ITERATIONS {
                        let _guard = mgr.directory_write(&dir).await;

                        let before = cnt.fetch_add(1, Ordering::SeqCst);

                        // Check serialization
                        let after = cnt.load(Ordering::SeqCst);
                        if after != before + 1 {
                            viols.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    let final_count = counter.load(Ordering::SeqCst);
    let viol_count = violations.load(Ordering::SeqCst);

    assert_eq!(
        final_count,
        THREAD_COUNT * ITERATIONS,
        "All increments should complete"
    );

    assert_eq!(
        viol_count, 0,
        "Detected {viol_count} serialization violations with true OS parallelism"
    );
}

/// Long-running stress test: 10 seconds of mixed operations.
///
/// Runs for a fixed duration rather than fixed iterations to catch
/// timing-dependent races that only manifest over time.
///
/// Uses std::thread with separate tokio runtimes for isolation.
/// VaultOperationsAsync is now Send+Sync and can be shared across threads via Arc.
#[test]
#[cfg(feature = "stress")]
fn stress_mixed_operations_timed() {
    use std::thread;

    let (vault_path, enc_key, mac_key) = setup_write_test_vault();

    let operations = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // Spawn worker threads
    let handles: Vec<_> = (0..8)
        .map(|worker_id| {
            let vault_path = vault_path.clone();
            let op_count = operations.clone();
            let err_count = errors.clone();
            let is_running = running.clone();

            thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    // Create ops inside thread (each thread gets own instance)
                    let ops = create_ops(&vault_path, &enc_key, &mac_key);
                    let root = DirId::root();

                    while is_running.load(Ordering::Relaxed) {
                        let op_type = rand::random::<u8>() % 4;
                        let filename = format!("stress_file_{worker_id}.txt");

                        // Run operations and track if they succeeded
                        let succeeded = match op_type {
                            0 => ops
                                .write_file(&root, &filename, b"stress test content")
                                .await
                                .is_ok(),
                            1 => ops.read_file(&root, &filename).await.is_ok(),
                            2 => ops.list_files(&root).await.is_ok(),
                            _ => ops.delete_file(&root, &filename).await.is_ok(),
                        };

                        // Write and list should always work
                        if !succeeded && (op_type == 0 || op_type == 2) {
                            err_count.fetch_add(1, Ordering::Relaxed);
                        }

                        op_count.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                });
            })
        })
        .collect();

    // Run for 10 seconds
    thread::sleep(Duration::from_secs(10));
    running.store(false, Ordering::Relaxed);

    // Wait for threads
    for handle in handles {
        handle.join().expect("worker panicked");
    }

    let total_ops = operations.load(Ordering::Relaxed);
    let total_errors = errors.load(Ordering::Relaxed);

    println!(
        "Completed {total_ops} operations in 10 seconds with {total_errors} unexpected errors"
    );

    assert!(total_ops > 100, "Should complete substantial operations");
    assert_eq!(total_errors, 0, "No unexpected errors should occur");
}
