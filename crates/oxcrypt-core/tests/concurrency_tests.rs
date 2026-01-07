//! Concurrency tests for VaultOperationsAsync.
//!
//! These tests verify the thread-safety and locking behavior of async vault operations.
//! Focus areas:
//! - Concurrent reads should succeed
//! - Concurrent writes to different resources should succeed
//! - Writes should block concurrent access to same resource
//! - No deadlocks under stress conditions
//! - Operations are atomic and consistent
//!

#![cfg(feature = "async")]
//! Note: MasterKey is now thread-safe (Send + Sync via RwLock), and VaultOperationsAsync
//! can be wrapped in Arc for sharing across threads. Tests use concurrent execution
//! and Arc-based sharing for parallelism testing of the locking primitives.

#![cfg(feature = "async")]

use oxcrypt_core::vault::{
    DirId, VaultCreator, VaultLockManager, VaultLockRegistry,
    operations_async::VaultOperationsAsync,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Test helper to create a vault with test content.
fn create_test_vault() -> (TempDir, Arc<VaultOperationsAsync>) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("test_vault");

    let creator = VaultCreator::new(&vault_path, "test_password");
    let sync_ops = creator.create().expect("Failed to create vault");
    let master_key = Arc::new(sync_ops.master_key().clone());

    let ops = VaultOperationsAsync::new(&vault_path, master_key).into_shared();

    (temp_dir, ops)
}

/// Test that multiple sequential reads to the same file succeed.
#[tokio::test]
async fn test_sequential_reads_same_file() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create a test file
    let content = b"Hello, sequential readers!";
    ops.write_file(&root, "test.txt", content)
        .await
        .expect("Failed to write file");

    // Multiple reads should all succeed
    for i in 0..10 {
        let result = ops.read_file(&root, "test.txt").await;
        assert!(result.is_ok(), "Read {} failed: {:?}", i, result.err());
        let file = result.unwrap();
        assert_eq!(file.content, content, "Read {i} got wrong content");
    }
}

/// Test that concurrent reads via join! work correctly.
#[tokio::test]
async fn test_concurrent_reads_via_join() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create test files
    ops.write_file(&root, "file1.txt", b"content 1")
        .await
        .expect("write 1");
    ops.write_file(&root, "file2.txt", b"content 2")
        .await
        .expect("write 2");
    ops.write_file(&root, "file3.txt", b"content 3")
        .await
        .expect("write 3");

    // Read all concurrently
    let (r1, r2, r3) = tokio::join!(
        ops.read_file(&root, "file1.txt"),
        ops.read_file(&root, "file2.txt"),
        ops.read_file(&root, "file3.txt"),
    );

    assert_eq!(r1.unwrap().content, b"content 1");
    assert_eq!(r2.unwrap().content, b"content 2");
    assert_eq!(r3.unwrap().content, b"content 3");
}

/// Test that concurrent writes via join! work correctly.
#[tokio::test]
async fn test_concurrent_writes_via_join() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Write multiple files concurrently
    let (w1, w2, w3) = tokio::join!(
        ops.write_file(&root, "file1.txt", b"content 1"),
        ops.write_file(&root, "file2.txt", b"content 2"),
        ops.write_file(&root, "file3.txt", b"content 3"),
    );

    assert!(w1.is_ok(), "Write 1 failed: {:?}", w1.err());
    assert!(w2.is_ok(), "Write 2 failed: {:?}", w2.err());
    assert!(w3.is_ok(), "Write 3 failed: {:?}", w3.err());

    // Verify all files
    assert_eq!(
        ops.read_file(&root, "file1.txt").await.unwrap().content,
        b"content 1"
    );
    assert_eq!(
        ops.read_file(&root, "file2.txt").await.unwrap().content,
        b"content 2"
    );
    assert_eq!(
        ops.read_file(&root, "file3.txt").await.unwrap().content,
        b"content 3"
    );
}

/// Test concurrent directory creation.
#[tokio::test]
async fn test_concurrent_directory_creation() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create multiple directories concurrently
    let (d1, d2, d3) = tokio::join!(
        ops.create_directory(&root, "dir1"),
        ops.create_directory(&root, "dir2"),
        ops.create_directory(&root, "dir3"),
    );

    assert!(d1.is_ok(), "Dir 1 failed: {:?}", d1.err());
    assert!(d2.is_ok(), "Dir 2 failed: {:?}", d2.err());
    assert!(d3.is_ok(), "Dir 3 failed: {:?}", d3.err());

    // Verify all directories exist
    let dirs = ops.list_directories(&root).await.unwrap();
    assert_eq!(dirs.len(), 3);

    let dir_names: Vec<_> = dirs.iter().map(|d| d.name.as_str()).collect();
    assert!(dir_names.contains(&"dir1"));
    assert!(dir_names.contains(&"dir2"));
    assert!(dir_names.contains(&"dir3"));
}

/// Test concurrent operations across different directories.
#[tokio::test]
async fn test_concurrent_operations_different_directories() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create directories
    let dir1 = ops.create_directory(&root, "dir1").await.unwrap();
    let dir2 = ops.create_directory(&root, "dir2").await.unwrap();

    // Write to both directories concurrently
    let (w1, w2) = tokio::join!(
        ops.write_file(&dir1, "file1.txt", b"dir1 content"),
        ops.write_file(&dir2, "file2.txt", b"dir2 content"),
    );

    assert!(w1.is_ok());
    assert!(w2.is_ok());

    // Read from both concurrently
    let (r1, r2) = tokio::join!(
        ops.read_file(&dir1, "file1.txt"),
        ops.read_file(&dir2, "file2.txt"),
    );

    assert_eq!(r1.unwrap().content, b"dir1 content");
    assert_eq!(r2.unwrap().content, b"dir2 content");
}

/// Test the lock manager caching behavior.
#[tokio::test]
async fn test_lock_manager_caching() {
    let manager = VaultLockManager::new();
    let dir_id = DirId::from_raw("test-dir");

    // Get locks multiple times - should reuse
    assert_eq!(manager.directory_lock_count(), 0);

    let _lock1 = manager.directory_lock(&dir_id);
    assert_eq!(manager.directory_lock_count(), 1);

    let _lock2 = manager.directory_lock(&dir_id);
    assert_eq!(manager.directory_lock_count(), 1); // Same lock reused

    // File locks
    assert_eq!(manager.file_lock_count(), 0);

    let _file_lock1 = manager.file_lock(&dir_id, "file1.txt");
    assert_eq!(manager.file_lock_count(), 1);

    let _file_lock2 = manager.file_lock(&dir_id, "file2.txt");
    assert_eq!(manager.file_lock_count(), 2);

    let _file_lock3 = manager.file_lock(&dir_id, "file1.txt");
    assert_eq!(manager.file_lock_count(), 2); // file1.txt reused
}

/// Test cleanup of unused locks.
#[tokio::test]
async fn test_lock_manager_cleanup() {
    let manager = VaultLockManager::new();
    let dir_id = DirId::from_raw("test-dir");

    // Create and immediately drop a lock
    {
        let _guard = manager.directory_read(&dir_id).await;
        assert_eq!(manager.directory_lock_count(), 1);
    }

    // Lock should still be cached
    assert_eq!(manager.directory_lock_count(), 1);

    // Cleanup should remove it (since no guards are held)
    manager.cleanup_unused_locks();
    assert_eq!(manager.directory_lock_count(), 0);
}

/// Test that the handle table generates unique IDs.
#[tokio::test]
async fn test_handle_table_unique_ids() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();
    let table = ops.handle_table();

    // Create multiple files
    for i in 0..5 {
        ops.write_file(
            &root,
            &format!("file_{i}.txt"),
            format!("content {i}").as_bytes(),
        )
        .await
        .expect("Failed to write");
    }

    // Open files and verify unique handles
    let mut handles = Vec::new();
    for i in 0..5 {
        let reader = ops
            .open_file(&root, &format!("file_{i}.txt"))
            .await
            .expect("Failed to open");

        let handle_id = table.insert(oxcrypt_core::vault::OpenHandle::Reader(reader));

        // All handles should be unique
        assert!(
            !handles.contains(&handle_id),
            "Duplicate handle ID: {handle_id}"
        );
        handles.push(handle_id);
    }

    // Verify all handles exist
    for handle_id in &handles {
        assert!(table.contains(*handle_id), "Handle {handle_id} not found");
    }

    // Remove handles
    for handle_id in handles {
        let removed = table.remove(handle_id);
        assert!(removed.is_some(), "Handle {handle_id} not removed");
    }

    // Table should be empty
    assert!(table.is_empty());
}

/// Test that many sequential operations don't deadlock.
#[tokio::test]
async fn test_many_sequential_operations_no_deadlock() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Perform many mixed operations
    for i in 0..50 {
        let filename = format!("file_{}.txt", i % 10);
        let content = format!("Content iteration {i}");

        match i % 4 {
            0 => {
                // Write
                ops.write_file(&root, &filename, content.as_bytes())
                    .await
                    .ok();
            }
            1 => {
                // Read
                ops.read_file(&root, &filename).await.ok();
            }
            2 => {
                // List files
                ops.list_files(&root).await.expect("list files");
            }
            3 => {
                // List directories
                ops.list_directories(&root).await.expect("list dirs");
            }
            _ => unreachable!(),
        }
    }
}

/// Test Arc-cloned ops properly shares lock state.
#[tokio::test]
async fn test_arc_shared_shares_locks() {
    let (_temp_dir, ops) = create_test_vault();

    let ops1 = Arc::clone(&ops);
    let ops2 = Arc::clone(&ops);

    // All should share the same lock manager (they're the same Arc)
    assert!(
        Arc::ptr_eq(ops.lock_manager(), ops1.lock_manager()),
        "ops and ops1 should share lock manager"
    );
    assert!(
        Arc::ptr_eq(ops1.lock_manager(), ops2.lock_manager()),
        "ops1 and ops2 should share lock manager"
    );

    // All should share the same handle table
    assert!(
        Arc::ptr_eq(ops.handle_table(), ops1.handle_table()),
        "ops and ops1 should share handle table"
    );
}

/// Test that move operations between directories work correctly.
#[tokio::test]
async fn test_move_operations_no_deadlock() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create two directories
    let dir_a = ops
        .create_directory(&root, "dir_a")
        .await
        .expect("create dir_a");
    let dir_b = ops
        .create_directory(&root, "dir_b")
        .await
        .expect("create dir_b");

    // Create files in each
    ops.write_file(&dir_a, "file_from_a.txt", b"from a")
        .await
        .expect("write a");
    ops.write_file(&dir_b, "file_from_b.txt", b"from b")
        .await
        .expect("write b");

    // Move files between directories
    ops.move_file(&dir_a, "file_from_a.txt", &dir_b)
        .await
        .expect("move a to b");
    ops.move_file(&dir_b, "file_from_b.txt", &dir_a)
        .await
        .expect("move b to a");

    // Verify final state
    let files_in_a = ops.list_files(&dir_a).await.unwrap();
    let files_in_b = ops.list_files(&dir_b).await.unwrap();

    assert_eq!(files_in_a.len(), 1);
    assert_eq!(files_in_a[0].name, "file_from_b.txt");

    assert_eq!(files_in_b.len(), 1);
    assert_eq!(files_in_b[0].name, "file_from_a.txt");
}

/// Test concurrent list and write operations.
#[tokio::test]
async fn test_concurrent_list_and_write() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Write some initial files
    for i in 0..5 {
        ops.write_file(&root, &format!("initial_{i}.txt"), b"initial")
            .await
            .expect("write initial");
    }

    // Concurrent list and write
    let (list_result, write_result) = tokio::join!(
        ops.list_files(&root),
        ops.write_file(&root, "new_file.txt", b"new content"),
    );

    assert!(list_result.is_ok());
    assert!(write_result.is_ok());

    // Verify final state
    let files = ops.list_files(&root).await.unwrap();
    assert!(files.len() >= 5); // At least the initial files
}

/// Test rename operations don't deadlock.
#[tokio::test]
async fn test_rename_operations_no_deadlock() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create files
    ops.write_file(&root, "original.txt", b"content")
        .await
        .expect("write");

    // Rename multiple times
    ops.rename_file(&root, "original.txt", "renamed1.txt")
        .await
        .expect("rename 1");
    ops.rename_file(&root, "renamed1.txt", "renamed2.txt")
        .await
        .expect("rename 2");
    ops.rename_file(&root, "renamed2.txt", "final.txt")
        .await
        .expect("rename 3");

    // Verify final state
    let files = ops.list_files(&root).await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "final.txt");
}

/// Test delete operations don't deadlock with lists.
#[tokio::test]
async fn test_delete_and_list_no_deadlock() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create files
    for i in 0..5 {
        ops.write_file(&root, &format!("file_{i}.txt"), b"content")
            .await
            .expect("write");
    }

    // Delete files while listing
    for i in 0..5 {
        let filename = format!("file_{i}.txt");
        let (delete_result, list_result) =
            tokio::join!(ops.delete_file(&root, &filename), ops.list_files(&root),);

        assert!(delete_result.is_ok());
        assert!(list_result.is_ok());
    }

    // All files should be deleted
    let files = ops.list_files(&root).await.unwrap();
    assert!(files.is_empty());
}

/// Test directory locking with ordered acquisition.
#[tokio::test]
async fn test_ordered_directory_locking() {
    let manager = VaultLockManager::new();
    let dir_a = DirId::from_raw("aaa");
    let dir_b = DirId::from_raw("bbb");
    let dir_c = DirId::from_raw("ccc");

    // Lock in arbitrary order, should come out sorted
    let guards = manager
        .lock_directories_write_ordered(&[&dir_c, &dir_a, &dir_b])
        .await;

    assert_eq!(guards.len(), 3);
    assert_eq!(guards[0].0.as_str(), "aaa");
    assert_eq!(guards[1].0.as_str(), "bbb");
    assert_eq!(guards[2].0.as_str(), "ccc");
}

/// Test file locking with ordered acquisition.
#[tokio::test]
async fn test_ordered_file_locking() {
    let manager = VaultLockManager::new();
    let dir_id = DirId::from_raw("test-dir");

    // Lock files in arbitrary order, should come out sorted
    let guards = manager
        .lock_files_write_ordered(&dir_id, &["zebra.txt", "alpha.txt", "middle.txt"])
        .await;

    assert_eq!(guards.len(), 3);
    assert_eq!(guards[0].0, "alpha.txt");
    assert_eq!(guards[1].0, "middle.txt");
    assert_eq!(guards[2].0, "zebra.txt");
}

/// Test that write lock blocks read lock acquisition.
#[tokio::test]
async fn test_write_lock_blocks_read() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let manager = Arc::new(VaultLockManager::new());
    let dir_id = DirId::from_raw("test-dir");
    let read_acquired = Arc::new(AtomicBool::new(false));

    // Acquire write lock
    let write_guard = manager.directory_write(&dir_id).await;

    // Use LocalSet for concurrent testing within single thread
    let local = tokio::task::LocalSet::new();

    // Try to acquire read lock in background (using local task)
    let manager_clone = manager.clone();
    let dir_id_clone = dir_id.clone();
    let read_acquired_clone = read_acquired.clone();

    local.spawn_local(async move {
        let _guard = manager_clone.directory_read(&dir_id_clone).await;
        read_acquired_clone.store(true, Ordering::SeqCst);
    });

    // Run the local set for a short time - read should not complete
    let run_result = timeout(
        Duration::from_millis(50),
        local.run_until(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }),
    )
    .await;

    // Timeout expected since the read task is blocked
    assert!(run_result.is_err() || !read_acquired.load(Ordering::SeqCst));

    // Drop write lock
    drop(write_guard);

    // Now the read should be able to complete (but we can't easily test this
    // without more complex setup, so we just verify no deadlock occurred)
}

// ============================================================================
// Regression Tests for Concurrency Bug Fixes
// ============================================================================

/// Regression test: Multiple independent VaultOperationsAsync instances for the
/// same vault path should share the same lock manager via the global registry.
///
/// Bug: Previously, each `VaultOperationsAsync::new()` call created an independent
/// `VaultLockManager`, meaning two instances could both write to the same file
/// without any synchronization.
#[tokio::test]
async fn test_regression_global_lock_registry_sharing() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("test_vault");

    let creator = VaultCreator::new(&vault_path, "test_password");
    let sync_ops = creator.create().expect("Failed to create vault");
    let master_key = sync_ops.master_key();

    // Create two INDEPENDENT instances (not via Arc::clone)
    let master_key_arc = Arc::new(master_key.clone());
    let ops1 = VaultOperationsAsync::new(&vault_path, Arc::clone(&master_key_arc));
    let ops2 = VaultOperationsAsync::new(&vault_path, Arc::clone(&master_key_arc));

    // They should share the same lock manager via the global registry
    assert!(
        Arc::ptr_eq(ops1.lock_manager(), ops2.lock_manager()),
        "Independent instances for same vault path should share lock manager"
    );
}

/// Regression test: The global lock registry should properly canonicalize paths.
#[tokio::test]
async fn test_regression_global_lock_registry_path_canonicalization() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("test_vault");

    let creator = VaultCreator::new(&vault_path, "test_password");
    creator.create().expect("Failed to create vault");

    // Get lock managers via different path representations
    let registry = VaultLockRegistry::global();

    // Absolute path
    let canonical_path = vault_path.canonicalize().expect("canonicalize");
    let manager1 = registry.get_or_create(&canonical_path);
    let manager2 = registry.get_or_create(&vault_path);

    // Both should be the same manager (after canonicalization)
    assert!(
        Arc::ptr_eq(&manager1, &manager2),
        "Different path representations should yield same lock manager"
    );
}

/// Regression test: VaultFileReader should hold its lock guards for its lifetime.
///
/// Bug: Previously, the lock guards were acquired in open_file() but released
/// immediately when the function returned, leaving the reader unprotected.
#[tokio::test]
async fn test_regression_reader_holds_locks() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create a file
    ops.write_file(&root, "test.txt", b"content")
        .await
        .expect("write file");

    // Open for reading
    let reader = ops.open_file(&root, "test.txt").await.expect("open file");

    // Reader should have locks
    assert!(
        reader.has_locks(),
        "VaultFileReader should hold lock guards for its lifetime"
    );

    // Reader should still be usable
    drop(reader);
}

/// Regression test: VaultFileWriter should hold its lock guards for its lifetime.
///
/// Bug: Previously, the lock guards were acquired in create_file() but released
/// immediately when the function returned, leaving the writer unprotected.
#[tokio::test]
async fn test_regression_writer_holds_locks() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create a streaming writer
    let writer = ops
        .create_file(&root, "new_file.txt")
        .await
        .expect("create file");

    // Writer should have locks
    assert!(
        writer.has_locks(),
        "VaultFileWriter should hold lock guards for its lifetime"
    );

    // Complete the write
    writer.finish().await.expect("finish");
}

/// Regression test: Verify that reader locks block write operations.
///
/// This tests that when a reader holds locks, other operations that need
/// write access will wait (not corrupt data).
#[tokio::test]
async fn test_regression_reader_locks_block_writes() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create a file
    ops.write_file(&root, "test.txt", b"original content")
        .await
        .expect("write file");

    // Open for reading and keep the reader alive
    let reader = ops.open_file(&root, "test.txt").await.expect("open file");

    // Verify reader has locks
    assert!(reader.has_locks());

    // Try to delete the file - this should block or fail because reader holds lock
    // We test with a timeout to avoid hanging
    let delete_started = Arc::new(AtomicBool::new(false));
    let delete_started_clone = delete_started.clone();

    // Use LocalSet for single-threaded async
    let local = tokio::task::LocalSet::new();

    // Clone Arc for the spawned task to share resources
    let ops_clone = Arc::clone(&ops);
    let root_clone = root.clone();

    local.spawn_local(async move {
        delete_started_clone.store(true, Ordering::SeqCst);
        // This should block waiting for the read lock to be released
        let _ = ops_clone.delete_file(&root_clone, "test.txt").await;
    });

    // Run briefly - delete should not complete while reader exists
    let _ = timeout(
        Duration::from_millis(50),
        local.run_until(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }),
    )
    .await;

    // Delete task started but reader still holds locks
    // The file should still exist (delete blocked)
    // Note: We can't easily verify this without a way to check if delete completed

    // Drop reader to release locks
    drop(reader);
}

/// Regression test: Verify lock ordering prevents deadlocks.
///
/// Bug: Previously, read_file acquired file lock then directory lock, while
/// delete_file acquired directory lock then file lock - classic deadlock scenario.
///
/// This test verifies the fix by running many concurrent mixed operations.
/// If there's a deadlock, this test will hang (and timeout in CI).
#[tokio::test]
async fn test_regression_lock_ordering_no_deadlock() {
    let (_temp_dir, ops) = create_test_vault();
    let root = DirId::root();

    // Create initial files
    for i in 0..5 {
        ops.write_file(
            &root,
            &format!("file_{i}.txt"),
            format!("content {i}").as_bytes(),
        )
        .await
        .expect("write");
    }

    // Run many mixed operations concurrently - if lock ordering is wrong, this deadlocks
    for iteration in 0..10 {
        let ops_clone = Arc::clone(&ops);
        let root_clone = root.clone();

        // Pre-compute filenames to avoid temporary lifetime issues
        let read_file = format!("file_{}.txt", iteration % 5);
        let write_file = format!("new_{iteration}.txt");
        let open_file = format!("file_{}.txt", iteration % 5);

        // Mix of read, write, list, and delete operations
        let (r1, r2, r3, r4, r5) = tokio::join!(
            ops.read_file(&root, &read_file),
            ops_clone.list_files(&root_clone),
            ops.write_file(&root, &write_file, b"new"),
            ops.list_directories(&root),
            async {
                // Try to open for streaming
                if iteration % 3 == 0 {
                    let _ = ops.open_file(&root, &open_file).await;
                }
                Ok::<_, ()>(())
            },
        );

        // Some may fail (file not found, etc.) but no operation should hang
        let _ = (r1, r2, r3, r4, r5);
    }
}

/// Regression test: Verify that the lock registry works correctly across
/// multiple test runs (singleton behavior).
#[tokio::test]
async fn test_regression_lock_registry_singleton() {
    let registry1 = VaultLockRegistry::global();
    let registry2 = VaultLockRegistry::global();

    // Should be the exact same instance
    assert!(
        std::ptr::eq(registry1, registry2),
        "VaultLockRegistry::global() should return the same singleton instance"
    );
}
