//! Test for directory deletion bug.
//!
//! This test reproduces the "Directory not empty (os error 66)" bug that occurs
//! when trying to recursively delete deeply nested directory structures.

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn mount_test_vault() -> (PathBuf, impl Drop) {
    use oxcrypt_fuse::FuseBackend;
    use oxcrypt_mount::MountBackend;

    let vault_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault");

    let mount_point = PathBuf::from("/tmp/fuse_deletion_test");
    fs::create_dir_all(&mount_point).unwrap();

    let backend = FuseBackend::new();
    let handle = backend
        .mount("deletion_test", &vault_path, "123456789", &mount_point)
        .expect("Failed to mount");

    // Brief delay to let mount settle
    thread::sleep(Duration::from_millis(100));

    (mount_point, handle)
}

#[test]
fn test_simple_directory_deletion() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let (mount_point, _handle) = mount_test_vault();

    // Create a simple nested directory structure
    let test_dir = mount_point.join("simple_nested");
    fs::create_dir_all(&test_dir.join("a/b/c")).expect("Failed to create directories");

    // Create a file at the deepest level
    fs::write(test_dir.join("a/b/c/file.txt"), b"test content").expect("Failed to write file");

    // Verify structure exists
    assert!(test_dir.join("a/b/c/file.txt").exists());

    // Try to delete it
    eprintln!("Attempting to delete {:?}", test_dir);
    match fs::remove_dir_all(&test_dir) {
        Ok(()) => {
            eprintln!("✓ Deletion succeeded");
            assert!(!test_dir.exists(), "Directory should be deleted");
        }
        Err(e) => {
            eprintln!("✗ Deletion failed: {}", e);
            panic!("remove_dir_all failed: {}", e);
        }
    }
}

#[test]
fn test_git_like_directory_deletion() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let (mount_point, _handle) = mount_test_vault();

    // Create a git-like .git/objects structure
    let git_dir = mount_point.join("git_test");
    fs::create_dir_all(&git_dir).expect("Failed to create git_test directory");

    // Create multiple object subdirectories (like git does)
    for prefix in ["00", "01", "ab", "cd", "ef"] {
        let objects_dir = git_dir.join(".git/objects").join(prefix);
        fs::create_dir_all(&objects_dir).expect("Failed to create objects directory");

        // Create a few "object" files in each subdirectory
        for i in 0..3 {
            let object_file = objects_dir.join(format!("object{}.txt", i));
            fs::write(&object_file, format!("object data {}", i))
                .expect("Failed to write object file");
        }
    }

    // Also create some other git-like files
    fs::create_dir_all(git_dir.join(".git/refs/heads")).unwrap();
    fs::write(git_dir.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();
    fs::write(git_dir.join(".git/config"), b"[core]\n\tbare = false\n").unwrap();

    // Verify structure exists
    assert!(git_dir.join(".git/objects/ab").exists());

    // Try to delete the entire git directory
    eprintln!("Attempting to delete {:?}", git_dir);
    match fs::remove_dir_all(&git_dir) {
        Ok(()) => {
            eprintln!("✓ Deletion succeeded");
            assert!(!git_dir.exists(), "Git directory should be deleted");
        }
        Err(e) => {
            eprintln!("✗ Deletion failed: {}", e);
            eprintln!("Error kind: {:?}", e.kind());

            // List what's still there
            if git_dir.exists() {
                eprintln!("Contents after failed deletion:");
                if let Ok(entries) = fs::read_dir(&git_dir) {
                    for entry in entries.flatten() {
                        eprintln!("  - {:?}", entry.path());
                    }
                }
            }

            panic!("remove_dir_all failed: {}", e);
        }
    }
}

#[test]
fn test_delete_and_recreate() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let (mount_point, _handle) = mount_test_vault();

    let test_dir = mount_point.join("recreate_test");

    // Create, delete, and recreate multiple times
    for iteration in 0..3 {
        eprintln!("\n=== Iteration {} ===", iteration);

        // Create nested structure
        fs::create_dir_all(&test_dir.join("nested/path")).unwrap();
        fs::write(test_dir.join("nested/path/file.txt"), b"data").unwrap();

        assert!(test_dir.exists());

        // Try to delete
        eprintln!("Deleting {:?}", test_dir);
        match fs::remove_dir_all(&test_dir) {
            Ok(()) => {
                eprintln!("✓ Iteration {} deletion succeeded", iteration);
                assert!(!test_dir.exists(), "Directory should be deleted");
            }
            Err(e) => {
                eprintln!("✗ Iteration {} deletion failed: {}", iteration, e);
                panic!("remove_dir_all failed on iteration {}: {}", iteration, e);
            }
        }

        // Brief pause between iterations
        thread::sleep(Duration::from_millis(100));
    }
}
