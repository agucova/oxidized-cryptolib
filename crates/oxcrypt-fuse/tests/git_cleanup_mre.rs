//! MRE for git repository cleanup bug.
//!
//! This test reproduces the exact sequence from the benchmark:
//! 1. Extract ripgrep source
//! 2. Initialize git repository
//! 3. Run git add/commit
//! 4. Immediately try to delete the directory
//!
//! Expected: Should succeed (like other tests)
//! Actual: May fail with "Directory not empty" (like benchmark)

use git2::{IndexAddOption, Repository, Signature};
use std::fs::{self, File};
use std::io::Cursor;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use zip::ZipArchive;

fn mount_test_vault() -> (PathBuf, impl Drop) {
    use oxcrypt_fuse::FuseBackend;
    use oxcrypt_mount::MountBackend;

    let vault_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault");

    let mount_point = PathBuf::from("/tmp/fuse_git_cleanup_mre");
    fs::create_dir_all(&mount_point).unwrap();

    let backend = FuseBackend::new();
    let handle = backend
        .mount("git_cleanup_mre", &vault_path, "123456789", &mount_point)
        .expect("Failed to mount");

    thread::sleep(Duration::from_millis(100));

    // Return the ACTUAL mount point from the handle, not the requested one
    let actual_mount_point = handle.mountpoint().to_path_buf();
    (actual_mount_point, handle)
}

#[test]
fn test_git_cleanup_like_benchmark() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    eprintln!("\n=== Reproducing benchmark git workflow cleanup ===");

    let (mount_point, handle) = mount_test_vault();

    // Use unique directory name to avoid conflicts with previous test runs
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let workload_dir = mount_point.join(format!("git_workload_{}", timestamp));
    let repo_path = workload_dir.join("repo");

    // Step 1: Extract ripgrep (exactly like benchmark)
    eprintln!("Step 1: Extracting ripgrep source...");
    fs::create_dir_all(&repo_path).expect("Failed to create repo directory");

    let zip_url = "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.1.0.zip";
    let cache_path = PathBuf::from("/tmp/ripgrep-14.1.0.zip");

    if !cache_path.exists() {
        eprintln!("  Downloading ripgrep...");
        let response = reqwest::blocking::get(zip_url).expect("Failed to download");
        fs::write(&cache_path, response.bytes().unwrap()).unwrap();
    }

    let zip_bytes = fs::read(&cache_path).unwrap();
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor).unwrap();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let file_path = file.enclosed_name().unwrap();

        let relative_path: PathBuf = file_path.components().skip(1).collect();
        if relative_path.as_os_str().is_empty() {
            continue;
        }

        let dest_path = repo_path.join(&relative_path);

        if file.is_dir() {
            fs::create_dir_all(&dest_path).unwrap();
        } else {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let mut outfile = File::create(&dest_path).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }
    eprintln!("  ✓ Extracted ripgrep");

    // Step 2: Initialize git repository (exactly like benchmark)
    eprintln!("Step 2: Initializing git repository...");
    let repo = Repository::init(&repo_path).expect("Failed to init git");

    {
        let mut config = repo.config().unwrap();
        config.set_bool("gc.auto", false).unwrap();
        config.set_i32("gc.autopacklimit", 0).unwrap();
    }
    eprintln!("  ✓ Git initialized");

    // Step 3: Stage all files (exactly like benchmark)
    eprintln!("Step 3: Running git add...");
    let mut index = repo.index().expect("Failed to get index");
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("Failed to add files");
    index.write().expect("Failed to write index");
    eprintln!("  ✓ Staged {} files", index.len());

    // Step 4: Create commit (exactly like benchmark)
    eprintln!("Step 4: Creating commit...");
    let tree_id = index.write_tree().expect("Failed to write tree");
    let tree = repo.find_tree(tree_id).expect("Failed to find tree");
    let sig = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
        .expect("Failed to commit");
    eprintln!("  ✓ Commit created");

    // Step 5: Immediately try to delete (exactly like benchmark cleanup)
    eprintln!("Step 5: Attempting cleanup (fs::remove_dir_all)...");
    eprintln!("  Target: {:?}", workload_dir);

    // Check what's in the directory before deletion
    eprintln!("  Checking directory contents before deletion:");
    if let Ok(entries) = fs::read_dir(&workload_dir) {
        for entry in entries.flatten() {
            eprintln!("    - {:?}", entry.file_name());
        }
    }

    // Try to delete
    match fs::remove_dir_all(&workload_dir) {
        Ok(()) => {
            eprintln!("  ✓ Cleanup succeeded!");
            assert!(!workload_dir.exists(), "Directory should be deleted");
        }
        Err(e) => {
            eprintln!("  ✗ Cleanup FAILED: {}", e);
            eprintln!("  Error kind: {:?}", e.kind());
            eprintln!("  Raw OS error: {:?}", e.raw_os_error());

            // List what's still there
            eprintln!("  Contents after failed deletion:");
            if let Ok(entries) = fs::read_dir(&workload_dir) {
                for entry in entries.flatten() {
                    eprintln!("    - {:?} (type: {:?})", entry.path(), entry.file_type());
                }
            }

            // Check if it's the git directory
            let git_dir = repo_path.join(".git");
            if git_dir.exists() {
                eprintln!("  .git directory still exists, checking objects:");
                let objects_dir = git_dir.join("objects");
                if let Ok(entries) = fs::read_dir(&objects_dir) {
                    let count = entries.count();
                    eprintln!("    - {} subdirectories in .git/objects/", count);
                }
            }

            panic!("Cleanup failed: {}", e);
        }
    }

    // Keep mount alive until test completes
    drop(handle);
}

#[test]
fn test_git_cleanup_with_explicit_close() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    eprintln!("\n=== Testing cleanup with explicit Repository drop ===");

    let (mount_point, handle) = mount_test_vault();

    // Use unique directory name
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let workload_dir = mount_point.join(format!("git_explicit_{}", timestamp));
    let repo_path = workload_dir.join("repo");

    fs::create_dir_all(&repo_path).unwrap();

    // Create a simple git repo
    {
        let repo = Repository::init(&repo_path).unwrap();

        // Create a test file
        fs::write(repo_path.join("test.txt"), b"test content").unwrap();

        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("Test", "test@example.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "Test", &tree, &[])
            .unwrap();

        // Explicitly drop in correct order (borrowed objects first)
        drop(tree);
        drop(index);
        drop(repo);
    }

    eprintln!("Repository closed explicitly");

    // Brief delay to let any async operations complete
    thread::sleep(Duration::from_millis(200));

    eprintln!("Attempting cleanup...");
    match fs::remove_dir_all(&workload_dir) {
        Ok(()) => {
            eprintln!("  ✓ Cleanup succeeded with explicit close");
        }
        Err(e) => {
            eprintln!("  ✗ Cleanup FAILED even with explicit close: {}", e);
            panic!("Cleanup failed: {}", e);
        }
    }

    // Keep mount alive until test completes
    drop(handle);
}

#[test]
fn test_git_cleanup_multiple_iterations() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    eprintln!("\n=== Testing cleanup across multiple iterations (like benchmark) ===");

    let (mount_point, handle) = mount_test_vault();

    // Run multiple iterations like the benchmark
    let base_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for iteration in 0..3 {
        eprintln!("\n--- Iteration {} ---", iteration);

        let workload_dir = mount_point.join(format!("git_multi_{}_{}", base_timestamp, iteration));
        let repo_path = workload_dir.join("repo");

        fs::create_dir_all(&repo_path).unwrap();

        // Create git repo with a few files
        {
            let repo = Repository::init(&repo_path).unwrap();

            for i in 0..5 {
                fs::write(
                    repo_path.join(format!("file{}.txt", i)),
                    format!("content {}", i),
                )
                .unwrap();
            }

            let mut index = repo.index().unwrap();
            index
                .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
                .unwrap();
            index.write().unwrap();

            let tree_id = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            let sig = Signature::now("Test", "test@example.com").unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "Test", &tree, &[])
                .unwrap();
        }

        eprintln!("  Git operations complete");

        // Immediate cleanup
        eprintln!("  Attempting cleanup...");
        match fs::remove_dir_all(&workload_dir) {
            Ok(()) => {
                eprintln!("  ✓ Iteration {} cleanup succeeded", iteration);
            }
            Err(e) => {
                eprintln!("  ✗ Iteration {} cleanup FAILED: {}", iteration, e);
                panic!("Cleanup failed on iteration {}: {}", iteration, e);
            }
        }

        // Brief delay between iterations
        thread::sleep(Duration::from_millis(100));
    }

    eprintln!("\n✓ All iterations completed successfully");

    // Keep mount alive until test completes
    drop(handle);
}
