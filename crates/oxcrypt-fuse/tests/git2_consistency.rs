//! Test git2 operations immediately after mount to reproduce the iteration 0 bug.

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

    let mount_point = PathBuf::from("/tmp/fuse_git2_test");
    fs::create_dir_all(&mount_point).unwrap();

    let backend = FuseBackend::new();
    let handle = backend
        .mount("git2_test", &vault_path, "123456789", &mount_point)
        .expect("Failed to mount");

    // Brief delay to let mount settle
    thread::sleep(Duration::from_millis(100));

    (mount_point, handle)
}

#[test]
fn test_git2_init_and_commit() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let (mount_point, _handle) = mount_test_vault();

    // Create a test repository directory
    let repo_path = mount_point.join("test_repo");
    // Clean up any leftover test data from previous runs
    let _ = fs::remove_dir_all(&repo_path);
    fs::create_dir_all(&repo_path).expect("Failed to create repo directory");

    // Create some test files
    fs::write(repo_path.join("file1.txt"), b"Hello, World!").unwrap();
    fs::write(repo_path.join("file2.txt"), b"Test content").unwrap();
    fs::write(repo_path.join("file3.txt"), b"More data").unwrap();

    eprintln!("Initializing git repository...");
    let repo = Repository::init(&repo_path).expect("Failed to initialize repository");

    eprintln!("Configuring git...");
    {
        let mut config = repo.config().unwrap();
        config.set_bool("gc.auto", false).unwrap();
        config.set_i32("gc.autopacklimit", 0).unwrap();
    }

    eprintln!("Adding files to index...");
    let mut index = repo.index().expect("Failed to get index");

    // This is where the benchmark fails - index.add_all() creates ODB objects
    // that can't be found immediately after
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("Failed to add files to index");

    index.write().expect("Failed to write index");

    eprintln!("Writing tree...");
    let tree_id = index.write_tree().expect("Failed to write tree");
    eprintln!("Tree ID: {}", tree_id);

    eprintln!("Finding tree object...");
    let tree = repo
        .find_tree(tree_id)
        .expect("Failed to find tree");

    eprintln!("Creating signature...");
    let sig = Signature::now("Test User", "test@example.com").unwrap();

    eprintln!("Creating commit...");
    repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
        .expect("Failed to create commit");

    eprintln!("Git operations completed successfully!");
}

#[test]
fn test_git2_multiple_iterations() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    // Test 3 iterations to see if the first one behaves differently
    for iteration in 0..3 {
        eprintln!("\n=== ITERATION {} ===", iteration);

        let (mount_point, handle) = mount_test_vault();

        let repo_path = mount_point.join(format!("iter{}_repo", iteration));
        // Clean up any leftover test data from previous runs
        let _ = fs::remove_dir_all(&repo_path);
        fs::create_dir_all(&repo_path).unwrap();

        // Create test files
        for i in 0..5 {
            fs::write(repo_path.join(format!("file{}.txt", i)), format!("Content {}", i))
                .unwrap();
        }

        let repo = Repository::init(&repo_path)
            .unwrap_or_else(|e| panic!("Iteration {}: Failed to init repo: {}", iteration, e));

        {
            let mut config = repo.config().unwrap();
            config.set_bool("gc.auto", false).unwrap();
            config.set_i32("gc.autopacklimit", 0).unwrap();
        }

        let mut index = repo.index().unwrap();

        // This is the critical operation that fails on iteration 0 in the benchmark
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap_or_else(|e| {
                panic!("Iteration {}: Failed to add files to index: {}", iteration, e)
            });

        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap_or_else(|e| {
            panic!("Iteration {}: Failed to find tree {}: {}", iteration, tree_id, e)
        });

        let sig = Signature::now("Test User", "test@example.com").unwrap();

        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        eprintln!("Iteration {} completed successfully", iteration);

        drop(handle);
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn test_ripgrep_extraction_then_git() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    eprintln!("\n=== Testing ripgrep extraction + git (like the benchmark) ===");

    let (mount_point, _handle) = mount_test_vault();

    let repo_path = mount_point.join("ripgrep_test");
    // Clean up any leftover test data from previous runs
    let _ = fs::remove_dir_all(&repo_path);
    fs::create_dir_all(&repo_path).expect("Failed to create repo directory");

    // Download or use cached ripgrep zip
    let zip_url = "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.1.0.zip";
    let cache_path = PathBuf::from("/tmp/ripgrep-14.1.0.zip");

    if !cache_path.exists() {
        eprintln!("Downloading ripgrep zip to cache...");
        let response = reqwest::blocking::get(zip_url).expect("Failed to download");
        fs::write(&cache_path, response.bytes().unwrap()).unwrap();
    }

    eprintln!("Reading ripgrep zip from cache...");
    let zip_bytes = fs::read(&cache_path).unwrap();

    eprintln!("Extracting ripgrep source to FUSE mount...");
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor).unwrap();

    // Extract all files
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let file_path = file.enclosed_name().unwrap();

        // Strip top-level directory
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

    eprintln!("Extraction complete. Initializing git...");

    let repo = Repository::init(&repo_path).expect("Failed to initialize repository");

    {
        let mut config = repo.config().unwrap();
        config.set_bool("gc.auto", false).unwrap();
        config.set_i32("gc.autopacklimit", 0).unwrap();
    }

    eprintln!("Adding files to index...");
    let mut index = repo.index().expect("Failed to get index");

    // This is where the benchmark fails on iteration 0
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("Failed to add files to index");

    index.write().expect("Failed to write index");

    eprintln!("Writing tree...");
    let tree_id = index.write_tree().expect("Failed to write tree");

    eprintln!("Finding tree object...");
    let tree = repo.find_tree(tree_id).expect("Failed to find tree");

    let sig = Signature::now("Test User", "test@example.com").unwrap();

    eprintln!("Creating commit...");
    repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
        .expect("Failed to create commit");

    eprintln!("Ripgrep extraction + git test PASSED!");
}
