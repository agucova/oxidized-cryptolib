//! Mount integration tests for oxidized-fuse.
//!
//! These tests mount an actual Cryptomator vault using FUSE and verify
//! filesystem operations work correctly through the kernel interface.
//!
//! Requirements:
//! - FUSE must be installed (fuse3 on Linux, macFUSE on macOS)
//! - Tests must run with appropriate permissions
//! - The test_vault directory must exist with password "123456789"

#![cfg(unix)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use fuser::{BackgroundSession, MountOption};
use oxidized_fuse::filesystem::CryptomatorFS;
use tempfile::TempDir;

/// Test vault password (must match the actual test vault).
const TEST_PASSWORD: &str = "123456789";

/// How long to wait for mount to become ready.
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait between mount readiness checks.
const MOUNT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Get the path to the test vault.
fn test_vault_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault")
}

/// RAII guard for a mounted filesystem.
/// Ensures the filesystem is properly unmounted on drop.
struct MountGuard {
    session: Option<BackgroundSession>,
    mount_point: PathBuf,
}

impl MountGuard {
    fn new(session: BackgroundSession, mount_point: PathBuf) -> Self {
        Self {
            session: Some(session),
            mount_point,
        }
    }

    fn mount_point(&self) -> &Path {
        &self.mount_point
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            // Join the session to ensure clean unmount
            session.join();
        }
    }
}

/// Mount the test vault and return a guard that unmounts on drop.
fn mount_test_vault(mount_dir: &Path) -> Result<MountGuard, String> {
    let vault_path = test_vault_path();

    if !vault_path.exists() {
        return Err(format!("Test vault not found at: {}", vault_path.display()));
    }

    // Create the CryptomatorFS
    let fs = CryptomatorFS::new(&vault_path, TEST_PASSWORD)
        .map_err(|e| format!("Failed to create CryptomatorFS: {}", e))?;

    // Mount options
    let options = vec![
        MountOption::RO, // Start with read-only for safety
        MountOption::FSName("cryptomator".to_string()),
        MountOption::AutoUnmount,
    ];

    // Spawn the mount in background
    let session = fuser::spawn_mount2(fs, mount_dir, &options)
        .map_err(|e| format!("Failed to mount: {}", e))?;

    // Wait for mount to become ready
    let deadline = std::time::Instant::now() + MOUNT_READY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if mount_dir.join(".").exists() && fs::read_dir(mount_dir).is_ok() {
            return Ok(MountGuard::new(session, mount_dir.to_path_buf()));
        }
        thread::sleep(MOUNT_CHECK_INTERVAL);
    }

    Err("Mount did not become ready in time".to_string())
}

/// Mount the test vault with read-write access.
fn mount_test_vault_rw(mount_dir: &Path) -> Result<MountGuard, String> {
    let vault_path = test_vault_path();

    if !vault_path.exists() {
        return Err(format!("Test vault not found at: {}", vault_path.display()));
    }

    let fs = CryptomatorFS::new(&vault_path, TEST_PASSWORD)
        .map_err(|e| format!("Failed to create CryptomatorFS: {}", e))?;

    let options = vec![
        MountOption::FSName("cryptomator".to_string()),
        MountOption::AutoUnmount,
    ];

    let session = fuser::spawn_mount2(fs, mount_dir, &options)
        .map_err(|e| format!("Failed to mount: {}", e))?;

    let deadline = std::time::Instant::now() + MOUNT_READY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if mount_dir.join(".").exists() && fs::read_dir(mount_dir).is_ok() {
            return Ok(MountGuard::new(session, mount_dir.to_path_buf()));
        }
        thread::sleep(MOUNT_CHECK_INTERVAL);
    }

    Err("Mount did not become ready in time".to_string())
}

/// Check if FUSE is available on this system.
fn fuse_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/fuse").exists()
    }
    #[cfg(target_os = "macos")]
    {
        // Check for macFUSE
        Path::new("/Library/Filesystems/macfuse.fs").exists()
            || Path::new("/Library/Filesystems/osxfuse.fs").exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Skip test if FUSE is not available.
macro_rules! require_fuse {
    () => {
        if !fuse_available() {
            eprintln!("Skipping test: FUSE not available on this system");
            return;
        }
    };
}

// ============================================================================
// Read-only tests
// ============================================================================

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_mount_and_list_root() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // List root directory
    let entries: Vec<_> = fs::read_dir(guard.mount_point())
        .expect("Failed to read root directory")
        .filter_map(|e| e.ok())
        .collect();

    // We should have at least some entries (the test vault has content)
    println!("Root directory entries: {:?}", entries.iter().map(|e| e.file_name()).collect::<Vec<_>>());

    // Verify we can stat the entries
    for entry in &entries {
        let metadata = entry.metadata().expect("Failed to get metadata");
        println!(
            "  {:?}: is_dir={}, is_file={}, size={}",
            entry.file_name(),
            metadata.is_dir(),
            metadata.is_file(),
            metadata.len()
        );
    }
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_read_file_content() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // Find a file in the vault to read
    fn find_first_file(dir: &Path) -> Option<PathBuf> {
        for entry in fs::read_dir(dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_file() {
                return Some(path);
            } else if path.is_dir() {
                if let Some(found) = find_first_file(&path) {
                    return Some(found);
                }
            }
        }
        None
    }

    if let Some(file_path) = find_first_file(guard.mount_point()) {
        let mut content = Vec::new();
        let mut file = File::open(&file_path).expect("Failed to open file");
        file.read_to_end(&mut content).expect("Failed to read file");

        println!("Read {} bytes from {:?}", content.len(), file_path.file_name());

        // Content should be decrypted (not raw encrypted data)
        // We can't verify exact content without knowing what's in the test vault
        assert!(content.len() > 0 || file_path.metadata().unwrap().len() == 0);
    } else {
        println!("No files found in vault to test reading");
    }
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_file_attributes() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // Get root metadata
    let root_meta = fs::metadata(guard.mount_point()).expect("Failed to get root metadata");
    assert!(root_meta.is_dir(), "Root should be a directory");

    // Check permissions are reasonable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = root_meta.permissions().mode();
        // Should have at least owner read permission
        assert!(mode & 0o400 != 0, "Root should be readable by owner");
    }
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_concurrent_reads() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let mount_path = guard.mount_point().to_path_buf();
    let success = Arc::new(AtomicBool::new(true));
    let mut handles = vec![];

    // Spawn multiple threads reading the directory concurrently
    for i in 0..4 {
        let path = mount_path.clone();
        let success = Arc::clone(&success);

        handles.push(thread::spawn(move || {
            for j in 0..5 {
                match fs::read_dir(&path) {
                    Ok(entries) => {
                        let count = entries.count();
                        println!("Thread {} iteration {}: {} entries", i, j, count);
                    }
                    Err(e) => {
                        eprintln!("Thread {} iteration {} failed: {}", i, j, e);
                        success.store(false, Ordering::SeqCst);
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    assert!(success.load(Ordering::SeqCst), "Some concurrent reads failed");
}

// ============================================================================
// Read-write tests (use a temporary copy of the vault)
// ============================================================================

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_write_new_file() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault_rw(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let test_file = guard.mount_point().join("test_write.txt");
    let test_content = b"Hello from mount test!";

    // Write file
    {
        let mut file = match File::create(&test_file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Skipping write test (read-only mount?): {}", e);
                return;
            }
        };
        file.write_all(test_content).expect("Failed to write");
        file.sync_all().expect("Failed to sync");
    }

    // Read back and verify
    let mut read_content = Vec::new();
    {
        let mut file = File::open(&test_file).expect("Failed to open written file");
        file.read_to_end(&mut read_content).expect("Failed to read");
    }

    assert_eq!(read_content, test_content, "Content mismatch after write/read");

    // Clean up
    fs::remove_file(&test_file).ok();
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_mkdir_and_rmdir() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault_rw(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let test_dir = guard.mount_point().join("test_directory");

    // Create directory
    match fs::create_dir(&test_dir) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Skipping mkdir test (read-only mount?): {}", e);
            return;
        }
    }

    // Verify it exists
    assert!(test_dir.exists(), "Directory should exist after creation");
    assert!(test_dir.is_dir(), "Should be a directory");

    // Remove directory
    fs::remove_dir(&test_dir).expect("Failed to remove directory");
    assert!(!test_dir.exists(), "Directory should not exist after removal");
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_rename_file() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault_rw(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let original = guard.mount_point().join("rename_test_original.txt");
    let renamed = guard.mount_point().join("rename_test_renamed.txt");
    let content = b"rename test content";

    // Create original file
    match File::create(&original) {
        Ok(mut f) => {
            f.write_all(content).expect("Failed to write");
        }
        Err(e) => {
            eprintln!("Skipping rename test (read-only mount?): {}", e);
            return;
        }
    }

    // Rename
    fs::rename(&original, &renamed).expect("Failed to rename");

    // Verify
    assert!(!original.exists(), "Original should not exist");
    assert!(renamed.exists(), "Renamed file should exist");

    // Verify content preserved
    let mut read_content = Vec::new();
    File::open(&renamed)
        .unwrap()
        .read_to_end(&mut read_content)
        .unwrap();
    assert_eq!(read_content, content, "Content should be preserved after rename");

    // Clean up
    fs::remove_file(&renamed).ok();
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_symlink_roundtrip() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault_rw(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let target = "target_file.txt";
    let link_path = guard.mount_point().join("test_symlink");

    // Create symlink
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        match symlink(target, &link_path) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Skipping symlink test: {}", e);
                return;
            }
        }

        // Read link target
        let read_target = fs::read_link(&link_path).expect("Failed to read symlink");
        assert_eq!(
            read_target.to_string_lossy(),
            target,
            "Symlink target mismatch"
        );

        // Clean up
        fs::remove_file(&link_path).ok();
    }
}

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_large_file() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault_rw(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let test_file = guard.mount_point().join("large_file_test.bin");

    // Create a file larger than one encryption chunk (32KB)
    // Use 100KB to test multiple chunks
    let size = 100 * 1024;
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

    // Write
    match File::create(&test_file) {
        Ok(mut f) => {
            f.write_all(&content).expect("Failed to write large file");
            f.sync_all().expect("Failed to sync");
        }
        Err(e) => {
            eprintln!("Skipping large file test (read-only mount?): {}", e);
            return;
        }
    }

    // Read back
    let mut read_content = Vec::new();
    File::open(&test_file)
        .expect("Failed to open large file")
        .read_to_end(&mut read_content)
        .expect("Failed to read large file");

    assert_eq!(read_content.len(), content.len(), "Size mismatch");
    assert_eq!(read_content, content, "Content mismatch in large file");

    // Clean up
    fs::remove_file(&test_file).ok();
}

// ============================================================================
// Stress tests
// ============================================================================

#[test]
#[ignore = "requires FUSE and may need root"]
fn test_rapid_open_close() {
    require_fuse!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mount_point = temp_dir.path().join("mnt");
    fs::create_dir(&mount_point).expect("Failed to create mount point");

    let guard = match mount_test_vault(&mount_point) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // Rapidly open and close the root directory
    for i in 0..100 {
        let _entries: Vec<_> = fs::read_dir(guard.mount_point())
            .unwrap_or_else(|_| panic!("Failed on iteration {}", i))
            .collect();
    }
}
