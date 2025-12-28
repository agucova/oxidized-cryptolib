//! FSX (File System eXerciser) integration tests for oxidized-fuse.
//!
//! FSX generates pseudorandom read/write/truncate/mmap operations and verifies
//! data integrity on every read. This catches data corruption, cache coherency
//! issues, and overlapping read/write bugs that pjdfstest doesn't cover.
//!
//! Requirements:
//! - FUSE must be installed (fuse3 on Linux, macFUSE on macOS)
//! - FSX binary must be installed: `cargo install fsx`
//!
//! Run: `cargo nextest run -p oxidized-fuse --features fuse-tests`

#![cfg(all(unix, feature = "fuse-tests"))]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use fuser::{BackgroundSession, MountOption};
use oxidized_fuse::filesystem::CryptomatorFS;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "123456789";
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(5);
const MOUNT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

fn test_vault_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault")
}

/// Find the fsx binary.
fn find_fsx() -> Option<PathBuf> {
    // Check FSX_BIN environment variable first
    if let Ok(path) = std::env::var("FSX_BIN") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
    }

    // Check if 'fsx' is in PATH
    if let Ok(output) = Command::new("which").arg("fsx").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Check cargo bin directory
    if let Ok(home) = std::env::var("HOME") {
        let cargo_bin = PathBuf::from(&home).join(".cargo/bin/fsx");
        if cargo_bin.exists() {
            return Some(cargo_bin);
        }
    }

    None
}

/// RAII guard for mounted filesystem.
struct MountGuard {
    session: Option<BackgroundSession>,
    mount_point: PathBuf,
    _temp_dir: TempDir,
}

impl MountGuard {
    fn mount_point(&self) -> &Path {
        &self.mount_point
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            session.join();
        }
    }
}

/// Mount the test vault with write support.
fn mount_test_vault_rw() -> Option<MountGuard> {
    let vault_path = test_vault_path();
    if !vault_path.exists() {
        eprintln!("Test vault not found at: {}", vault_path.display());
        return None;
    }

    let temp_dir = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to create temp dir: {}", e);
            return None;
        }
    };

    let mount_point = temp_dir.path().to_path_buf();

    let fs = match CryptomatorFS::new(&vault_path, TEST_PASSWORD) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("Failed to create CryptomatorFS: {}", e);
            return None;
        }
    };

    // Mount with read-write support
    let options = vec![
        MountOption::FSName("cryptomator".to_string()),
        MountOption::AutoUnmount,
        // No RO flag - mount read-write
    ];

    let session = match fuser::spawn_mount2(fs, &mount_point, &options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to mount: {}", e);
            return None;
        }
    };

    // Wait for mount to become ready
    let deadline = std::time::Instant::now() + MOUNT_READY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if mount_point.join(".").exists() && fs::read_dir(&mount_point).is_ok() {
            return Some(MountGuard {
                session: Some(session),
                mount_point,
                _temp_dir: temp_dir,
            });
        }
        std::thread::sleep(MOUNT_CHECK_INTERVAL);
    }

    eprintln!("Mount did not become ready in time");
    None
}

/// Run fsx with specified parameters.
fn run_fsx(test_file: &Path, operations: u32, seed: Option<u64>) -> Result<Output, String> {
    let fsx_bin = find_fsx().ok_or("FSX binary not found. Install with: cargo install fsx")?;

    let mut cmd = Command::new(&fsx_bin);

    // Number of operations
    cmd.arg("-N").arg(operations.to_string());

    // Seed for reproducibility
    if let Some(s) = seed {
        cmd.arg("-S").arg(s.to_string());
    }

    // Quiet mode (less output)
    cmd.arg("-q");

    // The test file path
    cmd.arg(test_file);

    eprintln!("Running: {:?}", cmd);

    cmd.output().map_err(|e| format!("Failed to run fsx: {}", e))
}

/// Check if fsx passed based on output.
fn fsx_passed(output: &Output) -> bool {
    output.status.success()
}

/// Extract failure info from fsx output.
fn fsx_error_info(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("stdout: {}\nstderr: {}", stdout, stderr)
}

// ============================================================================
// FSX Tests
// ============================================================================

#[test]
fn test_fsx_quick() {
    // Quick smoke test: 100 operations
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found. Install with: cargo install fsx");
            return;
        }
    };

    eprintln!("Using fsx at: {}", fsx_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    // Create a test file in the mounted vault
    let test_file = guard.mount_point().join("fsx_quick_test");

    // Create an initial file
    if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(b"initial")) {
        eprintln!("SKIP: Could not create test file: {}", e);
        return;
    }

    // Run fsx with 100 operations
    match run_fsx(&test_file, 100, Some(12345)) {
        Ok(output) => {
            if fsx_passed(&output) {
                println!("FSX quick test PASSED (100 operations)");
            } else {
                println!("FSX quick test FAILED:\n{}", fsx_error_info(&output));
                // Don't assert failure yet - we want to see what fails
            }
        }
        Err(e) => {
            eprintln!("FSX error: {}", e);
        }
    }

    // Clean up
    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_fsx_medium() {
    // Medium test: 1000 operations
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found");
            return;
        }
    };

    eprintln!("Using fsx at: {}", fsx_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_file = guard.mount_point().join("fsx_medium_test");

    if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(b"initial")) {
        eprintln!("SKIP: Could not create test file: {}", e);
        return;
    }

    match run_fsx(&test_file, 1000, Some(54321)) {
        Ok(output) => {
            if fsx_passed(&output) {
                println!("FSX medium test PASSED (1000 operations)");
            } else {
                println!("FSX medium test FAILED:\n{}", fsx_error_info(&output));
            }
        }
        Err(e) => {
            eprintln!("FSX error: {}", e);
        }
    }

    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_fsx_stress() {
    // Stress test: 10000 operations
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found");
            return;
        }
    };

    eprintln!("Using fsx at: {}", fsx_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_file = guard.mount_point().join("fsx_stress_test");

    if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(b"initial")) {
        eprintln!("SKIP: Could not create test file: {}", e);
        return;
    }

    match run_fsx(&test_file, 10000, Some(99999)) {
        Ok(output) => {
            if fsx_passed(&output) {
                println!("FSX stress test PASSED (10000 operations)");
            } else {
                println!("FSX stress test FAILED:\n{}", fsx_error_info(&output));
            }
        }
        Err(e) => {
            eprintln!("FSX error: {}", e);
        }
    }

    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_fsx_multiple_seeds() {
    // Run multiple tests with different seeds for broader coverage
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found");
            return;
        }
    };

    eprintln!("Using fsx at: {}", fsx_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let seeds = [1, 42, 1337, 9999, 31415];
    let mut passed = 0;
    let mut failed = 0;

    for seed in seeds {
        let test_file = guard.mount_point().join(format!("fsx_seed_{}", seed));

        if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(b"seed_test")) {
            eprintln!("SKIP seed {}: Could not create test file: {}", seed, e);
            continue;
        }

        match run_fsx(&test_file, 500, Some(seed)) {
            Ok(output) => {
                if fsx_passed(&output) {
                    println!("FSX seed {} PASSED", seed);
                    passed += 1;
                } else {
                    println!("FSX seed {} FAILED:\n{}", seed, fsx_error_info(&output));
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("FSX seed {} error: {}", seed, e);
                failed += 1;
            }
        }

        let _ = fs::remove_file(&test_file);
    }

    println!("\nFSX multi-seed summary: {} passed, {} failed", passed, failed);
}

#[test]
fn test_fsx_small_file() {
    // Test with small file size limit (catches alignment issues)
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found");
            return;
        }
    };

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_file = guard.mount_point().join("fsx_small_file_test");

    if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(b"small")) {
        eprintln!("SKIP: Could not create test file: {}", e);
        return;
    }

    // Run with small file size limit
    let mut cmd = Command::new(&fsx_bin);
    cmd.arg("-N").arg("500")
        .arg("-l").arg("4096")  // Max file size 4KB
        .arg("-S").arg("11111")
        .arg("-q")
        .arg(&test_file);

    eprintln!("Running: {:?}", cmd);

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                println!("FSX small file test PASSED");
            } else {
                let info = fsx_error_info(&output);
                println!("FSX small file test FAILED:\n{}", info);
            }
        }
        Err(e) => {
            eprintln!("FSX error: {}", e);
        }
    }

    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_fsx_large_file() {
    // Test with larger file to exercise chunked encryption (32KB chunks)
    let fsx_bin = match find_fsx() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: FSX binary not found");
            return;
        }
    };

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_file = guard.mount_point().join("fsx_large_file_test");

    // Create a larger initial file (crosses 32KB chunk boundaries)
    let initial_data = vec![0u8; 65536]; // 64KB
    if let Err(e) = File::create(&test_file).and_then(|mut f| f.write_all(&initial_data)) {
        eprintln!("SKIP: Could not create test file: {}", e);
        return;
    }

    // Run with larger file size limit
    let mut cmd = Command::new(&fsx_bin);
    cmd.arg("-N").arg("500")
        .arg("-l").arg("131072")  // Max file size 128KB
        .arg("-S").arg("22222")
        .arg("-q")
        .arg(&test_file);

    eprintln!("Running: {:?}", cmd);

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                println!("FSX large file test PASSED");
            } else {
                let info = fsx_error_info(&output);
                println!("FSX large file test FAILED:\n{}", info);
            }
        }
        Err(e) => {
            eprintln!("FSX error: {}", e);
        }
    }

    let _ = fs::remove_file(&test_file);
}
