//! fsstress integration tests for oxcrypt-fuse.
//!
//! fsstress is a filesystem stress testing tool from SGI/XFS that performs
//! multiple concurrent filesystem operations to find race conditions and
//! concurrency bugs.
//!
//! Requirements:
//! - FUSE must be installed (fuse3 on Linux)
//! - fsstress binary must be available (installed via devenv on Linux)
//! - Linux only (fsstress uses Linux-specific syscalls)
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests`

#![cfg(all(unix, target_os = "linux", feature = "fuse-tests"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use fuser::{BackgroundSession, MountOption};
use oxcrypt_fuse::filesystem::CryptomatorFS;
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

/// Find the fsstress binary.
fn find_fsstress() -> Option<PathBuf> {
    // Check FSSTRESS_BIN environment variable first
    if let Ok(path) = std::env::var("FSSTRESS_BIN") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
    }

    // Check if 'fsstress' is in PATH
    if let Ok(output) = Command::new("which").arg("fsstress").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
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

    let options = vec![
        MountOption::FSName("cryptomator".to_string()),
        MountOption::AutoUnmount,
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

/// Run fsstress with specified parameters.
fn run_fsstress(
    test_dir: &Path,
    num_ops: u32,
    num_procs: u32,
    seed: Option<u64>,
) -> Result<Output, String> {
    let fsstress_bin =
        find_fsstress().ok_or("fsstress binary not found (Linux only, install via devenv)")?;

    let mut cmd = Command::new(&fsstress_bin);

    // Directory to operate in
    cmd.arg("-d").arg(test_dir);

    // Number of operations per process
    cmd.arg("-n").arg(num_ops.to_string());

    // Number of processes
    cmd.arg("-p").arg(num_procs.to_string());

    // Seed for reproducibility
    if let Some(s) = seed {
        cmd.arg("-s").arg(s.to_string());
    }

    // Verbose output
    cmd.arg("-v");

    eprintln!("Running: {:?}", cmd);

    cmd.output()
        .map_err(|e| format!("Failed to run fsstress: {}", e))
}

/// Check if fsstress passed.
fn fsstress_passed(output: &Output) -> bool {
    output.status.success()
}

/// Extract info from fsstress output.
fn fsstress_info(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
}

// ============================================================================
// fsstress Tests
// ============================================================================

#[test]
fn test_fsstress_quick() {
    // Quick smoke test: 50 operations, single process
    let fsstress_bin = match find_fsstress() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: fsstress binary not found (Linux only)");
            return;
        }
    };

    eprintln!("Using fsstress at: {}", fsstress_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    // Create a subdirectory for fsstress to work in
    let test_dir = guard.mount_point().join("fsstress_quick");
    if let Err(e) = fs::create_dir_all(&test_dir) {
        eprintln!("SKIP: Could not create test directory: {}", e);
        return;
    }

    match run_fsstress(&test_dir, 50, 1, Some(12345)) {
        Ok(output) => {
            if fsstress_passed(&output) {
                println!("fsstress quick test PASSED (50 ops, 1 proc)");
            } else {
                println!("fsstress quick test FAILED:\n{}", fsstress_info(&output));
            }
        }
        Err(e) => {
            eprintln!("fsstress error: {}", e);
        }
    }

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_fsstress_concurrent() {
    // Concurrency test: 100 operations, 4 processes
    let fsstress_bin = match find_fsstress() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: fsstress binary not found");
            return;
        }
    };

    eprintln!("Using fsstress at: {}", fsstress_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_dir = guard.mount_point().join("fsstress_concurrent");
    if let Err(e) = fs::create_dir_all(&test_dir) {
        eprintln!("SKIP: Could not create test directory: {}", e);
        return;
    }

    match run_fsstress(&test_dir, 100, 4, Some(54321)) {
        Ok(output) => {
            if fsstress_passed(&output) {
                println!("fsstress concurrent test PASSED (100 ops, 4 procs)");
            } else {
                println!(
                    "fsstress concurrent test FAILED:\n{}",
                    fsstress_info(&output)
                );
            }
        }
        Err(e) => {
            eprintln!("fsstress error: {}", e);
        }
    }

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_fsstress_stress() {
    // Full stress test: 500 operations, 8 processes
    let fsstress_bin = match find_fsstress() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: fsstress binary not found");
            return;
        }
    };

    eprintln!("Using fsstress at: {}", fsstress_bin.display());

    let guard = match mount_test_vault_rw() {
        Some(g) => g,
        None => {
            eprintln!("SKIP: Could not mount test vault");
            return;
        }
    };

    let test_dir = guard.mount_point().join("fsstress_stress");
    if let Err(e) = fs::create_dir_all(&test_dir) {
        eprintln!("SKIP: Could not create test directory: {}", e);
        return;
    }

    match run_fsstress(&test_dir, 500, 8, Some(99999)) {
        Ok(output) => {
            if fsstress_passed(&output) {
                println!("fsstress stress test PASSED (500 ops, 8 procs)");
            } else {
                println!("fsstress stress test FAILED:\n{}", fsstress_info(&output));
            }
        }
        Err(e) => {
            eprintln!("fsstress error: {}", e);
        }
    }

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_fsstress_multiple_seeds() {
    // Run with multiple seeds for broader coverage
    let fsstress_bin = match find_fsstress() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: fsstress binary not found");
            return;
        }
    };

    eprintln!("Using fsstress at: {}", fsstress_bin.display());

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
        let test_dir = guard.mount_point().join(format!("fsstress_seed_{}", seed));
        if let Err(e) = fs::create_dir_all(&test_dir) {
            eprintln!("SKIP seed {}: Could not create test directory: {}", seed, e);
            continue;
        }

        match run_fsstress(&test_dir, 100, 2, Some(seed)) {
            Ok(output) => {
                if fsstress_passed(&output) {
                    println!("fsstress seed {} PASSED", seed);
                    passed += 1;
                } else {
                    println!("fsstress seed {} FAILED:\n{}", seed, fsstress_info(&output));
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("fsstress seed {} error: {}", seed, e);
                failed += 1;
            }
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    println!(
        "\nfsstress multi-seed summary: {} passed, {} failed",
        passed, failed
    );
}
