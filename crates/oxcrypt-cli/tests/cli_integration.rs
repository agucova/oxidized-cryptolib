#![allow(deprecated)] // cargo_bin! macro doesn't exist yet in assert_cmd 2.1

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::file_serial;
use std::ffi::OsString;
use std::sync::OnceLock;
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test-password-123";

fn oxcrypt() -> Command {
    let mut cmd = Command::cargo_bin("oxcrypt").unwrap();
    cmd.env("OXCRYPT_PASSWORD", TEST_PASSWORD);
    // Skip proactive cleanup to prevent interference with mock state files
    cmd.env("OXCRYPT_NO_STARTUP_CLEANUP", "1");
    if let Some(dir) = current_config_dir() {
        cmd.env("OXCRYPT_CONFIG_DIR", dir);
    }
    cmd
}

fn oxcrypt_no_password() -> Command {
    let mut cmd = Command::cargo_bin("oxcrypt").unwrap();
    // Skip proactive cleanup to prevent interference with mock state files
    cmd.env("OXCRYPT_NO_STARTUP_CLEANUP", "1");
    if let Some(dir) = current_config_dir() {
        cmd.env("OXCRYPT_CONFIG_DIR", dir);
    }
    cmd
}

/// Create a temporary vault and return the TempDir (keeps it alive)
fn create_temp_vault() -> TempDir {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");

    Command::cargo_bin("oxcrypt")
        .unwrap()
        .arg("init")
        .arg(&vault_path)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .envs(config_dir_env())
        .assert()
        .success();

    temp_dir
}

struct ConfigDirGuard {
    _temp: TempDir,
    previous: Option<OsString>,
}

impl ConfigDirGuard {
    fn new() -> Self {
        let temp = TempDir::new().expect("Failed to create config dir");
        let previous = std::env::var_os("OXCRYPT_CONFIG_DIR");
        unsafe {
            std::env::set_var("OXCRYPT_CONFIG_DIR", temp.path());
        }
        Self {
            _temp: temp,
            previous,
        }
    }
}

impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            unsafe {
                std::env::set_var("OXCRYPT_CONFIG_DIR", previous);
            }
        } else {
            unsafe {
                std::env::remove_var("OXCRYPT_CONFIG_DIR");
            }
        }
    }
}

fn current_config_dir() -> Option<OsString> {
    std::env::var_os("OXCRYPT_CONFIG_DIR")
}

fn config_dir_env() -> impl Iterator<Item = (OsString, OsString)> {
    static KEY: OnceLock<OsString> = OnceLock::new();
    let key = KEY.get_or_init(|| OsString::from("OXCRYPT_CONFIG_DIR")).clone();
    current_config_dir().map(|value| (key, value)).into_iter()
}

// ============================================================================
// Basic CLI tests
// ============================================================================

#[test]
fn test_help() {
    oxcrypt_no_password()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Command-line interface for Cryptomator vaults"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("ls"))
        .stdout(predicate::str::contains("cat"))
        .stdout(predicate::str::contains("tree"));
}

#[test]
fn test_version() {
    oxcrypt_no_password()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("oxcrypt"));
}

#[test]
fn test_missing_vault_for_ls() {
    // Vault-first syntax: ls requires a vault path as first argument
    oxcrypt_no_password()
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_nonexistent_vault() {
    // Command-first syntax: oxcrypt <command> <VAULT> [args]
    oxcrypt()
        .arg("ls")
        .arg("/nonexistent/path")
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

// ============================================================================
// Init command tests
// ============================================================================

#[test]
fn test_init_creates_vault() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("new_vault");

    oxcrypt()
        .arg("init")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Created new vault"));

    // Verify vault structure
    assert!(vault_path.join("vault.cryptomator").exists());
    assert!(vault_path.join("masterkey").exists());
    assert!(vault_path.join("d").exists());
}

#[test]
fn test_init_fails_on_existing_vault() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Try to init again at the same location
    oxcrypt()
        .arg("init")
        .arg(&vault_path)
        .assert()
        .failure();
}

// ============================================================================
// Read operations on ephemeral vault
// ============================================================================

#[test]
fn test_ls_empty_vault() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Vault-first syntax: oxcrypt ls <VAULT> [PATH]
    oxcrypt()
        .arg("ls")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().or(predicate::str::contains("")));
}

#[test]
fn test_tree_empty_vault() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("tree")
        .arg(&vault_path)
        .assert()
        .success();
}

#[test]
fn test_info_shows_vault_details() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("info")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Format"))
        .stdout(predicate::str::contains("Cipher"));
}

// ============================================================================
// Write operations on ephemeral vault
// ============================================================================

#[test]
fn test_touch_creates_empty_file() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create empty file
    oxcrypt()
        .arg("touch")
        .arg(&vault_path)
        .arg("/empty.txt")
        .assert()
        .success();

    // Verify it exists in ls output
    oxcrypt()
        .arg("ls")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("empty.txt"));

    // Verify it's empty
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/empty.txt")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_touch_idempotent() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Touch twice should succeed both times
    oxcrypt()
        .arg("touch")
        .arg(&vault_path)
        .arg("/file.txt")
        .assert()
        .success();

    oxcrypt()
        .arg("touch")
        .arg(&vault_path)
        .arg("/file.txt")
        .assert()
        .success();
}

#[test]
fn test_write_creates_file_with_content() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Write content via stdin
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/hello.txt")
        .write_stdin("Hello, World!")
        .assert()
        .success();

    // Read it back
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/hello.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello, World!"));
}

#[test]
fn test_write_overwrites_existing_file() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Write initial content
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/file.txt")
        .write_stdin("First content")
        .assert()
        .success();

    // Overwrite with new content
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/file.txt")
        .write_stdin("Second content")
        .assert()
        .success();

    // Verify new content
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/file.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Second content"))
        .stdout(predicate::str::contains("First").not());
}

#[test]
fn test_write_append_mode() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Write initial content
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/log.txt")
        .write_stdin("Line 1\n")
        .assert()
        .success();

    // Append more content
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("-a")
        .arg("/log.txt")
        .write_stdin("Line 2\n")
        .assert()
        .success();

    // Verify both lines present
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/log.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Line 1"))
        .stdout(predicate::str::contains("Line 2"));
}

#[test]
fn test_mkdir_creates_directory() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create directory
    oxcrypt()
        .arg("mkdir")
        .arg(&vault_path)
        .arg("/documents")
        .assert()
        .success();

    // Verify it shows in ls
    oxcrypt()
        .arg("ls")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("documents/"));
}

#[test]
fn test_mkdir_nested_with_parents() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create nested directories with -p
    oxcrypt()
        .arg("mkdir")
        .arg(&vault_path)
        .arg("-p")
        .arg("/a/b/c")
        .assert()
        .success();

    // Verify structure
    oxcrypt()
        .arg("tree")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("a"))
        .stdout(predicate::str::contains("b"))
        .stdout(predicate::str::contains("c"));
}

#[test]
fn test_cp_copies_file() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create source file
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/source.txt")
        .write_stdin("Copy me!")
        .assert()
        .success();

    // Copy to destination
    oxcrypt()
        .arg("cp")
        .arg(&vault_path)
        .arg("/source.txt")
        .arg("/dest.txt")
        .assert()
        .success();

    // Verify both exist with same content
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/source.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Copy me!"));

    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/dest.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Copy me!"));
}

#[test]
fn test_mv_moves_file() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create source file
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/old.txt")
        .write_stdin("Move me!")
        .assert()
        .success();

    // Move to new name
    oxcrypt()
        .arg("mv")
        .arg(&vault_path)
        .arg("/old.txt")
        .arg("/new.txt")
        .assert()
        .success();

    // Verify old doesn't exist
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/old.txt")
        .assert()
        .failure();

    // Verify new has content
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/new.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Move me!"));
}

#[test]
fn test_rm_removes_file() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create file
    oxcrypt()
        .arg("touch")
        .arg(&vault_path)
        .arg("/delete_me.txt")
        .assert()
        .success();

    // Remove it
    oxcrypt()
        .arg("rm")
        .arg(&vault_path)
        .arg("/delete_me.txt")
        .assert()
        .success();

    // Verify it's gone
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/delete_me.txt")
        .assert()
        .failure();
}

#[test]
fn test_rm_recursive_removes_directory() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create directory with file
    oxcrypt()
        .arg("mkdir")
        .arg(&vault_path)
        .arg("/mydir")
        .assert()
        .success();

    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/mydir/file.txt")
        .write_stdin("content")
        .assert()
        .success();

    // Remove directory recursively
    oxcrypt()
        .arg("rm")
        .arg(&vault_path)
        .arg("-r")
        .arg("/mydir")
        .assert()
        .success();

    // Verify directory is gone
    oxcrypt()
        .arg("ls")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("mydir").not());
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn test_cat_nonexistent_file_fails() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/nonexistent.txt")
        .assert()
        .failure();
}

#[test]
fn test_wrong_password_fails() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    Command::cargo_bin("oxcrypt")
        .unwrap()
        .env("OXCRYPT_PASSWORD", "wrong-password")
        .arg("ls")
        .arg(&vault_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("passphrase").or(predicate::str::contains("master key")));
}

// ============================================================================
// Mount command tests (without actual mounting)
// ============================================================================

/// Helper to get the state file path
fn get_state_file_path() -> PathBuf {
    if let Some(dir) = current_config_dir() {
        return PathBuf::from(dir).join("mounts.json");
    }
    directories::ProjectDirs::from("com", "oxcrypt", "oxcrypt")
        .expect("Failed to get project dirs")
        .config_dir()
        .join("mounts.json")
}

/// Helper to write a mock state file
fn write_mock_state(entries: &[serde_json::Value]) {
    let state_path = get_state_file_path();
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let state = serde_json::json!({
        "version": 1,
        "mounts": entries
    });
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
}

/// Helper to clean up the state file
fn cleanup_state_file() {
    let state_path = get_state_file_path();
    std::fs::remove_file(&state_path).ok();
}

/// Create a mock mount entry with a live PID (current process)
#[allow(dead_code)]
fn mock_entry_live(vault: &str, mountpoint: &str) -> serde_json::Value {
    serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "vault_path": vault,
        "mountpoint": mountpoint,
        "backend": "fuse",
        "pid": std::process::id(),  // Current process - always alive
        "started_at": chrono::Utc::now().to_rfc3339(),
        "is_daemon": true
    })
}

/// Create a mock mount entry with a dead PID
fn mock_entry_stale(vault: &str, mountpoint: &str) -> serde_json::Value {
    serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "vault_path": vault,
        "mountpoint": mountpoint,
        "backend": "fskit",
        "pid": 999999999u32,  // Very unlikely to be a real PID
        "started_at": "2024-01-01T00:00:00Z",
        "is_daemon": true
    })
}

#[test]
#[file_serial]
fn test_mounts_command_empty() {
    let _config_dir = ConfigDirGuard::new();
    cleanup_state_file();

    // mounts command should work without any vault
    // May see "No active mounts" or "0 active mount(s)" depending on whether
    // stale entries from other test runs were cleaned up
    oxcrypt_no_password()
        .arg("mounts")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("No active mounts")
                .or(predicate::str::contains("0 active mount(s)"))
        );
}

#[test]
#[file_serial]
fn test_mounts_json_output_empty() {
    let _config_dir = ConfigDirGuard::new();
    cleanup_state_file();

    oxcrypt_no_password()
        .arg("mounts")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"active\""))
        .stdout(predicate::str::contains("[]"));
}

#[test]
#[file_serial]
fn test_mounts_displays_entries_from_state_file() {
    let _config_dir = ConfigDirGuard::new();
    // Create a mock entry - note: it will be detected as stale since
    // the mountpoint doesn't actually exist, but with --include-stale it shows
    write_mock_state(&[
        mock_entry_stale("/home/user/vault1", "/mnt/vault1"),
    ]);

    oxcrypt_no_password()
        .arg("mounts")
        .arg("--include-stale")
        .arg("--no-cleanup")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault1"));

    cleanup_state_file();
}

#[test]
#[file_serial]
fn test_mounts_json_shows_stale_entries() {
    let _config_dir = ConfigDirGuard::new();
    write_mock_state(&[
        mock_entry_stale("/home/user/my-vault", "/tmp/my-mount"),
    ]);

    oxcrypt_no_password()
        .arg("mounts")
        .arg("--json")
        .arg("--include-stale")
        .arg("--no-cleanup")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"stale\""))
        .stdout(predicate::str::contains("my-vault"));

    cleanup_state_file();
}

#[test]
#[file_serial]
fn test_mounts_auto_cleanup_removes_stale() {
    let _config_dir = ConfigDirGuard::new();
    let state_path = get_state_file_path();

    // Write stale entry
    write_mock_state(&[
        mock_entry_stale("/vault", "/mnt"),
    ]);

    // Run mounts WITHOUT --no-cleanup (default behavior)
    oxcrypt_no_password()
        .arg("mounts")
        .assert()
        .success()
        .stderr(predicate::str::contains("Cleaned up"));

    // Verify state file is now empty or has no mounts
    let contents = std::fs::read_to_string(&state_path).unwrap_or_default();
    let state: serde_json::Value = serde_json::from_str(&contents).unwrap_or(serde_json::json!({}));
    let mounts = state.get("mounts").and_then(|m| m.as_array());
    assert!(mounts.is_none_or(Vec::is_empty), "Stale entry should be cleaned up");

    cleanup_state_file();
}

#[test]
#[file_serial]
fn test_mounts_no_cleanup_preserves_stale() {
    let _config_dir = ConfigDirGuard::new();
    let state_path = get_state_file_path();

    // Write stale entry
    write_mock_state(&[
        mock_entry_stale("/vault", "/mnt"),
    ]);

    // Run mounts WITH --no-cleanup
    oxcrypt_no_password()
        .arg("mounts")
        .arg("--no-cleanup")
        .assert()
        .success();

    // Verify state file still has the entry
    let contents = std::fs::read_to_string(&state_path).unwrap();
    let state: serde_json::Value = serde_json::from_str(&contents).unwrap();
    let mounts = state.get("mounts").and_then(|m| m.as_array()).unwrap();
    assert_eq!(mounts.len(), 1, "Entry should be preserved with --no-cleanup");

    cleanup_state_file();
}

#[test]
#[file_serial]
fn test_mounts_include_stale_shows_both() {
    let _config_dir = ConfigDirGuard::new();
    write_mock_state(&[
        mock_entry_stale("/vault1", "/mnt1"),
        mock_entry_stale("/vault2", "/mnt2"),
    ]);

    oxcrypt_no_password()
        .arg("mounts")
        .arg("--include-stale")
        .arg("--no-cleanup")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault1"))
        .stdout(predicate::str::contains("vault2"));

    cleanup_state_file();
}

#[test]
#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
fn test_mount_help_shows_daemon_flag() {
    oxcrypt_no_password()
        .arg("mount")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--foreground"))
        .stdout(predicate::str::contains("--backend"));
}

#[test]
#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
fn test_mount_requires_vault_or_mountpoint() {
    oxcrypt_no_password()
        .arg("mount")
        .assert()
        .failure()
        .stderr(predicate::str::contains("<VAULT>").or(predicate::str::contains("VAULT")));
}

#[test]
#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
fn test_backends_command() {
    oxcrypt_no_password()
        .arg("backends")
        .assert()
        .success()
        .stdout(predicate::str::contains("Backend"));
}

#[test]
#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
fn test_backends_json_output() {
    oxcrypt_no_password()
        .arg("backends")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"available\""));
}

#[test]
#[cfg(any(feature = "fuse", feature = "fskit", feature = "webdav"))]
fn test_unmount_nonexistent_path() {
    oxcrypt_no_password()
        .arg("unmount")
        .arg("/nonexistent/mount/path")
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

// ============================================================================
// Complex workflow tests
// ============================================================================

#[test]
fn test_full_file_workflow() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create directory structure
    oxcrypt()
        .arg("mkdir")
        .arg(&vault_path)
        .arg("-p")
        .arg("/projects/rust")
        .assert()
        .success();

    // Create a file
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/projects/rust/main.rs")
        .write_stdin("fn main() { println!(\"Hello\"); }")
        .assert()
        .success();

    // Copy it
    oxcrypt()
        .arg("cp")
        .arg(&vault_path)
        .arg("/projects/rust/main.rs")
        .arg("/projects/rust/backup.rs")
        .assert()
        .success();

    // Modify original
    oxcrypt()
        .arg("write")
        .arg(&vault_path)
        .arg("/projects/rust/main.rs")
        .write_stdin("fn main() { println!(\"Updated\"); }")
        .assert()
        .success();

    // Verify backup still has original
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/projects/rust/backup.rs")
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello"));

    // Verify original has new content
    oxcrypt()
        .arg("cat")
        .arg(&vault_path)
        .arg("/projects/rust/main.rs")
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated"));

    // Check tree shows everything
    oxcrypt()
        .arg("tree")
        .arg(&vault_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("projects"))
        .stdout(predicate::str::contains("rust"))
        .stdout(predicate::str::contains("main.rs"))
        .stdout(predicate::str::contains("backup.rs"));
}

// ============================================================================
// JSON output tests
// ============================================================================

#[test]
fn test_ls_json_output() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    // Create some files
    oxcrypt()
        .arg("touch")
        .arg(&vault_path)
        .arg("/file.txt")
        .assert()
        .success();

    oxcrypt()
        .arg("mkdir")
        .arg(&vault_path)
        .arg("/dir")
        .assert()
        .success();

    // Test JSON output
    oxcrypt()
        .arg("ls")
        .arg(&vault_path)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"entries\""))
        .stdout(predicate::str::contains("\"file.txt\""))
        .stdout(predicate::str::contains("\"dir\""));
}

#[test]
fn test_info_json_output() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("info")
        .arg(&vault_path)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"format\""))
        .stdout(predicate::str::contains("\"cipher\""));
}
