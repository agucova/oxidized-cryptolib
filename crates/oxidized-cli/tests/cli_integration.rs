#![allow(deprecated)] // cargo_bin! macro doesn't exist yet in assert_cmd 2.1

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test-password-123";

fn oxcrypt() -> Command {
    let mut cmd = Command::cargo_bin("oxcrypt").unwrap();
    cmd.env("OXCRYPT_PASSWORD", TEST_PASSWORD);
    cmd
}

fn oxcrypt_no_password() -> Command {
    Command::cargo_bin("oxcrypt").unwrap()
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
        .assert()
        .success();

    temp_dir
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
    oxcrypt_no_password()
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--vault"));
}

#[test]
fn test_nonexistent_vault() {
    oxcrypt()
        .arg("--vault")
        .arg("/nonexistent/path")
        .arg("ls")
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

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("ls")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().or(predicate::str::contains("")));
}

#[test]
fn test_tree_empty_vault() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("tree")
        .assert()
        .success();
}

#[test]
fn test_info_shows_vault_details() {
    let temp_dir = create_temp_vault();
    let vault_path = temp_dir.path().join("vault");

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("info")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("touch")
        .arg("/empty.txt")
        .assert()
        .success();

    // Verify it exists in ls output
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("ls")
        .assert()
        .success()
        .stdout(predicate::str::contains("empty.txt"));

    // Verify it's empty
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("touch")
        .arg("/file.txt")
        .assert()
        .success();

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("touch")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/hello.txt")
        .write_stdin("Hello, World!")
        .assert()
        .success();

    // Read it back
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/file.txt")
        .write_stdin("First content")
        .assert()
        .success();

    // Overwrite with new content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/file.txt")
        .write_stdin("Second content")
        .assert()
        .success();

    // Verify new content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/log.txt")
        .write_stdin("Line 1\n")
        .assert()
        .success();

    // Append more content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("-a")
        .arg("/log.txt")
        .write_stdin("Line 2\n")
        .assert()
        .success();

    // Verify both lines present
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("mkdir")
        .arg("/documents")
        .assert()
        .success();

    // Verify it shows in ls
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("ls")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("mkdir")
        .arg("-p")
        .arg("/a/b/c")
        .assert()
        .success();

    // Verify structure
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("tree")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/source.txt")
        .write_stdin("Copy me!")
        .assert()
        .success();

    // Copy to destination
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cp")
        .arg("/source.txt")
        .arg("/dest.txt")
        .assert()
        .success();

    // Verify both exist with same content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
        .arg("/source.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Copy me!"));

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/old.txt")
        .write_stdin("Move me!")
        .assert()
        .success();

    // Move to new name
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("mv")
        .arg("/old.txt")
        .arg("/new.txt")
        .assert()
        .success();

    // Verify old doesn't exist
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
        .arg("/old.txt")
        .assert()
        .failure();

    // Verify new has content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("touch")
        .arg("/delete_me.txt")
        .assert()
        .success();

    // Remove it
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("rm")
        .arg("/delete_me.txt")
        .assert()
        .success();

    // Verify it's gone
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("mkdir")
        .arg("/mydir")
        .assert()
        .success();

    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/mydir/file.txt")
        .write_stdin("content")
        .assert()
        .success();

    // Remove directory recursively
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("rm")
        .arg("-r")
        .arg("/mydir")
        .assert()
        .success();

    // Verify directory is gone
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("ls")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("passphrase").or(predicate::str::contains("master key")));
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
        .arg("--vault")
        .arg(&vault_path)
        .arg("mkdir")
        .arg("-p")
        .arg("/projects/rust")
        .assert()
        .success();

    // Create a file
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/projects/rust/main.rs")
        .write_stdin("fn main() { println!(\"Hello\"); }")
        .assert()
        .success();

    // Copy it
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cp")
        .arg("/projects/rust/main.rs")
        .arg("/projects/rust/backup.rs")
        .assert()
        .success();

    // Modify original
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("write")
        .arg("/projects/rust/main.rs")
        .write_stdin("fn main() { println!(\"Updated\"); }")
        .assert()
        .success();

    // Verify backup still has original
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
        .arg("/projects/rust/backup.rs")
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello"));

    // Verify original has new content
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("cat")
        .arg("/projects/rust/main.rs")
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated"));

    // Check tree shows everything
    oxcrypt()
        .arg("--vault")
        .arg(&vault_path)
        .arg("tree")
        .assert()
        .success()
        .stdout(predicate::str::contains("projects"))
        .stdout(predicate::str::contains("rust"))
        .stdout(predicate::str::contains("main.rs"))
        .stdout(predicate::str::contains("backup.rs"));
}
