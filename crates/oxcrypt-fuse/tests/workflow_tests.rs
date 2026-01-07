//! Workflow tests for FUSE filesystem.
//!
//! Tests multi-step operations that simulate real-world usage patterns.
//! Verifies that sequences of operations work correctly together.
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests workflow_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;

// =============================================================================
// Directory Lifecycle
// =============================================================================

#[test]
fn test_directory_create_populate_delete() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create directory
    mount.mkdir("project").expect("mkdir failed");
    assert_is_directory(&mount, "project");

    // Populate with files
    mount
        .write("project/readme.txt", b"README content")
        .expect("write readme failed");
    mount
        .write("project/main.rs", b"fn main() {}")
        .expect("write main failed");
    mount.mkdir("project/src").expect("mkdir src failed");
    mount
        .write("project/src/lib.rs", b"pub fn hello() {}")
        .expect("write lib failed");

    // Verify structure
    assert_dir_contains(&mount, "project", &["readme.txt", "main.rs", "src"]);
    assert_dir_entries(&mount, "project/src", &["lib.rs"]);

    // Modify files
    mount
        .write("project/readme.txt", b"Updated README")
        .expect("update readme failed");
    assert_file_content(&mount, "project/readme.txt", b"Updated README");

    // Clean up in correct order
    mount
        .remove("project/src/lib.rs")
        .expect("remove lib failed");
    mount.rmdir("project/src").expect("rmdir src failed");
    mount.remove("project/main.rs").expect("remove main failed");
    mount
        .remove("project/readme.txt")
        .expect("remove readme failed");
    mount.rmdir("project").expect("rmdir project failed");

    assert_not_found(&mount, "project");
}

#[test]
fn test_nested_directory_operations() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create 4 levels deep
    mount.mkdir_all("a/b/c/d").expect("mkdir_all failed");

    // Place files at each level
    mount.write("a/file.txt", b"level 1").expect("write failed");
    mount
        .write("a/b/file.txt", b"level 2")
        .expect("write failed");
    mount
        .write("a/b/c/file.txt", b"level 3")
        .expect("write failed");
    mount
        .write("a/b/c/d/file.txt", b"level 4")
        .expect("write failed");

    // Verify all files
    assert_file_content(&mount, "a/file.txt", b"level 1");
    assert_file_content(&mount, "a/b/file.txt", b"level 2");
    assert_file_content(&mount, "a/b/c/file.txt", b"level 3");
    assert_file_content(&mount, "a/b/c/d/file.txt", b"level 4");

    // Modify files at different levels
    mount
        .write("a/b/file.txt", b"level 2 updated")
        .expect("update failed");
    assert_file_content(&mount, "a/b/file.txt", b"level 2 updated");

    // Other files should be unchanged
    assert_file_content(&mount, "a/file.txt", b"level 1");
    assert_file_content(&mount, "a/b/c/file.txt", b"level 3");
}

// =============================================================================
// File Replacement
// =============================================================================

#[test]
fn test_delete_and_recreate() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let original = b"original content";
    let replacement = b"replacement content";

    mount
        .write("file.txt", original)
        .expect("write original failed");
    assert_file_content(&mount, "file.txt", original);

    mount.remove("file.txt").expect("delete failed");
    assert_not_found(&mount, "file.txt");

    mount
        .write("file.txt", replacement)
        .expect("write replacement failed");
    assert_file_content(&mount, "file.txt", replacement);
}

#[test]
fn test_rapid_replace_cycle() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    for i in 0..10 {
        let content = format!("iteration {}", i);
        mount
            .write("cycle.txt", content.as_bytes())
            .expect("write failed");
        assert_file_content(&mount, "cycle.txt", content.as_bytes());

        mount.remove("cycle.txt").expect("delete failed");
        assert_not_found(&mount, "cycle.txt");
    }

    // Final state: file doesn't exist
    assert_not_found(&mount, "cycle.txt");
}

// =============================================================================
// Size Transitions
// =============================================================================

#[test]
fn test_size_transition_workflow() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Empty
    mount
        .write("transitions.bin", b"")
        .expect("write empty failed");
    assert_file_size(&mount, "transitions.bin", 0);

    // Small (100 bytes)
    let small = random_bytes(100);
    mount
        .write("transitions.bin", &small)
        .expect("write small failed");
    assert_file_content(&mount, "transitions.bin", &small);

    // One chunk (32KB)
    let one_chunk = one_chunk_content();
    mount
        .write("transitions.bin", &one_chunk)
        .expect("write chunk failed");
    assert_file_content(&mount, "transitions.bin", &one_chunk);

    // Multiple chunks (3 * 32KB)
    let multi = multi_chunk_content(3);
    let multi_hash = sha256(&multi);
    mount
        .write("transitions.bin", &multi)
        .expect("write multi failed");
    assert_file_hash(&mount, "transitions.bin", &multi_hash);

    // Back to small
    mount
        .write("transitions.bin", &small)
        .expect("write small again failed");
    assert_file_content(&mount, "transitions.bin", &small);

    // Back to empty
    mount
        .write("transitions.bin", b"")
        .expect("write empty again failed");
    assert_file_size(&mount, "transitions.bin", 0);
}

#[test]
fn test_chunk_boundary_transitions() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // chunk - 1
    let cm1 = chunk_minus_one();
    mount.write("boundaries.bin", &cm1).expect("write failed");
    assert_file_content(&mount, "boundaries.bin", &cm1);

    // exactly chunk
    let exact = one_chunk_content();
    mount.write("boundaries.bin", &exact).expect("write failed");
    assert_file_content(&mount, "boundaries.bin", &exact);

    // chunk + 1
    let cp1 = chunk_plus_one();
    mount.write("boundaries.bin", &cp1).expect("write failed");
    assert_file_content(&mount, "boundaries.bin", &cp1);

    // back to chunk - 1
    mount.write("boundaries.bin", &cm1).expect("write failed");
    assert_file_content(&mount, "boundaries.bin", &cm1);
}

// =============================================================================
// Interleaved Reads and Writes
// =============================================================================

#[test]
fn test_interleaved_read_write() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial file
    mount
        .write("interleave.txt", b"initial")
        .expect("write failed");

    // Interleave reads and writes
    assert_file_content(&mount, "interleave.txt", b"initial");

    mount
        .write("interleave.txt", b"update 1")
        .expect("write 1 failed");
    assert_file_content(&mount, "interleave.txt", b"update 1");

    mount
        .write("interleave.txt", b"update 2")
        .expect("write 2 failed");
    assert_file_content(&mount, "interleave.txt", b"update 2");

    mount
        .write("interleave.txt", b"update 3")
        .expect("write 3 failed");
    assert_file_content(&mount, "interleave.txt", b"update 3");
}

#[test]
fn test_read_during_write_workflow() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create two files
    mount
        .write("file_a.txt", b"content A")
        .expect("write a failed");
    mount
        .write("file_b.txt", b"content B")
        .expect("write b failed");

    // Interleaved operations on both files
    let a = mount.read("file_a.txt").expect("read a failed");
    mount
        .write("file_b.txt", b"content B updated")
        .expect("update b failed");
    let b = mount.read("file_b.txt").expect("read b failed");
    mount
        .write("file_a.txt", b"content A updated")
        .expect("update a failed");

    assert_eq!(a, b"content A");
    assert_eq!(b, b"content B updated");
    assert_file_content(&mount, "file_a.txt", b"content A updated");
    assert_file_content(&mount, "file_b.txt", b"content B updated");
}

// =============================================================================
// Bulk Operations
// =============================================================================

#[test]
fn test_bulk_create_then_delete() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let file_count = 20;

    // Bulk create
    for i in 0..file_count {
        let filename = format!("bulk_{}.txt", i);
        let content = format!("content {}", i);
        mount
            .write(&filename, content.as_bytes())
            .expect("write failed");
    }

    // Verify all exist
    let entries = mount.list("/").expect("list failed");
    for i in 0..file_count {
        let filename = format!("bulk_{}.txt", i);
        assert!(entries.contains(&filename), "Missing {}", filename);
    }

    // Bulk delete
    for i in 0..file_count {
        let filename = format!("bulk_{}.txt", i);
        mount.remove(&filename).expect("delete failed");
    }

    // Verify all gone
    let after = mount.list("/").expect("list failed");
    for i in 0..file_count {
        let filename = format!("bulk_{}.txt", i);
        assert!(!after.contains(&filename), "Still exists: {}", filename);
    }
}

#[test]
fn test_bulk_directory_creation() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create multiple directories
    for i in 0..10 {
        mount.mkdir(&format!("dir_{}", i)).expect("mkdir failed");
    }

    // Place file in each
    for i in 0..10 {
        mount
            .write(&format!("dir_{}/file.txt", i), b"content")
            .expect("write failed");
    }

    // Verify all
    for i in 0..10 {
        assert_is_directory(&mount, &format!("dir_{}", i));
        assert_file_content(&mount, &format!("dir_{}/file.txt", i), b"content");
    }
}

// =============================================================================
// Project Setup Workflow
// =============================================================================

#[test]
fn test_project_setup_workflow() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create project structure
    mount.mkdir("myproject").expect("mkdir project failed");
    mount.mkdir("myproject/src").expect("mkdir src failed");
    mount.mkdir("myproject/tests").expect("mkdir tests failed");
    mount.mkdir("myproject/docs").expect("mkdir docs failed");

    // Create source files
    mount
        .write(
            "myproject/src/main.rs",
            b"fn main() {\n    println!(\"Hello\");\n}\n",
        )
        .expect("write main failed");
    mount
        .write("myproject/src/lib.rs", b"pub mod utils;\n")
        .expect("write lib failed");
    mount
        .write("myproject/src/utils.rs", b"pub fn helper() {}\n")
        .expect("write utils failed");

    // Create config files
    mount
        .write("myproject/Cargo.toml", b"[package]\nname = \"myproject\"\n")
        .expect("write cargo failed");
    mount
        .write("myproject/.gitignore", b"/target\n")
        .expect("write gitignore failed");

    // Create test files
    mount
        .write(
            "myproject/tests/integration.rs",
            b"#[test]\nfn it_works() {}\n",
        )
        .expect("write test failed");

    // Create docs
    mount
        .write("myproject/docs/README.md", b"# My Project\n")
        .expect("write readme failed");

    // Verify structure
    assert_dir_contains(
        &mount,
        "myproject",
        &["src", "tests", "docs", "Cargo.toml", ".gitignore"],
    );
    assert_dir_entries(&mount, "myproject/src", &["main.rs", "lib.rs", "utils.rs"]);
    assert_dir_entries(&mount, "myproject/tests", &["integration.rs"]);
    assert_dir_entries(&mount, "myproject/docs", &["README.md"]);

    // Verify file contents
    assert_file_content(
        &mount,
        "myproject/Cargo.toml",
        b"[package]\nname = \"myproject\"\n",
    );
    assert_file_content(
        &mount,
        "myproject/src/main.rs",
        b"fn main() {\n    println!(\"Hello\");\n}\n",
    );
}

// =============================================================================
// Rename Workflows
// =============================================================================

#[test]
fn test_reorganize_files() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial flat structure
    mount.write("a.txt", b"a").expect("write a failed");
    mount.write("b.txt", b"b").expect("write b failed");
    mount.write("c.txt", b"c").expect("write c failed");

    // Reorganize into directories
    mount.mkdir("letters").expect("mkdir failed");
    mount
        .rename("a.txt", "letters/a.txt")
        .expect("move a failed");
    mount
        .rename("b.txt", "letters/b.txt")
        .expect("move b failed");
    mount
        .rename("c.txt", "letters/c.txt")
        .expect("move c failed");

    // Verify new structure
    assert_not_found(&mount, "a.txt");
    assert_not_found(&mount, "b.txt");
    assert_not_found(&mount, "c.txt");
    assert_dir_entries(&mount, "letters", &["a.txt", "b.txt", "c.txt"]);
    assert_file_content(&mount, "letters/a.txt", b"a");
}

#[test]
fn test_rename_workflow_with_content_verify() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create large file
    let content = multi_chunk_content(5);
    let expected_hash = sha256(&content);

    mount.write("large.bin", &content).expect("write failed");

    // Move through multiple directories
    mount.mkdir("step1").expect("mkdir 1 failed");
    mount.mkdir("step2").expect("mkdir 2 failed");
    mount.mkdir("step3").expect("mkdir 3 failed");

    mount
        .rename("large.bin", "step1/large.bin")
        .expect("move 1 failed");
    mount
        .rename("step1/large.bin", "step2/large.bin")
        .expect("move 2 failed");
    mount
        .rename("step2/large.bin", "step3/large.bin")
        .expect("move 3 failed");
    mount
        .rename("step3/large.bin", "final.bin")
        .expect("move final failed");

    // Verify content preserved through all moves
    assert_file_hash(&mount, "final.bin", &expected_hash);
}

// =============================================================================
// Mixed Operations
// =============================================================================

#[test]
fn test_complex_mixed_workflow() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create base structure
    mount.mkdir("workspace").expect("mkdir failed");
    mount
        .mkdir("workspace/active")
        .expect("mkdir active failed");
    mount
        .mkdir("workspace/archive")
        .expect("mkdir archive failed");

    // Create active documents
    mount
        .write("workspace/active/doc1.txt", b"Document 1")
        .expect("write failed");
    mount
        .write("workspace/active/doc2.txt", b"Document 2")
        .expect("write failed");
    mount
        .write("workspace/active/doc3.txt", b"Document 3")
        .expect("write failed");

    // Modify some documents
    mount
        .write("workspace/active/doc1.txt", b"Document 1 - Updated")
        .expect("update failed");

    // Archive old documents
    mount
        .rename("workspace/active/doc2.txt", "workspace/archive/doc2.txt")
        .expect("archive failed");

    // Delete unwanted documents
    mount
        .remove("workspace/active/doc3.txt")
        .expect("delete failed");

    // Verify final state
    assert_file_content(&mount, "workspace/active/doc1.txt", b"Document 1 - Updated");
    assert_not_found(&mount, "workspace/active/doc2.txt");
    assert_not_found(&mount, "workspace/active/doc3.txt");
    assert_file_content(&mount, "workspace/archive/doc2.txt", b"Document 2");
}

#[test]
fn test_incremental_backup_workflow() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Initial state
    mount.mkdir("data").expect("mkdir data failed");
    mount
        .write("data/file1.txt", b"version 1")
        .expect("write failed");
    mount
        .write("data/file2.txt", b"version 1")
        .expect("write failed");

    // Create backup
    mount.mkdir("backup").expect("mkdir backup failed");
    mount
        .copy("data/file1.txt", "backup/file1.txt")
        .expect("copy failed");
    mount
        .copy("data/file2.txt", "backup/file2.txt")
        .expect("copy failed");

    // Modify originals
    mount
        .write("data/file1.txt", b"version 2")
        .expect("update failed");

    // Verify backup unchanged
    assert_file_content(&mount, "backup/file1.txt", b"version 1");
    assert_file_content(&mount, "backup/file2.txt", b"version 1");

    // Verify originals changed
    assert_file_content(&mount, "data/file1.txt", b"version 2");
    assert_file_content(&mount, "data/file2.txt", b"version 1");
}

// =============================================================================
// Error Recovery
// =============================================================================

#[test]
fn test_operation_after_error() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Trigger an error
    let _ = mount.read("nonexistent.txt"); // Should fail

    // Operations should still work after error
    mount
        .write("recovery.txt", b"recovered")
        .expect("write after error failed");
    assert_file_content(&mount, "recovery.txt", b"recovered");
}

#[test]
fn test_partial_cleanup_recovery() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create directory with contents
    mount.mkdir("partial").expect("mkdir failed");
    mount
        .write("partial/keep.txt", b"keep me")
        .expect("write failed");
    mount
        .write("partial/delete.txt", b"delete me")
        .expect("write failed");

    // Try to delete directory (should fail - not empty)
    let _ = mount.rmdir("partial"); // Expected to fail

    // Clean up properly
    mount.remove("partial/delete.txt").expect("remove failed");

    // Remaining content should be intact
    assert_file_content(&mount, "partial/keep.txt", b"keep me");
}
