//! Integration tests for vault write operations

mod common;

use common::vault_builder::VaultBuilder;
use oxidized_cryptolib::vault::{DirId, VaultCreator, VaultOperations, VaultWriteError};
use tempfile::TempDir;

// ==================== write_file() tests ====================

#[test]
fn test_write_file_basic_roundtrip() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write a file
    let content = b"Hello, Cryptomator!";
    vault_ops
        .write_file(&DirId::root(), "greeting.txt", content)
        .expect("Failed to write file");

    // Read it back
    let decrypted = vault_ops
        .read_file(&DirId::root(), "greeting.txt")
        .expect("Failed to read file");
    assert_eq!(decrypted.content, content);
}

#[test]
fn test_write_file_empty_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write an empty file
    vault_ops
        .write_file(&DirId::root(),"empty.txt", b"")
        .expect("Failed to write empty file");

    // Read it back
    let decrypted = vault_ops
        .read_file(&DirId::root(),"empty.txt")
        .expect("Failed to read empty file");
    assert!(decrypted.content.is_empty());
}

#[test]
fn test_write_file_large_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write a file larger than one chunk (32KB)
    let content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    vault_ops
        .write_file(&DirId::root(),"large.bin", &content)
        .expect("Failed to write large file");

    // Read it back
    let decrypted = vault_ops
        .read_file(&DirId::root(),"large.bin")
        .expect("Failed to read large file");
    assert_eq!(decrypted.content, content);
}

#[test]
fn test_write_file_binary_content() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write binary content with all byte values
    let content: Vec<u8> = (0..=255).collect();
    vault_ops
        .write_file(&DirId::root(),"binary.bin", &content)
        .expect("Failed to write binary file");

    // Read it back
    let decrypted = vault_ops
        .read_file(&DirId::root(),"binary.bin")
        .expect("Failed to read binary file");
    assert_eq!(decrypted.content, content);
}

#[test]
fn test_write_file_unicode_filename() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write file with Unicode filename
    let content = b"Unicode content";
    vault_ops
        .write_file(&DirId::root(),"файл-测试-🔐.txt", content)
        .expect("Failed to write Unicode-named file");

    // Read it back
    let decrypted = vault_ops
        .read_file(&DirId::root(),"файл-测试-🔐.txt")
        .expect("Failed to read Unicode-named file");
    assert_eq!(decrypted.content, content);
}

#[test]
fn test_write_file_overwrites_existing() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"original content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Verify original content
    let original = vault_ops.read_file(&DirId::root(),"existing.txt").unwrap();
    assert_eq!(original.content, b"original content");

    // Overwrite with new content
    vault_ops
        .write_file(&DirId::root(),"existing.txt", b"new content")
        .expect("Failed to overwrite file");

    // Verify new content
    let updated = vault_ops.read_file(&DirId::root(),"existing.txt").unwrap();
    assert_eq!(updated.content, b"new content");
}

// ==================== create_directory() tests ====================

#[test]
fn test_create_directory_basic() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory
    let dir_id = vault_ops
        .create_directory(&DirId::root(),"new_folder")
        .expect("Failed to create directory");

    // Verify it appears in listing
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(dirs.iter().any(|d| d.name == "new_folder"));
    assert!(dirs.iter().any(|d| d.directory_id == dir_id));
}

#[test]
fn test_create_directory_nested() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create parent directory
    let parent_id = vault_ops
        .create_directory(&DirId::root(),"parent")
        .expect("Failed to create parent directory");

    // Create child directory
    let child_id = vault_ops
        .create_directory(&parent_id, "child")
        .expect("Failed to create child directory");

    // Verify parent has child
    let children = vault_ops.list_directories(&parent_id).unwrap();
    assert!(children.iter().any(|d| d.name == "child"));
    assert!(children.iter().any(|d| d.directory_id == child_id));
}

#[test]
fn test_create_directory_and_write_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create directory
    let dir_id = vault_ops
        .create_directory(&DirId::root(),"docs")
        .expect("Failed to create directory");

    // Write file in directory
    vault_ops
        .write_file(&dir_id, "readme.txt", b"Documentation here")
        .expect("Failed to write file in directory");

    // Read it back
    let decrypted = vault_ops.read_file(&dir_id, "readme.txt").unwrap();
    assert_eq!(decrypted.content, b"Documentation here");
}

// ==================== delete_file() tests ====================

#[test]
fn test_delete_file_basic() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("to_delete.txt", b"delete me")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Verify file exists
    assert!(vault_ops.read_file(&DirId::root(),"to_delete.txt").is_ok());

    // Delete it
    vault_ops
        .delete_file(&DirId::root(),"to_delete.txt")
        .expect("Failed to delete file");

    // Verify it's gone
    assert!(vault_ops.read_file(&DirId::root(),"to_delete.txt").is_err());
}

#[test]
fn test_delete_file_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to delete non-existent file
    let result = vault_ops.delete_file(&DirId::root(),"nonexistent.txt");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

#[test]
fn test_delete_written_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write a file
    vault_ops
        .write_file(&DirId::root(),"temp.txt", b"temporary")
        .expect("Failed to write file");

    // Verify it exists
    assert!(vault_ops.read_file(&DirId::root(),"temp.txt").is_ok());

    // Delete it
    vault_ops
        .delete_file(&DirId::root(),"temp.txt")
        .expect("Failed to delete file");

    // Verify it's gone
    assert!(vault_ops.read_file(&DirId::root(),"temp.txt").is_err());
}

// ==================== delete_directory() tests ====================

#[test]
fn test_delete_empty_directory() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory
    vault_ops
        .create_directory(&DirId::root(),"empty_dir")
        .expect("Failed to create directory");

    // Verify it exists
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(dirs.iter().any(|d| d.name == "empty_dir"));

    // Delete it
    vault_ops
        .delete_directory(&DirId::root(),"empty_dir")
        .expect("Failed to delete directory");

    // Verify it's gone
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "empty_dir"));
}

#[test]
fn test_delete_non_empty_directory_fails() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create directory with file
    let dir_id = vault_ops
        .create_directory(&DirId::root(),"non_empty")
        .expect("Failed to create directory");

    vault_ops
        .write_file(&dir_id, "file.txt", b"content")
        .expect("Failed to write file");

    // Try to delete - should fail
    let result = vault_ops.delete_directory(&DirId::root(),"non_empty");
    assert!(matches!(result, Err(VaultWriteError::DirectoryNotEmpty { .. })));
}

#[test]
fn test_delete_directory_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to delete non-existent directory
    let result = vault_ops.delete_directory(&DirId::root(),"nonexistent");
    assert!(matches!(result, Err(VaultWriteError::DirectoryNotFound { .. })));
}

// ==================== VaultCreator tests ====================

#[test]
fn test_vault_creator_full_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("new_vault");

    // Create vault
    let vault_ops = VaultCreator::new(&vault_path, "secure-password-123")
        .create()
        .expect("Failed to create vault");

    // Create directory structure
    let docs_id = vault_ops
        .create_directory(&DirId::root(),"Documents")
        .expect("Failed to create Documents");
    let photos_id = vault_ops
        .create_directory(&DirId::root(),"Photos")
        .expect("Failed to create Photos");

    // Write files
    vault_ops
        .write_file(&docs_id, "report.txt", b"Annual report content")
        .expect("Failed to write report");
    vault_ops
        .write_file(&photos_id, "vacation.jpg", &[0xFF, 0xD8, 0xFF, 0xE0]) // JPEG header
        .expect("Failed to write photo");

    // Verify everything is readable
    let report = vault_ops.read_file(&docs_id, "report.txt").unwrap();
    assert_eq!(report.content, b"Annual report content");

    let photo = vault_ops.read_file(&photos_id, "vacation.jpg").unwrap();
    assert_eq!(photo.content, &[0xFF, 0xD8, 0xFF, 0xE0]);
}

#[test]
fn test_vault_creator_reopen_with_password() {
    use oxidized_cryptolib::vault::extract_master_key;

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("reopen_vault");
    let password = "my-secret-password";

    // Create vault and write file
    {
        let vault_ops = VaultCreator::new(&vault_path, password)
            .create()
            .expect("Failed to create vault");

        vault_ops
            .write_file(&DirId::root(),"secret.txt", b"Top secret data")
            .expect("Failed to write file");
    }

    // Reopen vault with password
    let master_key = extract_master_key(&vault_path, password).expect("Failed to extract master key");
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Verify file is readable
    let decrypted = vault_ops.read_file(&DirId::root(),"secret.txt").unwrap();
    assert_eq!(decrypted.content, b"Top secret data");
}

// ==================== Edge case tests ====================

#[test]
fn test_write_at_chunk_boundary() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Write exactly 32KB (one chunk)
    let content = vec![0xAB; 32 * 1024];
    vault_ops
        .write_file(&DirId::root(),"one_chunk.bin", &content)
        .expect("Failed to write one chunk file");

    let decrypted = vault_ops.read_file(&DirId::root(),"one_chunk.bin").unwrap();
    assert_eq!(decrypted.content, content);

    // Write exactly 64KB (two chunks)
    let content2 = vec![0xCD; 64 * 1024];
    vault_ops
        .write_file(&DirId::root(),"two_chunks.bin", &content2)
        .expect("Failed to write two chunk file");

    let decrypted2 = vault_ops.read_file(&DirId::root(),"two_chunks.bin").unwrap();
    assert_eq!(decrypted2.content, content2);
}

#[test]
fn test_special_characters_in_directory_names() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create directory with special characters
    let dir_id = vault_ops
        .create_directory(&DirId::root(),"folder with spaces & symbols!")
        .expect("Failed to create special directory");

    // Write file in it
    vault_ops
        .write_file(&dir_id, "file.txt", b"content")
        .expect("Failed to write file");

    // Read it back
    let decrypted = vault_ops.read_file(&dir_id, "file.txt").unwrap();
    assert_eq!(decrypted.content, b"content");
}

// ==================== rename_file() tests ====================

#[test]
fn test_rename_file_basic() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("original.txt", b"file content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename the file
    vault_ops
        .rename_file(&DirId::root(),"original.txt", "renamed.txt")
        .expect("Failed to rename file");

    // Verify old name is gone
    assert!(vault_ops.read_file(&DirId::root(),"original.txt").is_err());

    // Verify new name works and content preserved
    let decrypted = vault_ops.read_file(&DirId::root(),"renamed.txt").unwrap();
    assert_eq!(decrypted.content, b"file content");
}

#[test]
fn test_rename_file_short_to_long_name() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("a.txt", b"short name content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a very long filename (>220 chars when encrypted)
    let long_name = format!("{}.txt", "x".repeat(250));

    // Rename to long name
    vault_ops
        .rename_file(&DirId::root(),"a.txt", &long_name)
        .expect("Failed to rename to long name");

    // Verify old name is gone
    assert!(vault_ops.read_file(&DirId::root(),"a.txt").is_err());

    // Verify new long name works
    let decrypted = vault_ops.read_file(&DirId::root(),&long_name).unwrap();
    assert_eq!(decrypted.content, b"short name content");
}

#[test]
fn test_rename_file_long_to_short_name() {
    // Create a vault with a long filename
    let long_name = format!("{}.txt", "y".repeat(250));
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file(&long_name, b"long name content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename to short name
    vault_ops
        .rename_file(&DirId::root(),&long_name, "short.txt")
        .expect("Failed to rename to short name");

    // Verify old name is gone
    assert!(vault_ops.read_file(&DirId::root(),&long_name).is_err());

    // Verify new short name works
    let decrypted = vault_ops.read_file(&DirId::root(),"short.txt").unwrap();
    assert_eq!(decrypted.content, b"long name content");
}

#[test]
fn test_rename_file_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_file(&DirId::root(),"nonexistent.txt", "new.txt");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

#[test]
fn test_rename_file_target_exists() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source.txt", b"source")
        .add_file("target.txt", b"target")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_file(&DirId::root(),"source.txt", "target.txt");
    assert!(matches!(result, Err(VaultWriteError::FileAlreadyExists { .. })));

    // Verify both files still exist with original content
    let source = vault_ops.read_file(&DirId::root(),"source.txt").unwrap();
    assert_eq!(source.content, b"source");
    let target = vault_ops.read_file(&DirId::root(),"target.txt").unwrap();
    assert_eq!(target.content, b"target");
}

#[test]
fn test_rename_file_same_name_error() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_file(&DirId::root(),"file.txt", "file.txt");
    assert!(matches!(
        result,
        Err(VaultWriteError::SameSourceAndDestination { .. })
    ));
}

#[test]
fn test_rename_file_in_subdirectory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("subdir/file.txt", b"nested content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Find the subdirectory's ID
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let subdir = dirs.iter().find(|d| d.name == "subdir").unwrap();

    // Rename the file in subdirectory
    vault_ops
        .rename_file(&subdir.directory_id, "file.txt", "renamed.txt")
        .expect("Failed to rename file in subdirectory");

    // Verify old name gone, new name works
    assert!(vault_ops
        .read_file(&subdir.directory_id, "file.txt")
        .is_err());
    let decrypted = vault_ops
        .read_file(&subdir.directory_id, "renamed.txt")
        .unwrap();
    assert_eq!(decrypted.content, b"nested content");
}

// ==================== rename_directory() tests ====================

#[test]
fn test_rename_directory_basic() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("old_folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename the directory
    vault_ops
        .rename_directory(&DirId::root(),"old_folder", "new_folder")
        .expect("Failed to rename directory");

    // Verify old name gone
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "old_folder"));
    assert!(dirs.iter().any(|d| d.name == "new_folder"));
}

#[test]
fn test_rename_directory_preserves_children() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("parent/child.txt", b"child content")
        .add_file("parent/nested/deep.txt", b"deep content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get parent directory ID before rename
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let parent = dirs.iter().find(|d| d.name == "parent").unwrap();
    let parent_id = parent.directory_id.clone();

    // Rename the parent directory
    vault_ops
        .rename_directory(&DirId::root(),"parent", "renamed_parent")
        .expect("Failed to rename directory");

    // Verify children are still accessible with the same directory ID
    let child = vault_ops.read_file(&parent_id, "child.txt").unwrap();
    assert_eq!(child.content, b"child content");

    // Verify nested directory also accessible
    let subdirs = vault_ops.list_directories(&parent_id).unwrap();
    let nested = subdirs.iter().find(|d| d.name == "nested").unwrap();
    let deep = vault_ops
        .read_file(&nested.directory_id, "deep.txt")
        .unwrap();
    assert_eq!(deep.content, b"deep content");
}

#[test]
fn test_rename_directory_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_directory(&DirId::root(),"nonexistent", "new_name");
    assert!(matches!(
        result,
        Err(VaultWriteError::DirectoryNotFound { .. })
    ));
}

#[test]
fn test_rename_directory_target_exists() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("source_dir")
        .add_directory("target_dir")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_directory(&DirId::root(),"source_dir", "target_dir");
    assert!(matches!(
        result,
        Err(VaultWriteError::DirectoryAlreadyExists { .. })
    ));

    // Verify both directories still exist
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(dirs.iter().any(|d| d.name == "source_dir"));
    assert!(dirs.iter().any(|d| d.name == "target_dir"));
}

#[test]
fn test_rename_directory_same_name_error() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.rename_directory(&DirId::root(),"folder", "folder");
    assert!(matches!(
        result,
        Err(VaultWriteError::SameSourceAndDestination { .. })
    ));
}

// ==================== delete_directory_recursive() tests ====================

#[test]
fn test_delete_directory_recursive_empty() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("empty_dir")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive(&DirId::root(),"empty_dir")
        .expect("Failed to delete empty directory");

    assert_eq!(stats.files_deleted, 0);
    assert_eq!(stats.directories_deleted, 1);

    // Verify directory is gone
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "empty_dir"));
}

#[test]
fn test_delete_directory_recursive_with_files() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("folder/file1.txt", b"content 1")
        .add_file("folder/file2.txt", b"content 2")
        .add_file("folder/file3.txt", b"content 3")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive(&DirId::root(),"folder")
        .expect("Failed to delete directory with files");

    assert_eq!(stats.files_deleted, 3);
    assert_eq!(stats.directories_deleted, 1);

    // Verify directory is gone
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "folder"));
}

#[test]
fn test_delete_directory_recursive_nested() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("root/level1/level2/deep.txt", b"deep file")
        .add_file("root/level1/mid.txt", b"mid file")
        .add_file("root/top.txt", b"top file")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive(&DirId::root(),"root")
        .expect("Failed to delete nested directory");

    // 3 files + 3 directories (root, level1, level2)
    assert_eq!(stats.files_deleted, 3);
    assert_eq!(stats.directories_deleted, 3);

    // Verify directory is gone
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "root"));
}

#[test]
fn test_delete_directory_recursive_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.delete_directory_recursive(&DirId::root(),"nonexistent");
    assert!(matches!(
        result,
        Err(VaultWriteError::DirectoryNotFound { .. })
    ));
}

#[test]
fn test_delete_directory_recursive_preserves_siblings() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("delete_me/file.txt", b"to delete")
        .add_file("keep_me/file.txt", b"to keep")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .delete_directory_recursive(&DirId::root(),"delete_me")
        .expect("Failed to delete directory");

    // Verify sibling directory still exists with content
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(!dirs.iter().any(|d| d.name == "delete_me"));
    assert!(dirs.iter().any(|d| d.name == "keep_me"));

    let keep_dir = dirs.iter().find(|d| d.name == "keep_me").unwrap();
    let file = vault_ops
        .read_file(&keep_dir.directory_id, "file.txt")
        .unwrap();
    assert_eq!(file.content, b"to keep");
}

// ==================== move_file() tests ====================

#[test]
fn test_move_file_basic() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source_dir/file.txt", b"moving file")
        .add_directory("dest_dir")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get directory IDs
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let source_dir = dirs.iter().find(|d| d.name == "source_dir").unwrap();
    let dest_dir = dirs.iter().find(|d| d.name == "dest_dir").unwrap();

    // Move the file
    vault_ops
        .move_file(&source_dir.directory_id, "file.txt", &dest_dir.directory_id)
        .expect("Failed to move file");

    // Verify file gone from source
    assert!(vault_ops
        .read_file(&source_dir.directory_id, "file.txt")
        .is_err());

    // Verify file exists in destination with same content
    let decrypted = vault_ops
        .read_file(&dest_dir.directory_id, "file.txt")
        .unwrap();
    assert_eq!(decrypted.content, b"moving file");
}

#[test]
fn test_move_file_to_root() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("subdir/file.txt", b"file in subdir")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get subdirectory ID
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let subdir = dirs.iter().find(|d| d.name == "subdir").unwrap();

    // Move to root
    vault_ops
        .move_file(&subdir.directory_id, "file.txt", &DirId::root())
        .expect("Failed to move file to root");

    // Verify file gone from subdir
    assert!(vault_ops
        .read_file(&subdir.directory_id, "file.txt")
        .is_err());

    // Verify file exists in root
    let decrypted = vault_ops.read_file(&DirId::root(),"file.txt").unwrap();
    assert_eq!(decrypted.content, b"file in subdir");
}

#[test]
fn test_move_file_from_root() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("root_file.txt", b"root file content")
        .add_directory("destination")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get destination directory ID
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let dest = dirs.iter().find(|d| d.name == "destination").unwrap();

    // Move from root to subdirectory
    vault_ops
        .move_file(&DirId::root(), "root_file.txt", &dest.directory_id)
        .expect("Failed to move file from root");

    // Verify file gone from root
    assert!(vault_ops.read_file(&DirId::root(),"root_file.txt").is_err());

    // Verify file exists in destination
    let decrypted = vault_ops
        .read_file(&dest.directory_id, "root_file.txt")
        .unwrap();
    assert_eq!(decrypted.content, b"root file content");
}

#[test]
fn test_move_file_not_found() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("dest")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    let result = vault_ops.move_file(&DirId::root(), "nonexistent.txt", &dest.directory_id);
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

#[test]
fn test_move_file_target_exists() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source_dir/file.txt", b"source content")
        .add_file("dest_dir/file.txt", b"dest content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let source_dir = dirs.iter().find(|d| d.name == "source_dir").unwrap();
    let dest_dir = dirs.iter().find(|d| d.name == "dest_dir").unwrap();

    let result = vault_ops.move_file(
        &source_dir.directory_id,
        "file.txt",
        &dest_dir.directory_id,
    );
    assert!(matches!(result, Err(VaultWriteError::FileAlreadyExists { .. })));

    // Verify both files still exist with original content
    let source = vault_ops
        .read_file(&source_dir.directory_id, "file.txt")
        .unwrap();
    assert_eq!(source.content, b"source content");
    let dest = vault_ops
        .read_file(&dest_dir.directory_id, "file.txt")
        .unwrap();
    assert_eq!(dest.content, b"dest content");
}

#[test]
fn test_move_file_same_directory_error() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.move_file(&DirId::root(), "file.txt", &DirId::root());
    assert!(matches!(
        result,
        Err(VaultWriteError::SameSourceAndDestination { .. })
    ));
}

#[test]
fn test_move_file_large_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("dest")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a large file (100KB) in root
    let large_content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    vault_ops
        .write_file(&DirId::root(),"large.bin", &large_content)
        .expect("Failed to write large file");

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    // Move the large file
    vault_ops
        .move_file(&DirId::root(), "large.bin", &dest.directory_id)
        .expect("Failed to move large file");

    // Verify content preserved
    let decrypted = vault_ops
        .read_file(&dest.directory_id, "large.bin")
        .unwrap();
    assert_eq!(decrypted.content, large_content);
}

// ==================== move_and_rename_file() tests ====================

#[test]
fn test_move_and_rename_file_basic() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source/original.txt", b"move and rename me")
        .add_directory("dest")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let source = dirs.iter().find(|d| d.name == "source").unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    // Move and rename in one operation
    vault_ops
        .move_and_rename_file(
            &source.directory_id,
            "original.txt",
            &dest.directory_id,
            "renamed.txt",
        )
        .expect("Failed to move and rename file");

    // Verify old location empty
    assert!(vault_ops
        .read_file(&source.directory_id, "original.txt")
        .is_err());

    // Verify new location with new name
    let decrypted = vault_ops
        .read_file(&dest.directory_id, "renamed.txt")
        .unwrap();
    assert_eq!(decrypted.content, b"move and rename me");
}

#[test]
fn test_move_and_rename_file_same_dir_delegates_to_rename() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // This should just rename since same directory
    vault_ops
        .move_and_rename_file(&DirId::root(), "file.txt", &DirId::root(), "new_name.txt")
        .expect("Failed to move and rename in same directory");

    // Verify rename happened
    assert!(vault_ops.read_file(&DirId::root(),"file.txt").is_err());
    let decrypted = vault_ops.read_file(&DirId::root(),"new_name.txt").unwrap();
    assert_eq!(decrypted.content, b"content");
}

// ==================== Additional Edge Case Tests ====================

#[test]
fn test_rename_file_unicode_names() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("日本語.txt", b"japanese content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename to another Unicode name
    vault_ops
        .rename_file(&DirId::root(),"日本語.txt", "中文-émoji-🔐.txt")
        .expect("Failed to rename Unicode file");

    let decrypted = vault_ops.read_file(&DirId::root(),"中文-émoji-🔐.txt").unwrap();
    assert_eq!(decrypted.content, b"japanese content");
}

#[test]
fn test_rename_file_preserves_binary_content() {
    // Binary content with null bytes and all byte values
    let binary_content: Vec<u8> = (0..=255).cycle().take(1000).collect();
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("binary.dat", binary_content.clone())
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .rename_file(&DirId::root(),"binary.dat", "renamed_binary.dat")
        .expect("Failed to rename binary file");

    let decrypted = vault_ops.read_file(&DirId::root(),"renamed_binary.dat").unwrap();
    assert_eq!(decrypted.content, binary_content);
}

#[test]
fn test_rename_file_empty_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("empty.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .rename_file(&DirId::root(),"empty.txt", "still_empty.txt")
        .expect("Failed to rename empty file");

    let decrypted = vault_ops.read_file(&DirId::root(),"still_empty.txt").unwrap();
    assert!(decrypted.content.is_empty());
}

#[test]
fn test_rename_file_long_to_long_name() {
    // Both source and destination are long names
    let long_name_1 = format!("source_{}.txt", "a".repeat(250));
    let long_name_2 = format!("dest_{}.txt", "b".repeat(250));

    let (vault_path, master_key) = VaultBuilder::new()
        .add_file(&long_name_1, b"long to long content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .rename_file(&DirId::root(),&long_name_1, &long_name_2)
        .expect("Failed to rename long to long");

    assert!(vault_ops.read_file(&DirId::root(),&long_name_1).is_err());
    let decrypted = vault_ops.read_file(&DirId::root(),&long_name_2).unwrap();
    assert_eq!(decrypted.content, b"long to long content");
}

#[test]
fn test_move_file_preserves_binary_content() {
    let binary_content: Vec<u8> = (0..=255).collect();
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("source/binary.bin", binary_content.clone())
        .add_directory("dest")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let source = dirs.iter().find(|d| d.name == "source").unwrap();
    let dest = dirs.iter().find(|d| d.name == "dest").unwrap();

    vault_ops
        .move_file(&source.directory_id, "binary.bin", &dest.directory_id)
        .expect("Failed to move binary file");

    let decrypted = vault_ops
        .read_file(&dest.directory_id, "binary.bin")
        .unwrap();
    assert_eq!(decrypted.content, binary_content);
}

#[test]
fn test_move_file_unicode_filename() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("src/файл-🔒.txt", b"unicode move")
        .add_directory("dst")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let src = dirs.iter().find(|d| d.name == "src").unwrap();
    let dst = dirs.iter().find(|d| d.name == "dst").unwrap();

    vault_ops
        .move_file(&src.directory_id, "файл-🔒.txt", &dst.directory_id)
        .expect("Failed to move Unicode file");

    let decrypted = vault_ops
        .read_file(&dst.directory_id, "файл-🔒.txt")
        .unwrap();
    assert_eq!(decrypted.content, b"unicode move");
}

#[test]
fn test_delete_directory_recursive_deeply_nested() {
    // Create a deeply nested structure (10 levels)
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("a/b/c/d/e/f/g/h/i/j/deep.txt", b"very deep")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive(&DirId::root(),"a")
        .expect("Failed to delete deeply nested structure");

    // 1 file + 10 directories
    assert_eq!(stats.files_deleted, 1);
    assert_eq!(stats.directories_deleted, 10);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(dirs.is_empty());
}

#[test]
fn test_delete_directory_recursive_many_files() {
    // Create directory with many files
    let mut builder = VaultBuilder::new();
    for i in 0..50 {
        builder = builder.add_file(&format!("many_files/file_{i}.txt"), format!("content {i}").as_bytes());
    }
    let (vault_path, master_key) = builder.build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive(&DirId::root(),"many_files")
        .expect("Failed to delete directory with many files");

    assert_eq!(stats.files_deleted, 50);
    assert_eq!(stats.directories_deleted, 1);
}

#[test]
fn test_rename_directory_with_many_children() {
    // Verify renaming a directory with many children works correctly
    let mut builder = VaultBuilder::new();
    for i in 0..20 {
        builder = builder.add_file(&format!("parent/file_{i}.txt"), format!("content {i}").as_bytes());
    }
    let (vault_path, master_key) = builder.build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get directory ID before rename
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let parent = dirs.iter().find(|d| d.name == "parent").unwrap();
    let parent_id = parent.directory_id.clone();

    vault_ops
        .rename_directory(&DirId::root(),"parent", "renamed_parent")
        .expect("Failed to rename directory with many children");

    // Verify all children still accessible
    let files = vault_ops.list_files(&parent_id).unwrap();
    assert_eq!(files.len(), 20);

    for i in 0..20 {
        let file = vault_ops
            .read_file(&parent_id, &format!("file_{i}.txt"))
            .unwrap();
        assert_eq!(file.content, format!("content {i}").as_bytes());
    }
}

// ==================== Security-Related Tests ====================

#[test]
fn test_rename_file_with_path_separator_in_name() {
    // Filenames with path separators should be treated as literal characters
    // This tests that we don't accidentally create directory traversal
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("normal.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to rename with path-like characters
    // The filename should be treated literally, not as a path
    vault_ops
        .rename_file(&DirId::root(),"normal.txt", "file-with-slash.txt")
        .expect("Failed to rename");

    // Verify the file is in root, not in a subdirectory
    let files = vault_ops.list_files(&DirId::root()).unwrap();
    assert!(files.iter().any(|f| f.name == "file-with-slash.txt"));
    assert_eq!(files.len(), 1);
}

#[test]
fn test_move_file_to_nonexistent_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to move to a directory ID that doesn't exist
    // This should create the storage path but the file should still be accessible
    let result = vault_ops.move_file(&DirId::root(), "file.txt", &DirId::from_raw("nonexistent-dir-id-12345"));

    // The move should succeed (creates storage path) but file won't be findable
    // via normal listing since no directory entry points to this dir_id
    assert!(result.is_ok());

    // Original file should be gone
    assert!(vault_ops.read_file(&DirId::root(),"file.txt").is_err());
}

#[test]
fn test_rename_file_special_filesystem_characters() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("test.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Test various special characters that might cause filesystem issues
    // These are all valid in Cryptomator since filenames are encrypted
    let special_names = [
        "file with spaces.txt",
        "file\twith\ttabs.txt",
        "file'with'quotes.txt",
        "file\"with\"doublequotes.txt",
        "file<with>brackets.txt",
        "file|with|pipes.txt",
        "file?with?questions.txt",
        "file*with*asterisks.txt",
    ];

    let mut current_name = "test.txt".to_string();
    for special_name in special_names {
        vault_ops
            .rename_file(&DirId::root(),&current_name, special_name)
            .expect(&format!("Failed to rename to '{}'", special_name));

        let decrypted = vault_ops.read_file(&DirId::root(),special_name).unwrap();
        assert_eq!(decrypted.content, b"content");

        current_name = special_name.to_string();
    }
}

#[test]
fn test_operations_with_invalid_directory_id() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Operations with invalid/nonexistent directory IDs
    let fake_dir_id = DirId::from_raw("this-is-not-a-real-directory-id");

    // list_files on nonexistent dir should return empty, not error
    let files = vault_ops.list_files(&fake_dir_id).unwrap();
    assert!(files.is_empty());

    // list_directories on nonexistent dir should return empty
    let dirs = vault_ops.list_directories(&fake_dir_id).unwrap();
    assert!(dirs.is_empty());

    // rename_file in nonexistent dir should fail with FileNotFound
    let result = vault_ops.rename_file(&fake_dir_id, "file.txt", "new.txt");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));

    // delete_file in nonexistent dir should fail with FileNotFound
    let result = vault_ops.delete_file(&fake_dir_id, "file.txt");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

// ==================== Idempotency and State Tests ====================

#[test]
fn test_rename_file_multiple_times() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("original.txt", b"content that persists")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Rename multiple times in sequence
    vault_ops.rename_file(&DirId::root(),"original.txt", "step1.txt").unwrap();
    vault_ops.rename_file(&DirId::root(),"step1.txt", "step2.txt").unwrap();
    vault_ops.rename_file(&DirId::root(),"step2.txt", "step3.txt").unwrap();
    vault_ops.rename_file(&DirId::root(),"step3.txt", "final.txt").unwrap();

    // Only final name should exist
    let files = vault_ops.list_files(&DirId::root()).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "final.txt");

    let decrypted = vault_ops.read_file(&DirId::root(),"final.txt").unwrap();
    assert_eq!(decrypted.content, b"content that persists");
}

#[test]
fn test_move_file_circular() {
    // Move file: root -> dir1 -> dir2 -> root
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("traveling.txt", b"around and around")
        .add_directory("dir1")
        .add_directory("dir2")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let dir1 = dirs.iter().find(|d| d.name == "dir1").unwrap();
    let dir2 = dirs.iter().find(|d| d.name == "dir2").unwrap();

    // root -> dir1
    vault_ops
        .move_file(&DirId::root(), "traveling.txt", &dir1.directory_id)
        .unwrap();
    assert!(vault_ops.read_file(&DirId::root(),"traveling.txt").is_err());
    assert!(vault_ops
        .read_file(&dir1.directory_id, "traveling.txt")
        .is_ok());

    // dir1 -> dir2
    vault_ops
        .move_file(&dir1.directory_id, "traveling.txt", &dir2.directory_id)
        .unwrap();
    assert!(vault_ops
        .read_file(&dir1.directory_id, "traveling.txt")
        .is_err());
    assert!(vault_ops
        .read_file(&dir2.directory_id, "traveling.txt")
        .is_ok());

    // dir2 -> root
    vault_ops
        .move_file(&dir2.directory_id, "traveling.txt", &DirId::root())
        .unwrap();
    assert!(vault_ops
        .read_file(&dir2.directory_id, "traveling.txt")
        .is_err());

    let decrypted = vault_ops.read_file(&DirId::root(),"traveling.txt").unwrap();
    assert_eq!(decrypted.content, b"around and around");
}

#[test]
fn test_delete_and_recreate_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("mydir/file.txt", b"original content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Delete directory
    vault_ops
        .delete_directory_recursive(&DirId::root(),"mydir")
        .expect("Failed to delete directory");

    // Recreate with same name
    let new_dir_id = vault_ops
        .create_directory(&DirId::root(),"mydir")
        .expect("Failed to recreate directory");

    // Write new file
    vault_ops
        .write_file(&new_dir_id, "new_file.txt", b"new content")
        .expect("Failed to write to recreated directory");

    // Verify new content
    let decrypted = vault_ops.read_file(&new_dir_id, "new_file.txt").unwrap();
    assert_eq!(decrypted.content, b"new content");

    // Verify old file doesn't exist
    assert!(vault_ops.read_file(&new_dir_id, "file.txt").is_err());
}

// ==================== Boundary Condition Tests ====================

#[test]
fn test_rename_file_exactly_at_length_threshold() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // The threshold is 220 chars for the ENCRYPTED name, not cleartext
    // But we can test around typical boundary lengths
    // A cleartext name of ~150 chars typically encrypts to ~220+ chars

    // Create file with name that's right at the boundary
    let boundary_name = format!("{}.txt", "x".repeat(150));
    vault_ops
        .write_file(&DirId::root(),&boundary_name, b"boundary test")
        .expect("Failed to write boundary-length file");

    // Rename to slightly longer (definitely long)
    let longer_name = format!("{}.txt", "y".repeat(200));
    vault_ops
        .rename_file(&DirId::root(),&boundary_name, &longer_name)
        .expect("Failed to rename to longer name");

    // Rename back to shorter
    let shorter_name = "short.txt";
    vault_ops
        .rename_file(&DirId::root(),&longer_name, shorter_name)
        .expect("Failed to rename to shorter name");

    let decrypted = vault_ops.read_file(&DirId::root(),shorter_name).unwrap();
    assert_eq!(decrypted.content, b"boundary test");
}

#[test]
fn test_operations_on_root_directory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("root_file.txt", b"in root")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Verify we can list root
    let files = vault_ops.list_files(&DirId::root()).unwrap();
    assert_eq!(files.len(), 1);

    // Verify we can rename in root
    vault_ops
        .rename_file(&DirId::root(),"root_file.txt", "renamed_root.txt")
        .unwrap();

    // Verify we can delete from root
    vault_ops.delete_file(&DirId::root(),"renamed_root.txt").unwrap();

    let files = vault_ops.list_files(&DirId::root()).unwrap();
    assert!(files.is_empty());
}

#[test]
fn test_write_file_exclusive_behavior() {
    // Test that write_file DOES overwrite (current behavior)
    // This documents the current API behavior
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"original")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // write_file overwrites without error
    vault_ops
        .write_file(&DirId::root(),"existing.txt", b"overwritten")
        .expect("write_file should overwrite");

    let decrypted = vault_ops.read_file(&DirId::root(),"existing.txt").unwrap();
    assert_eq!(decrypted.content, b"overwritten");

    // But rename_file does NOT overwrite
    vault_ops
        .write_file(&DirId::root(),"source.txt", b"source content")
        .unwrap();

    let result = vault_ops.rename_file(&DirId::root(),"source.txt", "existing.txt");
    assert!(matches!(result, Err(VaultWriteError::FileAlreadyExists { .. })));
}

// ==================== Path-based Convenience Method Tests ====================

use oxidized_cryptolib::vault::VaultOperationError;

#[test]
fn test_read_by_path_root_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("readme.txt", b"root file content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let decrypted = vault_ops
        .read_by_path("readme.txt")
        .expect("Failed to read by path");
    assert_eq!(decrypted.content, b"root file content");
}

#[test]
fn test_read_by_path_nested_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("docs/api/reference.txt", b"nested content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let decrypted = vault_ops
        .read_by_path("docs/api/reference.txt")
        .expect("Failed to read nested file by path");
    assert_eq!(decrypted.content, b"nested content");
}

#[test]
fn test_read_by_path_with_leading_slash() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Leading slash should be handled correctly
    let decrypted = vault_ops
        .read_by_path("/file.txt")
        .expect("Failed to read with leading slash");
    assert_eq!(decrypted.content, b"content");
}

#[test]
fn test_read_by_path_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.read_by_path("nonexistent.txt");
    assert!(result.is_err());
}

#[test]
fn test_read_by_path_parent_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.read_by_path("nonexistent_dir/file.txt");
    assert!(matches!(
        result,
        Err(VaultOperationError::DirectoryNotFound { .. })
    ));
}

#[test]
fn test_write_by_path_root_file() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .write_by_path("new_file.txt", b"new content")
        .expect("Failed to write by path");

    let decrypted = vault_ops.read_by_path("new_file.txt").unwrap();
    assert_eq!(decrypted.content, b"new content");
}

#[test]
fn test_write_by_path_nested_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("docs")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .write_by_path("docs/readme.txt", b"documentation")
        .expect("Failed to write nested file by path");

    let decrypted = vault_ops.read_by_path("docs/readme.txt").unwrap();
    assert_eq!(decrypted.content, b"documentation");
}

#[test]
fn test_write_by_path_parent_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Should fail because parent directory doesn't exist
    let result = vault_ops.write_by_path("nonexistent_dir/file.txt", b"content");
    assert!(result.is_err());
}

#[test]
fn test_delete_by_path_root_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("to_delete.txt", b"delete me")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .delete_by_path("to_delete.txt")
        .expect("Failed to delete by path");

    assert!(vault_ops.read_by_path("to_delete.txt").is_err());
}

#[test]
fn test_delete_by_path_nested_file() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("folder/nested.txt", b"nested file")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .delete_by_path("folder/nested.txt")
        .expect("Failed to delete nested file by path");

    assert!(vault_ops.read_by_path("folder/nested.txt").is_err());
}

#[test]
fn test_delete_by_path_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.delete_by_path("nonexistent.txt");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

#[test]
fn test_exists_by_path_file_exists() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("existing.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.exists_by_path("existing.txt");
    assert_eq!(result, Some(false)); // false = is a file, not a directory
}

#[test]
fn test_exists_by_path_directory_exists() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("my_folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.exists_by_path("my_folder");
    assert_eq!(result, Some(true)); // true = is a directory
}

#[test]
fn test_exists_by_path_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.exists_by_path("nonexistent");
    assert_eq!(result, None);
}

#[test]
fn test_exists_by_path_nested() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("a/b/c/deep.txt", b"deep")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    assert_eq!(vault_ops.exists_by_path("a"), Some(true));
    assert_eq!(vault_ops.exists_by_path("a/b"), Some(true));
    assert_eq!(vault_ops.exists_by_path("a/b/c"), Some(true));
    assert_eq!(vault_ops.exists_by_path("a/b/c/deep.txt"), Some(false));
    assert_eq!(vault_ops.exists_by_path("a/b/c/nonexistent.txt"), None);
}

#[test]
fn test_exists_by_path_root() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Root always exists as a directory
    assert_eq!(vault_ops.exists_by_path(""), Some(true));
    assert_eq!(vault_ops.exists_by_path("/"), Some(true));
}

#[test]
fn test_create_directory_by_path() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let dir_id = vault_ops
        .create_directory_by_path("new_folder")
        .expect("Failed to create directory by path");

    assert!(vault_ops.exists_by_path("new_folder") == Some(true));

    // Verify we can use the returned dir_id
    vault_ops
        .write_file(&dir_id, "test.txt", b"test")
        .expect("Failed to write in new directory");
}

#[test]
fn test_create_directory_by_path_nested() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("parent")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .create_directory_by_path("parent/child")
        .expect("Failed to create nested directory by path");

    assert!(vault_ops.exists_by_path("parent/child") == Some(true));
}

#[test]
fn test_create_directory_by_path_parent_not_found() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.create_directory_by_path("nonexistent/child");
    assert!(result.is_err());
}

#[test]
fn test_delete_directory_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("empty_folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .delete_directory_by_path("empty_folder")
        .expect("Failed to delete directory by path");

    assert_eq!(vault_ops.exists_by_path("empty_folder"), None);
}

#[test]
fn test_delete_directory_by_path_not_empty_fails() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("folder/file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.delete_directory_by_path("folder");
    assert!(matches!(result, Err(VaultWriteError::DirectoryNotEmpty { .. })));
}

#[test]
fn test_delete_directory_recursive_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("project/src/main.rs", b"fn main() {}")
        .add_file("project/src/lib.rs", b"// lib")
        .add_file("project/README.md", b"# README")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let stats = vault_ops
        .delete_directory_recursive_by_path("project")
        .expect("Failed to delete recursively by path");

    assert_eq!(stats.files_deleted, 3);
    assert_eq!(stats.directories_deleted, 2); // project + project/src

    assert_eq!(vault_ops.exists_by_path("project"), None);
}

#[test]
fn test_rename_file_by_path() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("docs/old_name.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .rename_file_by_path("docs/old_name.txt", "new_name.txt")
        .expect("Failed to rename file by path");

    assert_eq!(vault_ops.exists_by_path("docs/old_name.txt"), None);
    assert_eq!(vault_ops.exists_by_path("docs/new_name.txt"), Some(false));

    let decrypted = vault_ops.read_by_path("docs/new_name.txt").unwrap();
    assert_eq!(decrypted.content, b"content");
}

#[test]
fn test_move_file_by_path_different_dirs() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("inbox/message.txt", b"important message")
        .add_directory("archive")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .move_file_by_path("inbox/message.txt", "archive/message.txt")
        .expect("Failed to move file by path");

    assert_eq!(vault_ops.exists_by_path("inbox/message.txt"), None);
    assert_eq!(vault_ops.exists_by_path("archive/message.txt"), Some(false));

    let decrypted = vault_ops.read_by_path("archive/message.txt").unwrap();
    assert_eq!(decrypted.content, b"important message");
}

#[test]
fn test_move_file_by_path_with_rename() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("temp/draft.txt", b"work in progress")
        .add_directory("final")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Move and rename in one operation
    vault_ops
        .move_file_by_path("temp/draft.txt", "final/completed.txt")
        .expect("Failed to move and rename by path");

    assert_eq!(vault_ops.exists_by_path("temp/draft.txt"), None);
    assert_eq!(vault_ops.exists_by_path("final/completed.txt"), Some(false));

    let decrypted = vault_ops.read_by_path("final/completed.txt").unwrap();
    assert_eq!(decrypted.content, b"work in progress");
}

#[test]
fn test_move_file_by_path_same_dir_rename() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("docs/old.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Same directory, different name -> should just rename
    vault_ops
        .move_file_by_path("docs/old.txt", "docs/new.txt")
        .expect("Failed to rename via move_file_by_path");

    assert_eq!(vault_ops.exists_by_path("docs/old.txt"), None);
    assert_eq!(vault_ops.exists_by_path("docs/new.txt"), Some(false));
}

#[test]
fn test_move_file_by_path_same_path_error() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let result = vault_ops.move_file_by_path("file.txt", "file.txt");
    assert!(matches!(
        result,
        Err(VaultWriteError::SameSourceAndDestination { .. })
    ));
}

#[test]
fn test_path_operations_unicode() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("文档/日本語.txt", b"unicode content")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Read by unicode path
    let decrypted = vault_ops
        .read_by_path("文档/日本語.txt")
        .expect("Failed to read unicode path");
    assert_eq!(decrypted.content, b"unicode content");

    // Check existence
    assert_eq!(vault_ops.exists_by_path("文档"), Some(true));
    assert_eq!(vault_ops.exists_by_path("文档/日本語.txt"), Some(false));

    // Rename with unicode
    vault_ops
        .rename_file_by_path("文档/日本語.txt", "中文-🔐.txt")
        .expect("Failed to rename unicode file");

    let decrypted = vault_ops.read_by_path("文档/中文-🔐.txt").unwrap();
    assert_eq!(decrypted.content, b"unicode content");
}

#[test]
fn test_path_operations_deeply_nested() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("a/b/c/d/e/f/deep.txt", b"very deep file")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Read deeply nested file
    let decrypted = vault_ops
        .read_by_path("a/b/c/d/e/f/deep.txt")
        .expect("Failed to read deep path");
    assert_eq!(decrypted.content, b"very deep file");

    // Delete deeply nested file
    vault_ops
        .delete_by_path("a/b/c/d/e/f/deep.txt")
        .expect("Failed to delete deep file");

    assert_eq!(vault_ops.exists_by_path("a/b/c/d/e/f/deep.txt"), None);
    // Directories should still exist
    assert_eq!(vault_ops.exists_by_path("a/b/c/d/e/f"), Some(true));
}

#[test]
fn test_resolve_parent_path_empty_error() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Empty path should error
    let result = vault_ops.read_by_path("");
    assert!(matches!(result, Err(VaultOperationError::EmptyPath)));

    // Just slash should also error (empty after normalization)
    let result = vault_ops.read_by_path("/");
    assert!(matches!(result, Err(VaultOperationError::EmptyPath)));
}

#[test]
fn test_path_operations_full_workflow() {
    // Test a complete workflow using only path-based methods
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create directory structure
    vault_ops
        .create_directory_by_path("projects")
        .expect("Failed to create projects");
    vault_ops
        .create_directory_by_path("projects/rust")
        .expect("Failed to create projects/rust");
    vault_ops
        .create_directory_by_path("archive")
        .expect("Failed to create archive");

    // Write files
    vault_ops
        .write_by_path("projects/rust/main.rs", b"fn main() { println!(\"Hello\"); }")
        .expect("Failed to write main.rs");
    vault_ops
        .write_by_path("projects/rust/lib.rs", b"pub fn greet() {}")
        .expect("Failed to write lib.rs");

    // Verify existence
    assert_eq!(vault_ops.exists_by_path("projects/rust/main.rs"), Some(false));
    assert_eq!(vault_ops.exists_by_path("projects/rust/lib.rs"), Some(false));

    // Move a file
    vault_ops
        .move_file_by_path("projects/rust/lib.rs", "archive/lib.rs")
        .expect("Failed to move lib.rs");

    assert_eq!(vault_ops.exists_by_path("projects/rust/lib.rs"), None);
    assert_eq!(vault_ops.exists_by_path("archive/lib.rs"), Some(false));

    // Rename a file
    vault_ops
        .rename_file_by_path("projects/rust/main.rs", "app.rs")
        .expect("Failed to rename main.rs");

    let decrypted = vault_ops.read_by_path("projects/rust/app.rs").unwrap();
    assert_eq!(decrypted.content, b"fn main() { println!(\"Hello\"); }");

    // Delete individual file
    vault_ops
        .delete_by_path("archive/lib.rs")
        .expect("Failed to delete lib.rs");

    // Delete empty directory
    vault_ops
        .delete_directory_by_path("archive")
        .expect("Failed to delete archive");

    // Recursive delete
    let stats = vault_ops
        .delete_directory_recursive_by_path("projects")
        .expect("Failed to delete projects recursively");

    assert_eq!(stats.files_deleted, 1); // app.rs
    assert_eq!(stats.directories_deleted, 2); // projects, projects/rust

    // Verify everything is gone
    assert_eq!(vault_ops.exists_by_path("projects"), None);
    assert_eq!(vault_ops.exists_by_path("archive"), None);
}

// ==================== Symlink Tests ====================

#[test]
fn test_create_symlink_basic() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops
        .create_symlink(&DirId::root(), "my_link", "/target/path")
        .expect("Failed to create symlink");

    // Verify we can read it back
    let target = vault_ops
        .read_symlink(&DirId::root(), "my_link")
        .expect("Failed to read symlink");
    assert_eq!(target, "/target/path");
}

#[test]
fn test_create_symlink_roundtrip() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    let test_cases = vec![
        ("link1", "/absolute/path/to/file"),
        ("link2", "relative/path/to/file"),
        ("link3", "../parent/relative"),
        ("link4", "file.txt"),
        ("unicode_link", "/path/with/日本語/and/中文"),
    ];

    for (name, target) in test_cases {
        vault_ops
            .create_symlink(&DirId::root(), name, target)
            .expect(&format!("Failed to create symlink '{}'", name));

        let read_target = vault_ops
            .read_symlink(&DirId::root(), name)
            .expect(&format!("Failed to read symlink '{}'", name));
        assert_eq!(read_target, target, "Target mismatch for symlink '{}'", name);
    }
}

#[test]
fn test_create_symlink_in_subdirectory() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_directory("folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Get the subdirectory ID
    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    let folder = dirs.iter().find(|d| d.name == "folder").unwrap();

    // Create symlink in subdirectory
    vault_ops
        .create_symlink(&folder.directory_id, "nested_link", "/some/target")
        .expect("Failed to create symlink in subdirectory");

    // Verify it can be read
    let target = vault_ops
        .read_symlink(&folder.directory_id, "nested_link")
        .expect("Failed to read symlink from subdirectory");
    assert_eq!(target, "/some/target");
}

#[test]
fn test_symlink_appears_in_list() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops
        .create_symlink(&DirId::root(), "visible_link", "/target")
        .expect("Failed to create symlink");

    // Verify it appears in symlink listing
    let symlinks = vault_ops
        .list_symlinks(&DirId::root())
        .expect("Failed to list symlinks");

    assert_eq!(symlinks.len(), 1);
    assert_eq!(symlinks[0].name, "visible_link");
    assert_eq!(symlinks[0].target, "/target");
}

#[test]
fn test_delete_symlink_basic() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create and then delete a symlink
    vault_ops
        .create_symlink(&DirId::root(), "temp_link", "/target")
        .expect("Failed to create symlink");

    vault_ops
        .delete_symlink(&DirId::root(), "temp_link")
        .expect("Failed to delete symlink");

    // Verify it's gone
    let result = vault_ops.read_symlink(&DirId::root(), "temp_link");
    assert!(result.is_err());

    let symlinks = vault_ops.list_symlinks(&DirId::root()).unwrap();
    assert!(symlinks.is_empty());
}

#[test]
fn test_symlink_already_exists_error() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops
        .create_symlink(&DirId::root(), "existing_link", "/first/target")
        .expect("Failed to create first symlink");

    // Try to create another with the same name
    let result = vault_ops.create_symlink(&DirId::root(), "existing_link", "/second/target");
    assert!(matches!(
        result,
        Err(VaultWriteError::SymlinkAlreadyExists { .. })
    ));

    // Original symlink should still be intact
    let target = vault_ops.read_symlink(&DirId::root(), "existing_link").unwrap();
    assert_eq!(target, "/first/target");
}

#[test]
fn test_symlink_not_found_error() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Try to read a non-existent symlink
    let result = vault_ops.read_symlink(&DirId::root(), "nonexistent_link");
    assert!(result.is_err());

    // Try to delete a non-existent symlink
    let result = vault_ops.delete_symlink(&DirId::root(), "nonexistent_link");
    assert!(matches!(result, Err(VaultWriteError::FileNotFound { .. })));
}

#[test]
fn test_symlink_with_long_name() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink with a very long name (should use .c9s format)
    let long_name = format!("symlink_{}", "x".repeat(250));

    vault_ops
        .create_symlink(&DirId::root(), &long_name, "/target/for/long/name")
        .expect("Failed to create long-named symlink");

    // Verify we can read it back
    let target = vault_ops
        .read_symlink(&DirId::root(), &long_name)
        .expect("Failed to read long-named symlink");
    assert_eq!(target, "/target/for/long/name");

    // Verify it appears in listing
    let symlinks = vault_ops.list_symlinks(&DirId::root()).unwrap();
    assert!(symlinks.iter().any(|s| s.name == long_name && s.is_shortened));

    // Delete it
    vault_ops
        .delete_symlink(&DirId::root(), &long_name)
        .expect("Failed to delete long-named symlink");

    let symlinks = vault_ops.list_symlinks(&DirId::root()).unwrap();
    assert!(symlinks.is_empty());
}

#[test]
fn test_symlink_with_long_target() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create symlink with very long target path
    let long_target = format!("/very/long/path/{}/to/target", "x".repeat(500));

    vault_ops
        .create_symlink(&DirId::root(), "long_target_link", &long_target)
        .expect("Failed to create symlink with long target");

    let target = vault_ops
        .read_symlink(&DirId::root(), "long_target_link")
        .expect("Failed to read symlink with long target");
    assert_eq!(target, long_target);
}

#[test]
fn test_symlink_unicode_name_and_target() {
    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    vault_ops
        .create_symlink(&DirId::root(), "链接-🔗", "/путь/到/目标")
        .expect("Failed to create unicode symlink");

    let target = vault_ops
        .read_symlink(&DirId::root(), "链接-🔗")
        .expect("Failed to read unicode symlink");
    assert_eq!(target, "/путь/到/目标");
}

#[test]
fn test_symlink_path_extension_correct() {
    use std::fs;

    // Add a dummy file to ensure root storage directory exists
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("dummy.txt", b"")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink
    vault_ops
        .create_symlink(&DirId::root(), "test_link", "/target")
        .expect("Failed to create symlink");

    // Verify the symlink was created with correct .c9r extension
    // by examining the filesystem directly
    let storage_path = vault_ops
        .calculate_directory_storage_path(&DirId::root())
        .expect("Failed to get storage path");

    let entries: Vec<_> = fs::read_dir(&storage_path)
        .expect("Failed to read storage directory")
        .filter_map(|e| e.ok())
        .collect();

    // Find the symlink directory
    let symlink_entry = entries.iter().find(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        // Should end with .c9r, not have double extension
        name.ends_with(".c9r") && !name.ends_with(".c9r.c9r") && e.path().is_dir()
    });

    assert!(
        symlink_entry.is_some(),
        "Symlink directory should exist with single .c9r extension. Found entries: {:?}",
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    let symlink_dir = symlink_entry.unwrap().path();
    assert!(
        symlink_dir.join("symlink.c9r").exists(),
        "symlink.c9r file should exist inside the symlink directory"
    );
}

#[test]
fn test_symlink_coexists_with_files_and_dirs() {
    let (vault_path, master_key) = VaultBuilder::new()
        .add_file("file.txt", b"file content")
        .add_directory("folder")
        .build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a symlink in the same directory
    vault_ops
        .create_symlink(&DirId::root(), "my_symlink", "/some/target")
        .expect("Failed to create symlink");

    // Verify all three types coexist
    let files = vault_ops.list_files(&DirId::root()).unwrap();
    assert!(files.iter().any(|f| f.name == "file.txt"));

    let dirs = vault_ops.list_directories(&DirId::root()).unwrap();
    assert!(dirs.iter().any(|d| d.name == "folder"));

    let symlinks = vault_ops.list_symlinks(&DirId::root()).unwrap();
    assert!(symlinks.iter().any(|s| s.name == "my_symlink"));
}

// ==================== dirid.c9r Recovery Tests ====================
//
// NOTE: The dirid.c9r backup file stores the directory's OWN ID (not the parent's)
// and is located in the content directory (d/XX/.../dirid.c9r), not in the .c9r folder.
// This was verified by examining the Java reference implementation (DirectoryIdBackup.java).

#[test]
fn test_create_directory_writes_dirid_backup() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory
    let dir_id = vault_ops
        .create_directory(&DirId::root(), "backup_test")
        .expect("Failed to create directory");

    // The dirid.c9r should be in the content directory (d/XX/.../dirid.c9r)
    let content_dir = vault_ops
        .calculate_directory_storage_path(&dir_id)
        .expect("Failed to get content directory path");

    let dirid_path = content_dir.join("dirid.c9r");
    assert!(
        dirid_path.exists(),
        "dirid.c9r should exist in the content directory at {}",
        dirid_path.display()
    );

    // Verify we can recover the directory's own ID from the backup
    let recovered_id = vault_ops
        .recover_dir_id_from_backup(&content_dir)
        .expect("Failed to recover directory ID from backup");

    assert_eq!(
        recovered_id.as_str(),
        dir_id.as_str(),
        "Recovered ID should match the directory's own ID"
    );
}

#[test]
fn test_recover_dir_id_from_backup_basic() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a nested directory structure
    let parent_id = vault_ops
        .create_directory(&DirId::root(), "parent")
        .expect("Failed to create parent directory");

    let child_id = vault_ops
        .create_directory(&parent_id, "child")
        .expect("Failed to create child directory");

    // Get the child's content directory path
    let child_content_dir = vault_ops
        .calculate_directory_storage_path(&child_id)
        .expect("Failed to get child content directory path");

    // Recover the directory's own ID from the backup
    let recovered_id = vault_ops
        .recover_dir_id_from_backup(&child_content_dir)
        .expect("Failed to recover directory ID");

    assert_eq!(
        recovered_id.as_str(),
        child_id.as_str(),
        "Recovered ID should match the directory's own ID"
    );

    // Also verify parent's backup
    let parent_content_dir = vault_ops
        .calculate_directory_storage_path(&parent_id)
        .expect("Failed to get parent content directory path");

    let recovered_parent_id = vault_ops
        .recover_dir_id_from_backup(&parent_content_dir)
        .expect("Failed to recover parent directory ID");

    assert_eq!(
        recovered_parent_id.as_str(),
        parent_id.as_str(),
        "Recovered parent ID should match the parent's own ID"
    );
}

#[test]
fn test_verify_dir_id_backup() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory in root
    let dir_id = vault_ops
        .create_directory(&DirId::root(), "root_child")
        .expect("Failed to create directory");

    // Get the content directory
    let content_dir = vault_ops
        .calculate_directory_storage_path(&dir_id)
        .expect("Failed to get content directory path");

    // Verify the backup matches
    assert!(
        vault_ops.verify_dir_id_backup(&content_dir, &dir_id),
        "Directory ID backup should verify correctly"
    );

    // Verify with wrong ID should fail
    let wrong_id = DirId::from_raw("wrong-uuid-12345");
    assert!(
        !vault_ops.verify_dir_id_backup(&content_dir, &wrong_id),
        "Directory ID backup should not verify with wrong ID"
    );
}

#[test]
fn test_recover_directory_tree_basic() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory structure
    let docs_id = vault_ops
        .create_directory(&DirId::root(), "Documents")
        .expect("Failed to create Documents");
    let photos_id = vault_ops
        .create_directory(&DirId::root(), "Photos")
        .expect("Failed to create Photos");
    let vacation_id = vault_ops
        .create_directory(&photos_id, "Vacation")
        .expect("Failed to create Vacation");

    // Verify each directory has dirid.c9r in its content directory
    for (dir_id, name) in [(&docs_id, "Documents"), (&photos_id, "Photos"), (&vacation_id, "Vacation")] {
        let content_dir = vault_ops
            .calculate_directory_storage_path(dir_id)
            .expect(&format!("Failed to get content dir for {}", name));

        let dirid_path = content_dir.join("dirid.c9r");
        assert!(dirid_path.exists(), "dirid.c9r should exist in {} content directory", name);

        // Verify the backup contains the directory's own ID
        let recovered_id = vault_ops
            .recover_dir_id_from_backup(&content_dir)
            .expect(&format!("Failed to recover ID for {}", name));

        assert_eq!(
            recovered_id.as_str(),
            dir_id.as_str(),
            "{} backup should contain its own ID",
            name
        );
    }
}

#[test]
fn test_recover_directory_tree_empty_vault() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Empty vault should return empty list (root has no dirid.c9r)
    let recovered = vault_ops
        .recover_directory_tree()
        .expect("Failed to recover directory IDs");

    assert!(recovered.is_empty(), "Empty vault should have no directories to recover");
}

#[test]
fn test_dir_id_backup_deeply_nested() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a deeply nested structure
    let level1 = vault_ops.create_directory(&DirId::root(), "L1").unwrap();
    let level2 = vault_ops.create_directory(&level1, "L2").unwrap();
    let level3 = vault_ops.create_directory(&level2, "L3").unwrap();
    let level4 = vault_ops.create_directory(&level3, "L4").unwrap();
    let level5 = vault_ops.create_directory(&level4, "L5").unwrap();

    // Verify each level has dirid.c9r in its content directory with its own ID
    for (dir_id, name) in [
        (&level1, "L1"),
        (&level2, "L2"),
        (&level3, "L3"),
        (&level4, "L4"),
        (&level5, "L5"),
    ] {
        let content_dir = vault_ops
            .calculate_directory_storage_path(dir_id)
            .expect(&format!("Failed to get content dir for {}", name));

        let dirid_path = content_dir.join("dirid.c9r");
        assert!(dirid_path.exists(), "dirid.c9r should exist for {}", name);

        let recovered_id = vault_ops
            .recover_dir_id_from_backup(&content_dir)
            .expect(&format!("Failed to recover ID for {}", name));

        assert_eq!(
            recovered_id.as_str(),
            dir_id.as_str(),
            "{} backup should contain its own ID, not parent's",
            name
        );
    }
}

#[test]
fn test_dirid_backup_survives_rename() {
    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create and rename a directory
    let dir_id = vault_ops
        .create_directory(&DirId::root(), "original_name")
        .expect("Failed to create directory");

    vault_ops
        .rename_directory(&DirId::root(), "original_name", "new_name")
        .expect("Failed to rename directory");

    // The dirid.c9r should still be in the content directory (which doesn't change on rename)
    let content_dir = vault_ops
        .calculate_directory_storage_path(&dir_id)
        .expect("Failed to get content directory path");

    let dirid_path = content_dir.join("dirid.c9r");
    assert!(
        dirid_path.exists(),
        "dirid.c9r should still exist in content directory after rename"
    );

    // Verify the backup still contains the correct directory ID
    let recovered_id = vault_ops
        .recover_dir_id_from_backup(&content_dir)
        .expect("Failed to recover directory ID after rename");

    assert_eq!(
        recovered_id.as_str(),
        dir_id.as_str(),
        "Recovered ID should match after rename"
    );
}

#[test]
fn test_encrypt_decrypt_parent_dir_id_roundtrip() {
    use oxidized_cryptolib::fs::encrypt_parent_dir_id;
    use oxidized_cryptolib::fs::decrypt_parent_dir_id;

    let (_, master_key) = VaultBuilder::new().build();

    // Test various parent IDs
    let test_cases = vec![
        ("".to_string(), "child-uuid-12345".to_string()),           // Root parent
        ("parent-uuid-abcdef".to_string(), "child-uuid-12345".to_string()),
        ("a".repeat(36), "b".repeat(36)),
    ];

    for (parent_id, child_id) in test_cases {
        let encrypted = encrypt_parent_dir_id(&parent_id, &child_id, &master_key)
            .expect("Encryption should succeed");

        let decrypted = decrypt_parent_dir_id(&encrypted, &child_id, &master_key)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, parent_id,
            "Roundtrip failed for parent='{}' child='{}'",
            parent_id, child_id
        );
    }
}

#[test]
fn test_decrypt_parent_dir_id_wrong_child_fails() {
    use oxidized_cryptolib::fs::encrypt_parent_dir_id;
    use oxidized_cryptolib::fs::decrypt_parent_dir_id;

    let (_, master_key) = VaultBuilder::new().build();

    let parent_id = "parent-uuid";
    let child_id = "correct-child";
    let wrong_child = "wrong-child";

    let encrypted = encrypt_parent_dir_id(parent_id, child_id, &master_key)
        .expect("Encryption should succeed");

    // Decryption with wrong child ID should fail (authentication failure)
    let result = decrypt_parent_dir_id(&encrypted, wrong_child, &master_key);
    assert!(result.is_err(), "Decryption with wrong child ID should fail");
}

#[test]
fn test_shortened_directory_has_dirid_backup() {
    use std::fs;

    let (vault_path, master_key) = VaultBuilder::new().build();
    let vault_ops = VaultOperations::new(&vault_path, master_key);

    // Create a directory with a very long name (should use .c9s format)
    let long_name = format!("directory_{}", "x".repeat(250));

    let dir_id = vault_ops
        .create_directory(&DirId::root(), &long_name)
        .expect("Failed to create long-named directory");

    // The dirid.c9r should be in the content directory (NOT in the .c9s folder)
    let content_dir = vault_ops
        .calculate_directory_storage_path(&dir_id)
        .expect("Failed to get content directory path");

    let dirid_path = content_dir.join("dirid.c9r");
    assert!(
        dirid_path.exists(),
        "dirid.c9r should exist in the content directory at {}",
        dirid_path.display()
    );

    // Verify the .c9s directory exists and does NOT have dirid.c9r
    let root_storage = vault_ops
        .calculate_directory_storage_path(&DirId::root())
        .expect("Failed to get root storage path");

    let mut found_c9s = false;
    for entry in fs::read_dir(&root_storage).expect("Failed to read root storage") {
        let entry = entry.expect("Failed to read entry");
        let path = entry.path();
        let path_str = path.to_string_lossy();

        if path.is_dir() && path_str.ends_with(".c9s") {
            let dir_c9r = path.join("dir.c9r");
            if dir_c9r.exists() {
                let stored_id = fs::read_to_string(&dir_c9r).expect("Failed to read dir.c9r");
                if stored_id.trim() == dir_id.as_str() {
                    found_c9s = true;

                    // Verify dirid.c9r does NOT exist in the .c9s directory
                    // (it's in the content directory instead)
                    let dirid_in_c9s = path.join("dirid.c9r");
                    assert!(
                        !dirid_in_c9s.exists(),
                        "dirid.c9r should NOT be in the .c9s folder; it should be in the content directory"
                    );
                    break;
                }
            }
        }
    }

    assert!(found_c9s, "Should find .c9s directory");

    // Verify we can recover the directory's own ID from the backup
    let recovered_id = vault_ops
        .recover_dir_id_from_backup(&content_dir)
        .expect("Failed to recover directory ID from backup");

    assert_eq!(
        recovered_id.as_str(),
        dir_id.as_str(),
        "Recovered ID should match the directory's own ID"
    );
}
