//! Directory traversal and tree building for Cryptomator vaults.
//!
//! This module provides the [`VaultExplorer`] for traversing encrypted vault
//! directory structures and building a cleartext representation of the file tree.
//!
//! # Reference Implementation
//!
//! - Java: [`CryptoPathMapper`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoPathMapper.java)
//!   handles path resolution and directory ID management
//! - Java: [`CryptoDirectoryStream`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/dir/CryptoDirectoryStream.java)
//!   provides directory listing functionality

use crate::crypto::keys::MasterKey;
use crate::fs::name::{decrypt_filename, hash_dir_id, NameError};
use crate::fs::symlink::decrypt_symlink_target;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during directory exploration operations.
#[derive(Error, Debug)]
pub enum DirectoryError {
    /// IO error during directory operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Filename or directory ID encryption/decryption error.
    ///
    /// Note: Decryption failures may indicate **integrity violations** -
    /// see `NameError` documentation for security classification.
    #[error("Name error: {0}")]
    Name(#[from] NameError),

    /// The vault structure is invalid or corrupted.
    #[error("Invalid vault structure: {0}")]
    InvalidStructure(String),

    /// A required file is missing from the vault.
    #[error("Missing file: {0}")]
    MissingFile(PathBuf),
}

/// The type of a directory entry.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory with its unique ID.
    Directory { id: String },
    /// A symbolic link with its target path.
    Symlink { target: String },
}

impl EntryKind {
    /// Returns true if this is a directory.
    pub fn is_directory(&self) -> bool {
        matches!(self, EntryKind::Directory { .. })
    }

    /// Returns true if this is a file.
    pub fn is_file(&self) -> bool {
        matches!(self, EntryKind::File)
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self, EntryKind::Symlink { .. })
    }

    /// Returns the directory ID if this is a directory.
    pub fn directory_id(&self) -> Option<&str> {
        match self {
            EntryKind::Directory { id } => Some(id),
            _ => None,
        }
    }

    /// Returns the symlink target if this is a symlink.
    pub fn symlink_target(&self) -> Option<&str> {
        match self {
            EntryKind::Symlink { target } => Some(target),
            _ => None,
        }
    }
}

/// A decrypted directory entry in the vault.
#[derive(Debug)]
pub struct DirectoryEntry {
    /// The decrypted name of this entry.
    pub name: String,
    /// The encrypted path on disk.
    pub path: PathBuf,
    /// The type of this entry (file, directory, or symlink).
    pub kind: EntryKind,
    /// Child entries (only populated for directories).
    pub children: Vec<DirectoryEntry>,
}

impl DirectoryEntry {
    /// Returns true if this is a directory.
    pub fn is_directory(&self) -> bool {
        self.kind.is_directory()
    }

    /// Returns true if this is a file.
    pub fn is_file(&self) -> bool {
        self.kind.is_file()
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.kind.is_symlink()
    }

    /// Returns the directory ID if this is a directory.
    pub fn directory_id(&self) -> Option<&str> {
        self.kind.directory_id()
    }

    /// Returns the symlink target if this is a symlink.
    pub fn symlink_target(&self) -> Option<&str> {
        self.kind.symlink_target()
    }
}

/// Explores an encrypted Cryptomator vault and builds a cleartext directory tree.
///
/// # Reference Implementation
///
/// - Java: [`CryptoPathMapper`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoPathMapper.java)
///   provides the `getCiphertextDir()` method for resolving directory IDs to paths
/// - Java: [`CryptoDirectoryStream`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/dir/CryptoDirectoryStream.java)
///   iterates over encrypted directory contents
pub struct VaultExplorer {
    vault_path: PathBuf,
}

impl VaultExplorer {
    pub fn new(vault_path: &Path) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
        }
    }

    pub fn build_directory_tree(
        &self,
        master_key: &MasterKey,
    ) -> Result<DirectoryEntry, DirectoryError> {
        let dir_map = self.build_directory_map()?;

        let mut root = DirectoryEntry {
            name: "/".to_string(),
            path: self.vault_path.clone(),
            kind: EntryKind::Directory { id: String::new() }, // Root directory ID is empty string
            children: vec![],
        };

        println!("\n[DEBUG] Starting directory tree build from root");
        self.explore_directory(&mut root, master_key, &dir_map)?;

        Ok(root)
    }

    fn build_directory_map(&self) -> Result<HashMap<String, String>, DirectoryError> {
        let mut dir_map = HashMap::new();
        let d_dir = self.vault_path.join("d");

        // Walk through all directories under /d/
        for prefix_entry in fs::read_dir(&d_dir)? {
            let prefix_entry = prefix_entry?;
            let prefix_path = prefix_entry.path();

            if prefix_path.is_dir() {
                for hash_entry in fs::read_dir(&prefix_path)? {
                    let hash_entry = hash_entry?;
                    let hash_path = hash_entry.path();

                    if hash_path.is_dir() {
                        // Note: dirid.c9r files are encrypted, not plain text
                        // We'll skip the directory mapping for now and rely on dir.c9r files
                        let hash_name = hash_path
                            .file_name()
                            .ok_or_else(|| DirectoryError::InvalidStructure(
                                format!("Directory path has no filename: {:?}", hash_path)
                            ))?
                            .to_string_lossy()
                            .to_string();
                        println!("[DEBUG] Found directory: {hash_name}");
                        // For now, just note that this directory exists
                        dir_map.insert(hash_name, "unknown".to_string());
                    }
                }
            }
        }

        Ok(dir_map)
    }

    fn explore_directory(
        &self,
        parent_entry: &mut DirectoryEntry,
        master_key: &MasterKey,
        dir_map: &HashMap<String, String>,
    ) -> Result<(), DirectoryError> {
        // Clone the directory ID to avoid borrow issues
        let parent_dir_id = parent_entry
            .directory_id()
            .ok_or_else(|| DirectoryError::InvalidStructure(
                format!("Directory '{}' has no directory ID", parent_entry.name)
            ))?
            .to_string();

        println!(
            "\n[DEBUG] Exploring directory: {} (ID: '{}')",
            parent_entry.name, parent_dir_id
        );

        // Calculate storage path for this directory
        let storage_path = self.calculate_directory_path(&parent_dir_id, master_key)?;
        println!("[DEBUG] Storage path: {storage_path:?}");

        if !storage_path.exists() {
            println!("[DEBUG] Storage path doesn't exist, directory is empty");
            return Ok(());
        }

        self.process_items_in_directory(
            parent_entry,
            &storage_path,
            &parent_dir_id,
            master_key,
            dir_map,
        )?;

        Ok(())
    }

    fn process_items_in_directory(
        &self,
        parent_entry: &mut DirectoryEntry,
        dir_path: &Path,
        parent_dir_id: &str,
        master_key: &MasterKey,
        dir_map: &HashMap<String, String>,
    ) -> Result<(), DirectoryError> {
        println!("\n[DEBUG] Processing items in directory: {dir_path:?}");
        println!(
            "[DEBUG] Parent directory ID for decryption: '{parent_dir_id}'"
        );

        let mut item_count = 0;

        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            println!(
                "[DEBUG] Found item: {} (is_dir: {})",
                file_name,
                path.is_dir()
            );
            item_count += 1;

            // Skip special files
            if file_name == "dirid.c9r" {
                println!("[DEBUG] Skipping dirid.c9r");
                continue;
            }

            // Process based on file type
            if file_name.ends_with(".c9r") {
                if path.is_dir() {
                    // This is a directory
                    self.process_directory(&path, &file_name, parent_dir_id, master_key, parent_entry, dir_map)?;
                } else {
                    // This is a regular file
                    self.process_file(&path, &file_name, parent_dir_id, master_key, parent_entry)?;
                }
            } else if file_name.ends_with(".c9s") {
                // Handle shortened names
                self.process_shortened_item(&path, &file_name, parent_dir_id, master_key, parent_entry, dir_map)?;
            }
        }

        println!("[DEBUG] Processed {item_count} items in directory");

        // Sort children by name for consistent output
        parent_entry.children.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(())
    }

    fn process_directory(
        &self,
        path: &Path,
        file_name: &str,
        parent_dir_id: &str,
        master_key: &MasterKey,
        parent_entry: &mut DirectoryEntry,
        dir_map: &HashMap<String, String>,
    ) -> Result<(), DirectoryError> {
        println!("[DEBUG] Processing directory: {file_name}");

        // Check if this is a symlink (has symlink.c9r)
        let symlink_file = path.join("symlink.c9r");
        if symlink_file.exists() {
            println!("[DEBUG] Found symlink.c9r - processing as symlink");
            return self.process_symlink(path, file_name, parent_dir_id, master_key, parent_entry, false);
        }

        match self.read_directory_id(path) {
            Ok(dir_id) => {
                println!("[DEBUG] Directory ID: '{dir_id}'");

                match decrypt_filename(file_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted directory name: {decrypted_name}");

                        let mut dir_entry = DirectoryEntry {
                            name: decrypted_name,
                            path: path.to_path_buf(),
                            kind: EntryKind::Directory { id: dir_id },
                            children: vec![],
                        };

                        // Recursively explore this directory
                        self.explore_directory(&mut dir_entry, master_key, dir_map)?;
                        parent_entry.children.push(dir_entry);
                    }
                    Err(e) => {
                        println!(
                            "[ERROR] Failed to decrypt directory name {file_name}: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                println!(
                    "[ERROR] Failed to read directory ID from {}: {}",
                    path.display(),
                    e
                );
            }
        }

        Ok(())
    }

    fn process_file(
        &self,
        path: &Path,
        file_name: &str,
        parent_dir_id: &str,
        master_key: &MasterKey,
        parent_entry: &mut DirectoryEntry,
    ) -> Result<(), DirectoryError> {
        println!("[DEBUG] Processing file: {file_name}");

        match decrypt_filename(file_name, parent_dir_id, master_key) {
            Ok(decrypted_name) => {
                println!("[DEBUG] Decrypted file name: {decrypted_name}");

                parent_entry.children.push(DirectoryEntry {
                    name: decrypted_name,
                    path: path.to_path_buf(),
                    kind: EntryKind::File,
                    children: vec![],
                });
            }
            Err(e) => {
                println!("[ERROR] Failed to decrypt file name {file_name}: {e}");
            }
        }

        Ok(())
    }

    fn process_symlink(
        &self,
        path: &Path,
        file_name: &str,
        parent_dir_id: &str,
        master_key: &MasterKey,
        parent_entry: &mut DirectoryEntry,
        _is_shortened: bool,
    ) -> Result<(), DirectoryError> {
        // For shortened symlinks, file_name is the original encrypted name from name.c9s
        // For regular symlinks, file_name is the .c9r directory name
        let encrypted_name = file_name;

        println!("[DEBUG] Processing symlink: {encrypted_name}");

        match decrypt_filename(encrypted_name, parent_dir_id, master_key) {
            Ok(decrypted_name) => {
                println!("[DEBUG] Decrypted symlink name: {decrypted_name}");

                // Read and decrypt the symlink target
                let symlink_file = path.join("symlink.c9r");
                match fs::read(&symlink_file) {
                    Ok(encrypted_data) => {
                        match decrypt_symlink_target(&encrypted_data, master_key) {
                            Ok(target) => {
                                println!("[DEBUG] Symlink target: {target}");
                                parent_entry.children.push(DirectoryEntry {
                                    name: decrypted_name,
                                    path: path.to_path_buf(),
                                    kind: EntryKind::Symlink { target },
                                    children: vec![],
                                });
                            }
                            Err(e) => {
                                println!("[ERROR] Failed to decrypt symlink target: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to read symlink.c9r: {e}");
                    }
                }
            }
            Err(e) => {
                println!("[ERROR] Failed to decrypt symlink name {encrypted_name}: {e}");
            }
        }

        Ok(())
    }

    fn process_shortened_item(
        &self,
        path: &Path,
        file_name: &str,
        parent_dir_id: &str,
        master_key: &MasterKey,
        parent_entry: &mut DirectoryEntry,
        dir_map: &HashMap<String, String>,
    ) -> Result<(), DirectoryError> {
        println!("[DEBUG] Processing shortened name: {file_name}");

        match self.read_shortened_name(path) {
            Ok(original_name) => {
                println!("[DEBUG] Original encrypted name: {original_name}");

                let is_dir = path.join("dir.c9r").exists();
                let is_symlink = path.join("symlink.c9r").exists();

                if is_symlink {
                    // Process as a symlink - use original_name for decryption
                    println!("[DEBUG] Found symlink.c9r - processing as shortened symlink");
                    return self.process_symlink(path, &original_name, parent_dir_id, master_key, parent_entry, true);
                }

                match decrypt_filename(&original_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted shortened name: {decrypted_name}");

                        if is_dir {
                            match self.read_directory_id(path) {
                                Ok(dir_id) => {
                                    let mut dir_entry = DirectoryEntry {
                                        name: decrypted_name,
                                        path: path.to_path_buf(),
                                        kind: EntryKind::Directory { id: dir_id },
                                        children: vec![],
                                    };

                                    self.explore_directory(&mut dir_entry, master_key, dir_map)?;
                                    parent_entry.children.push(dir_entry);
                                }
                                Err(e) => {
                                    println!("[ERROR] Failed to read directory ID from shortened dir: {e}");
                                }
                            }
                        } else {
                            parent_entry.children.push(DirectoryEntry {
                                name: decrypted_name,
                                path: path.to_path_buf(),
                                kind: EntryKind::File,
                                children: vec![],
                            });
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to decrypt shortened name: {e}");
                    }
                }
            }
            Err(e) => {
                println!("[ERROR] Failed to read shortened name: {e}");
            }
        }

        Ok(())
    }

    fn calculate_directory_path(&self, dir_id: &str, master_key: &MasterKey) -> Result<PathBuf, DirectoryError> {
        println!("[DEBUG] Calculating directory path for ID: '{dir_id}'");

        let hashed = hash_dir_id(dir_id, master_key)?;
        println!("[DEBUG] Hashed directory ID: {hashed}");

        if hashed.len() < 32 {
            return Err(DirectoryError::InvalidStructure(format!(
                "Hashed directory ID is too short: {}",
                hashed.len()
            )));
        }

        let hash_chars: Vec<char> = hashed.chars().collect();

        let first_two: String = hash_chars[0..2].iter().collect();
        let remaining: String = hash_chars[2..32].iter().collect();

        let path = self.vault_path.join("d").join(&first_two).join(&remaining);
        println!("[DEBUG] Calculated path: {path:?}");

        Ok(path)
    }

    fn read_directory_id(&self, dir_path: &Path) -> Result<String, DirectoryError> {
        let dir_file = dir_path.join("dir.c9r");

        assert!(
            dir_file.exists(),
            "dir.c9r doesn't exist at: {dir_file:?}"
        );

        let content = fs::read_to_string(&dir_file)?;
        let trimmed = content.trim().to_string();

        println!(
            "[DEBUG] Read directory ID from {dir_file:?}: '{trimmed}'"
        );

        Ok(trimmed)
    }

    fn read_shortened_name(&self, dir_path: &Path) -> Result<String, DirectoryError> {
        let name_file = dir_path.join("name.c9s");

        assert!(
            name_file.exists(),
            "name.c9s doesn't exist at: {name_file:?}"
        );

        let content = fs::read_to_string(&name_file)?;
        let trimmed = content.trim().to_string();

        println!(
            "[DEBUG] Read shortened name from {name_file:?}: '{trimmed}'"
        );

        Ok(trimmed)
    }
}

pub fn print_tree(entry: &DirectoryEntry, depth: usize) {
    let indent = "  ".repeat(depth);
    let prefix = match &entry.kind {
        EntryKind::Directory { .. } => "📁",
        EntryKind::File => "📄",
        EntryKind::Symlink { target } => {
            println!("{indent}🔗 {} -> {target}", entry.name);
            return;
        }
    };

    println!("{}{} {}", indent, prefix, entry.name);

    for child in &entry.children {
        print_tree(child, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKey;
    use crate::fs::name::{encrypt_filename, hash_dir_id};
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_master_key() -> MasterKey {
        // Create a deterministic master key for testing
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        // Fill with test data
        for i in 0..32 {
            aes_key[i] = i as u8;
            mac_key[i] = (32 + i) as u8;
        }

        MasterKey::new(aes_key, mac_key).unwrap()
    }

    fn create_test_vault_structure(temp_dir: &TempDir, master_key: &MasterKey) -> Result<(), DirectoryError> {
        let vault_path = temp_dir.path();
        
        // Create basic vault structure
        fs::create_dir_all(vault_path.join("d"))?;

        // Create root directory hash
        let root_hash = hash_dir_id("", master_key)?;
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();

        let root_dir_path = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_dir_path)?;

        // Create some test files in root directory
        let test_file1_name = encrypt_filename("test1.txt", "", master_key)?;
        let test_file2_name = encrypt_filename("test2.doc", "", master_key)?;

        // Create actual files
        fs::File::create(root_dir_path.join(&test_file1_name))?;
        fs::File::create(root_dir_path.join(&test_file2_name))?;

        // Create a subdirectory
        let subdir_id = "test-subdir-id-12345";
        let subdir_name = encrypt_filename("subdir", "", master_key)?;
        let subdir_path = root_dir_path.join(&subdir_name);
        fs::create_dir_all(&subdir_path)?;

        // Write directory ID to dir.c9r
        let mut dir_file = fs::File::create(subdir_path.join("dir.c9r"))?;
        dir_file.write_all(subdir_id.as_bytes())?;

        // Create storage directory for subdirectory
        let subdir_hash = hash_dir_id(subdir_id, master_key)?;
        let subdir_hash_chars: Vec<char> = subdir_hash.chars().collect();
        let subdir_first_two: String = subdir_hash_chars[0..2].iter().collect();
        let subdir_remaining: String = subdir_hash_chars[2..32].iter().collect();

        let subdir_storage_path = vault_path.join("d").join(&subdir_first_two).join(&subdir_remaining);
        fs::create_dir_all(&subdir_storage_path)?;

        // Create a file in the subdirectory
        let subdir_file_name = encrypt_filename("nested_file.txt", subdir_id, master_key)?;
        fs::File::create(subdir_storage_path.join(&subdir_file_name))?;

        Ok(())
    }

    #[test]
    fn test_vault_explorer_creation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        
        let explorer = VaultExplorer::new(vault_path);
        assert_eq!(explorer.vault_path, vault_path);
    }

    #[test]
    fn test_build_directory_map_empty_vault() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        
        // Create just the d directory structure
        fs::create_dir_all(vault_path.join("d")).unwrap();
        
        let explorer = VaultExplorer::new(vault_path);
        let dir_map = explorer.build_directory_map().unwrap();
        
        assert!(dir_map.is_empty(), "Empty vault should have empty directory map");
    }

    #[test]
    fn test_build_directory_map_with_directories() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();
        
        // Create test structure
        create_test_vault_structure(&temp_dir, &master_key).unwrap();
        
        let explorer = VaultExplorer::new(vault_path);
        let dir_map = explorer.build_directory_map().unwrap();
        
        // Should find at least the directories we created
        assert!(!dir_map.is_empty(), "Directory map should not be empty");
    }

    #[test]
    fn test_calculate_directory_path() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        let explorer = VaultExplorer::new(vault_path);

        // Test root directory path calculation
        let root_path = explorer.calculate_directory_path("", &master_key).unwrap();
        let expected_hash = hash_dir_id("", &master_key).unwrap();
        let expected_hash_chars: Vec<char> = expected_hash.chars().collect();
        let expected_first_two: String = expected_hash_chars[0..2].iter().collect();
        let expected_remaining: String = expected_hash_chars[2..32].iter().collect();
        let expected_path = vault_path.join("d").join(&expected_first_two).join(&expected_remaining);

        assert_eq!(root_path, expected_path);

        // Test non-root directory path calculation
        let test_dir_id = "test-dir-123";
        let test_path = explorer.calculate_directory_path(test_dir_id, &master_key).unwrap();
        let test_hash = hash_dir_id(test_dir_id, &master_key).unwrap();
        let test_hash_chars: Vec<char> = test_hash.chars().collect();
        let test_first_two: String = test_hash_chars[0..2].iter().collect();
        let test_remaining: String = test_hash_chars[2..32].iter().collect();
        let expected_test_path = vault_path.join("d").join(&test_first_two).join(&test_remaining);

        assert_eq!(test_path, expected_test_path);
    }

    #[test]
    fn test_read_directory_id() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();
        
        let test_dir_id = "test-directory-id-12345";
        let dir_file = test_dir.join("dir.c9r");
        
        let mut file = fs::File::create(&dir_file).unwrap();
        file.write_all(test_dir_id.as_bytes()).unwrap();
        
        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);
        
        let read_id = explorer.read_directory_id(&test_dir).unwrap();
        assert_eq!(read_id, test_dir_id);
    }

    #[test]
    fn test_read_directory_id_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();
        
        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);
        
        // Should panic because dir.c9r doesn't exist
        let result = std::panic::catch_unwind(|| {
            explorer.read_directory_id(&test_dir).unwrap()
        });
        assert!(result.is_err(), "Should panic when dir.c9r is missing");
    }

    #[test]
    fn test_read_shortened_name() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();
        
        let original_name = "very-long-encrypted-filename-that-needs-shortening.c9r";
        let name_file = test_dir.join("name.c9s");
        
        let mut file = fs::File::create(&name_file).unwrap();
        file.write_all(original_name.as_bytes()).unwrap();
        
        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);
        
        let read_name = explorer.read_shortened_name(&test_dir).unwrap();
        assert_eq!(read_name, original_name);
    }

    #[test]
    fn test_read_shortened_name_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();
        
        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);
        
        // Should panic because name.c9s doesn't exist
        let result = std::panic::catch_unwind(|| {
            explorer.read_shortened_name(&test_dir).unwrap()
        });
        assert!(result.is_err(), "Should panic when name.c9s is missing");
    }

    #[test]
    fn test_directory_entry_creation() {
        let test_path = PathBuf::from("/test/path");
        let entry = DirectoryEntry {
            name: "test".to_string(),
            path: test_path.clone(),
            kind: EntryKind::Directory { id: "test-id".to_string() },
            children: vec![],
        };

        assert_eq!(entry.name, "test");
        assert_eq!(entry.path, test_path);
        assert!(entry.is_directory());
        assert_eq!(entry.directory_id(), Some("test-id"));
        assert!(entry.children.is_empty());

        // Test file entry
        let file_entry = DirectoryEntry {
            name: "file.txt".to_string(),
            path: PathBuf::from("/test/file.txt"),
            kind: EntryKind::File,
            children: vec![],
        };
        assert!(file_entry.is_file());
        assert!(!file_entry.is_directory());
        assert!(!file_entry.is_symlink());

        // Test symlink entry
        let symlink_entry = DirectoryEntry {
            name: "link".to_string(),
            path: PathBuf::from("/test/link"),
            kind: EntryKind::Symlink { target: "/target/path".to_string() },
            children: vec![],
        };
        assert!(symlink_entry.is_symlink());
        assert_eq!(symlink_entry.symlink_target(), Some("/target/path"));
        assert!(!symlink_entry.is_file());
        assert!(!symlink_entry.is_directory());
    }

    #[test]
    fn test_print_tree_format() {
        // Create a simple directory structure with files, directories, and symlinks
        let root = DirectoryEntry {
            name: "/".to_string(),
            path: PathBuf::from("/"),
            kind: EntryKind::Directory { id: String::new() },
            children: vec![
                DirectoryEntry {
                    name: "file1.txt".to_string(),
                    path: PathBuf::from("/file1.txt"),
                    kind: EntryKind::File,
                    children: vec![],
                },
                DirectoryEntry {
                    name: "subdir".to_string(),
                    path: PathBuf::from("/subdir"),
                    kind: EntryKind::Directory { id: "subdir-id".to_string() },
                    children: vec![
                        DirectoryEntry {
                            name: "nested.txt".to_string(),
                            path: PathBuf::from("/subdir/nested.txt"),
                            kind: EntryKind::File,
                            children: vec![],
                        },
                    ],
                },
                DirectoryEntry {
                    name: "link".to_string(),
                    path: PathBuf::from("/link"),
                    kind: EntryKind::Symlink { target: "/target".to_string() },
                    children: vec![],
                },
            ],
        };

        // This test mainly ensures print_tree doesn't panic
        // In a real test environment, you might want to capture stdout
        print_tree(&root, 0);
    }

    // =====================================================================
    // Additional tests for improved coverage
    // =====================================================================

    #[test]
    fn test_directory_error_io_error() {
        // Test that IO errors are properly wrapped
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test error");
        let dir_err: DirectoryError = io_err.into();

        assert!(matches!(dir_err, DirectoryError::Io(_)));
        let error_string = dir_err.to_string();
        assert!(error_string.contains("IO error"));
    }

    #[test]
    fn test_directory_error_invalid_structure() {
        let err = DirectoryError::InvalidStructure("test message".to_string());
        let error_string = err.to_string();
        assert!(error_string.contains("Invalid vault structure"));
        assert!(error_string.contains("test message"));
    }

    #[test]
    fn test_directory_error_missing_file() {
        let err = DirectoryError::MissingFile(PathBuf::from("/test/path"));
        let error_string = err.to_string();
        assert!(error_string.contains("Missing file"));
        assert!(error_string.contains("/test/path"));
    }

    #[test]
    fn test_entry_kind_directory_id_returns_none_for_non_directory() {
        let file_kind = EntryKind::File;
        assert!(file_kind.directory_id().is_none());

        let symlink_kind = EntryKind::Symlink { target: "/target".to_string() };
        assert!(symlink_kind.directory_id().is_none());
    }

    #[test]
    fn test_entry_kind_symlink_target_returns_none_for_non_symlink() {
        let file_kind = EntryKind::File;
        assert!(file_kind.symlink_target().is_none());

        let dir_kind = EntryKind::Directory { id: "test-id".to_string() };
        assert!(dir_kind.symlink_target().is_none());
    }

    #[test]
    fn test_build_directory_map_missing_d_directory() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Do NOT create the d directory
        let explorer = VaultExplorer::new(vault_path);
        let result = explorer.build_directory_map();

        // Should fail with IO error
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DirectoryError::Io(_)));
    }

    #[test]
    fn test_build_directory_map_with_files_in_prefix_dir() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Create d directory with a file instead of subdirectory
        let d_dir = vault_path.join("d");
        fs::create_dir_all(&d_dir).unwrap();

        // Create a prefix directory with a file instead of hash directory
        let prefix_dir = d_dir.join("AB");
        fs::create_dir_all(&prefix_dir).unwrap();
        fs::write(prefix_dir.join("some_file.txt"), "content").unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let dir_map = explorer.build_directory_map().unwrap();

        // The file should be ignored, only directories are processed
        assert!(dir_map.is_empty());
    }

    #[test]
    fn test_read_directory_id_with_whitespace() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();

        // Write directory ID with leading/trailing whitespace
        let test_dir_id = "  test-directory-id  \n";
        let dir_file = test_dir.join("dir.c9r");

        let mut file = fs::File::create(&dir_file).unwrap();
        file.write_all(test_dir_id.as_bytes()).unwrap();

        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);

        let read_id = explorer.read_directory_id(&test_dir).unwrap();
        // Should be trimmed
        assert_eq!(read_id, "test-directory-id");
    }

    #[test]
    fn test_read_shortened_name_with_whitespace() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();

        // Write name with leading/trailing whitespace
        let original_name = "  encrypted-name.c9r  \n";
        let name_file = test_dir.join("name.c9s");

        let mut file = fs::File::create(&name_file).unwrap();
        file.write_all(original_name.as_bytes()).unwrap();

        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);

        let read_name = explorer.read_shortened_name(&test_dir).unwrap();
        // Should be trimmed
        assert_eq!(read_name, "encrypted-name.c9r");
    }

    #[test]
    fn test_build_directory_tree_with_empty_storage_path() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create the d directory but NOT the root storage directory
        fs::create_dir_all(vault_path.join("d")).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Root should exist but have no children (storage path doesn't exist)
        assert_eq!(tree.name, "/");
        assert!(tree.is_directory());
        assert!(tree.children.is_empty());
    }

    #[test]
    fn test_process_items_skips_dirid_c9r() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a dirid.c9r file (should be skipped)
        fs::write(root_storage.join("dirid.c9r"), "encrypted-parent-id").unwrap();

        // Create a regular file to verify normal processing works
        let file_name = encrypt_filename("regular.txt", "", &master_key).unwrap();
        fs::File::create(root_storage.join(format!("{file_name}.c9r"))).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have one child (the regular file), not the dirid.c9r
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, "regular.txt");
    }

    #[test]
    fn test_children_are_sorted_by_name() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create files in non-alphabetical order (by encrypted name)
        let names = ["zebra.txt", "apple.txt", "mango.txt"];
        for name in names {
            let encrypted = encrypt_filename(name, "", &master_key).unwrap();
            fs::File::create(root_storage.join(format!("{encrypted}.c9r"))).unwrap();
        }

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Children should be sorted alphabetically
        assert_eq!(tree.children.len(), 3);
        assert_eq!(tree.children[0].name, "apple.txt");
        assert_eq!(tree.children[1].name, "mango.txt");
        assert_eq!(tree.children[2].name, "zebra.txt");
    }

    #[test]
    fn test_entry_kind_clone() {
        let dir_kind = EntryKind::Directory { id: "test-id".to_string() };
        let cloned = dir_kind.clone();
        assert_eq!(cloned, dir_kind);

        let file_kind = EntryKind::File;
        let cloned_file = file_kind.clone();
        assert_eq!(cloned_file, file_kind);

        let symlink_kind = EntryKind::Symlink { target: "/target".to_string() };
        let cloned_symlink = symlink_kind.clone();
        assert_eq!(cloned_symlink, symlink_kind);
    }

    #[test]
    fn test_directory_entry_debug_format() {
        let entry = DirectoryEntry {
            name: "test".to_string(),
            path: PathBuf::from("/test"),
            kind: EntryKind::File,
            children: vec![],
        };

        // Ensure Debug trait works
        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("File"));
    }

    #[test]
    fn test_entry_kind_debug_format() {
        let dir = EntryKind::Directory { id: "abc".to_string() };
        let debug_str = format!("{dir:?}");
        assert!(debug_str.contains("Directory"));
        assert!(debug_str.contains("abc"));

        let file = EntryKind::File;
        let debug_str = format!("{file:?}");
        assert!(debug_str.contains("File"));

        let symlink = EntryKind::Symlink { target: "/path".to_string() };
        let debug_str = format!("{symlink:?}");
        assert!(debug_str.contains("Symlink"));
        assert!(debug_str.contains("/path"));
    }

    #[test]
    fn test_directory_error_debug_format() {
        let io_err = DirectoryError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let debug_str = format!("{io_err:?}");
        assert!(debug_str.contains("Io"));

        let invalid_err = DirectoryError::InvalidStructure("bad".to_string());
        let debug_str = format!("{invalid_err:?}");
        assert!(debug_str.contains("InvalidStructure"));

        let missing_err = DirectoryError::MissingFile(PathBuf::from("/missing"));
        let debug_str = format!("{missing_err:?}");
        assert!(debug_str.contains("MissingFile"));
    }

    #[test]
    fn test_build_directory_tree_nested_empty_directories() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create an empty subdirectory
        let subdir_id = "empty-subdir-id";
        let subdir_name = encrypt_filename("empty_dir", "", &master_key).unwrap();
        let subdir_path = root_storage.join(format!("{subdir_name}.c9r"));
        fs::create_dir_all(&subdir_path).unwrap();
        fs::write(subdir_path.join("dir.c9r"), subdir_id).unwrap();

        // Create storage for the empty subdirectory (but leave it empty)
        let subdir_hash = hash_dir_id(subdir_id, &master_key).unwrap();
        let subdir_hash_chars: Vec<char> = subdir_hash.chars().collect();
        let sub_first_two: String = subdir_hash_chars[0..2].iter().collect();
        let sub_remaining: String = subdir_hash_chars[2..32].iter().collect();
        let subdir_storage = vault_path.join("d").join(&sub_first_two).join(&sub_remaining);
        fs::create_dir_all(&subdir_storage).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Root should have one child (the empty directory)
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, "empty_dir");
        assert!(tree.children[0].is_directory());
        assert!(tree.children[0].children.is_empty());
    }

    #[test]
    fn test_build_directory_tree_deeply_nested() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create a chain of nested directories: root -> level1 -> level2 -> level3
        let levels = ["", "level1-id", "level2-id", "level3-id"];
        let names = ["root", "level1", "level2", "level3"];

        for i in 0..levels.len() {
            let parent_id = levels[i];
            let hash = hash_dir_id(parent_id, &master_key).unwrap();
            let hash_chars: Vec<char> = hash.chars().collect();
            let first_two: String = hash_chars[0..2].iter().collect();
            let remaining: String = hash_chars[2..32].iter().collect();
            let storage = vault_path.join("d").join(&first_two).join(&remaining);
            fs::create_dir_all(&storage).unwrap();

            // If not the last level, create the next directory
            if i < levels.len() - 1 {
                let next_name = names[i + 1];
                let next_id = levels[i + 1];
                let encrypted = encrypt_filename(next_name, parent_id, &master_key).unwrap();
                let dir_path = storage.join(format!("{encrypted}.c9r"));
                fs::create_dir_all(&dir_path).unwrap();
                fs::write(dir_path.join("dir.c9r"), next_id).unwrap();
            } else {
                // Last level: add a file
                let file_name = encrypt_filename("deep_file.txt", parent_id, &master_key).unwrap();
                fs::File::create(storage.join(format!("{file_name}.c9r"))).unwrap();
            }
        }

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Verify the nested structure
        assert_eq!(tree.name, "/");
        assert_eq!(tree.children.len(), 1);

        let level1 = &tree.children[0];
        assert_eq!(level1.name, "level1");
        assert!(level1.is_directory());
        assert_eq!(level1.children.len(), 1);

        let level2 = &level1.children[0];
        assert_eq!(level2.name, "level2");
        assert!(level2.is_directory());
        assert_eq!(level2.children.len(), 1);

        let level3 = &level2.children[0];
        assert_eq!(level3.name, "level3");
        assert!(level3.is_directory());
        assert_eq!(level3.children.len(), 1);

        let deep_file = &level3.children[0];
        assert_eq!(deep_file.name, "deep_file.txt");
        assert!(deep_file.is_file());
    }

    #[test]
    fn test_files_without_c9r_extension_are_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create files with different extensions (should be ignored)
        fs::write(root_storage.join("random_file.txt"), "content").unwrap();
        fs::write(root_storage.join("another.dat"), "data").unwrap();
        fs::write(root_storage.join(".hidden"), "hidden").unwrap();

        // Create a valid .c9r file
        let file_name = encrypt_filename("valid.txt", "", &master_key).unwrap();
        fs::File::create(root_storage.join(format!("{file_name}.c9r"))).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Only the valid .c9r file should be in the tree
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, "valid.txt");
    }

    #[test]
    fn test_print_tree_with_empty_root() {
        let root = DirectoryEntry {
            name: "/".to_string(),
            path: PathBuf::from("/"),
            kind: EntryKind::Directory { id: String::new() },
            children: vec![],
        };

        // Should not panic with empty tree
        print_tree(&root, 0);
    }

    #[test]
    fn test_print_tree_with_deep_nesting() {
        // Create deeply nested structure
        let mut current = DirectoryEntry {
            name: "deepest".to_string(),
            path: PathBuf::from("/a/b/c/d/e/deepest"),
            kind: EntryKind::File,
            children: vec![],
        };

        for i in (0..5).rev() {
            current = DirectoryEntry {
                name: format!("level{i}"),
                path: PathBuf::from(format!("/level{i}")),
                kind: EntryKind::Directory { id: format!("id-{i}") },
                children: vec![current],
            };
        }

        // Should not panic with deep nesting
        print_tree(&current, 0);
    }

    #[test]
    fn test_vault_explorer_with_unicode_paths() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create files with unicode names
        let unicode_names = ["cafe.txt", "emoji-file.txt", "chinese-characters.txt"];
        for name in unicode_names {
            let encrypted = encrypt_filename(name, "", &master_key).unwrap();
            fs::File::create(root_storage.join(format!("{encrypted}.c9r"))).unwrap();
        }

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // All unicode files should be found
        assert_eq!(tree.children.len(), 3);
    }

    #[test]
    fn test_build_directory_map_with_empty_prefix_directories() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Create d directory with empty prefix directories
        let d_dir = vault_path.join("d");
        fs::create_dir_all(d_dir.join("AB")).unwrap();
        fs::create_dir_all(d_dir.join("CD")).unwrap();
        fs::create_dir_all(d_dir.join("EF")).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let dir_map = explorer.build_directory_map().unwrap();

        // Empty prefix directories should result in empty map
        assert!(dir_map.is_empty());
    }

    #[test]
    fn test_entry_kind_equality() {
        // Test PartialEq for EntryKind
        let file1 = EntryKind::File;
        let file2 = EntryKind::File;
        assert_eq!(file1, file2);

        let dir1 = EntryKind::Directory { id: "same-id".to_string() };
        let dir2 = EntryKind::Directory { id: "same-id".to_string() };
        let dir3 = EntryKind::Directory { id: "different-id".to_string() };
        assert_eq!(dir1, dir2);
        assert_ne!(dir1, dir3);

        let sym1 = EntryKind::Symlink { target: "/path".to_string() };
        let sym2 = EntryKind::Symlink { target: "/path".to_string() };
        let sym3 = EntryKind::Symlink { target: "/other".to_string() };
        assert_eq!(sym1, sym2);
        assert_ne!(sym1, sym3);

        // Different types should not be equal
        assert_ne!(file1, dir1);
        assert_ne!(file1, sym1);
        assert_ne!(dir1, sym1);
    }

    #[test]
    fn test_directory_entry_symlink_target_delegation() {
        // Test that DirectoryEntry.symlink_target() correctly delegates to EntryKind
        let file_entry = DirectoryEntry {
            name: "file.txt".to_string(),
            path: PathBuf::from("/file.txt"),
            kind: EntryKind::File,
            children: vec![],
        };
        assert!(file_entry.symlink_target().is_none());

        let dir_entry = DirectoryEntry {
            name: "dir".to_string(),
            path: PathBuf::from("/dir"),
            kind: EntryKind::Directory { id: "id".to_string() },
            children: vec![],
        };
        assert!(dir_entry.symlink_target().is_none());

        let symlink_entry = DirectoryEntry {
            name: "link".to_string(),
            path: PathBuf::from("/link"),
            kind: EntryKind::Symlink { target: "/target/path".to_string() },
            children: vec![],
        };
        assert_eq!(symlink_entry.symlink_target(), Some("/target/path"));
    }

    #[test]
    fn test_mixed_files_and_directories() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a file
        let file_name = encrypt_filename("document.pdf", "", &master_key).unwrap();
        fs::File::create(root_storage.join(format!("{file_name}.c9r"))).unwrap();

        // Create a directory
        let dir_id = "subdir-unique-id";
        let dir_name = encrypt_filename("folder", "", &master_key).unwrap();
        let dir_path = root_storage.join(format!("{dir_name}.c9r"));
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join("dir.c9r"), dir_id).unwrap();

        // Create storage for the directory
        let dir_hash = hash_dir_id(dir_id, &master_key).unwrap();
        let dir_hash_chars: Vec<char> = dir_hash.chars().collect();
        let dir_first_two: String = dir_hash_chars[0..2].iter().collect();
        let dir_remaining: String = dir_hash_chars[2..32].iter().collect();
        let dir_storage = vault_path.join("d").join(&dir_first_two).join(&dir_remaining);
        fs::create_dir_all(&dir_storage).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have both a file and a directory
        assert_eq!(tree.children.len(), 2);

        // Find the file and directory entries (sorted alphabetically)
        let has_file = tree.children.iter().any(|e| e.name == "document.pdf" && e.is_file());
        let has_dir = tree.children.iter().any(|e| e.name == "folder" && e.is_directory());

        assert!(has_file, "Should have document.pdf file");
        assert!(has_dir, "Should have folder directory");
    }

    #[test]
    fn test_build_directory_tree_with_symlink() {
        use crate::fs::symlink::encrypt_symlink_target;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a symlink entry
        let symlink_name = encrypt_filename("my_link", "", &master_key).unwrap();
        let symlink_dir = root_storage.join(format!("{symlink_name}.c9r"));
        fs::create_dir_all(&symlink_dir).unwrap();

        // Create symlink.c9r with encrypted target
        let encrypted_target = encrypt_symlink_target("../target_file.txt", &master_key).unwrap();
        fs::write(symlink_dir.join("symlink.c9r"), &encrypted_target).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have one symlink child
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, "my_link");
        assert!(tree.children[0].is_symlink());
        assert_eq!(tree.children[0].symlink_target(), Some("../target_file.txt"));
    }

    #[test]
    fn test_build_directory_tree_with_shortened_file() {
        use crate::fs::name::create_c9s_filename;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a long filename that gets shortened
        let long_name = "this_is_a_very_long_filename_that_exceeds_the_normal_limit.txt";
        let encrypted_name = encrypt_filename(long_name, "", &master_key).unwrap();
        let encrypted_with_ext = format!("{encrypted_name}.c9r");

        // Create the shortened (.c9s) structure
        let c9s_hash = create_c9s_filename(&encrypted_with_ext);
        let c9s_dir = root_storage.join(format!("{c9s_hash}.c9s"));
        fs::create_dir_all(&c9s_dir).unwrap();

        // Write name.c9s with the original encrypted name
        fs::write(c9s_dir.join("name.c9s"), &encrypted_with_ext).unwrap();

        // Create contents.c9r as an empty file (represents the actual file content)
        fs::File::create(c9s_dir.join("contents.c9r")).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have one file child with the decrypted name
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, long_name);
        assert!(tree.children[0].is_file());
    }

    #[test]
    fn test_build_directory_tree_with_shortened_directory() {
        use crate::fs::name::create_c9s_filename;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a long directory name that gets shortened
        let long_name = "this_is_a_very_long_directory_name_that_exceeds_the_normal_limit";
        let encrypted_name = encrypt_filename(long_name, "", &master_key).unwrap();
        let encrypted_with_ext = format!("{encrypted_name}.c9r");

        // Create the shortened (.c9s) structure
        let c9s_hash = create_c9s_filename(&encrypted_with_ext);
        let c9s_dir = root_storage.join(format!("{c9s_hash}.c9s"));
        fs::create_dir_all(&c9s_dir).unwrap();

        // Write name.c9s with the original encrypted name
        fs::write(c9s_dir.join("name.c9s"), &encrypted_with_ext).unwrap();

        // Create dir.c9r with directory ID
        let dir_id = "shortened-dir-id";
        fs::write(c9s_dir.join("dir.c9r"), dir_id).unwrap();

        // Create storage for the directory
        let dir_hash = hash_dir_id(dir_id, &master_key).unwrap();
        let dir_hash_chars: Vec<char> = dir_hash.chars().collect();
        let dir_first_two: String = dir_hash_chars[0..2].iter().collect();
        let dir_remaining: String = dir_hash_chars[2..32].iter().collect();
        let dir_storage = vault_path.join("d").join(&dir_first_two).join(&dir_remaining);
        fs::create_dir_all(&dir_storage).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have one directory child with the decrypted name
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, long_name);
        assert!(tree.children[0].is_directory());
        assert_eq!(tree.children[0].directory_id(), Some(dir_id));
    }

    #[test]
    fn test_build_directory_tree_with_shortened_symlink() {
        use crate::fs::name::create_c9s_filename;
        use crate::fs::symlink::encrypt_symlink_target;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // Create a long symlink name that gets shortened
        let long_name = "this_is_a_very_long_symlink_name_that_exceeds_the_normal_limit";
        let encrypted_name = encrypt_filename(long_name, "", &master_key).unwrap();
        let encrypted_with_ext = format!("{encrypted_name}.c9r");

        // Create the shortened (.c9s) structure
        let c9s_hash = create_c9s_filename(&encrypted_with_ext);
        let c9s_dir = root_storage.join(format!("{c9s_hash}.c9s"));
        fs::create_dir_all(&c9s_dir).unwrap();

        // Write name.c9s with the original encrypted name
        fs::write(c9s_dir.join("name.c9s"), &encrypted_with_ext).unwrap();

        // Create symlink.c9r with encrypted target
        let encrypted_target = encrypt_symlink_target("/absolute/target/path", &master_key).unwrap();
        fs::write(c9s_dir.join("symlink.c9r"), &encrypted_target).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have one symlink child with the decrypted name
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].name, long_name);
        assert!(tree.children[0].is_symlink());
        assert_eq!(tree.children[0].symlink_target(), Some("/absolute/target/path"));
    }

    #[test]
    fn test_build_directory_tree_mixed_entry_types() {
        use crate::fs::name::create_c9s_filename;
        use crate::fs::symlink::encrypt_symlink_target;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        // Create root directory structure
        let root_hash = hash_dir_id("", &master_key).unwrap();
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        let root_storage = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_storage).unwrap();

        // 1. Create a regular file
        let file_name = encrypt_filename("file.txt", "", &master_key).unwrap();
        fs::File::create(root_storage.join(format!("{file_name}.c9r"))).unwrap();

        // 2. Create a directory
        let dir_id = "subdir-id";
        let dir_name = encrypt_filename("directory", "", &master_key).unwrap();
        let dir_path = root_storage.join(format!("{dir_name}.c9r"));
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join("dir.c9r"), dir_id).unwrap();

        // Create storage for the directory
        let dir_hash = hash_dir_id(dir_id, &master_key).unwrap();
        let dir_hash_chars: Vec<char> = dir_hash.chars().collect();
        let dir_first_two: String = dir_hash_chars[0..2].iter().collect();
        let dir_remaining: String = dir_hash_chars[2..32].iter().collect();
        fs::create_dir_all(vault_path.join("d").join(&dir_first_two).join(&dir_remaining)).unwrap();

        // 3. Create a symlink
        let symlink_name = encrypt_filename("link", "", &master_key).unwrap();
        let symlink_dir = root_storage.join(format!("{symlink_name}.c9r"));
        fs::create_dir_all(&symlink_dir).unwrap();
        let encrypted_target = encrypt_symlink_target("./file.txt", &master_key).unwrap();
        fs::write(symlink_dir.join("symlink.c9r"), &encrypted_target).unwrap();

        // 4. Create a shortened file
        let long_name = "long_filename_that_needs_shortening.txt";
        let encrypted_long = encrypt_filename(long_name, "", &master_key).unwrap();
        let encrypted_long_with_ext = format!("{encrypted_long}.c9r");
        let c9s_hash = create_c9s_filename(&encrypted_long_with_ext);
        let c9s_dir = root_storage.join(format!("{c9s_hash}.c9s"));
        fs::create_dir_all(&c9s_dir).unwrap();
        fs::write(c9s_dir.join("name.c9s"), &encrypted_long_with_ext).unwrap();
        fs::File::create(c9s_dir.join("contents.c9r")).unwrap();

        let explorer = VaultExplorer::new(vault_path);
        let tree = explorer.build_directory_tree(&master_key).unwrap();

        // Should have 4 children: file, directory, symlink, and shortened file
        assert_eq!(tree.children.len(), 4);

        // Verify each type is present (children are sorted alphabetically)
        let names: Vec<&str> = tree.children.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"file.txt"));
        assert!(names.contains(&"directory"));
        assert!(names.contains(&"link"));
        assert!(names.contains(&long_name));

        // Verify types
        let file_entry = tree.children.iter().find(|e| e.name == "file.txt").unwrap();
        assert!(file_entry.is_file());

        let dir_entry = tree.children.iter().find(|e| e.name == "directory").unwrap();
        assert!(dir_entry.is_directory());

        let symlink_entry = tree.children.iter().find(|e| e.name == "link").unwrap();
        assert!(symlink_entry.is_symlink());
        assert_eq!(symlink_entry.symlink_target(), Some("./file.txt"));

        let shortened_entry = tree.children.iter().find(|e| e.name == long_name).unwrap();
        assert!(shortened_entry.is_file());
    }

    #[test]
    fn test_build_directory_map_missing_d_directory_io_error_kind() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Do NOT create the d directory
        let explorer = VaultExplorer::new(vault_path);
        let result = explorer.build_directory_map();

        assert!(result.is_err());
        if let Err(DirectoryError::Io(io_err)) = result {
            assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
        } else {
            panic!("Expected DirectoryError::Io with NotFound kind");
        }
    }

    #[test]
    fn test_directory_id_with_special_characters() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();

        // Write directory ID with special characters (realistic UUID format)
        let test_dir_id = "e9250eb8-078d-4fc0-8835-be92a313360c";
        let dir_file = test_dir.join("dir.c9r");

        let mut file = fs::File::create(&dir_file).unwrap();
        file.write_all(test_dir_id.as_bytes()).unwrap();

        let vault_path = temp_dir.path();
        let explorer = VaultExplorer::new(vault_path);

        let read_id = explorer.read_directory_id(&test_dir).unwrap();
        assert_eq!(read_id, test_dir_id);
    }

    #[test]
    fn test_calculate_directory_path_hash_format() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();
        let master_key = create_test_master_key();

        let explorer = VaultExplorer::new(vault_path);
        let dir_id = "test-uuid-12345";

        let path = explorer.calculate_directory_path(dir_id, &master_key).unwrap();

        // Path should be: vault_path/d/XX/YYYYYY... (2 char prefix + 30 char remainder)
        assert!(path.starts_with(vault_path.join("d")));

        // Extract the hash portion
        let d_dir = vault_path.join("d");
        let relative_path = path.strip_prefix(&d_dir).unwrap();
        let components: Vec<_> = relative_path.components().collect();

        // Should have exactly 2 components: prefix (2 chars) and remainder (30 chars)
        assert_eq!(components.len(), 2);

        let prefix = components[0].as_os_str().to_string_lossy();
        let remainder = components[1].as_os_str().to_string_lossy();

        assert_eq!(prefix.len(), 2);
        assert_eq!(remainder.len(), 30);

        // Both should be valid Base32 characters (A-Z, 2-7)
        for ch in prefix.chars() {
            assert!(
                ('A'..='Z').contains(&ch) || ('2'..='7').contains(&ch),
                "Prefix should be Base32: found '{ch}'"
            );
        }
        for ch in remainder.chars() {
            assert!(
                ('A'..='Z').contains(&ch) || ('2'..='7').contains(&ch),
                "Remainder should be Base32: found '{ch}'"
            );
        }
    }
}