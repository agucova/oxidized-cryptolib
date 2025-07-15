use crate::crypto::keys::MasterKey;
use crate::fs::name::{decrypt_filename, hash_dir_id};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_directory: bool,
    pub directory_id: Option<String>,
    pub children: Vec<DirectoryEntry>,
}

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
    ) -> Result<DirectoryEntry, Box<dyn std::error::Error>> {
        let dir_map = self.build_directory_map()?;

        let mut root = DirectoryEntry {
            name: "/".to_string(),
            path: self.vault_path.clone(),
            is_directory: true,
            directory_id: Some("".to_string()), // Root directory ID is empty string
            children: vec![],
        };

        println!("\n[DEBUG] Starting directory tree build from root");
        self.explore_directory(&mut root, master_key, &dir_map)?;

        Ok(root)
    }

    fn build_directory_map(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
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
                        let hash_name = hash_path.file_name().unwrap().to_string_lossy().to_string();
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Clone the directory ID to avoid borrow issues
        let parent_dir_id = parent_entry.directory_id.as_ref().unwrap().clone();

        println!(
            "\n[DEBUG] Exploring directory: {} (ID: '{}')",
            parent_entry.name, parent_dir_id
        );

        // Calculate storage path for this directory
        let storage_path = self.calculate_directory_path(&parent_dir_id, master_key);
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
    ) -> Result<(), Box<dyn std::error::Error>> {
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("[DEBUG] Processing directory: {file_name}");

        match self.read_directory_id(path) {
            Ok(dir_id) => {
                println!("[DEBUG] Directory ID: '{dir_id}'");

                match decrypt_filename(file_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted directory name: {decrypted_name}");

                        let mut dir_entry = DirectoryEntry {
                            name: decrypted_name,
                            path: path.to_path_buf(),
                            is_directory: true,
                            directory_id: Some(dir_id),
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("[DEBUG] Processing file: {file_name}");

        match decrypt_filename(file_name, parent_dir_id, master_key) {
            Ok(decrypted_name) => {
                println!("[DEBUG] Decrypted file name: {decrypted_name}");

                parent_entry.children.push(DirectoryEntry {
                    name: decrypted_name,
                    path: path.to_path_buf(),
                    is_directory: false,
                    directory_id: None,
                    children: vec![],
                });
            }
            Err(e) => {
                println!("[ERROR] Failed to decrypt file name {file_name}: {e}");
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("[DEBUG] Processing shortened name: {file_name}");

        match self.read_shortened_name(path) {
            Ok(original_name) => {
                println!("[DEBUG] Original encrypted name: {original_name}");

                match decrypt_filename(&original_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted shortened name: {decrypted_name}");

                        let is_dir = path.join("dir.c9r").exists();

                        if is_dir {
                            match self.read_directory_id(path) {
                                Ok(dir_id) => {
                                    let mut dir_entry = DirectoryEntry {
                                        name: decrypted_name,
                                        path: path.to_path_buf(),
                                        is_directory: true,
                                        directory_id: Some(dir_id),
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
                                is_directory: false,
                                directory_id: None,
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

    fn calculate_directory_path(&self, dir_id: &str, master_key: &MasterKey) -> PathBuf {
        println!("[DEBUG] Calculating directory path for ID: '{dir_id}'");

        let hashed = hash_dir_id(dir_id, master_key);
        println!("[DEBUG] Hashed directory ID: {hashed}");

        assert!(
            hashed.len() >= 32,
            "Hashed directory ID is too short: {}",
            hashed.len()
        );

        let hash_chars: Vec<char> = hashed.chars().collect();

        let first_two: String = hash_chars[0..2].iter().collect();
        let remaining: String = hash_chars[2..32].iter().collect();

        let path = self.vault_path.join("d").join(&first_two).join(&remaining);
        println!("[DEBUG] Calculated path: {path:?}");

        path
    }

    fn read_directory_id(&self, dir_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
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

    fn read_shortened_name(&self, dir_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
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
    let prefix = if entry.is_directory { "📁" } else { "📄" };

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

        MasterKey {
            aes_master_key: secrecy::Secret::new(aes_key),
            mac_master_key: secrecy::Secret::new(mac_key),
        }
    }

    fn create_test_vault_structure(temp_dir: &TempDir, master_key: &MasterKey) -> Result<(), Box<dyn std::error::Error>> {
        let vault_path = temp_dir.path();
        
        // Create basic vault structure
        fs::create_dir_all(vault_path.join("d"))?;
        
        // Create root directory hash
        let root_hash = hash_dir_id("", master_key);
        let root_hash_chars: Vec<char> = root_hash.chars().collect();
        let first_two: String = root_hash_chars[0..2].iter().collect();
        let remaining: String = root_hash_chars[2..32].iter().collect();
        
        let root_dir_path = vault_path.join("d").join(&first_two).join(&remaining);
        fs::create_dir_all(&root_dir_path)?;
        
        // Create some test files in root directory
        let test_file1_name = encrypt_filename("test1.txt", "", master_key);
        let test_file2_name = encrypt_filename("test2.doc", "", master_key);
        
        // Create actual files
        fs::File::create(root_dir_path.join(&test_file1_name))?;
        fs::File::create(root_dir_path.join(&test_file2_name))?;
        
        // Create a subdirectory
        let subdir_id = "test-subdir-id-12345";
        let subdir_name = encrypt_filename("subdir", "", master_key);
        let subdir_path = root_dir_path.join(&subdir_name);
        fs::create_dir_all(&subdir_path)?;
        
        // Write directory ID to dir.c9r
        let mut dir_file = fs::File::create(subdir_path.join("dir.c9r"))?;
        dir_file.write_all(subdir_id.as_bytes())?;
        
        // Create storage directory for subdirectory
        let subdir_hash = hash_dir_id(subdir_id, master_key);
        let subdir_hash_chars: Vec<char> = subdir_hash.chars().collect();
        let subdir_first_two: String = subdir_hash_chars[0..2].iter().collect();
        let subdir_remaining: String = subdir_hash_chars[2..32].iter().collect();
        
        let subdir_storage_path = vault_path.join("d").join(&subdir_first_two).join(&subdir_remaining);
        fs::create_dir_all(&subdir_storage_path)?;
        
        // Create a file in the subdirectory
        let subdir_file_name = encrypt_filename("nested_file.txt", subdir_id, master_key);
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
        let root_path = explorer.calculate_directory_path("", &master_key);
        let expected_hash = hash_dir_id("", &master_key);
        let expected_hash_chars: Vec<char> = expected_hash.chars().collect();
        let expected_first_two: String = expected_hash_chars[0..2].iter().collect();
        let expected_remaining: String = expected_hash_chars[2..32].iter().collect();
        let expected_path = vault_path.join("d").join(&expected_first_two).join(&expected_remaining);
        
        assert_eq!(root_path, expected_path);
        
        // Test non-root directory path calculation
        let test_dir_id = "test-dir-123";
        let test_path = explorer.calculate_directory_path(test_dir_id, &master_key);
        let test_hash = hash_dir_id(test_dir_id, &master_key);
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
            is_directory: true,
            directory_id: Some("test-id".to_string()),
            children: vec![],
        };
        
        assert_eq!(entry.name, "test");
        assert_eq!(entry.path, test_path);
        assert!(entry.is_directory);
        assert_eq!(entry.directory_id, Some("test-id".to_string()));
        assert!(entry.children.is_empty());
    }

    #[test]
    fn test_print_tree_format() {
        // Create a simple directory structure
        let root = DirectoryEntry {
            name: "/".to_string(),
            path: PathBuf::from("/"),
            is_directory: true,
            directory_id: Some("".to_string()),
            children: vec![
                DirectoryEntry {
                    name: "file1.txt".to_string(),
                    path: PathBuf::from("/file1.txt"),
                    is_directory: false,
                    directory_id: None,
                    children: vec![],
                },
                DirectoryEntry {
                    name: "subdir".to_string(),
                    path: PathBuf::from("/subdir"),
                    is_directory: true,
                    directory_id: Some("subdir-id".to_string()),
                    children: vec![
                        DirectoryEntry {
                            name: "nested.txt".to_string(),
                            path: PathBuf::from("/subdir/nested.txt"),
                            is_directory: false,
                            directory_id: None,
                            children: vec![],
                        },
                    ],
                },
            ],
        };
        
        // This test mainly ensures print_tree doesn't panic
        // In a real test environment, you might want to capture stdout
        print_tree(&root, 0);
    }
}