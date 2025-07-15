use crate::master_key::MasterKey;
use crate::names::{decrypt_filename, hash_dir_id};
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
                        println!("[DEBUG] Found directory: {}", hash_name);
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
        println!("[DEBUG] Storage path: {:?}", storage_path);

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
        println!("\n[DEBUG] Processing items in directory: {:?}", dir_path);
        println!(
            "[DEBUG] Parent directory ID for decryption: '{}'",
            parent_dir_id
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

        println!("[DEBUG] Processed {} items in directory", item_count);

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
        println!("[DEBUG] Processing directory: {}", file_name);

        match self.read_directory_id(path) {
            Ok(dir_id) => {
                println!("[DEBUG] Directory ID: '{}'", dir_id);

                match decrypt_filename(file_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted directory name: {}", decrypted_name);

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
                            "[ERROR] Failed to decrypt directory name {}: {}",
                            file_name, e
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
        println!("[DEBUG] Processing file: {}", file_name);

        match decrypt_filename(file_name, parent_dir_id, master_key) {
            Ok(decrypted_name) => {
                println!("[DEBUG] Decrypted file name: {}", decrypted_name);

                parent_entry.children.push(DirectoryEntry {
                    name: decrypted_name,
                    path: path.to_path_buf(),
                    is_directory: false,
                    directory_id: None,
                    children: vec![],
                });
            }
            Err(e) => {
                println!("[ERROR] Failed to decrypt file name {}: {}", file_name, e);
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
        println!("[DEBUG] Processing shortened name: {}", file_name);

        match self.read_shortened_name(path) {
            Ok(original_name) => {
                println!("[DEBUG] Original encrypted name: {}", original_name);

                match decrypt_filename(&original_name, parent_dir_id, master_key) {
                    Ok(decrypted_name) => {
                        println!("[DEBUG] Decrypted shortened name: {}", decrypted_name);

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
                                    println!("[ERROR] Failed to read directory ID from shortened dir: {}", e);
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
                        println!("[ERROR] Failed to decrypt shortened name: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("[ERROR] Failed to read shortened name: {}", e);
            }
        }

        Ok(())
    }

    fn calculate_directory_path(&self, dir_id: &str, master_key: &MasterKey) -> PathBuf {
        println!("[DEBUG] Calculating directory path for ID: '{}'", dir_id);

        let hashed = hash_dir_id(dir_id, master_key);
        println!("[DEBUG] Hashed directory ID: {}", hashed);

        assert!(
            hashed.len() >= 32,
            "Hashed directory ID is too short: {}",
            hashed.len()
        );

        let hash_chars: Vec<char> = hashed.chars().collect();

        let first_two: String = hash_chars[0..2].iter().collect();
        let remaining: String = hash_chars[2..32].iter().collect();

        let path = self.vault_path.join("d").join(&first_two).join(&remaining);
        println!("[DEBUG] Calculated path: {:?}", path);

        path
    }

    fn read_directory_id(&self, dir_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let dir_file = dir_path.join("dir.c9r");

        assert!(
            dir_file.exists(),
            "dir.c9r doesn't exist at: {:?}",
            dir_file
        );

        let content = fs::read_to_string(&dir_file)?;
        let trimmed = content.trim().to_string();

        println!(
            "[DEBUG] Read directory ID from {:?}: '{}'",
            dir_file, trimmed
        );

        Ok(trimmed)
    }

    fn read_shortened_name(&self, dir_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let name_file = dir_path.join("name.c9s");

        assert!(
            name_file.exists(),
            "name.c9s doesn't exist at: {:?}",
            name_file
        );

        let content = fs::read_to_string(&name_file)?;
        let trimmed = content.trim().to_string();

        println!(
            "[DEBUG] Read shortened name from {:?}: '{}'",
            name_file, trimmed
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