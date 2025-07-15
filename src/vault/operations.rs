//! High-level vault operations combining directory and file functionality.
//! 
//! This module provides convenient APIs for common Cryptomator vault operations
//! that will be useful for FUSE filesystem implementation and debugging.

use crate::{
    fs::file::{decrypt_file, DecryptedFile},
    crypto::keys::MasterKey,
    fs::name::{decrypt_filename, hash_dir_id},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultOperationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("File decryption error: {0}")]
    FileDecryption(#[from] crate::fs::file::FileError),
    
    #[error("Filename decryption error: {0}")]
    FilenameDecryption(String),
    
    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),
    
    #[error("Invalid vault structure: {0}")]
    InvalidVaultStructure(String),
}

/// Information about a file in the vault
#[derive(Debug)]
pub struct VaultFileInfo {
    /// Decrypted filename
    pub name: String,
    /// Encrypted filename (as stored on disk)
    pub encrypted_name: String,
    /// Full path to the encrypted file
    pub encrypted_path: PathBuf,
    /// Size of the encrypted file
    pub encrypted_size: u64,
    /// Whether this is a shortened name (.c9s)
    pub is_shortened: bool,
}

/// Information about a directory in the vault
#[derive(Debug)]
pub struct VaultDirectoryInfo {
    /// Decrypted directory name
    pub name: String,
    /// Directory ID
    pub directory_id: String,
    /// Encrypted path on disk
    pub encrypted_path: PathBuf,
    /// Parent directory ID
    pub parent_directory_id: String,
}

/// High-level interface for vault operations
pub struct VaultOperations {
    vault_path: PathBuf,
    master_key: MasterKey,
}

impl VaultOperations {
    /// Create a new VaultOperations instance
    pub fn new(vault_path: &Path, master_key: MasterKey) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            master_key,
        }
    }
    
    /// Calculate the storage path for a directory given its ID
    pub fn calculate_directory_storage_path(&self, dir_id: &str) -> PathBuf {
        let hashed = hash_dir_id(dir_id, &self.master_key);
        let hash_chars: Vec<char> = hashed.chars().collect();
        
        if hash_chars.len() < 32 {
            panic!("Hashed directory ID is too short: {}", hash_chars.len());
        }
        
        let first_two: String = hash_chars[0..2].iter().collect();
        let remaining: String = hash_chars[2..32].iter().collect();
        
        self.vault_path.join("d").join(&first_two).join(&remaining)
    }
    
    /// List all files in a directory (by directory ID)
    pub fn list_files(
        &self,
        directory_id: &str,
    ) -> Result<Vec<VaultFileInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id);
        
        if !dir_path.exists() {
            return Ok(Vec::new()); // Empty directory
        }
        
        let mut files = Vec::new();
        
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            
            // Skip special files
            if file_name == "dirid.c9r" {
                continue;
            }
            
            // Skip .c9r directories (these are handled by list_directories)
            if path.is_dir() && file_name.ends_with(".c9r") {
                continue;
            }
            
            // Skip other directories that aren't .c9s 
            if path.is_dir() && !file_name.ends_with(".c9s") {
                continue;
            }
            
            if file_name.ends_with(".c9r") {
                match decrypt_filename(&file_name, directory_id, &self.master_key) {
                    Ok(decrypted_name) => {
                        let metadata = fs::metadata(&path)?;
                        files.push(VaultFileInfo {
                            name: decrypted_name,
                            encrypted_name: file_name,
                            encrypted_path: path,
                            encrypted_size: metadata.len(),
                            is_shortened: false,
                        });
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to decrypt filename {file_name}: {e}");
                    }
                }
            } else if file_name.ends_with(".c9s") && path.is_dir() {
                // Handle shortened names
                if let Ok(info) = self.read_shortened_file_info(&path, directory_id) {
                    files.push(info);
                }
            }
        }
        
        Ok(files)
    }
    
    /// List all subdirectories in a directory (by directory ID)
    pub fn list_directories(
        &self,
        directory_id: &str,
    ) -> Result<Vec<VaultDirectoryInfo>, VaultOperationError> {
        let dir_path = self.calculate_directory_storage_path(directory_id);
        
        if !dir_path.exists() {
            return Ok(Vec::new()); // Empty directory
        }
        
        let mut directories = Vec::new();
        
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            
            if path.is_dir() && file_name.ends_with(".c9r") {
                // This is a regular directory
                if let Ok(dir_info) = self.read_directory_info(&path, &file_name, directory_id) {
                    directories.push(dir_info);
                }
            } else if path.is_dir() && file_name.ends_with(".c9s") {
                // This might be a shortened directory
                if path.join("dir.c9r").exists()
                    && let Ok(dir_info) = self.read_shortened_directory_info(&path, directory_id) {
                        directories.push(dir_info);
                    }
            }
        }
        
        Ok(directories)
    }
    
    /// Read a file's contents by providing the directory ID and filename
    pub fn read_file(
        &self,
        directory_id: &str,
        filename: &str,
    ) -> Result<DecryptedFile, VaultOperationError> {
        // First, find the file
        let files = self.list_files(directory_id)?;
        let file_info = files
            .into_iter()
            .find(|f| f.name == filename)
            .ok_or_else(|| {
                VaultOperationError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File '{filename}' not found in directory"),
                ))
            })?;
        
        // Then decrypt it
        let decrypted = decrypt_file(&file_info.encrypted_path, &self.master_key)?;
        Ok(decrypted)
    }
    
    /// Get the full path for a file/directory by walking from root
    pub fn resolve_path(&self, path: &str) -> Result<(String, bool), VaultOperationError> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        if components.is_empty() {
            return Ok(("".to_string(), true)); // Root directory
        }
        
        let mut current_dir_id = String::new(); // Root directory ID
        let mut is_directory = true;
        
        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            
            if is_last {
                // Check if it's a file or directory
                let files = self.list_files(&current_dir_id)?;
                if files.iter().any(|f| f.name == *component) {
                    is_directory = false;
                    break;
                }
            }
            
            // Look for directory
            let dirs = self.list_directories(&current_dir_id)?;
            let dir = dirs
                .into_iter()
                .find(|d| d.name == *component)
                .ok_or_else(|| {
                    VaultOperationError::DirectoryNotFound(component.to_string())
                })?;
            
            current_dir_id = dir.directory_id;
        }
        
        Ok((current_dir_id, is_directory))
    }
    
    // Helper methods
    
    fn read_directory_info(
        &self,
        dir_path: &Path,
        encrypted_name: &str,
        parent_dir_id: &str,
    ) -> Result<VaultDirectoryInfo, VaultOperationError> {
        let dir_id_file = dir_path.join("dir.c9r");
        let dir_id = fs::read_to_string(&dir_id_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure(
                format!("Failed to read directory ID: {e}")
            ))?
            .trim()
            .to_string();
        
        let decrypted_name = decrypt_filename(encrypted_name, parent_dir_id, &self.master_key)
            .map_err(VaultOperationError::FilenameDecryption)?;
        
        Ok(VaultDirectoryInfo {
            name: decrypted_name,
            directory_id: dir_id,
            encrypted_path: dir_path.to_path_buf(),
            parent_directory_id: parent_dir_id.to_string(),
        })
    }
    
    fn read_shortened_directory_info(
        &self,
        dir_path: &Path,
        parent_dir_id: &str,
    ) -> Result<VaultDirectoryInfo, VaultOperationError> {
        let name_file = dir_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure(
                format!("Failed to read shortened name: {e}")
            ))?
            .trim()
            .to_string();
        
        let dir_id_file = dir_path.join("dir.c9r");
        let dir_id = fs::read_to_string(&dir_id_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure(
                format!("Failed to read directory ID: {e}")
            ))?
            .trim()
            .to_string();
        
        let decrypted_name = decrypt_filename(&original_name, parent_dir_id, &self.master_key)
            .map_err(VaultOperationError::FilenameDecryption)?;
        
        Ok(VaultDirectoryInfo {
            name: decrypted_name,
            directory_id: dir_id,
            encrypted_path: dir_path.to_path_buf(),
            parent_directory_id: parent_dir_id.to_string(),
        })
    }
    
    fn read_shortened_file_info(
        &self,
        dir_path: &Path,
        parent_dir_id: &str,
    ) -> Result<VaultFileInfo, VaultOperationError> {
        let name_file = dir_path.join("name.c9s");
        let original_name = fs::read_to_string(&name_file)
            .map_err(|e| VaultOperationError::InvalidVaultStructure(
                format!("Failed to read shortened name: {e}")
            ))?
            .trim()
            .to_string();
        
        let decrypted_name = decrypt_filename(&original_name, parent_dir_id, &self.master_key)
            .map_err(VaultOperationError::FilenameDecryption)?;
        
        let contents_file = dir_path.join("contents.c9r");
        let metadata = fs::metadata(&contents_file)?;
        
        Ok(VaultFileInfo {
            name: decrypted_name,
            encrypted_name: dir_path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            encrypted_path: contents_file,
            encrypted_size: metadata.len(),
            is_shortened: true,
        })
    }
}

/// Debug helper to read and display files in a directory tree
pub fn debug_read_files_in_tree(
    vault_ops: &VaultOperations,
    directory_id: &str,
    _dir_name: &str,
    depth: usize,
) -> Result<(), VaultOperationError> {
    let indent = "  ".repeat(depth);
    
    // List and display files
    let files = vault_ops.list_files(directory_id)?;
    for file in files {
        println!("\n{}📄 {}", indent, file.name);
        println!("{}   Size: {} bytes (encrypted)", indent, file.encrypted_size);
        
        // For text files, show content preview
        if file.name.ends_with(".txt") || file.name.ends_with(".md") 
            || file.name.ends_with(".c") || file.name.ends_with(".rs") {
            
            match decrypt_file(&file.encrypted_path, &vault_ops.master_key) {
                Ok(decrypted) => {
                    println!("{}   Decrypted size: {} bytes", indent, decrypted.content.len());
                    
                    let content_str = if decrypted.content.is_empty() {
                        "(empty file)".to_string()
                    } else {
                        let preview_len = decrypted.content.len().min(200);
                        match String::from_utf8(decrypted.content[..preview_len].to_vec()) {
                            Ok(s) => s,
                            Err(_) => "(binary content)".to_string()
                        }
                    };
                    
                    println!("{indent}   Content preview:");
                    for line in content_str.lines().take(5) {
                        println!("{indent}   | {line}");
                    }
                    if decrypted.content.len() > 200 {
                        println!("{indent}   | ... (truncated)");
                    }
                }
                Err(e) => {
                    println!("{indent}   ❌ Failed to decrypt: {e}");
                }
            }
        }
    }
    
    // Recursively process subdirectories
    let subdirs = vault_ops.list_directories(directory_id)?;
    for subdir in subdirs {
        println!("\n{}📁 {}", indent, subdir.name);
        debug_read_files_in_tree(vault_ops, &subdir.directory_id, &subdir.name, depth + 1)?;
    }
    
    Ok(())
}