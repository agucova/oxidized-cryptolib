use oxidized_cryptolib::{
    crypto::keys::MasterKey,
    fs::{
        file::{encrypt_file_content, encrypt_file_header},
        name::encrypt_filename,
    },
    vault::{
        config::{create_vault_config, VaultConfig},
        master_key::create_masterkey_file,
    },
};
use assert_fs::TempDir;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// A builder for creating test vaults with known structure and content
pub struct VaultBuilder {
    temp_dir: TempDir,
    master_key: MasterKey,
    passphrase: String,
    vault_id: String,
    files: Vec<(String, Vec<u8>)>,
    directories: Vec<String>,
    rng_seed: Option<u64>,
}

impl VaultBuilder {
    /// Create a new vault builder with default test values
    pub fn new() -> Self {
        Self {
            temp_dir: assert_fs::TempDir::new().unwrap(),
            master_key: super::create_test_master_key(),
            passphrase: super::TEST_PASSPHRASE.to_string(),
            vault_id: super::TEST_VAULT_ID.to_string(),
            files: Vec::new(),
            directories: Vec::new(),
            rng_seed: Some(42), // Default deterministic seed
        }
    }
    
    /// Set a custom master key
    pub fn with_master_key(mut self, master_key: MasterKey) -> Self {
        self.master_key = master_key;
        self
    }
    
    /// Use a specific RNG seed for deterministic content keys
    pub fn with_rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self
    }
    
    /// Add a file to the vault
    pub fn add_file(mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.files.push((path.into(), content.into()));
        self
    }
    
    
    /// Add files from test structure
    pub fn add_file_structure(mut self, entries: Vec<super::test_structures::FileEntry>) -> Self {
        for entry in entries {
            self.files.push((entry.path.to_string(), entry.content));
        }
        self
    }
    
    /// Add a directory (without files)
    pub fn add_directory(mut self, path: impl Into<String>) -> Self {
        self.directories.push(path.into());
        self
    }
    
    /// Build the vault and return the path and master key
    pub fn build(self) -> (PathBuf, MasterKey) {
        let vault_path = self.temp_dir.path().to_path_buf();
        
        // Create vault structure
        fs::create_dir_all(vault_path.join("d")).unwrap();
        fs::create_dir_all(vault_path.join("masterkey")).unwrap();
        
        // Create vault.cryptomator
        let config = VaultConfig {
            jti: self.vault_id.clone(),
            format: 8,
            ciphertext_dir: Some(oxidized_cryptolib::vault::config::CiphertextDir("d".to_string())),
            payload: None,
        };
        
        let jwt = create_vault_config(&config, &self.master_key).unwrap();
        fs::write(vault_path.join("vault.cryptomator"), jwt).unwrap();
        
        // Create masterkey file
        let masterkey_content = create_masterkey_file(&self.master_key, &self.passphrase).unwrap();
        fs::write(
            vault_path.join("masterkey").join("masterkey.cryptomator"),
            masterkey_content,
        ).unwrap();
        
        // Track directory structure
        let mut dir_map: HashMap<String, String> = HashMap::new();
        dir_map.insert("".to_string(), "".to_string()); // Root directory
        
        // Create RNG for content keys
        let mut rng: Box<dyn RngCore> = if let Some(seed) = self.rng_seed {
            Box::new(StdRng::seed_from_u64(seed))
        } else {
            Box::new(rand::thread_rng())
        };
        
        // Process files and directories to create directory structure
        let mut all_paths: Vec<String> = self.files.iter()
            .map(|(path, _)| path.clone())
            .chain(self.directories.clone())
            .collect();
        all_paths.sort(); // Process in order for deterministic results
        
        // Create all necessary directories
        for path in &all_paths {
            let parts: Vec<&str> = path.split('/').collect();
            
            // For files, we need all parent directories
            // For explicit directories, we need the directory itself
            let dir_parts = if self.files.iter().any(|(f, _)| f == path) {
                // This is a file, create parent directories
                if parts.len() > 1 {
                    &parts[..parts.len()-1]
                } else {
                    continue; // File in root, no directories to create
                }
            } else {
                // This is an explicit directory, create it
                &parts[..]
            };
            
            // Create each level of the directory hierarchy
            for i in 1..=dir_parts.len() {
                let dir_path = dir_parts[..i].join("/");
                if !dir_map.contains_key(&dir_path) {
                    let parent_dir_id = if i == 1 {
                        ""
                    } else {
                        &dir_map[&dir_parts[..i-1].join("/")]
                    };
                    
                    let dir_name = dir_parts[i-1];
                    let dir_id = format!("dir-{}-{}", dir_path.replace('/', "-"), i);
                    
                    self.create_directory(&vault_path, parent_dir_id, dir_name, &dir_id);
                    dir_map.insert(dir_path, dir_id);
                }
            }
        }
        
        // Create files
        for (path, content) in &self.files {
            let parts: Vec<&str> = path.split('/').collect();
            let filename = parts.last().unwrap();
            
            let parent_dir_id = if parts.len() > 1 {
                &dir_map[&parts[..parts.len()-1].join("/")]
            } else {
                ""
            };
            
            self.create_file(&vault_path, parent_dir_id, filename, content, &mut *rng);
        }
        
        // Create empty directories
        for dir_path in &self.directories {
            if !self.files.iter().any(|(f, _)| f.starts_with(dir_path)) {
                let parts: Vec<&str> = dir_path.split('/').collect();
                let dir_name = parts.last().unwrap();
                
                let parent_dir_id = if parts.len() > 1 {
                    &dir_map[&parts[..parts.len()-1].join("/")]
                } else {
                    ""
                };
                
                if !dir_map.contains_key(dir_path) {
                    let dir_id = format!("dir-{}", dir_path.replace('/', "-"));
                    self.create_directory(&vault_path, parent_dir_id, dir_name, &dir_id);
                    dir_map.insert(dir_path.clone(), dir_id);
                }
            }
        }
        
        // Keep temp_dir alive by leaking it
        let _ = self.temp_dir.into_persistent();
        
        (vault_path, self.master_key)
    }
    
    /// Create a directory in the vault
    fn create_directory(&self, vault_path: &Path, parent_dir_id: &str, name: &str, dir_id: &str) {
        let encrypted_name = encrypt_filename(name, parent_dir_id, &self.master_key);
        let dir_hash = oxidized_cryptolib::fs::name::hash_dir_id(parent_dir_id, &self.master_key);
        
        let storage_path = vault_path
            .join("d")
            .join(&dir_hash[..2])
            .join(&dir_hash[2..32]);
        
        fs::create_dir_all(&storage_path).unwrap();
        
        let encrypted_dir_path = storage_path.join(format!("{encrypted_name}.c9r"));
        fs::create_dir_all(&encrypted_dir_path).unwrap();
        fs::write(encrypted_dir_path.join("dir.c9r"), dir_id).unwrap();
    }
    
    /// Create a file in the vault
    fn create_file(
        &self,
        vault_path: &Path,
        parent_dir_id: &str,
        filename: &str,
        content: &[u8],
        rng: &mut dyn RngCore,
    ) {
        let encrypted_name = encrypt_filename(filename, parent_dir_id, &self.master_key);
        let dir_hash = oxidized_cryptolib::fs::name::hash_dir_id(parent_dir_id, &self.master_key);
        
        let storage_path = vault_path
            .join("d")
            .join(&dir_hash[..2])
            .join(&dir_hash[2..32]);
        
        fs::create_dir_all(&storage_path).unwrap();
        
        // Generate content key and header nonce
        let mut content_key = [0u8; 32];
        rng.fill_bytes(&mut content_key);
        
        // Encrypt header (this includes its own nonce)
        let header = encrypt_file_header(&content_key, &self.master_key).unwrap();
        
        // Extract header nonce for content encryption (first 12 bytes of header)
        let header_nonce: [u8; 12] = header[0..12].try_into().unwrap();
        
        // Encrypt content
        let encrypted_content = encrypt_file_content(content, &content_key, &header_nonce).unwrap();
        
        // Combine header and content
        let mut file_data = Vec::new();
        file_data.extend_from_slice(&header);
        file_data.extend_from_slice(&encrypted_content);
        
        let file_path = if encrypted_name.len() > 220 {
            // Handle long filenames
            let hash = oxidized_cryptolib::fs::name::create_c9s_filename(&encrypted_name);
            let short_dir = storage_path.join(format!("{hash}.c9s"));
            fs::create_dir_all(&short_dir).unwrap();
            fs::write(short_dir.join("name.c9s"), &encrypted_name).unwrap();
            short_dir.join("contents.c9r")
        } else {
            storage_path.join(format!("{encrypted_name}.c9r"))
        };
        
        fs::write(file_path, file_data).unwrap();
    }
}

impl Default for VaultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick helper to create a vault with test files
pub fn create_test_vault_with_files(files: Vec<(&str, &[u8])>) -> (PathBuf, MasterKey) {
    let mut builder = VaultBuilder::new();
    for (path, content) in files {
        builder = builder.add_file(path, content);
    }
    builder.build()
}

/// Create a standard test vault with various file types
pub fn create_standard_test_vault() -> (PathBuf, MasterKey) {
    VaultBuilder::new()
        .add_file_structure(super::test_structures::nested_structure())
        .build()
}

/// Create a vault for testing edge cases
pub fn create_edge_case_vault() -> (PathBuf, MasterKey) {
    VaultBuilder::new()
        .add_file_structure(super::test_structures::edge_case_structure())
        .build()
}