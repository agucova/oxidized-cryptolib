#![forbid(unsafe_code)]
#![allow(dead_code)]

use cryptolib::fs::directory::{print_tree, VaultExplorer};
use cryptolib::fs::name::hash_dir_id;
use cryptolib::vault::config::{extract_master_key, validate_vault_claims};
use cryptolib::vault::operations::{debug_read_files_in_tree, VaultOperations};
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new("test_vault");
    let passphrase = "123456789";

    println!("Vault path: {:?}", vault_path.canonicalize()?);
    assert!(vault_path.exists(), "Vault path doesn't exist");
    assert!(vault_path.is_dir(), "Vault path is not a directory");

    let master_key = extract_master_key(vault_path, passphrase)?;

    let vault_config = fs::read_to_string(vault_path.join("vault.cryptomator"))?;
    let claims = validate_vault_claims(&vault_config, &master_key)?;

    println!("Validated claims: {claims:?}");

    // Calculate where the root directory's contents should be
    println!("\n[DEBUG] Calculating root directory location");
    let root_dir_hash = hash_dir_id("", &master_key);
    println!("[DEBUG] Root directory hash: {root_dir_hash}");

    // Build and print the directory tree
    let explorer = VaultExplorer::new(vault_path);
    let tree = explorer.build_directory_tree(&master_key)?;

    println!("\nVault Directory Structure:");
    println!("========================");
    print_tree(&tree, 0);

    // Create vault operations instance for high-level operations
    let vault_ops = VaultOperations::new(vault_path, master_key);
    
    // Demonstrate various vault operations
    println!("\n\nVault Operations Demo:");
    println!("======================");
    
    // 1. List files in root directory
    println!("\n1. Files in root directory:");
    let root_files = vault_ops.list_files("")?;
    for file in &root_files {
        println!("   📄 {} ({} bytes)", file.name, file.encrypted_size);
    }
    
    // 2. List subdirectories in root
    println!("\n2. Subdirectories in root:");
    let root_dirs = vault_ops.list_directories("")?;
    for dir in &root_dirs {
        println!("   📁 {} (ID: {})", dir.name, dir.directory_id);
    }
    
    // 3. Read a specific file
    println!("\n3. Reading a specific file (aes-wrap.c):");
    match vault_ops.read_file("", "aes-wrap.c") {
        Ok(decrypted) => {
            println!("   File size: {} bytes", decrypted.content.len());
            let preview = String::from_utf8_lossy(&decrypted.content[..200.min(decrypted.content.len())]);
            println!("   Preview: {}", preview.lines().take(3).collect::<Vec<_>>().join("\n            "));
        }
        Err(e) => println!("   Error: {e}"),
    }
    
    // 4. Resolve a path
    println!("\n4. Path resolution:");
    match vault_ops.resolve_path("test_folder/a.txt") {
        Ok((id, is_dir)) => {
            println!("   Path 'test_folder/a.txt' resolves to:");
            println!("   - Directory ID: {id}");
            println!("   - Is directory: {is_dir}");
        }
        Err(e) => println!("   Error: {e}"),
    }
    
    // 5. Debug helper: Read all files in tree
    println!("\n5. Full tree with file contents:");
    println!("================================");
    debug_read_files_in_tree(&vault_ops, "", "/", 0)?;

    Ok(())
}