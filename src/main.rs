#![forbid(unsafe_code)]
#![allow(dead_code)]

use cryptolib::directory::{print_tree, VaultExplorer};
use cryptolib::names::hash_dir_id;
use cryptolib::vault::{extract_master_key, validate_vault_claims};
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

    println!("Validated claims: {:?}", claims);

    // Calculate where the root directory's contents should be
    println!("\n[DEBUG] Calculating root directory location");
    let root_dir_hash = hash_dir_id("", &master_key);
    println!("[DEBUG] Root directory hash: {}", root_dir_hash);

    // Build and print the directory tree
    let explorer = VaultExplorer::new(vault_path);
    let tree = explorer.build_directory_tree(&master_key)?;

    println!("\nVault Directory Structure:");
    println!("========================");
    print_tree(&tree, 0);

    Ok(())
}