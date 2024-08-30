#![forbid(unsafe_code)]
#![allow(dead_code)]

use cryptolib::files::decrypt_file;
use std::fs;
use std::path::Path;

use cryptolib::vault::{extract_master_key, validate_vault_claims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new("test_vault");
    let passphrase = "123456789";

    let master_key = extract_master_key(vault_path, passphrase)?;

    let vault_config = fs::read_to_string(vault_path.join("vault.cryptomator"))?;
    let claims = validate_vault_claims(&vault_config, &master_key)?;

    println!("Validated claims: {:?}", claims);

    // Iterate over all files in the vault tree
    for entry in walkdir::WalkDir::new(vault_path.join("d"))
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && path.extension().unwrap() == "c9r" {
            if path.file_name().unwrap() == "dir.c9r" {
                continue;
            }
            println!("Decrypting file on: {:?}", path);
            let decrypted_file = decrypt_file(&path, &master_key).unwrap();
            println!("{:?}", decrypted_file);
        }
    }

    Ok(())
}
