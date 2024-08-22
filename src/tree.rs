use std::collections::HashMap;
use std::fs;
use std::path::Path;

use generic_array::{typenum::U16, typenum::U32, GenericArray};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use secrecy::ExposeSecret;

use crate::master_key::MasterKey;
use crate::names::decrypt_filename;

#[derive(Debug)]
pub struct DecryptedNode {
    name: String,
    children: HashMap<String, DecryptedNode>,
}

fn process_directory(
    dir_path: &Path,
    parent_dir_id: &GenericArray<u8, U16>,
    master_key: &MasterKey,
    root: &mut DecryptedNode,
) {
    println!("Processing directory: {:?}", dir_path);
    println!("Parent directory ID: {:?}", parent_dir_id);

    let dirid_bytes = read_dirid_file(dir_path, master_key);
    println!("Directory ID bytes: {:?}", dirid_bytes);
    let dirid_string = format!("{:?}", dirid_bytes);
    println!("Directory ID string: {}", dirid_string);

    let current_node = root
        .children
        .entry(dirid_string.clone())
        .or_insert(DecryptedNode {
            name: dirid_string,
            children: HashMap::new(),
        });

    println!("Current node name: {}", current_node.name);

    for file in fs::read_dir(dir_path).unwrap() {
        let file = file.unwrap();
        let file_name = file.file_name().to_str().unwrap().to_string();
        println!("Processing file: {}", file_name);

        if file_name.starts_with('0') {
            println!("Identified as directory: {}", file_name);
            // This is a directory
            let sub_dir_path = file.path();
            process_directory(&sub_dir_path, &dirid_bytes, master_key, current_node);
        } else if file_name != "dirid.c9r" {
            println!("Identified as file: {}", file_name);
            // This is a file
            let clear_file_name = decrypt_filename(&file_name, dirid_bytes, master_key);
            println!("Decrypted file name: {}", clear_file_name);
            current_node.children.insert(
                clear_file_name.clone(),
                DecryptedNode {
                    name: clear_file_name,
                    children: HashMap::new(),
                },
            );
        } else {
            println!("Skipping dirid.c9r file");
        }
    }

    println!("Finished processing directory: {:?}", dir_path);
}

fn read_dirid_file(dir_path: &Path, master_key: &MasterKey) -> GenericArray<u8, U16> {
    let dirid_path = dir_path.join("dirid.c9r");
    println!("Reading directory id from: {}", dirid_path.display());
    let encrypted_content = fs::read(dirid_path).expect("Failed to read dirid.c9r");

    // The first 12 bytes are the nonce for the file header
    let header_nonce = Nonce::from_slice(&encrypted_content[..12]);

    // The next 40 bytes are the encrypted file header
    let encrypted_header = &encrypted_content[12..52];

    // The last 16 bytes of the file header are the tag
    let header_tag = &encrypted_content[52..68];

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(master_key.aes_master_key.expose_secret().into());

    // Decrypt the file header
    let decrypted_header = cipher
        .decrypt(header_nonce, encrypted_header)
        .expect("Failed to decrypt file header");

    // The last 32 bytes of the decrypted header contain the content key
    let content_key = GenericArray::clone_from_slice(&decrypted_header[8..40]);

    // Create a new cipher with the content key
    let content_cipher = Aes256Gcm::new(&content_key);

    // The remaining content is the encrypted payload
    let encrypted_payload = &encrypted_content[68..];

    // Decrypt the content
    let decrypted = content_cipher
        .decrypt(header_nonce, encrypted_payload)
        .expect("Decryption failed");

    // The decrypted content should be exactly 16 bytes (the directory ID)
    assert_eq!(decrypted.len(), 16, "Decrypted dirid is not 16 bytes");

    GenericArray::clone_from_slice(&decrypted)
}

pub fn decrypt_vault(vault_root: &Path, master_key: &MasterKey) -> Result<DecryptedNode, String> {
    let mut root = DecryptedNode {
        name: String::from("/"),
        children: HashMap::new(),
    };

    let root_dir_id = GenericArray::default(); // Empty for root directory

    for entry in fs::read_dir(vault_root.join("d")).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            for subentry in fs::read_dir(&path).unwrap() {
                let subentry = subentry.unwrap();
                let subpath = subentry.path();
                if subpath.is_dir() {
                    process_directory(&subpath, &root_dir_id, master_key, &mut root);
                }
            }
        }
    }

    Ok(root)
}

pub fn print_decrypted_tree(node: &DecryptedNode, indent: usize) {
    println!("{}{}/", " ".repeat(indent), node.name);
    for (name, child) in &node.children {
        if child.children.is_empty() {
            println!("{}  {} (file)", " ".repeat(indent), name);
        } else {
            print_decrypted_tree(child, indent + 2);
        }
    }
}

pub fn print_decrypted_vault_tree(vault_root: &Path, master_key: &MasterKey) {
    if !vault_root.exists() || !vault_root.is_dir() {
        println!("Error: The specified vault path does not exist or is not a directory.");
        return;
    }

    println!(
        "Decrypting and printing vault structure for: {}",
        vault_root.display()
    );

    match decrypt_vault(vault_root, master_key) {
        Ok(decrypted_tree) => {
            println!("Decrypted Vault Structure:");
            print_decrypted_tree(&decrypted_tree, 0);
        }
        Err(e) => {
            println!("Error decrypting vault: {}", e);
        }
    }
}
