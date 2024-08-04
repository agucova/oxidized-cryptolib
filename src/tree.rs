use std::collections::HashMap;
use std::fs;
use std::path::Path;

use generic_array::{typenum::U16, GenericArray};

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
    let dir_id = read_directory_id(dir_path);
    let clear_dir_name = read_directory_name(dir_path, parent_dir_id, master_key);

    let current_node = root
        .children
        .entry(clear_dir_name.clone())
        .or_insert(DecryptedNode {
            name: clear_dir_name,
            children: HashMap::new(),
        });

    for file in fs::read_dir(dir_path).unwrap() {
        let file = file.unwrap();
        let file_name = file.file_name().to_str().unwrap().to_string();

        if file_name.starts_with('0') {
            // This is a directory
            let sub_dir_path = file.path();
            process_directory(&sub_dir_path, &dir_id, master_key, current_node);
        } else if file_name != "dirid.c9r" {
            // This is a file
            let clear_file_name = decrypt_filename(&file_name, dir_id, master_key);
            current_node.children.insert(
                clear_file_name.clone(),
                DecryptedNode {
                    name: clear_file_name,
                    children: HashMap::new(),
                },
            );
        }
    }
}

fn read_directory_id(dir_path: &Path) -> GenericArray<u8, U16> {
    let dirid_path = dir_path.join("dirid.c9r");
    let dir_id = fs::read(dirid_path).unwrap();
    GenericArray::clone_from_slice(&dir_id[..16])
}

fn read_directory_name(
    dir_path: &Path,
    parent_dir_id: &GenericArray<u8, U16>,
    master_key: &MasterKey,
) -> String {
    let file_name = dir_path.file_name().unwrap().to_str().unwrap();
    // Remove the leading '0' from the directory name
    let encrypted_name = &file_name[1..];
    decrypt_filename(encrypted_name, *parent_dir_id, master_key)
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
