#![forbid(unsafe_code)]

use generic_array::{typenum::U16, GenericArray};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use url::Url;

use cryptolib::master_key_file::MasterKeyFile;
use cryptolib::names::decrypt_filename;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultConfigurationClaims {
    format: i32,
    shortening_threshold: i32,
    jti: String,
    cipher_combo: String,
}

fn main() {
    // Path to the vault
    let vault_path = Path::new("test_vault");
    // Path to the vault's configuration file (vault.cryptomator)
    let vault_config_path = vault_path.join("vault.cryptomator");

    // Read the vault configuration file
    let vault_config = fs::read_to_string(&vault_config_path).unwrap();
    // Read the header from JWT in the config file
    let header = jsonwebtoken::decode_header(&vault_config).unwrap();
    // Get the kid to retrieve the masterkey from the given URI
    let kid = header.kid.unwrap();
    // Get the masterkey path from the URI given in the kid
    let masterkey_uri = Url::parse(&kid).unwrap();
    assert_eq!(masterkey_uri.scheme(), "masterkeyfile");
    let master_key_path = vault_path.join(Path::new(masterkey_uri.path()));
    // Read the master key configuration JSON from the masterkey path
    let master_key_data_json = fs::read_to_string(&master_key_path).unwrap();
    // Decode the master key configuration JSON to a struct
    let master_key_data: MasterKeyFile = serde_json::from_str(&master_key_data_json).unwrap();
    // Unwrap the AES and MAC keys from the master key
    let master_key = master_key_data.unlock("123456789");
    dbg!(&master_key);
    // Generate raw key
    let raw_key = master_key.raw_key();
    dbg!(&raw_key);

    // Test decryption of README
    let folder_path = vault_path.join("d").join("IM").join("WKTPKIODILK3E2NMJRS7A3TOUXSZ2E");
    // Read the dirid.c9r
    let dirid_path = folder_path.join("dirid.c9r");
    let mut dirid: GenericArray<u8, U16> = GenericArray::default();
    let dirid_data = fs::read(&dirid_path).unwrap();
    dirid.copy_from_slice(&dirid_data);

    // Read other files in the folder (skipping dirid.c9r)
    let mut files = fs::read_dir(&folder_path).unwrap();
    while let Some(file) = files.next() {
        let file = file.unwrap();
        let file_path = file.path();
        if file_path.file_name().unwrap() == "dirid.c9r" {
            continue;
        }
        let file_name = file_path.file_name().unwrap().to_str().unwrap();
        let decrypted_name = decrypt_filename(file_name, dirid, &master_key);
        dbg!(&decrypted_name);
    }
}
