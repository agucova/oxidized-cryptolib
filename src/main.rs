#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use url::Url;

mod lib;

use lib::{
    master_key_file::MasterKeyFile
};


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
    let vault_path = Path::new("vault");
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
    // Derive the KEK from the passphrase using scrypt
    let kek = master_key_data.derive_key("123456789");
    dbg!(kek.len());
}
