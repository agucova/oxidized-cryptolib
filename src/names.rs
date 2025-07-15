#![allow(dead_code)]

use aes_siv::{siv::Aes256Siv, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use data_encoding::BASE32;
use ring::digest;
use secrecy::ExposeSecret;

use crate::master_key::MasterKey;

pub fn hash_dir_id(dir_id: &str, master_key: &MasterKey) -> String {
    // For AES-SIV, we need to use both keys - MAC key first, then encryption key
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(master_key.mac_master_key.expose_secret());
    key[32..].copy_from_slice(master_key.aes_master_key.expose_secret());

    let mut cipher = Aes256Siv::new(&key.into());

    // Encrypt directory ID with no associated data (null in the spec)
    let associated_data: &[&[u8]] = &[];
    let encrypted = cipher
        .encrypt(associated_data, dir_id.as_bytes())
        .expect("Failed to encrypt directory ID");

    let hashed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &encrypted);
    BASE32.encode(hashed.as_ref())
}

pub fn encrypt_filename(name: &str, parent_dir_id: &str, master_key: &MasterKey) -> String {
    // For AES-SIV, we need to use both keys - MAC key first, then encryption key
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(master_key.mac_master_key.expose_secret());
    key[32..].copy_from_slice(master_key.aes_master_key.expose_secret());

    let mut cipher = Aes256Siv::new(&key.into());

    // Encrypt with parent directory ID as associated data
    let associated_data: &[&[u8]] = &[parent_dir_id.as_bytes()];
    let encrypted = cipher
        .encrypt(associated_data, name.as_bytes())
        .expect("Encryption failed");

    let encoded = general_purpose::URL_SAFE.encode(&encrypted); // Note: using URL_SAFE with padding

    encoded + ".c9r"
}

pub fn decrypt_filename(
    encrypted_name: &str,
    parent_dir_id: &str,
    master_key: &MasterKey,
) -> Result<String, String> {
    let name_without_extension = encrypted_name.trim_end_matches(".c9r");

    // Try to decode - use URL_SAFE which handles padding
    let decoded = general_purpose::URL_SAFE
        .decode(name_without_extension.as_bytes())
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // For AES-SIV, we need to use both keys - MAC key first, then encryption key
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(master_key.mac_master_key.expose_secret());
    key[32..].copy_from_slice(master_key.aes_master_key.expose_secret());

    let mut cipher = Aes256Siv::new(&key.into());

    // Decrypt with parent directory ID as associated data
    let associated_data: &[&[u8]] = &[parent_dir_id.as_bytes()];
    let decrypted = cipher
        .decrypt(associated_data, &decoded)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    let result =
        String::from_utf8(decrypted.to_vec()).map_err(|e| format!("UTF-8 decode error: {}", e))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_key::MasterKey;

    fn create_test_master_key() -> MasterKey {
        // Create a deterministic master key for testing
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        // Fill with test data
        for i in 0..32 {
            aes_key[i] = i as u8;
            mac_key[i] = (32 + i) as u8;
        }

        MasterKey {
            aes_master_key: secrecy::Secret::new(aes_key),
            mac_master_key: secrecy::Secret::new(mac_key),
        }
    }

    #[test]
    fn test_deterministic_encryption_of_filenames() {
        let master_key = create_test_master_key();
        let orig_name = "test.txt";
        let parent_dir_id = ""; // Root directory

        let encrypted1 = encrypt_filename(&orig_name, parent_dir_id, &master_key);
        let encrypted2 = encrypt_filename(&orig_name, parent_dir_id, &master_key);

        println!("Encrypted: {}", encrypted1);

        assert_eq!(encrypted1, encrypted2, "Encryption should be deterministic");

        let decrypted = decrypt_filename(&encrypted1, parent_dir_id, &master_key).unwrap();
        assert_eq!(orig_name, decrypted);
    }

    #[test]
    fn test_real_filename_decryption() {
        // This test would need the actual master key from your vault
        // For now, we'll skip it
    }
}
