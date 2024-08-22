#![allow(dead_code)]

use aead::Aead;
use aes_siv::{Aes256SivAead, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use generic_array::GenericArray;
use secrecy::Zeroize;

use crate::master_key::MasterKey;

use data_encoding::{BASE32, BASE64URL, BASE64URL_NOPAD};

use ring::digest;

use generic_array::typenum::{U16, U20};

// Module for encrypting and decrypting file and directory names
// according to the Cryptomator protocol using AES-SIV

pub fn hash_dir_id(dir_id: GenericArray<u8, U16>, master_key: &MasterKey) -> GenericArray<u8, U20> {
    let key = master_key.raw_key();
    let nonce = Nonce::from([0u8; 16]);
    let cipher = Aes256SivAead::new(&key);
    let encrypted = cipher.encrypt(&nonce, &*dir_id).unwrap();
    let hashed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &encrypted);
    GenericArray::clone_from_slice(hashed.as_ref())
}

pub fn encrypt_filename(
    name: &str,
    parent_dir_id: GenericArray<u8, U16>,
    master_key: &MasterKey,
) -> String {
    let cipher = Aes256SivAead::new(&master_key.raw_key());
    let nonce = Nonce::from_slice(&parent_dir_id);
    let encrypted = cipher
        .encrypt(nonce, name.as_bytes())
        .expect("Encryption failed");
    general_purpose::URL_SAFE_NO_PAD.encode(&encrypted) + ".c9r"
}

pub fn decrypt_filename(
    name: &str,
    parent_dir_id: GenericArray<u8, U16>,
    master_key: &MasterKey,
) -> String {
    println!("Decrypting filename: {}", name);
    let mut key = master_key.raw_key();
    let nonce = Nonce::from(parent_dir_id);
    let cipher = Aes256SivAead::new(&key);
    let name_without_extension = name.trim_end_matches(".c9r");
    println!("Name without extension: {}", name_without_extension);

    let decoded = BASE64URL.decode(name_without_extension.as_bytes());

    if decoded.is_err() {
        println!("Decoding failed: {:?}", decoded);
        return String::from("Decoding failed");
    }

    let decoded = decoded.unwrap();

    println!("Decoded (hex): {}", hex::encode(&decoded));

    let decrypted = cipher.decrypt(&nonce, &*decoded).unwrap();
    key.zeroize();
    println!("Decrypted (hex): {}", hex::encode(&decrypted));
    println!("Decrypted (utf-8): {}", String::from_utf8_lossy(&decrypted));
    String::from_utf8(decrypted).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_key::MasterKey;
    use generic_array::GenericArray;
    use uuid::Uuid;

    fn create_master_key() -> MasterKey {
        MasterKey::random()
    }

    #[test]
    fn test_deterministic_encryption_of_filenames() {
        let master_key = create_master_key();
        let orig_name = Uuid::new_v4().to_string();
        let parent_dir_id = GenericArray::from([0u8; 16]);

        let encrypted1 = encrypt_filename(&orig_name, parent_dir_id, &master_key);
        let encrypted2 = encrypt_filename(&orig_name, parent_dir_id, &master_key);
        let decrypted = decrypt_filename(&encrypted1, parent_dir_id, &master_key);

        assert_eq!(encrypted1, encrypted2);
        assert_eq!(orig_name, decrypted);
    }

    #[test]
    fn test_deterministic_encryption_of_128bit_filename() {
        let master_key = create_master_key();
        let orig_name = "aaaabbbbccccdddd"; // 128 bit ascii
        let parent_dir_id = GenericArray::from([0u8; 16]);

        let encrypted1 = encrypt_filename(orig_name, parent_dir_id, &master_key);
        let encrypted2 = encrypt_filename(orig_name, parent_dir_id, &master_key);
        let decrypted = decrypt_filename(&encrypted1, parent_dir_id, &master_key);

        assert_eq!(encrypted1, encrypted2);
        assert_eq!(orig_name, decrypted);
    }

    #[test]
    fn test_deterministic_hashing_of_directory_ids() {
        let master_key = create_master_key();
        let orig_dir_id = GenericArray::from(*Uuid::new_v4().as_bytes());

        let hashed1 = hash_dir_id(orig_dir_id, &master_key);
        let hashed2 = hash_dir_id(orig_dir_id, &master_key);

        assert_eq!(hashed1, hashed2);
        assert_eq!(hashed1.len(), 20); // SHA-1 produces a 20-byte hash
    }

    #[test]
    fn test_encryption_with_different_associated_data() {
        let master_key = create_master_key();
        let orig_name = "test";
        let parent_dir_id1 = GenericArray::from(Uuid::new_v4().as_bytes().clone());
        let parent_dir_id2 = GenericArray::from(Uuid::new_v4().as_bytes().clone());

        let encrypted1 = encrypt_filename(orig_name, parent_dir_id1, &master_key);
        let encrypted2 = encrypt_filename(orig_name, parent_dir_id2, &master_key);

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_decryption_with_incorrect_associated_data() {
        let master_key = create_master_key();
        let orig_name = "test";
        let correct_parent_dir_id = GenericArray::from(Uuid::new_v4().as_bytes().clone());
        let incorrect_parent_dir_id = GenericArray::from(Uuid::new_v4().as_bytes().clone());

        let encrypted = encrypt_filename(orig_name, correct_parent_dir_id, &master_key);

        // This should panic due to decryption failure
        let result = std::panic::catch_unwind(|| {
            decrypt_filename(&encrypted, incorrect_parent_dir_id, &master_key)
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_non_ciphertext() {
        let master_key = create_master_key();
        let parent_dir_id = GenericArray::from([0u8; 16]);

        let result =
            std::panic::catch_unwind(|| decrypt_filename("lol", parent_dir_id, &master_key));

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let master_key = create_master_key();
        let parent_dir_id = GenericArray::from([0u8; 16]);
        let orig_name = "test";

        let encrypted = encrypt_filename(orig_name, parent_dir_id, &master_key);

        // Create a new string with the first character changed
        let tampered = if let Some(first_char) = encrypted.chars().next() {
            let mut tampered_chars: Vec<char> = encrypted.chars().collect();
            tampered_chars[0] = ((first_char as u8) ^ 0x01) as char;
            tampered_chars.into_iter().collect()
        } else {
            encrypted.clone() // In case of an empty string
        };

        let result =
            std::panic::catch_unwind(|| decrypt_filename(&tampered, parent_dir_id, &master_key));

        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_encryption_with_associated_data() {
        let master_key = create_master_key();
        let parent_dir_id = GenericArray::from(*Uuid::new_v4().as_bytes());
        let orig_name = "test";

        let encrypted = encrypt_filename(orig_name, parent_dir_id, &master_key);
        let decrypted = decrypt_filename(&encrypted, parent_dir_id, &master_key);

        assert_eq!(orig_name, decrypted);
    }

    #[test]
    fn test_multiple_encryptions() {
        let master_key = create_master_key();
        let parent_dir_id = GenericArray::from([0u8; 16]);

        for _ in 0..100 {
            let orig_name = Uuid::new_v4().to_string();
            let encrypted = encrypt_filename(&orig_name, parent_dir_id, &master_key);
            let decrypted = decrypt_filename(&encrypted, parent_dir_id, &master_key);
            assert_eq!(orig_name, decrypted);
        }
    }
}
