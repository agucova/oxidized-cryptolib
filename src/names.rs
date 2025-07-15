#![allow(dead_code)]

use aes_siv::{siv::Aes256Siv, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use data_encoding::BASE32;
use ring::digest;

use crate::master_key::MasterKey;

pub fn hash_dir_id(dir_id: &str, master_key: &MasterKey) -> String {
    master_key.with_siv_key(|key| {
        let mut cipher = Aes256Siv::new(key);

        // Encrypt directory ID with no associated data (null in the spec)
        let associated_data: &[&[u8]] = &[];
        let encrypted = cipher
            .encrypt(associated_data, dir_id.as_bytes())
            .expect("Failed to encrypt directory ID");

        let hashed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &encrypted);
        BASE32.encode(hashed.as_ref())
    })
}

pub fn encrypt_filename(name: &str, parent_dir_id: &str, master_key: &MasterKey) -> String {
    master_key.with_siv_key(|key| {
        let mut cipher = Aes256Siv::new(key);

        // Encrypt with parent directory ID as associated data
        let associated_data: &[&[u8]] = &[parent_dir_id.as_bytes()];
        let encrypted = cipher
            .encrypt(associated_data, name.as_bytes())
            .expect("Encryption failed");

        let encoded = general_purpose::URL_SAFE.encode(&encrypted); // Note: using URL_SAFE with padding

        encoded + ".c9r"
    })
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

    master_key.with_siv_key(|key| {
        let mut cipher = Aes256Siv::new(key);

        // Decrypt with parent directory ID as associated data
        let associated_data: &[&[u8]] = &[parent_dir_id.as_bytes()];
        let decrypted = cipher
            .decrypt(associated_data, &decoded)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let result =
            String::from_utf8(decrypted.to_vec()).map_err(|e| format!("UTF-8 decode error: {}", e))?;

        Ok(result)
    })
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

    fn create_different_master_key() -> MasterKey {
        // Create a different deterministic master key for testing
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        // Fill with different test data
        for i in 0..32 {
            aes_key[i] = (i + 100) as u8;
            mac_key[i] = (i + 200) as u8;
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

        assert_eq!(encrypted1, encrypted2, "Encryption should be deterministic");

        let decrypted = decrypt_filename(&encrypted1, parent_dir_id, &master_key).unwrap();
        assert_eq!(orig_name, decrypted);
    }

    #[test]
    fn test_filename_roundtrip() {
        let master_key = create_test_master_key();
        let test_cases = vec![
            ("simple.txt", ""),
            ("file with spaces.doc", ""),
            ("unicode-café.txt", ""),
            ("numbers123.dat", ""),
            ("special!@#$%^&*()_+-=[]{}|;':\",./<>?.tmp", ""),
            ("very_long_filename_that_tests_the_limits_of_what_can_be_encrypted.extension", ""),
            ("", ""), // Empty filename
            (".", ""), // Current directory
            ("..", ""), // Parent directory
            (".hidden", ""), // Hidden file
            ("file.with.multiple.dots", ""),
        ];

        for (original, parent_dir_id) in test_cases {
            let encrypted = encrypt_filename(original, parent_dir_id, &master_key);
            let decrypted = decrypt_filename(&encrypted, parent_dir_id, &master_key)
                .unwrap_or_else(|e| panic!("Failed to decrypt '{}': {}", original, e));
            
            assert_eq!(original, decrypted, "Roundtrip failed for '{}'", original);
        }
    }

    #[test]
    fn test_filename_encryption_with_different_parent_dirs() {
        let master_key = create_test_master_key();
        let filename = "test.txt";
        let parent_dir_ids = vec![
            "",
            "root-dir-id",
            "e9250eb8-078d-4fc0-8835-be92a313360c",
            "very-long-directory-id-that-might-cause-issues",
            "unicode-café-dir-id",
            "special!@#$%^&*()_+-=[]{}|;':\",./<>?",
        ];

        for parent_dir_id in parent_dir_ids {
            let encrypted = encrypt_filename(filename, parent_dir_id, &master_key);
            let decrypted = decrypt_filename(&encrypted, parent_dir_id, &master_key)
                .unwrap_or_else(|e| panic!("Failed with parent_dir_id '{}': {}", parent_dir_id, e));
            
            assert_eq!(filename, decrypted, "Failed with parent_dir_id '{}'", parent_dir_id);
        }
    }

    #[test]
    fn test_filename_encryption_is_context_dependent() {
        let master_key = create_test_master_key();
        let filename = "test.txt";
        let parent_dir_id1 = "";
        let parent_dir_id2 = "different-parent";

        let encrypted1 = encrypt_filename(filename, parent_dir_id1, &master_key);
        let encrypted2 = encrypt_filename(filename, parent_dir_id2, &master_key);

        // Same filename with different parent directory IDs should produce different encrypted names
        assert_ne!(encrypted1, encrypted2, 
            "Same filename with different parent dirs should produce different encrypted names");

        // But each should decrypt correctly with their respective parent ID
        let decrypted1 = decrypt_filename(&encrypted1, parent_dir_id1, &master_key).unwrap();
        let decrypted2 = decrypt_filename(&encrypted2, parent_dir_id2, &master_key).unwrap();
        
        assert_eq!(filename, decrypted1);
        assert_eq!(filename, decrypted2);
    }

    #[test]
    fn test_filename_decryption_with_wrong_parent_dir_fails() {
        let master_key = create_test_master_key();
        let filename = "test.txt";
        let correct_parent_dir_id = "correct-parent";
        let wrong_parent_dir_id = "wrong-parent";

        let encrypted = encrypt_filename(filename, correct_parent_dir_id, &master_key);
        
        // Should decrypt successfully with correct parent dir ID
        let decrypted = decrypt_filename(&encrypted, correct_parent_dir_id, &master_key);
        assert!(decrypted.is_ok());
        assert_eq!(filename, decrypted.unwrap());

        // Should fail with wrong parent dir ID
        let failed_decryption = decrypt_filename(&encrypted, wrong_parent_dir_id, &master_key);
        assert!(failed_decryption.is_err(), "Decryption should fail with wrong parent dir ID");
    }

    #[test]
    fn test_filename_decryption_with_wrong_key_fails() {
        let master_key1 = create_test_master_key();
        let master_key2 = create_different_master_key();
        let filename = "test.txt";
        let parent_dir_id = "";

        let encrypted = encrypt_filename(filename, parent_dir_id, &master_key1);
        
        // Should decrypt successfully with correct key
        let decrypted = decrypt_filename(&encrypted, parent_dir_id, &master_key1);
        assert!(decrypted.is_ok());
        assert_eq!(filename, decrypted.unwrap());

        // Should fail with wrong key
        let failed_decryption = decrypt_filename(&encrypted, parent_dir_id, &master_key2);
        assert!(failed_decryption.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_filename_with_invalid_base64_fails() {
        let master_key = create_test_master_key();
        let parent_dir_id = "";
        
        let invalid_filenames = vec![
            "invalid-base64!.c9r",
            "not-base64-at-all.c9r",
            "=invalid=.c9r",
            "spaces in base64.c9r",
            ".c9r", // No base64 part
        ];

        for invalid_filename in invalid_filenames {
            let result = decrypt_filename(invalid_filename, parent_dir_id, &master_key);
            assert!(result.is_err(), "Invalid filename '{}' should fail to decrypt", invalid_filename);
        }
    }

    #[test]
    fn test_directory_id_hashing() {
        let master_key = create_test_master_key();
        
        // Test that directory ID hashing is deterministic
        let dir_id = "test-directory-id";
        let hash1 = hash_dir_id(dir_id, &master_key);
        let hash2 = hash_dir_id(dir_id, &master_key);
        
        assert_eq!(hash1, hash2, "Directory ID hashing should be deterministic");
        
        // Test that different directory IDs produce different hashes
        let dir_id2 = "different-directory-id";
        let hash3 = hash_dir_id(dir_id2, &master_key);
        
        assert_ne!(hash1, hash3, "Different directory IDs should produce different hashes");
        
        // Test root directory (empty string)
        let root_hash = hash_dir_id("", &master_key);
        assert_ne!(root_hash, hash1, "Root directory should have different hash than regular directory");
    }

    #[test]
    fn test_directory_id_hashing_with_different_keys() {
        let master_key1 = create_test_master_key();
        let master_key2 = create_different_master_key();
        let dir_id = "test-directory-id";
        
        let hash1 = hash_dir_id(dir_id, &master_key1);
        let hash2 = hash_dir_id(dir_id, &master_key2);
        
        assert_ne!(hash1, hash2, "Same directory ID with different keys should produce different hashes");
    }

    #[test]
    fn test_directory_id_hash_format() {
        let master_key = create_test_master_key();
        let dir_id = "test-directory-id";
        
        let hash = hash_dir_id(dir_id, &master_key);
        
        // Should be Base32 encoded (A-Z, 2-7, no padding for SHA1)
        assert!(!hash.is_empty(), "Hash should not be empty");
        assert!(hash.len() >= 32, "Hash should be at least 32 characters long");
        
        // Should only contain valid Base32 characters
        for ch in hash.chars() {
            assert!(ch.is_ascii_alphanumeric() || ch == '=', 
                "Hash should only contain Base32 characters, found: {}", ch);
        }
    }

    #[test]
    fn test_edge_cases_for_directory_ids() {
        let master_key = create_test_master_key();
        
        let test_cases = vec![
            "", // Root directory
            "a", // Single character
            "very-long-directory-id-that-might-cause-issues-with-encryption-or-hashing",
            "unicode-café-directory-id",
            "special!@#$%^&*()_+-=[]{}|;':\",./<>?",
            "numbers123456789",
            "mixed-CASE-Directory-ID",
            "e9250eb8-078d-4fc0-8835-be92a313360c", // UUID format
        ];
        
        for dir_id in test_cases {
            let hash = hash_dir_id(dir_id, &master_key);
            assert!(!hash.is_empty(), "Hash should not be empty for dir_id: '{}'", dir_id);
            assert!(hash.len() >= 32, "Hash should be at least 32 characters for dir_id: '{}'", dir_id);
        }
    }

    #[test]
    fn test_encrypted_filename_format() {
        let master_key = create_test_master_key();
        let filename = "test.txt";
        let parent_dir_id = "";
        
        let encrypted = encrypt_filename(filename, parent_dir_id, &master_key);
        
        // Should end with .c9r extension
        assert!(encrypted.ends_with(".c9r"), "Encrypted filename should end with .c9r");
        
        // Should be longer than the original
        assert!(encrypted.len() > filename.len(), "Encrypted filename should be longer than original");
        
        // The part before .c9r should be valid base64
        let base64_part = encrypted.trim_end_matches(".c9r");
        assert!(!base64_part.is_empty(), "Base64 part should not be empty");
        
        // Should be able to decode as base64
        let decoded = general_purpose::URL_SAFE.decode(base64_part.as_bytes());
        assert!(decoded.is_ok(), "Base64 part should be valid base64");
    }
}
