use oxidized_cryptolib::{
    crypto::keys::MasterKey,
    vault::{
        config::{CiphertextDir, Payload, VaultConfig},
    },
};
use assert_fs::TempDir;
use secrecy::Secret;
use std::path::Path;

pub mod vault_builder;
pub mod test_data;

pub const TEST_PASSPHRASE: &str = "test-passphrase-12345";
pub const TEST_VAULT_ID: &str = "test-vault-id";

/// Create a deterministic MasterKey for testing
pub fn create_test_master_key() -> MasterKey {
    MasterKey {
        aes_master_key: Secret::new([0x01; 32]),
        mac_master_key: Secret::new([0x02; 32]),
    }
}

/// Create a MasterKey from a seed value for deterministic testing
pub fn create_seeded_master_key(seed: u8) -> MasterKey {
    let mut aes_key = [seed; 32];
    let mut mac_key = [seed + 1; 32];
    
    // Make keys more unique while still deterministic
    for i in 0..32 {
        aes_key[i] = aes_key[i].wrapping_add(i as u8);
        mac_key[i] = mac_key[i].wrapping_add(i as u8 * 2);
    }
    
    MasterKey {
        aes_master_key: Secret::new(aes_key),
        mac_master_key: Secret::new(mac_key),
    }
}

/// Create a test vault config with default values
pub fn create_test_vault_config() -> VaultConfig {
    VaultConfig {
        jti: TEST_VAULT_ID.to_string(),
        format: 8,
        ciphertext_dir: Some(CiphertextDir("d".to_string())),
        payload: Some(Payload {
            key: "test-key".to_string(),
            other_fields: Default::default(),
        }),
    }
}

/// Create a temporary directory for testing
pub fn create_temp_vault() -> TempDir {
    assert_fs::TempDir::new().unwrap()
}

/// Standard test file contents
pub mod test_files {
    pub const EMPTY_FILE: &[u8] = b"";
    pub const SMALL_TEXT: &[u8] = b"Hello, World!";
    pub const LOREM_IPSUM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    
    /// Create content of exactly the specified size
    pub fn create_sized_content(size: usize) -> Vec<u8> {
        let pattern = b"0123456789ABCDEF";
        let mut content = Vec::with_capacity(size);
        
        for i in 0..size {
            content.push(pattern[i % pattern.len()]);
        }
        
        content
    }
    
    /// Create content that will test chunk boundaries (32KB chunks)
    pub fn create_chunk_boundary_content() -> Vec<u8> {
        // 32KB - 1, 32KB, 32KB + 1
        vec![
            create_sized_content(32767),
            create_sized_content(32768),
            create_sized_content(32769),
            create_sized_content(65536), // 2 chunks exactly
            create_sized_content(65537), // 2 chunks + 1 byte
        ]
        .into_iter()
        .flatten()
        .collect()
    }
    
    /// File content with special characters
    pub fn create_special_char_content() -> Vec<u8> {
        "Special chars: 🚀 émojis ñ UTF-8 \0 null bytes \r\n line endings".as_bytes().to_vec()
    }
}

/// Standard test filenames
pub mod test_filenames {
    pub const NORMAL_FILES: &[&str] = &[
        "test.txt",
        "document.pdf",
        "image.png",
        "data.json",
    ];
    
    pub const SPECIAL_CHAR_FILES: &[&str] = &[
        "file with spaces.txt",
        "émojis-🚀.txt",
        "special@#$%^chars.doc",
        "very_long_filename_that_might_exceed_normal_limits_and_cause_shortening_to_c9s_format_because_cryptomator_has_a_220_character_limit_for_encrypted_filenames_so_this_should_definitely_trigger_that_behavior_when_encrypted.txt",
    ];
    
    pub const HIDDEN_FILES: &[&str] = &[
        ".hidden",
        ".gitignore",
        ".config",
    ];
}

/// Test directory structures
pub mod test_structures {
    use super::*;
    
    pub struct FileEntry {
        pub path: &'static str,
        pub content: Vec<u8>,
    }
    
    /// Simple flat directory with a few files
    pub fn simple_structure() -> Vec<FileEntry> {
        vec![
            FileEntry {
                path: "file1.txt",
                content: test_files::SMALL_TEXT.to_vec(),
            },
            FileEntry {
                path: "file2.txt",
                content: test_files::LOREM_IPSUM.to_vec(),
            },
        ]
    }
    
    /// Nested directory structure
    pub fn nested_structure() -> Vec<FileEntry> {
        vec![
            FileEntry {
                path: "root.txt",
                content: b"Root file".to_vec(),
            },
            FileEntry {
                path: "docs/readme.md",
                content: b"# Documentation".to_vec(),
            },
            FileEntry {
                path: "docs/guide.md",
                content: b"User guide content".to_vec(),
            },
            FileEntry {
                path: "src/main.rs",
                content: b"fn main() {}".to_vec(),
            },
            FileEntry {
                path: "src/lib.rs",
                content: b"pub mod test;".to_vec(),
            },
            FileEntry {
                path: "src/test/mod.rs",
                content: b"#[test]\nfn test() {}".to_vec(),
            },
            FileEntry {
                path: "assets/images/logo.png",
                content: test_files::create_sized_content(1024),
            },
            FileEntry {
                path: "assets/data.json",
                content: b"{\"test\": true}".to_vec(),
            },
        ]
    }
    
    /// Edge case structure with various file types and sizes
    pub fn edge_case_structure() -> Vec<FileEntry> {
        vec![
            FileEntry {
                path: "empty.txt",
                content: test_files::EMPTY_FILE.to_vec(),
            },
            FileEntry {
                path: "chunk_boundary.bin",
                content: test_files::create_chunk_boundary_content(),
            },
            FileEntry {
                path: "special_chars.txt",
                content: test_files::create_special_char_content(),
            },
            FileEntry {
                path: test_filenames::SPECIAL_CHAR_FILES[0],
                content: b"File with spaces in name".to_vec(),
            },
            FileEntry {
                path: test_filenames::SPECIAL_CHAR_FILES[1],
                content: b"File with emoji in name".to_vec(),
            },
            FileEntry {
                path: test_filenames::SPECIAL_CHAR_FILES[3],
                content: b"Very long filename".to_vec(),
            },
            FileEntry {
                path: "nested/deeply/nested/structure/file.txt",
                content: b"Deeply nested file".to_vec(),
            },
        ]
    }
}

/// Utility functions for assertions
pub mod assertions {
    use super::*;
    use oxidized_cryptolib::fs::file::{decrypt_file, DecryptedFile};
    
    /// Assert that a decrypted file matches expected content
    pub fn assert_file_content(decrypted: &DecryptedFile, expected: &[u8]) {
        assert_eq!(
            decrypted.content, expected,
            "File content mismatch. Expected {} bytes, got {} bytes",
            expected.len(),
            decrypted.content.len()
        );
    }
    
    /// Assert that a file can be decrypted and matches expected content
    pub fn assert_file_decrypts_to(
        encrypted_path: &Path,
        master_key: &MasterKey,
        expected_content: &[u8],
    ) {
        let decrypted = decrypt_file(encrypted_path, master_key)
            .expect("Failed to decrypt file");
        assert_file_content(&decrypted, expected_content);
    }
    
    /// Assert vault structure contains expected directories
    pub fn assert_vault_has_directories(vault_path: &Path, expected_dirs: &[&str]) {
        for dir in expected_dirs {
            let path = vault_path.join(dir);
            assert!(
                path.exists() && path.is_dir(),
                "Expected directory {} to exist",
                dir
            );
        }
    }
}