use oxidized_cryptolib::crypto::keys::MasterKey;

pub mod vault_builder;
pub mod test_data;

pub const TEST_PASSPHRASE: &str = "test-passphrase-12345";
pub const TEST_VAULT_ID: &str = "test-vault-id";

/// Create a deterministic MasterKey for testing
pub fn create_test_master_key() -> MasterKey {
    MasterKey::new([0x01; 32], [0x02; 32]).unwrap()
}



/// Standard test file contents  
pub mod test_files {
    
    /// Create content of exactly the specified size
    pub fn create_sized_content(size: usize) -> Vec<u8> {
        let pattern = b"0123456789ABCDEF";
        let mut content = Vec::with_capacity(size);
        
        for i in 0..size {
            content.push(pattern[i % pattern.len()]);
        }
        
        content
    }
    
    /// File content with special characters
    #[allow(dead_code)] // Used in vault_integration_tests
    pub fn create_special_char_content() -> Vec<u8> {
        "Special chars: 🚀 émojis ñ UTF-8 \0 null bytes \r\n line endings".as_bytes().to_vec()
    }
    
    /// Create content that will test chunk boundaries (32KB chunks)
    #[allow(dead_code)] // Used in vault_integration_tests
    pub fn create_chunk_boundary_content() -> Vec<u8> {
        create_sized_content(65537) // 2 chunks + 1 byte
    }
}

/// Standard test filenames
#[allow(dead_code)] // Used in snapshot_tests
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
    ];
    
    pub const HIDDEN_FILES: &[&str] = &[
        ".hidden",
        ".gitignore",
        ".config",
    ];
}

/// Test directory structures
#[allow(dead_code)] // Available for future tests
pub mod test_structures {
    pub struct FileEntry {
        pub path: &'static str,
        pub content: Vec<u8>,
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
                content: super::test_files::create_sized_content(1024),
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
                content: Vec::new(),
            },
            FileEntry {
                path: "chunk_boundary.bin",
                content: super::test_files::create_sized_content(65537), // 2 chunks + 1 byte
            },
            FileEntry {
                path: "special_chars.txt",
                content: "Special chars: 🚀 émojis ñ UTF-8 \0 null bytes \r\n line endings".as_bytes().to_vec(),
            },
            FileEntry {
                path: "file with spaces.txt",
                content: b"File with spaces in name".to_vec(),
            },
            FileEntry {
                path: "émojis-🚀.txt",
                content: b"File with emoji in name".to_vec(),
            },
            FileEntry {
                path: "very_long_filename_that_might_exceed_normal_limits_and_cause_shortening_to_c9s_format_because_cryptomator_has_a_220_character_limit_for_encrypted_filenames_so_this_should_definitely_trigger_that_behavior_when_encrypted.txt",
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
    use oxidized_cryptolib::fs::file::DecryptedFile;
    
    /// Assert that a decrypted file matches expected content
    #[allow(dead_code)] // Used in vault_integration_tests
    pub fn assert_file_content(decrypted: &DecryptedFile, expected: &[u8]) {
        assert_eq!(
            decrypted.content, expected,
            "File content mismatch. Expected {} bytes, got {} bytes",
            expected.len(),
            decrypted.content.len()
        );
    }
    
}