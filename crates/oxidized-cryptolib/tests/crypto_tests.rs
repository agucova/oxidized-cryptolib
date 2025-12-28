mod crypto_tests {
    use oxidized_cryptolib::fs::file::{
        decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
    };
    use oxidized_cryptolib::crypto::keys::MasterKey;
    use proptest::prelude::*;
    use rand::RngCore;

    fn generate_content_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_header_roundtrip(content in any::<[u8; 32]>()) {
            let master_key = MasterKey::random().unwrap();
            let encrypted_header = encrypt_file_header(&content, &master_key).unwrap();
            let decrypted_header = decrypt_file_header(&encrypted_header, &master_key).unwrap();
            prop_assert_eq!(content, *decrypted_header.content_key);
        }

        #[test]
        fn test_content_roundtrip(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce);
            let encrypted_content = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
            let decrypted_content = decrypt_file_content(&encrypted_content, &content_key, &header_nonce).unwrap();
            prop_assert_eq!(content, decrypted_content);
        }

        #[test]
        fn test_content_integrity(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce);
            let mut encrypted_content = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();

            // Tamper with the encrypted content
            let mid = encrypted_content.len() / 2;
            if mid < encrypted_content.len() {
                encrypted_content[mid] ^= 0xFF;
            }

            let result = decrypt_file_content(&encrypted_content, &content_key, &header_nonce);
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_header_integrity(content_key in any::<[u8; 32]>()) {
            let master_key = MasterKey::random().unwrap();
            let mut encrypted_header = encrypt_file_header(&content_key, &master_key).unwrap();

            // Tamper with the encrypted header
            let mid = encrypted_header.len() / 2;
            if mid < encrypted_header.len() {
                encrypted_header[mid] ^= 0xFF;
            }

            let result = decrypt_file_header(&encrypted_header, &master_key);
            prop_assert!(result.is_err());
        }


        #[test]
        fn test_different_keys(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key1 = generate_content_key();
            let content_key2 = generate_content_key();
            let mut header_nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce);
            let encrypted_content = encrypt_file_content(&content, &content_key1, &header_nonce).unwrap();
            let result = decrypt_file_content(&encrypted_content, &content_key2, &header_nonce);
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_different_nonces(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce1 = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce1);
            let mut header_nonce2 = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce2);
            let encrypted_content = encrypt_file_content(&content, &content_key, &header_nonce1).unwrap();
            let result = decrypt_file_content(&encrypted_content, &content_key, &header_nonce2);
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn test_empty_content() {
        let content_key = generate_content_key();
        let mut header_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut header_nonce);
        let encrypted_content = encrypt_file_content(&[], &content_key, &header_nonce).unwrap();
        let decrypted_content =
            decrypt_file_content(&encrypted_content, &content_key, &header_nonce).unwrap();
        assert_eq!(decrypted_content, Vec::<u8>::new());
    }

    #[test]
    fn test_large_content() {
        let content = vec![0u8; 10 * 1024 * 1024]; // 10 MB
        let content_key = generate_content_key();
        let mut header_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut header_nonce);
        let encrypted_content =
            encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
        let decrypted_content =
            decrypt_file_content(&encrypted_content, &content_key, &header_nonce).unwrap();
        assert_eq!(content, decrypted_content);
    }

    /// Test that headers with non-0xFF reserved bytes can still be decrypted.
    ///
    /// This tests forward compatibility: the Java implementation does not validate
    /// reserved bytes, and future versions might use them. We should accept any value.
    #[test]
    fn test_header_with_non_standard_reserved_bytes() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};

        let master_key = MasterKey::random().unwrap();
        let content_key: [u8; 32] = generate_content_key();

        // Generate a nonce
        let mut header_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut header_nonce);

        // Create a header with non-0xFF reserved bytes (e.g., all zeros)
        let mut plaintext = vec![0x00; 8];  // Non-standard reserved bytes
        plaintext.extend_from_slice(&content_key);

        // Encrypt manually with the master key
        let encrypted_header = master_key.with_aes_key(|aes_key| {
            let key: &Key<Aes256Gcm> = aes_key.into();
            let cipher = Aes256Gcm::new(key);

            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&header_nonce), plaintext.as_ref())
                .expect("encryption should succeed");

            let mut result = Vec::with_capacity(68);
            result.extend_from_slice(&header_nonce);
            result.extend_from_slice(&ciphertext);
            Ok::<_, std::convert::Infallible>(result)
        }).expect("key access should succeed").expect("encryption should succeed");

        // Decryption should succeed despite non-standard reserved bytes
        let decrypted = decrypt_file_header(&encrypted_header, &master_key)
            .expect("decryption should succeed with non-standard reserved bytes");

        assert_eq!(*decrypted.content_key, content_key);
    }

    /// Test that headers we write still use 0xFF for reserved bytes.
    #[test]
    fn test_header_encryption_uses_standard_reserved_bytes() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};

        let master_key = MasterKey::random().unwrap();
        let content_key: [u8; 32] = generate_content_key();

        // Encrypt a header
        let encrypted_header = encrypt_file_header(&content_key, &master_key)
            .expect("encryption should succeed");

        // Decrypt manually to inspect the reserved bytes
        let nonce = &encrypted_header[0..12];
        let ciphertext_with_tag = &encrypted_header[12..68];

        let decrypted_plaintext = master_key.with_aes_key(|aes_key| {
            let key: &Key<Aes256Gcm> = aes_key.into();
            let cipher = Aes256Gcm::new(key);

            let plaintext = cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
                .expect("decryption should succeed");

            Ok::<_, std::convert::Infallible>(plaintext)
        }).expect("key access should succeed").expect("decryption should succeed");

        // Verify reserved bytes are 0xFF
        assert_eq!(&decrypted_plaintext[0..8], &[0xFF; 8],
            "encrypted headers should use 0xFF for reserved bytes");

        // Verify content key is correct
        assert_eq!(&decrypted_plaintext[8..40], &content_key);
    }

    /// Test various reserved byte patterns for forward compatibility.
    #[test]
    fn test_header_various_reserved_byte_patterns() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};

        let master_key = MasterKey::random().unwrap();
        let content_key: [u8; 32] = generate_content_key();

        // Test various reserved byte patterns that might be used in future versions
        let reserved_patterns: [[u8; 8]; 5] = [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // All zeros
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // Version byte
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],  // Partial fill
            [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],  // Random pattern
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],  // Sequential
        ];

        for reserved in &reserved_patterns {
            // Generate a nonce
            let mut header_nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut header_nonce);

            // Create header with custom reserved bytes
            let mut plaintext = reserved.to_vec();
            plaintext.extend_from_slice(&content_key);

            // Encrypt manually
            let encrypted_header = master_key.with_aes_key(|aes_key| {
                let key: &Key<Aes256Gcm> = aes_key.into();
                let cipher = Aes256Gcm::new(key);

                let ciphertext = cipher
                    .encrypt(Nonce::from_slice(&header_nonce), plaintext.as_ref())
                    .expect("encryption should succeed");

                let mut result = Vec::with_capacity(68);
                result.extend_from_slice(&header_nonce);
                result.extend_from_slice(&ciphertext);
                Ok::<_, std::convert::Infallible>(result)
            }).expect("key access should succeed").expect("encryption should succeed");

            // Decryption should succeed
            let decrypted = decrypt_file_header(&encrypted_header, &master_key)
                .unwrap_or_else(|e| panic!(
                    "decryption should succeed with reserved bytes {:02X?}, but got error: {}",
                    reserved, e
                ));

            assert_eq!(*decrypted.content_key, content_key,
                "content key should match for reserved bytes {:02X?}", reserved);
        }
    }
}

mod ctrmac_tests {
    use oxidized_cryptolib::crypto::keys::MasterKey;
    use oxidized_cryptolib::fs::file_ctrmac::{
        decrypt_content, decrypt_header, encrypt_content, encrypt_header, NONCE_SIZE, PAYLOAD_SIZE,
    };
    use oxidized_cryptolib::error::FileContext;
    use proptest::prelude::*;
    use rand::RngCore;

    fn generate_content_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }

    fn generate_mac_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_header_roundtrip(content_key in any::<[u8; 32]>()) {
            let master_key = MasterKey::random().unwrap();
            let encrypted = encrypt_header(&content_key, &master_key).unwrap();
            let header = decrypt_header(&encrypted, &master_key, FileContext::new()).unwrap();
            prop_assert_eq!(content_key, *header.content_key);
        }

        #[test]
        fn test_content_roundtrip(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let header_nonce = generate_nonce();
            let mac_key = generate_mac_key();

            let encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key).unwrap();
            let decrypted = decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new()).unwrap();
            prop_assert_eq!(content, decrypted);
        }

        #[test]
        fn test_content_integrity(content in prop::collection::vec(any::<u8>(), 1..100_000)) {
            let content_key = generate_content_key();
            let header_nonce = generate_nonce();
            let mac_key = generate_mac_key();

            let mut encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key).unwrap();

            // Tamper with the encrypted content (in the middle to avoid hitting the nonce)
            let mid = encrypted.len() / 2;
            encrypted[mid] ^= 0xFF;

            let result = decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new());
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_header_integrity(content_key in any::<[u8; 32]>()) {
            let master_key = MasterKey::random().unwrap();
            let mut encrypted = encrypt_header(&content_key, &master_key).unwrap();

            // Tamper with the encrypted header
            let mid = encrypted.len() / 2;
            encrypted[mid] ^= 0xFF;

            let result = decrypt_header(&encrypted, &master_key, FileContext::new());
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_different_content_keys(content in prop::collection::vec(any::<u8>(), 1..10_000)) {
            let content_key1 = generate_content_key();
            let content_key2 = generate_content_key();
            let header_nonce = generate_nonce();
            let mac_key = generate_mac_key();

            let encrypted = encrypt_content(&content, &content_key1, &header_nonce, &mac_key).unwrap();
            // Decryption with wrong content key should still succeed (HMAC doesn't depend on content key)
            // but produce garbage output. The content will be wrong, not an error.
            let decrypted = decrypt_content(&encrypted, &content_key2, &header_nonce, &mac_key, FileContext::new());
            // This actually succeeds because HMAC verification passes (doesn't include content key)
            // but the decrypted content will be garbage
            if let Ok(dec) = decrypted {
                prop_assert_ne!(content, dec);
            }
        }

        #[test]
        fn test_different_nonces(content in prop::collection::vec(any::<u8>(), 1..10_000)) {
            let content_key = generate_content_key();
            let header_nonce1 = generate_nonce();
            let header_nonce2 = generate_nonce();
            let mac_key = generate_mac_key();

            let encrypted = encrypt_content(&content, &content_key, &header_nonce1, &mac_key).unwrap();
            let result = decrypt_content(&encrypted, &content_key, &header_nonce2, &mac_key, FileContext::new());
            // Wrong header nonce causes HMAC verification to fail
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_different_mac_keys(content in prop::collection::vec(any::<u8>(), 1..10_000)) {
            let content_key = generate_content_key();
            let header_nonce = generate_nonce();
            let mac_key1 = generate_mac_key();
            let mac_key2 = generate_mac_key();

            let encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key1).unwrap();
            let result = decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key2, FileContext::new());
            // Wrong MAC key causes HMAC verification to fail
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn test_empty_content() {
        let content_key = generate_content_key();
        let header_nonce = generate_nonce();
        let mac_key = generate_mac_key();

        let encrypted = encrypt_content(&[], &content_key, &header_nonce, &mac_key).unwrap();
        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new())
                .unwrap();
        assert_eq!(decrypted, Vec::<u8>::new());
    }

    #[test]
    fn test_large_content() {
        let content = vec![0u8; 10 * 1024 * 1024]; // 10 MB
        let content_key = generate_content_key();
        let header_nonce = generate_nonce();
        let mac_key = generate_mac_key();

        let encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key).unwrap();
        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new())
                .unwrap();
        assert_eq!(content, decrypted);
    }

    #[test]
    fn test_chunk_boundary_content() {
        // Test content exactly at chunk boundary
        let content = vec![0xAB; PAYLOAD_SIZE];
        let content_key = generate_content_key();
        let header_nonce = generate_nonce();
        let mac_key = generate_mac_key();

        let encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key).unwrap();
        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new())
                .unwrap();
        assert_eq!(content, decrypted);
    }

    #[test]
    fn test_chunk_boundary_plus_one() {
        // Test content just over chunk boundary (requires 2 chunks)
        let content = vec![0xCD; PAYLOAD_SIZE + 1];
        let content_key = generate_content_key();
        let header_nonce = generate_nonce();
        let mac_key = generate_mac_key();

        let encrypted = encrypt_content(&content, &content_key, &header_nonce, &mac_key).unwrap();
        let decrypted =
            decrypt_content(&encrypted, &content_key, &header_nonce, &mac_key, FileContext::new())
                .unwrap();
        assert_eq!(content, decrypted);
    }
}

#[test]
fn test_decrypt_java_dirid_c9r_files() {
    // This test verifies that we can decrypt dirid.c9r files created by Java Cryptomator
    // The file format is: 68-byte header + AES-GCM encrypted content chunks
    //
    // Based on analysis of the Java reference implementation:
    // - DirectoryIdBackup.write(ciphertextDir) stores ciphertextDir.dirId()
    // - The file is stored in ciphertextDir.path() (the content directory)
    // - So dirid.c9r contains the DIRECTORY'S OWN ID, not the parent's ID
    //
    // Note: The Cryptomator documentation says "parent folder's ID" but this appears
    // to be incorrect based on the actual Java code.
    use oxidized_cryptolib::fs::file::{decrypt_file_header, decrypt_file_content};
    use oxidized_cryptolib::vault::extract_master_key;
    use std::fs;
    use std::path::{Path, PathBuf};

    // The test_vault is in the repo root, not the crate directory
    let vault_path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_vault")
        .canonicalize()
        .expect("test_vault should exist");

    // Load the master key from the test vault (password: "123456789")
    let master_key = extract_master_key(&vault_path, "123456789")
        .expect("Failed to extract master key");

    // Test 1: Root directory's content folder (d/IM/.../dirid.c9r) - 68 bytes
    // This should contain "" (empty string = root's own ID)
    let root_dirid_path = vault_path.join("d/IM/WKTPKIODILK3E2NMJRS7A3TOUXSZ2E/dirid.c9r");
    if root_dirid_path.exists() {
        let encrypted_data = fs::read(&root_dirid_path).expect("Failed to read root dirid.c9r");
        println!("Root dirid.c9r file size: {} bytes", encrypted_data.len());

        let header = decrypt_file_header(&encrypted_data[..68], &master_key)
            .expect("Failed to decrypt root dirid.c9r header");

        let content = if encrypted_data.len() > 68 {
            decrypt_file_content(&encrypted_data[68..], &header.content_key, &encrypted_data[..12])
                .expect("Failed to decrypt root dirid.c9r content")
        } else {
            Vec::new()
        };

        let decrypted_str = String::from_utf8(content).expect("content should be valid UTF-8");
        println!("Root dirid.c9r content: '{}' (length: {})", decrypted_str, decrypted_str.len());

        // Root directory's ID is empty string
        assert_eq!(decrypted_str, "", "Root's dirid.c9r should contain empty string (root's own ID)");
    }

    // Test 2: test_folder's content folder (d/QB/.../dirid.c9r) - 132 bytes
    // This should contain test_folder's own ID: "e9250eb8-078d-4fc0-8835-be92a313360c"
    let subfolder_dirid_path = vault_path.join("d/QB/EVY6BL4GCYX5AFNFLCLPVO554CCSMU/dirid.c9r");
    if subfolder_dirid_path.exists() {
        let encrypted_data = fs::read(&subfolder_dirid_path).expect("Failed to read subfolder dirid.c9r");
        println!("Subfolder dirid.c9r file size: {} bytes", encrypted_data.len());

        let header = decrypt_file_header(&encrypted_data[..68], &master_key)
            .expect("Failed to decrypt subfolder dirid.c9r header");

        let content = if encrypted_data.len() > 68 {
            decrypt_file_content(&encrypted_data[68..], &header.content_key, &encrypted_data[..12])
                .expect("Failed to decrypt subfolder dirid.c9r content")
        } else {
            Vec::new()
        };

        let decrypted_str = String::from_utf8(content).expect("content should be valid UTF-8");
        println!("Subfolder dirid.c9r content: '{}' (length: {})", decrypted_str, decrypted_str.len());

        // test_folder's own ID is e9250eb8-078d-4fc0-8835-be92a313360c
        assert_eq!(
            decrypted_str,
            "e9250eb8-078d-4fc0-8835-be92a313360c",
            "test_folder's dirid.c9r should contain its own ID, not parent's"
        );
    }
}
