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

#[test]
fn test_decrypt_java_dirid_c9r_file() {
    // This test verifies that we can decrypt dirid.c9r files created by Java Cryptomator
    // The file format is: 68-byte header + AES-GCM encrypted content chunks
    use oxidized_cryptolib::fs::file::{decrypt_file_header, decrypt_file_content};
    use oxidized_cryptolib::vault::extract_master_key;
    use std::fs;
    use std::path::Path;

    let vault_path = Path::new("test_vault");

    // Load the master key from the test vault (password: "123456789")
    let master_key = extract_master_key(vault_path, "123456789")
        .expect("Failed to extract master key");

    // Try to decrypt the dirid.c9r file in the test_folder's content directory
    // d/QB/EVY6BL4GCYX5AFNFLCLPVO554CCSMU/dirid.c9r (132 bytes)
    let dirid_path = vault_path.join("d/QB/EVY6BL4GCYX5AFNFLCLPVO554CCSMU/dirid.c9r");

    if !dirid_path.exists() {
        println!("dirid.c9r file not found at {:?}, skipping test", dirid_path);
        return;
    }

    let encrypted_data = fs::read(&dirid_path).expect("Failed to read dirid.c9r");
    println!("dirid.c9r file size: {} bytes", encrypted_data.len());

    // Verify it's in file content format (68+ bytes)
    assert!(encrypted_data.len() >= 68, "dirid.c9r should be at least 68 bytes (file header size)");

    // Try to decrypt as a regular file
    let header = decrypt_file_header(&encrypted_data[..68], &master_key)
        .expect("Failed to decrypt dirid.c9r header - this means Java uses different format!");

    let content = if encrypted_data.len() > 68 {
        decrypt_file_content(&encrypted_data[68..], &header.content_key, &encrypted_data[..12])
            .expect("Failed to decrypt dirid.c9r content")
    } else {
        Vec::new()
    };

    let decrypted_str = String::from_utf8(content).expect("dirid.c9r content should be valid UTF-8");
    println!("Decrypted dirid.c9r content: '{}'", decrypted_str);

    // The content should be a directory ID (either empty string or UUID format)
    assert!(
        decrypted_str.is_empty() || decrypted_str.len() == 36,
        "dirid.c9r should contain empty string or UUID, got: '{}'",
        decrypted_str
    );
}
