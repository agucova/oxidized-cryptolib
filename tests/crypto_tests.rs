mod crypto_tests {
    use oxidized_cryptolib::fs::file::{
        decrypt_file_content, decrypt_file_header, encrypt_file_content, encrypt_file_header,
    };
    use oxidized_cryptolib::crypto::keys::MasterKey;
    use proptest::prelude::*;
    use rand::{rngs::OsRng, RngCore};

    fn generate_content_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_header_roundtrip(content in any::<[u8; 32]>()) {
            let master_key = MasterKey::random();
            let encrypted_header = encrypt_file_header(&content, &master_key).unwrap();
            let decrypted_header = decrypt_file_header(&encrypted_header, &master_key).unwrap();
            prop_assert_eq!(content, decrypted_header.content_key);
        }

        #[test]
        fn test_content_roundtrip(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce = [0u8; 12];
            OsRng.fill_bytes(&mut header_nonce);
            let encrypted_content = encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
            let decrypted_content = decrypt_file_content(&encrypted_content, &content_key, &header_nonce).unwrap();
            prop_assert_eq!(content, decrypted_content);
        }

        #[test]
        fn test_content_integrity(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce = [0u8; 12];
            OsRng.fill_bytes(&mut header_nonce);
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
            let master_key = MasterKey::random();
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
            OsRng.fill_bytes(&mut header_nonce);
            let encrypted_content = encrypt_file_content(&content, &content_key1, &header_nonce).unwrap();
            let result = decrypt_file_content(&encrypted_content, &content_key2, &header_nonce);
            prop_assert!(result.is_err());
        }

        #[test]
        fn test_different_nonces(content in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let content_key = generate_content_key();
            let mut header_nonce1 = [0u8; 12];
            OsRng.fill_bytes(&mut header_nonce1);
            let mut header_nonce2 = [0u8; 12];
            OsRng.fill_bytes(&mut header_nonce2);
            let encrypted_content = encrypt_file_content(&content, &content_key, &header_nonce1).unwrap();
            let result = decrypt_file_content(&encrypted_content, &content_key, &header_nonce2);
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn test_empty_content() {
        let content_key = generate_content_key();
        let mut header_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut header_nonce);
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
        OsRng.fill_bytes(&mut header_nonce);
        let encrypted_content =
            encrypt_file_content(&content, &content_key, &header_nonce).unwrap();
        let decrypted_content =
            decrypt_file_content(&encrypted_content, &content_key, &header_nonce).unwrap();
        assert_eq!(content, decrypted_content);
    }
}
