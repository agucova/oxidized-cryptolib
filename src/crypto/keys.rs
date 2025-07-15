#![forbid(unsafe_code)]

use generic_array::{typenum::U64, GenericArray};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use zeroize::{Zeroize, Zeroizing};

/// Master key pair for Cryptomator vault operations.
///
/// This struct holds both the AES encryption key and MAC authentication key,
/// each 256 bits (32 bytes) for a total of 512 bits of key material.
///
/// # Security
///
/// The keys are stored using the `secrecy` crate's `Secret` type, which:
/// - Prevents the keys from being accidentally logged or displayed
/// - Ensures the memory is zeroed when the keys are dropped
/// - Provides controlled access through the `expose_secret()` method
///
/// Access to key material is provided through scoped access methods that
/// ensure keys are only exposed for the minimum necessary time and are
/// automatically cleaned up.
#[derive(Debug, Clone)]
pub struct MasterKey {
    pub aes_master_key: Secret<[u8; 32]>,
    pub mac_master_key: Secret<[u8; 32]>,
}

impl MasterKey {
    /// Generate a new random master key pair using a cryptographically secure RNG.
    pub fn random() -> Self {
        let mut aes_master_key = [0u8; 32];
        let mut mac_master_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_master_key);
        OsRng.fill_bytes(&mut mac_master_key);
        MasterKey {
            aes_master_key: Secret::new(aes_master_key),
            mac_master_key: Secret::new(mac_master_key),
        }
    }

    /// Execute a function with access to the raw 512-bit combined key material.
    ///
    /// This method provides controlled access to the full 64-byte key material
    /// (AES key || MAC key) through a callback. The key material is automatically
    /// zeroed when the callback completes.
    ///
    /// # Security
    ///
    /// This follows the scoped access pattern used by libraries like `ring`:
    /// - The key material never escapes this function
    /// - The callback cannot store references to the key
    /// - Memory is automatically zeroed after use
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// let master_key = MasterKey::random();
    ///
    /// let result = master_key.with_raw_key(|key_bytes| {
    ///     // Use key_bytes here - it will be zeroed after this scope
    ///     assert_eq!(key_bytes.len(), 64);
    ///     // Return some result from your crypto operation
    ///     42
    /// });
    /// assert_eq!(result, 42);
    /// ```
    pub fn with_raw_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut key = Zeroizing::new([0u8; 64]);
        key.as_mut()[..32].copy_from_slice(self.aes_master_key.expose_secret());
        key.as_mut()[32..].copy_from_slice(self.mac_master_key.expose_secret());
        f(key.as_ref())
    }

    /// Execute a function with access to the raw 512-bit combined key as a GenericArray.
    ///
    /// Similar to `with_raw_key` but provides the key as a `GenericArray<u8, U64>`
    /// for compatibility with APIs that expect this type.
    ///
    /// # Security
    ///
    /// Same security properties as `with_raw_key` - the key is automatically
    /// zeroed after the callback completes.
    pub fn with_raw_key_array<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&GenericArray<u8, U64>) -> R,
    {
        // Custom wrapper since GenericArray doesn't implement DefaultIsZeroes
        struct ZeroizeOnDrop(GenericArray<u8, U64>);
        
        impl Drop for ZeroizeOnDrop {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        
        let mut key = ZeroizeOnDrop(GenericArray::<u8, U64>::default());
        key.0[..32].copy_from_slice(self.aes_master_key.expose_secret());
        key.0[32..].copy_from_slice(self.mac_master_key.expose_secret());
        f(&key.0)
    }

    /// Execute a function with access to just the AES encryption key.
    ///
    /// This method provides controlled access to the 32-byte AES key through
    /// a callback. Use this when you only need the encryption key, not the MAC key.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use aes_gcm::{Aes256Gcm, Key, KeyInit};
    /// let master_key = MasterKey::random();
    ///
    /// let cipher = master_key.with_aes_key(|key_bytes| {
    ///     let key: &Key<Aes256Gcm> = key_bytes.into();
    ///     Aes256Gcm::new(key)
    /// });
    /// ```
    pub fn with_aes_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        f(self.aes_master_key.expose_secret())
    }

    /// Execute a function with access to just the MAC key.
    ///
    /// This method provides controlled access to the 32-byte MAC key through
    /// a callback. Use this when you only need the MAC key, not the encryption key.
    pub fn with_mac_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        f(self.mac_master_key.expose_secret())
    }

    /// Execute a function with access to both keys in AES-SIV order (MAC || AES).
    ///
    /// For AES-SIV operations, the key order is MAC key first, then AES key.
    /// This method provides the keys in the correct order for use with AES-SIV.
    ///
    /// # Security
    ///
    /// The 64-byte combined key is automatically zeroed after the callback completes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use aes_siv::{siv::Aes256Siv, KeyInit};
    /// let master_key = MasterKey::random();
    ///
    /// let cipher = master_key.with_siv_key(|key_bytes| {
    ///     Aes256Siv::new(key_bytes.into())
    /// });
    /// ```
    pub fn with_siv_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&GenericArray<u8, U64>) -> R,
    {
        // Custom wrapper since GenericArray doesn't implement DefaultIsZeroes
        struct ZeroizeOnDrop(GenericArray<u8, U64>);
        
        impl Drop for ZeroizeOnDrop {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        
        let mut key = ZeroizeOnDrop(GenericArray::<u8, U64>::default());
        // Note: SIV uses MAC key first, then AES key
        key.0[..32].copy_from_slice(self.mac_master_key.expose_secret());
        key.0[32..].copy_from_slice(self.aes_master_key.expose_secret());
        f(&key.0)
    }

    /// Create an AES-SIV cipher for filename encryption/decryption.
    ///
    /// This is a convenience method that creates an `Aes256Siv` cipher
    /// with the correct key ordering for Cryptomator filename operations.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// let master_key = MasterKey::random();
    /// let mut cipher = master_key.create_name_cipher();
    ///
    /// // Use cipher for filename encryption
    /// let parent_dir_id = b"parent-directory-id";
    /// let filename = "test.txt";
    /// let encrypted = cipher.encrypt(&[parent_dir_id], filename.as_bytes())
    ///     .expect("Encryption failed");
    /// ```
    pub fn create_name_cipher(&self) -> aes_siv::siv::Aes256Siv {
        self.with_siv_key(|key| {
            use aes_siv::KeyInit;
            aes_siv::siv::Aes256Siv::new(key)
        })
    }

    /// Create a JWT decoding key for vault validation.
    ///
    /// This method creates a `jsonwebtoken::DecodingKey` using the combined
    /// master key material. Note that `DecodingKey` internally copies the key
    /// and does not provide zeroization.
    ///
    /// # Security Warning
    ///
    /// The `jsonwebtoken` crate does not zeroize key material. Use this method
    /// only for short-lived operations and be aware that the key material may
    /// remain in memory after the `DecodingKey` is dropped.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use jsonwebtoken::{encode, decode, Header, Validation, Algorithm};
    /// # #[derive(serde::Deserialize, serde::Serialize)]
    /// # struct Claims { sub: String }
    /// let master_key = MasterKey::random();
    /// 
    /// // First create a token to decode
    /// let my_claims = Claims { sub: "user123".to_string() };
    /// let encoding_key = master_key.create_jwt_encoding_key();
    /// let token = encode(&Header::default(), &my_claims, &encoding_key).unwrap();
    /// 
    /// // Now decode it with relaxed validation
    /// let decoding_key = master_key.create_jwt_decoding_key();
    /// let mut validation = Validation::new(Algorithm::HS256);
    /// validation.required_spec_claims.clear(); // Don't require exp, iat, etc.
    /// let token_data = decode::<Claims>(
    ///     &token,
    ///     &decoding_key,
    ///     &validation
    /// ).unwrap();
    /// assert_eq!(token_data.claims.sub, "user123");
    /// ```
    pub fn create_jwt_decoding_key(&self) -> jsonwebtoken::DecodingKey {
        self.with_raw_key(jsonwebtoken::DecodingKey::from_secret)
    }

    /// Create a JWT encoding key for token signing.
    ///
    /// This method creates a `jsonwebtoken::EncodingKey` using the combined
    /// master key material. Note that `EncodingKey` internally copies the key
    /// and does not provide zeroization.
    ///
    /// # Security Warning
    ///
    /// The `jsonwebtoken` crate does not zeroize key material. Use this method
    /// only for short-lived operations and be aware that the key material may
    /// remain in memory after the `EncodingKey` is dropped.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use jsonwebtoken::{encode, Header, Algorithm};
    /// # #[derive(serde::Serialize)]
    /// # struct Claims { sub: String }
    /// let master_key = MasterKey::random();
    /// let encoding_key = master_key.create_jwt_encoding_key();
    ///
    /// let claims = Claims { sub: "user123".to_string() };
    /// let token = encode(
    ///     &Header::new(Algorithm::HS256),
    ///     &claims,
    ///     &encoding_key
    /// ).unwrap();
    /// assert!(!token.is_empty());
    /// ```
    pub fn create_jwt_encoding_key(&self) -> jsonwebtoken::EncodingKey {
        self.with_raw_key(jsonwebtoken::EncodingKey::from_secret)
    }

    /// Validate and decode a JWT using the master key.
    ///
    /// This is a high-level method that handles the entire JWT validation
    /// process, minimizing the time that key material is exposed.
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token string to validate
    /// * `validation` - JWT validation parameters
    ///
    /// # Security
    ///
    /// This method creates a temporary `DecodingKey` and immediately uses it,
    /// reducing the window where unprotected key material exists in memory.
    pub fn validate_jwt<T>(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
    ) -> Result<T, jsonwebtoken::errors::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.with_raw_key(|key_bytes| {
            let decoding_key = jsonwebtoken::DecodingKey::from_secret(key_bytes);
            jsonwebtoken::decode::<T>(token, &decoding_key, validation)
                .map(|token_data| token_data.claims)
        })
    }

    /// Deprecated: Use scoped access methods instead.
    ///
    /// This method is deprecated because it returns unprotected key material.
    /// Use one of the `with_*` methods instead:
    /// - `with_raw_key()` for general access
    /// - `with_aes_key()` for AES operations
    /// - `with_mac_key()` for MAC operations
    /// - `with_siv_key()` for AES-SIV operations
    #[deprecated(
        since = "0.2.0",
        note = "Use scoped access methods like with_raw_key() instead"
    )]
    pub fn raw_key(&self) -> GenericArray<u8, U64> {
        self.with_raw_key_array(|key| *key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoped_access() {
        let master_key = MasterKey::random();

        // Test that we can use the key in a callback
        let result = master_key.with_raw_key(|key| {
            assert_eq!(key.len(), 64);
            key.len()
        });
        assert_eq!(result, 64);
    }

    #[test]
    fn test_key_ordering() {
        let aes_key = [1u8; 32];
        let mac_key = [2u8; 32];

        let master_key = MasterKey {
            aes_master_key: Secret::new(aes_key),
            mac_master_key: Secret::new(mac_key),
        };

        // Test raw key order (AES || MAC)
        master_key.with_raw_key(|key| {
            assert_eq!(&key[..32], &[1u8; 32]);
            assert_eq!(&key[32..], &[2u8; 32]);
        });

        // Test SIV key order (MAC || AES)
        master_key.with_siv_key(|key| {
            assert_eq!(&key[..32], &[2u8; 32]);
            assert_eq!(&key[32..], &[1u8; 32]);
        });
    }
}
