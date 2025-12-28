#![forbid(unsafe_code)]

use std::sync::RwLock;

use generic_array::{typenum::U64, GenericArray};
use memsafe::MemSafe;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

/// Error type for key access operations.
///
/// This error can occur when accessing protected key material, either due to
/// memory protection failures or lock poisoning (a thread panicked while holding the lock).
#[derive(Debug, Error)]
pub enum KeyAccessError {
    /// Memory protection operation failed (mlock, mprotect, etc.)
    #[error("Memory protection operation failed: {0}")]
    MemoryProtection(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Lock was poisoned (a thread panicked while holding it)
    #[error("Key lock was poisoned")]
    LockPoisoned,
}

impl KeyAccessError {
    /// Create a memory protection error from any error type.
    pub fn memory_protection<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        KeyAccessError::MemoryProtection(Box::new(err))
    }
}

/// Error type for JWT validation operations.
///
/// This error can occur when validating a JWT, either due to key access
/// failures or JWT parsing/validation errors.
#[derive(Debug, Error)]
pub enum JwtValidationError {
    /// Key access failed
    #[error("Key access failed: {0}")]
    KeyAccess(#[from] KeyAccessError),

    /// JWT validation failed
    #[error("JWT validation failed: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
}

/// Master key pair for Cryptomator vault operations.
///
/// This struct holds both the AES encryption key and MAC authentication key,
/// each 256 bits (32 bytes) for a total of 512 bits of key material.
///
/// # Security
///
/// The keys are stored using the `memsafe` crate's `MemSafe` type, which provides:
/// - **Memory locking**: Keys are pinned in RAM via `mlock`, preventing swap to disk
/// - **Access control**: Memory is protected with `mprotect(PROT_NONE)` when not in use
/// - **Dump exclusion**: On Linux, `MADV_DONTDUMP` excludes keys from core dumps
/// - **Zeroization**: Memory is securely zeroed when the key is dropped
///
/// Access to key material is provided through scoped access methods that
/// temporarily elevate memory permissions to read the key, then immediately
/// revoke access when the operation completes.
///
/// The fields are intentionally private to enforce the use of scoped access
/// methods (`with_raw_key`, `with_aes_key`, etc.) which provide better security
/// guarantees than direct field access.
///
/// # Thread Safety
///
/// `MasterKey` is thread-safe (`Send + Sync`) and can be shared across threads
/// using `Arc<MasterKey>`. The internal `RwLock` ensures safe concurrent access.
/// If a thread panics while holding the lock, the key becomes inaccessible
/// (lock poisoning) as a safety measure.
#[derive(Debug)]
pub struct MasterKey {
    aes_master_key: RwLock<MemSafe<[u8; 32]>>,
    mac_master_key: RwLock<MemSafe<[u8; 32]>>,
}

impl Clone for MasterKey {
    /// Clone the master key.
    ///
    /// # Panics
    ///
    /// Panics if the key is currently borrowed or if memory protection fails.
    /// For fallible cloning, use `try_clone()`.
    fn clone(&self) -> Self {
        self.try_clone()
            .expect("Failed to clone MasterKey: memory protection error")
    }
}

impl MasterKey {
    /// Try to clone the master key, returning an error on failure.
    pub fn try_clone(&self) -> Result<Self, KeyAccessError> {
        let aes_key = {
            let mut lock = self
                .aes_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            *guard
        };
        let mac_key = {
            let mut lock = self
                .mac_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            *guard
        };
        Self::new(aes_key, mac_key)
    }
}

impl MasterKey {
    /// Generate a new random master key pair using a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if memory protection initialization fails.
    /// This can happen if the system's mlock limit is exceeded or if the
    /// memory protection syscalls fail.
    pub fn random() -> Result<Self, KeyAccessError> {
        let mut aes_master_key = [0u8; 32];
        let mut mac_master_key = [0u8; 32];
        rand::rng().fill_bytes(&mut aes_master_key);
        rand::rng().fill_bytes(&mut mac_master_key);
        Self::new(aes_master_key, mac_master_key)
    }

    /// Create a new master key pair from raw key material.
    ///
    /// # Arguments
    ///
    /// * `aes_key` - The 256-bit AES encryption key
    /// * `mac_key` - The 256-bit MAC authentication key
    ///
    /// # Security
    ///
    /// The provided key arrays are copied into `MemSafe` containers, which:
    /// - Lock the memory in RAM (preventing swap)
    /// - Apply `PROT_NONE` protection when not in use
    /// - Automatically zero the memory when dropped
    ///
    /// The caller is responsible for zeroing the original arrays if they
    /// contain sensitive data.
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if memory protection initialization fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use zeroize::Zeroizing;
    /// // In practice, these would come from key derivation or unwrapping
    /// let mut aes_key = Zeroizing::new([0u8; 32]);
    /// let mut mac_key = Zeroizing::new([0u8; 32]);
    /// // ... populate keys ...
    ///
    /// let master_key = MasterKey::new(*aes_key, *mac_key).unwrap();
    /// ```
    pub fn new(aes_key: [u8; 32], mac_key: [u8; 32]) -> Result<Self, KeyAccessError> {
        Ok(MasterKey {
            aes_master_key: RwLock::new(
                MemSafe::new(aes_key).map_err(KeyAccessError::memory_protection)?,
            ),
            mac_master_key: RwLock::new(
                MemSafe::new(mac_key).map_err(KeyAccessError::memory_protection)?,
            ),
        })
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
    /// - Memory permissions are elevated only for the duration of access
    /// - Memory is automatically zeroed after use
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the lock is poisoned or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// let master_key = MasterKey::random().unwrap();
    ///
    /// let result = master_key.with_raw_key(|key_bytes| {
    ///     // Use key_bytes here - permissions revoked after this scope
    ///     assert_eq!(key_bytes.len(), 64);
    ///     // Return some result from your crypto operation
    ///     42
    /// }).unwrap();
    /// assert_eq!(result, 42);
    /// ```
    pub fn with_raw_key<F, R>(&self, f: F) -> Result<R, KeyAccessError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Custom wrapper for zeroization
        struct ZeroOnDrop([u8; 64]);
        impl Drop for ZeroOnDrop {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        let mut key = ZeroOnDrop([0u8; 64]);

        // Read AES key
        {
            let mut lock = self
                .aes_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[..32].copy_from_slice(&*guard);
        }

        // Read MAC key
        {
            let mut lock = self
                .mac_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[32..].copy_from_slice(&*guard);
        }

        Ok(f(&key.0))
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
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the lock is poisoned or if
    /// memory protection operations fail.
    pub fn with_raw_key_array<F, R>(&self, f: F) -> Result<R, KeyAccessError>
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

        // Read AES key
        {
            let mut lock = self
                .aes_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[..32].copy_from_slice(&*guard);
        }

        // Read MAC key
        {
            let mut lock = self
                .mac_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[32..].copy_from_slice(&*guard);
        }

        Ok(f(&key.0))
    }

    /// Execute a function with access to just the AES encryption key.
    ///
    /// This method provides controlled access to the 32-byte AES key through
    /// a callback. Use this when you only need the encryption key, not the MAC key.
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the lock is poisoned or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use aes_gcm::{Aes256Gcm, Key, KeyInit};
    /// let master_key = MasterKey::random().unwrap();
    ///
    /// let cipher = master_key.with_aes_key(|key_bytes| {
    ///     let key: &Key<Aes256Gcm> = key_bytes.into();
    ///     Aes256Gcm::new(key)
    /// }).unwrap();
    /// ```
    pub fn with_aes_key<F, R>(&self, f: F) -> Result<R, KeyAccessError>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let mut lock = self
            .aes_master_key
            .write()
            .map_err(|_| KeyAccessError::LockPoisoned)?;
        let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
        Ok(f(&guard))
    }

    /// Execute a function with access to just the MAC key.
    ///
    /// This method provides controlled access to the 32-byte MAC key through
    /// a callback. Use this when you only need the MAC key, not the encryption key.
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the lock is poisoned or if
    /// memory protection operations fail.
    pub fn with_mac_key<F, R>(&self, f: F) -> Result<R, KeyAccessError>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let mut lock = self
            .mac_master_key
            .write()
            .map_err(|_| KeyAccessError::LockPoisoned)?;
        let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
        Ok(f(&guard))
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
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the lock is poisoned or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use aes_siv::{siv::Aes256Siv, KeyInit};
    /// let master_key = MasterKey::random().unwrap();
    ///
    /// let cipher = master_key.with_siv_key(|key_bytes| {
    ///     Aes256Siv::new(key_bytes.into())
    /// }).unwrap();
    /// ```
    pub fn with_siv_key<F, R>(&self, f: F) -> Result<R, KeyAccessError>
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
        // Read MAC key
        {
            let mut lock = self
                .mac_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[..32].copy_from_slice(&*guard);
        }

        // Read AES key
        {
            let mut lock = self
                .aes_master_key
                .write()
                .map_err(|_| KeyAccessError::LockPoisoned)?;
            let guard = lock.read().map_err(KeyAccessError::memory_protection)?;
            key.0[32..].copy_from_slice(&*guard);
        }

        Ok(f(&key.0))
    }

    /// Create an AES-SIV cipher for filename encryption/decryption.
    ///
    /// This is a convenience method that creates an `Aes256Siv` cipher
    /// with the correct key ordering for Cryptomator filename operations.
    ///
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the key is already borrowed or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// let master_key = MasterKey::random().unwrap();
    /// let mut cipher = master_key.create_name_cipher().unwrap();
    ///
    /// // Use cipher for filename encryption
    /// let parent_dir_id = b"parent-directory-id";
    /// let filename = "test.txt";
    /// let encrypted = cipher.encrypt(&[parent_dir_id], filename.as_bytes())
    ///     .expect("Encryption failed");
    /// ```
    pub fn create_name_cipher(&self) -> Result<aes_siv::siv::Aes256Siv, KeyAccessError> {
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
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the key is already borrowed or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use jsonwebtoken::{encode, decode, Header, Validation, Algorithm};
    /// # #[derive(serde::Deserialize, serde::Serialize)]
    /// # struct Claims { sub: String }
    /// let master_key = MasterKey::random().unwrap();
    ///
    /// // First create a token to decode
    /// let my_claims = Claims { sub: "user123".to_string() };
    /// let encoding_key = master_key.create_jwt_encoding_key().unwrap();
    /// let token = encode(&Header::default(), &my_claims, &encoding_key).unwrap();
    ///
    /// // Now decode it with relaxed validation
    /// let decoding_key = master_key.create_jwt_decoding_key().unwrap();
    /// let mut validation = Validation::new(Algorithm::HS256);
    /// validation.required_spec_claims.clear(); // Don't require exp, iat, etc.
    /// let token_data = decode::<Claims>(
    ///     &token,
    ///     &decoding_key,
    ///     &validation
    /// ).unwrap();
    /// assert_eq!(token_data.claims.sub, "user123");
    /// ```
    pub fn create_jwt_decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, KeyAccessError> {
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
    /// # Errors
    ///
    /// Returns a `KeyAccessError` if the key is already borrowed or if
    /// memory protection operations fail.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxidized_cryptolib::crypto::keys::MasterKey;
    /// # use jsonwebtoken::{encode, Header, Algorithm};
    /// # #[derive(serde::Serialize)]
    /// # struct Claims { sub: String }
    /// let master_key = MasterKey::random().unwrap();
    /// let encoding_key = master_key.create_jwt_encoding_key().unwrap();
    ///
    /// let claims = Claims { sub: "user123".to_string() };
    /// let token = encode(
    ///     &Header::new(Algorithm::HS256),
    ///     &claims,
    ///     &encoding_key
    /// ).unwrap();
    /// assert!(!token.is_empty());
    /// ```
    pub fn create_jwt_encoding_key(&self) -> Result<jsonwebtoken::EncodingKey, KeyAccessError> {
        self.with_raw_key(jsonwebtoken::EncodingKey::from_secret)
    }

    /// Error type for JWT validation that can fail due to key access or JWT parsing.
    ///
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
    /// # Errors
    ///
    /// Returns an error if the key cannot be accessed or if JWT validation fails.
    ///
    /// # Security
    ///
    /// This method creates a temporary `DecodingKey` and immediately uses it,
    /// reducing the window where unprotected key material exists in memory.
    pub fn validate_jwt<T>(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
    ) -> Result<T, JwtValidationError>
    where
        T: serde::de::DeserializeOwned,
    {
        let jwt_result = self.with_raw_key(|key_bytes| {
            let decoding_key = jsonwebtoken::DecodingKey::from_secret(key_bytes);
            jsonwebtoken::decode::<T>(token, &decoding_key, validation)
                .map(|token_data| token_data.claims)
        })?;
        jwt_result.map_err(JwtValidationError::from)
    }

    /// Deprecated: Use scoped access methods instead.
    ///
    /// This method is deprecated because it returns unprotected key material.
    /// Use one of the `with_*` methods instead:
    /// - `with_raw_key()` for general access
    /// - `with_aes_key()` for AES operations
    /// - `with_mac_key()` for MAC operations
    /// - `with_siv_key()` for AES-SIV operations
    ///
    /// # Panics
    ///
    /// Panics if key access fails.
    #[deprecated(
        since = "0.2.0",
        note = "Use scoped access methods like with_raw_key() instead"
    )]
    pub fn raw_key(&self) -> GenericArray<u8, U64> {
        self.with_raw_key_array(|key| *key)
            .expect("Failed to access key material")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoped_access() {
        let master_key = MasterKey::random().unwrap();

        // Test that we can use the key in a callback
        let result = master_key
            .with_raw_key(|key| {
                assert_eq!(key.len(), 64);
                key.len()
            })
            .unwrap();
        assert_eq!(result, 64);
    }

    #[test]
    fn test_key_ordering() {
        let aes_key = [1u8; 32];
        let mac_key = [2u8; 32];

        let master_key = MasterKey::new(aes_key, mac_key).unwrap();

        // Test raw key order (AES || MAC)
        master_key
            .with_raw_key(|key| {
                assert_eq!(&key[..32], &[1u8; 32]);
                assert_eq!(&key[32..], &[2u8; 32]);
            })
            .unwrap();

        // Test SIV key order (MAC || AES)
        master_key
            .with_siv_key(|key| {
                assert_eq!(&key[..32], &[2u8; 32]);
                assert_eq!(&key[32..], &[1u8; 32]);
            })
            .unwrap();
    }
}
