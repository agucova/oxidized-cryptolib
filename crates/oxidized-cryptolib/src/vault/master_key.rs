#![forbid(unsafe_code)]

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use unicode_normalization::UnicodeNormalization;

use crate::crypto::{keys::{KeyAccessError, MasterKey}, key_wrap, CryptoError};

/// Default scrypt parameters matching Java Cryptomator implementation.
///
/// These constants are defined in `MasterkeyFileAccess.java`:
/// - `DEFAULT_SCRYPT_SALT_LENGTH = 8`
/// - `DEFAULT_SCRYPT_COST_PARAM = 1 << 15` (32768)
/// - `DEFAULT_SCRYPT_BLOCK_SIZE = 8`
/// - Parallelization `P = 1` (hardcoded in Scrypt.java)
const DEFAULT_SCRYPT_SALT_LENGTH: usize = 8;
const DEFAULT_SCRYPT_COST_PARAM_LOG2: u8 = 15; // 2^15 = 32768
const DEFAULT_SCRYPT_BLOCK_SIZE: u32 = 8;
const DEFAULT_SCRYPT_PARALLELIZATION: u32 = 1;

/// Fast scrypt cost parameter for testing (N = 2^10 = 1024).
///
/// This is ~32x faster than the default and should ONLY be used for testing.
/// Enable by setting the `OXCRYPT_FAST_KDF` environment variable to `1`.
const FAST_SCRYPT_COST_PARAM_LOG2: u8 = 10; // 2^10 = 1024

/// Check if fast KDF mode is enabled via environment variable.
///
/// When `OXCRYPT_FAST_KDF=1` is set, vault creation uses weaker scrypt
/// parameters (N=1024 instead of N=32768) for ~32x faster key derivation.
///
/// **WARNING**: This is for testing only. Never use in production!
#[inline]
fn is_fast_kdf_enabled() -> bool {
    std::env::var("OXCRYPT_FAST_KDF")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Get the scrypt cost parameter log2 value to use.
///
/// Returns the fast parameter if `OXCRYPT_FAST_KDF=1`, otherwise the default.
fn get_scrypt_cost_param_log2() -> u8 {
    if is_fast_kdf_enabled() {
        FAST_SCRYPT_COST_PARAM_LOG2
    } else {
        DEFAULT_SCRYPT_COST_PARAM_LOG2
    }
}

/// Default vault version for masterkey files.
/// This is a legacy field (version 999) used in vault format 8.
const DEFAULT_MASTERKEY_FILE_VERSION: u32 = 999;

/// Errors that can occur when creating a master key file.
#[derive(Error, Debug)]
pub enum MasterKeyCreationError {
    #[error("RNG failed: {0}")]
    Rng(String),

    #[error("Invalid scrypt parameters: {0}")]
    InvalidScryptParams(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Key wrap failed: {0}")]
    KeyWrap(#[from] key_wrap::WrapError),

    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Key access failed: {0}")]
    KeyAccess(#[from] KeyAccessError),
}

/// The master key file format (`masterkey.cryptomator`).
///
/// Contains the encrypted master keys (AES and MAC) wrapped with a key encryption key (KEK)
/// derived from the user's passphrase via scrypt.
///
/// # Pepper Support
///
/// The Java implementation supports an optional "pepper" that is concatenated with the salt
/// before key derivation: `scrypt(passphrase, salt || pepper, ...)`. The default pepper in
/// Cryptomator is empty (zero-length byte array), so by default no pepper is used.
///
/// When unlocking vaults created by other applications that may use a pepper, use
/// [`MasterKeyFile::unlock_with_pepper`] instead of [`MasterKeyFile::unlock`].
///
/// # Reference Implementation
/// - Java: [`MasterkeyFile`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFile.java)
/// - Java: [`MasterkeyFileAccess`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFileAccess.java) (for load/persist operations)
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterKeyFile {
    /// Legacy vault version field (deprecated since vault format 8).
    /// Always set to 999 for new vaults.
    version: u32,

    /// Salt for scrypt key derivation.
    /// Standard Cryptomator vaults use 8 bytes (see `DEFAULT_SCRYPT_SALT_LENGTH` in Java).
    #[serde_as(as = "Base64")]
    pub scrypt_salt: Vec<u8>,

    /// Scrypt cost parameter N (must be a power of 2).
    /// Standard Cryptomator default is 32768 (2^15).
    pub scrypt_cost_param: i32,

    /// Scrypt block size parameter r.
    /// Standard Cryptomator default is 8.
    pub scrypt_block_size: i32,

    /// The wrapped (encrypted) AES master key.
    /// This is ciphertext from RFC 3394 AES Key Wrap, not plaintext.
    /// The unwrapped key is 32 bytes (256 bits).
    #[serde_as(as = "Base64")]
    pub primary_master_key: Vec<u8>,

    /// The wrapped (encrypted) MAC master key.
    /// This is ciphertext from RFC 3394 AES Key Wrap, not plaintext.
    /// The unwrapped key is 32 bytes (256 bits).
    #[serde_as(as = "Base64")]
    pub hmac_master_key: Vec<u8>,

    /// HMAC-SHA256 of the vault version (as big-endian 4-byte integer).
    /// Used to verify the integrity of the version field.
    #[serde_as(as = "Base64")]
    pub version_mac: Vec<u8>,
}

impl MasterKeyFile {
    /// Derive a key encryption key (KEK) from a passphrase using scrypt.
    ///
    /// This method uses only the salt stored in the file. For pepper support,
    /// use [`derive_key_with_pepper`](Self::derive_key_with_pepper).
    ///
    /// # Reference Implementation
    /// - Java: [`MasterkeyFileAccess.load()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFileAccess.java) (scrypt derivation step)
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters in the master key file
    /// - `CryptoError::KeyDerivationFailed`: Scrypt key derivation failed
    pub fn derive_key(&self, passphrase: &str) -> Result<SecretBox<[u8; 32]>, CryptoError> {
        self.derive_key_with_pepper(passphrase, &[])
    }

    /// Derive a key encryption key (KEK) from a passphrase using scrypt with pepper.
    ///
    /// The pepper is concatenated with the salt before key derivation:
    /// `scrypt(passphrase, salt || pepper, ...)`.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The user's passphrase (will be NFC-normalized)
    /// * `pepper` - Additional secret bytes to mix with salt (can be empty)
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters in the master key file
    /// - `CryptoError::KeyDerivationFailed`: Scrypt key derivation failed
    pub fn derive_key_with_pepper(
        &self,
        passphrase: &str,
        pepper: &[u8],
    ) -> Result<SecretBox<[u8; 32]>, CryptoError> {
        // We use NFC normalization on the passphrase (matching Java implementation)
        let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());

        // Define the scrypt parameters
        let log2_n: u8 = log_2(self.scrypt_cost_param) as u8;
        let r: u32 = self.scrypt_block_size as u32;
        let p: u32 = DEFAULT_SCRYPT_PARALLELIZATION;

        let scrypt_params = scrypt::Params::new(log2_n, r, p, 32).map_err(|e| {
            CryptoError::InvalidScryptParams(format!(
                "Invalid scrypt parameters (N=2^{}, r={}, p={}): {}",
                log2_n, r, p, e
            ))
        })?;

        // Combine salt and pepper as in Java: saltAndPepper = salt || pepper
        let mut salt_and_pepper = Zeroizing::new(Vec::with_capacity(self.scrypt_salt.len() + pepper.len()));
        salt_and_pepper.extend_from_slice(&self.scrypt_salt);
        salt_and_pepper.extend_from_slice(pepper);

        // Initialize kek to 256-bit empty array
        let mut kek = Zeroizing::new([0u8; 32]);

        // Derive the kek from the normalized passphrase
        scrypt::scrypt(
            normalized_passphrase.as_bytes(),
            &salt_and_pepper,
            &scrypt_params,
            &mut kek[..],
        )
        .map_err(|e| CryptoError::KeyDerivationFailed(format!("Scrypt derivation failed: {}", e)))?;

        Ok(SecretBox::new(Box::new(*kek)))
    }

    /// Unlock the vault with a passphrase, deriving the KEK and unwrapping the master keys.
    ///
    /// This method uses no pepper (empty pepper). For pepper support, use
    /// [`unlock_with_pepper`](Self::unlock_with_pepper).
    ///
    /// # Reference Implementation
    /// - Java: [`MasterkeyFileAccess.load()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFileAccess.java)
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters
    /// - `CryptoError::KeyDerivationFailed`: Scrypt key derivation failed
    /// - `CryptoError::KeyUnwrapIntegrityFailed`: Wrong passphrase or corrupted/tampered vault
    /// - `CryptoError::HmacVerificationFailed`: **[INTEGRITY VIOLATION]** Vault version tampered
    pub fn unlock(&self, passphrase: &str) -> Result<MasterKey, CryptoError> {
        self.unlock_with_pepper(passphrase, &[])
    }

    /// Unlock the vault with a passphrase and pepper.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The user's passphrase
    /// * `pepper` - Additional secret bytes for key derivation (can be empty)
    ///
    /// # Errors
    ///
    /// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters
    /// - `CryptoError::KeyDerivationFailed`: Scrypt key derivation failed
    /// - `CryptoError::KeyUnwrapIntegrityFailed`: Wrong passphrase or corrupted/tampered vault
    /// - `CryptoError::HmacVerificationFailed`: **[INTEGRITY VIOLATION]** Vault version tampered
    pub fn unlock_with_pepper(&self, passphrase: &str, pepper: &[u8]) -> Result<MasterKey, CryptoError> {
        let kek = self.derive_key_with_pepper(passphrase, pepper)?;
        self.unlock_with_kek(&kek)
    }

    fn unlock_with_kek(&self, kek: &SecretBox<[u8; 32]>) -> Result<MasterKey, CryptoError> {
        // Unwrap the primary master key (encryption key) first
        // Note: unwrap failure typically means wrong password (though could also be tampering)
        let aes_key = key_wrap::unwrap_key(&self.primary_master_key, kek)?;
        let aes_key: [u8; 32] = aes_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: aes_key.len(),
            })?;

        // Unwrap the MAC key second (same order as Java implementation)
        let hmac_key = key_wrap::unwrap_key(&self.hmac_master_key, kek)?;
        let hmac_key: [u8; 32] = hmac_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: hmac_key.len(),
            })?;
        let hmac_key = SecretBox::new(Box::new(hmac_key));

        // Verify the version MAC - failure indicates INTEGRITY VIOLATION
        // Note: We need to extract the hmac_key value before check_vault_version
        let hmac_key_bytes: [u8; 32] = *hmac_key.expose_secret();
        self.check_vault_version(&hmac_key)?;

        // Construct key using the public constructor
        MasterKey::new(aes_key, hmac_key_bytes).map_err(CryptoError::from)
    }

    /// Verify the version MAC using HMAC-SHA256.
    ///
    /// The version is encoded as a big-endian 4-byte integer before MAC computation,
    /// matching the Java implementation: `ByteBuffer.allocate(4).putInt(version).array()`.
    fn check_vault_version(&self, mac_key: &SecretBox<[u8; 32]>) -> Result<(), CryptoError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key.expose_secret());

        // Java uses big-endian encoding for the version integer
        hmac::verify(&key, &self.version.to_be_bytes(), &self.version_mac)
            .map_err(|_| CryptoError::HmacVerificationFailed)
    }
}

// From: https://users.rust-lang.org/t/logarithm-of-integers/8506/5
const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: i32) -> u32 {
    assert!(x > 0);
    num_bits::<i32>() as u32 - x.leading_zeros() - 1
}

/// Create a master key file content with default parameters.
///
/// Uses the default Cryptomator scrypt parameters:
/// - Salt length: 8 bytes
/// - Cost parameter (N): 2^15 = 32768
/// - Block size (r): 8
/// - Parallelization (p): 1
///
/// # Reference Implementation
/// - Java: [`MasterkeyFileAccess.persist()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFileAccess.java)
///
/// # Errors
///
/// - `MasterKeyCreationError::Rng`: RNG failed to generate salt
/// - `MasterKeyCreationError::InvalidScryptParams`: Invalid scrypt parameters
/// - `MasterKeyCreationError::KeyDerivation`: Scrypt key derivation failed
/// - `MasterKeyCreationError::KeyWrap`: AES key wrap failed
/// - `MasterKeyCreationError::Serialization`: JSON serialization failed
pub fn create_masterkey_file(
    master_key: &MasterKey,
    passphrase: &str,
) -> Result<String, MasterKeyCreationError> {
    create_masterkey_file_with_pepper(master_key, passphrase, &[])
}

/// Create a master key file content with pepper support.
///
/// Uses the default Cryptomator scrypt parameters:
/// - Salt length: 8 bytes
/// - Cost parameter (N): 2^15 = 32768
/// - Block size (r): 8
/// - Parallelization (p): 1
///
/// # Arguments
///
/// * `master_key` - The master key to wrap
/// * `passphrase` - The user's passphrase (will be NFC-normalized)
/// * `pepper` - Additional secret bytes for key derivation (can be empty)
///
/// # Errors
///
/// - `MasterKeyCreationError::Rng`: RNG failed to generate salt
/// - `MasterKeyCreationError::InvalidScryptParams`: Invalid scrypt parameters
/// - `MasterKeyCreationError::KeyDerivation`: Scrypt key derivation failed
/// - `MasterKeyCreationError::KeyWrap`: AES key wrap failed
/// - `MasterKeyCreationError::Serialization`: JSON serialization failed
pub fn create_masterkey_file_with_pepper(
    master_key: &MasterKey,
    passphrase: &str,
    pepper: &[u8],
) -> Result<String, MasterKeyCreationError> {
    use crate::crypto::key_wrap::wrap_key;

    // Generate salt (8 bytes, matching Java DEFAULT_SCRYPT_SALT_LENGTH)
    let mut salt = vec![0u8; DEFAULT_SCRYPT_SALT_LENGTH];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| MasterKeyCreationError::Rng("Failed to generate salt".to_string()))?;

    // Scrypt parameters (matching Java Cryptomator defaults)
    let log2_n = get_scrypt_cost_param_log2();
    let r = DEFAULT_SCRYPT_BLOCK_SIZE;
    let p = DEFAULT_SCRYPT_PARALLELIZATION;

    // Combine salt and pepper as in Java
    let mut salt_and_pepper = Zeroizing::new(Vec::with_capacity(salt.len() + pepper.len()));
    salt_and_pepper.extend_from_slice(&salt);
    salt_and_pepper.extend_from_slice(pepper);

    // Derive KEK from passphrase
    let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());
    let scrypt_params = scrypt::Params::new(log2_n, r, p, 32).map_err(|e| {
        MasterKeyCreationError::InvalidScryptParams(format!(
            "Invalid scrypt parameters (N=2^{}, r={}, p={}): {}",
            log2_n, r, p, e
        ))
    })?;
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(
        normalized_passphrase.as_bytes(),
        &salt_and_pepper,
        &scrypt_params,
        &mut kek[..],
    )
    .map_err(|e| MasterKeyCreationError::KeyDerivation(format!("Scrypt derivation failed: {}", e)))?;
    let kek_secret = SecretBox::new(Box::new(*kek));

    // Wrap the keys (encryption key first, then MAC key - same order as Java)
    let wrapped_aes = master_key.with_aes_key(|key| wrap_key(key, &kek_secret))??;
    let wrapped_mac = master_key.with_mac_key(|key| wrap_key(key, &kek_secret))??;

    // Create version MAC using big-endian encoding (matching Java)
    let version = DEFAULT_MASTERKEY_FILE_VERSION;
    let version_mac = master_key.with_mac_key(|key| {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, &version.to_be_bytes());
        tag.as_ref().to_vec()
    })?;

    // Create MasterKeyFile structure
    let masterkey_file = MasterKeyFile {
        version,
        scrypt_salt: salt,
        scrypt_cost_param: (1i32 << log2_n),
        scrypt_block_size: r as i32,
        primary_master_key: wrapped_aes,
        hmac_master_key: wrapped_mac,
        version_mac,
    };

    // Serialize to JSON
    Ok(serde_json::to_string_pretty(&masterkey_file)?)
}

/// Change the vault password by re-wrapping the master keys with a new passphrase.
///
/// This function:
/// 1. Reads the existing masterkey file
/// 2. Unlocks with the old passphrase to retrieve the raw keys
/// 3. Re-wraps the same keys with a new passphrase-derived KEK
/// 4. Returns the new masterkey file JSON content
///
/// The master keys (AES and MAC) never change - only the key encryption key (KEK)
/// derived from the passphrase is replaced.
///
/// # Arguments
///
/// * `masterkey_path` - Path to the existing masterkey.cryptomator file
/// * `old_passphrase` - Current passphrase (for unlocking)
/// * `new_passphrase` - New passphrase (for re-wrapping)
///
/// # Errors
///
/// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters in the master key file
/// - `CryptoError::KeyDerivationFailed`: Scrypt key derivation failed
/// - `CryptoError::KeyUnwrapIntegrityFailed`: Wrong old passphrase or corrupted vault
/// - `MasterKeyCreationError`: Failed to create new masterkey file
///
/// # Reference Implementation
/// - Swift: [`MasterkeyFile.changePassphrase()`](https://github.com/cryptomator/cryptomator-ios/blob/main/Cryptomator/Util/MasterkeyFileHelper.swift)
pub fn change_password(
    masterkey_path: &std::path::Path,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<String, ChangePasswordError> {
    // 1. Read existing masterkey file
    let file_content = std::fs::read_to_string(masterkey_path)?;
    let masterkey_file: MasterKeyFile = serde_json::from_str(&file_content)?;

    // 2. Unlock with old passphrase to get raw keys
    let master_key = masterkey_file.unlock(old_passphrase)?;

    // 3. Re-wrap with new passphrase and return new file content
    let new_content = create_masterkey_file(&master_key, new_passphrase)?;

    Ok(new_content)
}

/// Change the vault password with pepper support.
///
/// Similar to [`change_password`], but supports vaults created with a pepper.
/// Both old and new passphrases use the same pepper.
///
/// # Arguments
///
/// * `masterkey_path` - Path to the existing masterkey.cryptomator file
/// * `old_passphrase` - Current passphrase (for unlocking)
/// * `new_passphrase` - New passphrase (for re-wrapping)
/// * `pepper` - Additional secret bytes for key derivation (must match original)
pub fn change_password_with_pepper(
    masterkey_path: &std::path::Path,
    old_passphrase: &str,
    new_passphrase: &str,
    pepper: &[u8],
) -> Result<String, ChangePasswordError> {
    // 1. Read existing masterkey file
    let file_content = std::fs::read_to_string(masterkey_path)?;
    let masterkey_file: MasterKeyFile = serde_json::from_str(&file_content)?;

    // 2. Unlock with old passphrase and pepper to get raw keys
    let master_key = masterkey_file.unlock_with_pepper(old_passphrase, pepper)?;

    // 3. Re-wrap with new passphrase and same pepper
    let new_content = create_masterkey_file_with_pepper(&master_key, new_passphrase, pepper)?;

    Ok(new_content)
}

/// Errors that can occur when changing the vault password.
#[derive(Error, Debug)]
pub enum ChangePasswordError {
    #[error("Failed to read masterkey file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse masterkey file: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Failed to unlock vault: {0}")]
    Unlock(#[from] CryptoError),

    #[error("Failed to create new masterkey file: {0}")]
    Create(#[from] MasterKeyCreationError),
}

/// Derive a new master key and KEK from a passphrase.
///
/// Note: This function generates a new salt each time it's called, so the returned
/// KEK will be different even with the same passphrase. Use [`create_masterkey_file`]
/// to persist the derived keys with their salt.
///
/// # Errors
///
/// - `CryptoError::KeyDerivationFailed`: RNG or scrypt derivation failed
/// - `CryptoError::InvalidScryptParams`: Invalid scrypt parameters (shouldn't happen with defaults)
/// - `CryptoError::KeyAccess`: Memory protection initialization failed
pub fn derive_keys(passphrase: &str) -> Result<(MasterKey, SecretBox<[u8; 32]>), CryptoError> {
    let master_key = MasterKey::random()?;

    // Generate salt (8 bytes, matching Java DEFAULT_SCRYPT_SALT_LENGTH)
    let mut salt = vec![0u8; DEFAULT_SCRYPT_SALT_LENGTH];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| CryptoError::KeyDerivationFailed("RNG failed to generate salt".to_string()))?;

    // Scrypt parameters (matching Java Cryptomator defaults)
    let log2_n = get_scrypt_cost_param_log2();
    let r = DEFAULT_SCRYPT_BLOCK_SIZE;
    let p = DEFAULT_SCRYPT_PARALLELIZATION;

    // Derive KEK from passphrase
    let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());
    let scrypt_params = scrypt::Params::new(log2_n, r, p, 32).map_err(|e| {
        CryptoError::InvalidScryptParams(format!(
            "Invalid scrypt parameters (N=2^{}, r={}, p={}): {}",
            log2_n, r, p, e
        ))
    })?;
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(
        normalized_passphrase.as_bytes(),
        &salt,
        &scrypt_params,
        &mut kek[..],
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(format!("Scrypt derivation failed: {}", e)))?;

    Ok((master_key, SecretBox::new(Box::new(*kek))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_masterkey_file() {
        // Create a master key
        let master_key = MasterKey::random().unwrap();
        let passphrase = "test-passphrase-123";

        // Create masterkey file
        let json = create_masterkey_file(&master_key, passphrase).unwrap();

        // Parse and unlock
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();
        let unlocked = masterkey_file.unlock(passphrase).unwrap();

        // Verify keys match
        master_key.with_aes_key(|orig_aes| {
            unlocked.with_aes_key(|unlocked_aes| {
                assert_eq!(orig_aes, unlocked_aes, "AES keys should match");
            })
        }).unwrap().unwrap();

        master_key.with_mac_key(|orig_mac| {
            unlocked.with_mac_key(|unlocked_mac| {
                assert_eq!(orig_mac, unlocked_mac, "MAC keys should match");
            })
        }).unwrap().unwrap();
    }

    #[test]
    fn test_roundtrip_with_pepper() {
        let master_key = MasterKey::random().unwrap();
        let passphrase = "test-passphrase-123";
        let pepper = b"my-secret-pepper";

        // Create masterkey file with pepper
        let json = create_masterkey_file_with_pepper(&master_key, passphrase, pepper).unwrap();

        // Parse and unlock with same pepper
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();
        let unlocked = masterkey_file.unlock_with_pepper(passphrase, pepper).unwrap();

        // Verify keys match
        master_key.with_aes_key(|orig_aes| {
            unlocked.with_aes_key(|unlocked_aes| {
                assert_eq!(orig_aes, unlocked_aes, "AES keys should match");
            })
        }).unwrap().unwrap();
    }

    #[test]
    fn test_wrong_pepper_fails() {
        let master_key = MasterKey::random().unwrap();
        let passphrase = "test-passphrase-123";
        let pepper = b"correct-pepper";

        // Create masterkey file with pepper
        let json = create_masterkey_file_with_pepper(&master_key, passphrase, pepper).unwrap();

        // Try to unlock with wrong pepper - should fail
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();
        let result = masterkey_file.unlock_with_pepper(passphrase, b"wrong-pepper");
        assert!(result.is_err(), "Should fail with wrong pepper");
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let master_key = MasterKey::random().unwrap();
        let passphrase = "correct-passphrase";

        // Create masterkey file
        let json = create_masterkey_file(&master_key, passphrase).unwrap();

        // Try to unlock with wrong passphrase - should fail
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();
        let result = masterkey_file.unlock("wrong-passphrase");
        assert!(result.is_err(), "Should fail with wrong passphrase");
    }

    #[test]
    fn test_default_parameters() {
        let master_key = MasterKey::random().unwrap();
        let passphrase = "test";

        let json = create_masterkey_file(&master_key, passphrase).unwrap();
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();

        // Verify default parameters match Java implementation
        assert_eq!(masterkey_file.scrypt_salt.len(), 8, "Salt should be 8 bytes");
        assert_eq!(masterkey_file.scrypt_cost_param, 32768, "Cost param should be 2^15");
        assert_eq!(masterkey_file.scrypt_block_size, 8, "Block size should be 8");
        assert_eq!(masterkey_file.version, 999, "Version should be 999");
    }

    #[test]
    fn test_unicode_passphrase_normalization() {
        let master_key = MasterKey::random().unwrap();

        // These should produce the same result due to NFC normalization:
        // - "e\u{0301}" is 'e' followed by combining acute accent
        // - "\u{00e9}" is pre-composed 'e' with acute accent
        let passphrase_composed = "\u{00e9}"; // e with acute
        let passphrase_decomposed = "e\u{0301}"; // e + combining acute

        let json = create_masterkey_file(&master_key, passphrase_composed).unwrap();
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();

        // Both forms should unlock successfully
        let result = masterkey_file.unlock(passphrase_decomposed);
        assert!(result.is_ok(), "NFC normalization should make both forms equivalent");
    }

    #[test]
    fn test_version_mac_big_endian() {
        let master_key = MasterKey::random().unwrap();
        let passphrase = "test";

        let json = create_masterkey_file(&master_key, passphrase).unwrap();
        let masterkey_file: MasterKeyFile = serde_json::from_str(&json).unwrap();

        // Manually verify the version MAC
        let expected_version_bytes = 999u32.to_be_bytes();
        assert_eq!(expected_version_bytes, [0x00, 0x00, 0x03, 0xe7]);

        master_key.with_mac_key(|mac_key| {
            let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
            let computed = hmac::sign(&key, &expected_version_bytes);
            assert_eq!(computed.as_ref(), masterkey_file.version_mac.as_slice());
        }).unwrap();
    }

    #[test]
    fn test_change_password() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        // Create a master key and initial masterkey file
        let master_key = MasterKey::random().unwrap();
        let old_passphrase = "old-password-123";
        let new_passphrase = "new-password-456";

        // Create initial masterkey file
        let json = create_masterkey_file(&master_key, old_passphrase).unwrap();

        // Write to temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(json.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Change password
        let new_json = change_password(temp_file.path(), old_passphrase, new_passphrase).unwrap();

        // Verify new file can be unlocked with new password
        let new_masterkey_file: MasterKeyFile = serde_json::from_str(&new_json).unwrap();
        let unlocked = new_masterkey_file.unlock(new_passphrase).unwrap();

        // Verify keys match original
        master_key.with_aes_key(|orig_aes| {
            unlocked.with_aes_key(|unlocked_aes| {
                assert_eq!(orig_aes, unlocked_aes, "AES keys should match after password change");
            })
        }).unwrap().unwrap();

        master_key.with_mac_key(|orig_mac| {
            unlocked.with_mac_key(|unlocked_mac| {
                assert_eq!(orig_mac, unlocked_mac, "MAC keys should match after password change");
            })
        }).unwrap().unwrap();

        // Verify old password no longer works
        let result = new_masterkey_file.unlock(old_passphrase);
        assert!(result.is_err(), "Old password should not work after change");
    }

    #[test]
    fn test_change_password_wrong_old_password() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let master_key = MasterKey::random().unwrap();
        let correct_passphrase = "correct-password";
        let wrong_passphrase = "wrong-password";

        // Create initial masterkey file
        let json = create_masterkey_file(&master_key, correct_passphrase).unwrap();

        // Write to temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(json.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Try to change password with wrong old password
        let result = change_password(temp_file.path(), wrong_passphrase, "new-password");
        assert!(result.is_err(), "Should fail with wrong old password");
    }
}
