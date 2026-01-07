#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use url::Url;

use crate::{
    crypto::CryptoError,
    crypto::keys::{JwtValidationError, KeyAccessError, MasterKey},
    fs::file::{
        DecryptedFile, FileContext, FileDecryptionError, FileEncryptionError, decrypt_file_content,
        decrypt_file_header, encrypt_file_content, encrypt_file_header,
    },
    fs::file_ctrmac,
    vault::master_key::MasterKeyFile,
};
use rand::RngCore;
use zeroize::Zeroize;

use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Default shortening threshold for filenames (in characters of encrypted name)
pub const DEFAULT_SHORTENING_THRESHOLD: usize = 220;

/// Cipher combination used by a vault.
///
/// Cryptomator supports two cipher combos:
/// - `SIV_GCM`: AES-SIV for filenames, AES-GCM for file content (default for new vaults)
/// - `SIV_CTRMAC`: AES-SIV for filenames, AES-CTR + HMAC-SHA256 for file content (legacy)
///
/// # Reference Implementation
/// - Java: [`CryptorProvider.Scheme`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/api/CryptorProvider.java)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherCombo {
    /// AES-SIV for filenames, AES-GCM for content (v2)
    ///
    /// File header: 68 bytes (12-byte nonce + 40-byte payload + 16-byte tag)
    /// Chunk overhead: 28 bytes (12-byte nonce + 16-byte tag)
    SivGcm,
    /// AES-SIV for filenames, AES-CTR + HMAC-SHA256 for content (v1)
    ///
    /// File header: 88 bytes (16-byte nonce + 40-byte payload + 32-byte HMAC)
    /// Chunk overhead: 48 bytes (16-byte nonce + 32-byte HMAC)
    SivCtrMac,
}

/// Error returned when parsing an invalid cipher combo string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCipherComboError(String);

impl fmt::Display for ParseCipherComboError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown cipher combo: {}", self.0)
    }
}

impl std::error::Error for ParseCipherComboError {}

impl FromStr for CipherCombo {
    type Err = ParseCipherComboError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIV_GCM" => Ok(CipherCombo::SivGcm),
            "SIV_CTRMAC" => Ok(CipherCombo::SivCtrMac),
            _ => Err(ParseCipherComboError(s.to_owned())),
        }
    }
}

impl CipherCombo {
    /// Convert to configuration string.
    pub fn as_str(&self) -> &'static str {
        match self {
            CipherCombo::SivGcm => "SIV_GCM",
            CipherCombo::SivCtrMac => "SIV_CTRMAC",
        }
    }

    // ==================== File Encryption ====================

    /// Encrypt file content (header + chunks) using this cipher combo.
    ///
    /// This is the primary entry point for file encryption. It generates a random
    /// content key, encrypts the header, and encrypts all content chunks.
    ///
    /// # Returns
    ///
    /// The complete encrypted file data (header + encrypted chunks).
    pub fn encrypt_file(
        &self,
        content: &[u8],
        master_key: &MasterKey,
    ) -> Result<Vec<u8>, FileEncryptionError> {
        // Generate random content key
        let mut content_key = [0u8; 32];
        rand::rng().fill_bytes(&mut content_key);

        let result = self.encrypt_file_with_key(content, &content_key, master_key);

        // Zeroize content key
        content_key.zeroize();

        result
    }

    /// Encrypt file content with a specific content key.
    ///
    /// This is useful when you need to control the content key (e.g., for testing).
    pub fn encrypt_file_with_key(
        &self,
        content: &[u8],
        content_key: &[u8; 32],
        master_key: &MasterKey,
    ) -> Result<Vec<u8>, FileEncryptionError> {
        match self {
            CipherCombo::SivGcm => {
                let header = encrypt_file_header(content_key, master_key)?;
                let header_nonce: [u8; 12] = header[0..12].try_into().unwrap();
                let encrypted_content = encrypt_file_content(content, content_key, &header_nonce)?;

                let mut data = Vec::with_capacity(header.len() + encrypted_content.len());
                data.extend_from_slice(&header);
                data.extend_from_slice(&encrypted_content);
                Ok(data)
            }
            CipherCombo::SivCtrMac => {
                let header = file_ctrmac::encrypt_header(content_key, master_key).map_err(|e| {
                    FileEncryptionError::HeaderEncryption {
                        reason: format!("CTRMAC header encryption failed: {e}"),
                        context: FileContext::new(),
                    }
                })?;
                let header_nonce: [u8; file_ctrmac::NONCE_SIZE] =
                    header[0..file_ctrmac::NONCE_SIZE].try_into().unwrap();

                let encrypted_content = master_key
                    .with_mac_key(|mac_key| {
                        file_ctrmac::encrypt_content(content, content_key, &header_nonce, mac_key)
                    })
                    .map_err(FileEncryptionError::KeyAccess)?
                    .map_err(|e| FileEncryptionError::ContentEncryption {
                        reason: format!("CTRMAC content encryption failed: {e}"),
                        context: FileContext::new(),
                    })?;

                let mut data = Vec::with_capacity(header.len() + encrypted_content.len());
                data.extend_from_slice(&header);
                data.extend_from_slice(&encrypted_content);
                Ok(data)
            }
        }
    }

    // ==================== File Decryption ====================

    /// Decrypt file content using this cipher combo.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The complete encrypted file (header + chunks)
    /// * `master_key` - The vault's master key
    ///
    /// # Returns
    ///
    /// The decrypted file content.
    pub fn decrypt_file(
        &self,
        encrypted_data: &[u8],
        master_key: &MasterKey,
    ) -> Result<DecryptedFile, FileDecryptionError> {
        self.decrypt_file_with_context(encrypted_data, master_key, FileContext::new())
    }

    /// Decrypt file content with context for better error messages.
    pub fn decrypt_file_with_context(
        &self,
        encrypted_data: &[u8],
        master_key: &MasterKey,
        context: FileContext,
    ) -> Result<DecryptedFile, FileDecryptionError> {
        match self {
            CipherCombo::SivGcm => {
                // GCM header is 68 bytes
                if encrypted_data.len() < 68 {
                    return Err(FileDecryptionError::InvalidHeader {
                        reason: format!(
                            "File too small for GCM header: {} bytes",
                            encrypted_data.len()
                        ),
                        context,
                    });
                }

                let header = decrypt_file_header(&encrypted_data[..68], master_key)?;
                // Header nonce is the first 12 bytes of the encrypted header
                let header_nonce = &encrypted_data[0..12];
                let content =
                    decrypt_file_content(&encrypted_data[68..], &header.content_key, header_nonce)?;

                Ok(DecryptedFile { header, content })
            }
            CipherCombo::SivCtrMac => {
                // CTRMAC header is 88 bytes
                if encrypted_data.len() < file_ctrmac::HEADER_SIZE {
                    return Err(FileDecryptionError::InvalidHeader {
                        reason: format!(
                            "File too small for CTRMAC header: {} bytes",
                            encrypted_data.len()
                        ),
                        context,
                    });
                }

                let ctrmac_header = file_ctrmac::decrypt_header(
                    &encrypted_data[..file_ctrmac::HEADER_SIZE],
                    master_key,
                    &context,
                )
                .map_err(|_| FileDecryptionError::HeaderDecryption {
                    context: context.clone(),
                })?;

                let content = master_key
                    .with_mac_key(|mac_key| {
                        file_ctrmac::decrypt_content(
                            &encrypted_data[file_ctrmac::HEADER_SIZE..],
                            &ctrmac_header.content_key,
                            &ctrmac_header.nonce,
                            mac_key,
                            &context,
                        )
                    })
                    .map_err(FileDecryptionError::KeyAccess)?
                    .map_err(|_| FileDecryptionError::ContentDecryption {
                        context: context.clone(),
                    })?;

                // Convert CTRMAC header to GCM-style FileHeader for uniform API
                use crate::fs::file::FileHeader;
                let header = FileHeader {
                    content_key: ctrmac_header.content_key,
                    tag: [0u8; 16], // CTRMAC doesn't use GCM tags
                };

                Ok(DecryptedFile { header, content })
            }
        }
    }

    // ==================== Directory ID Backup ====================

    /// Encrypt a directory ID for the dirid.c9r backup file.
    ///
    /// The dirid.c9r file stores the directory's own ID using the vault's
    /// cipher combo for file content encryption.
    pub fn encrypt_dir_id_backup(
        &self,
        dir_id: &str,
        master_key: &MasterKey,
    ) -> Result<Vec<u8>, FileEncryptionError> {
        self.encrypt_file(dir_id.as_bytes(), master_key)
    }

    /// Decrypt a directory ID from a dirid.c9r backup file.
    pub fn decrypt_dir_id_backup(
        &self,
        encrypted_data: &[u8],
        master_key: &MasterKey,
    ) -> Result<String, FileDecryptionError> {
        let context = FileContext::new().with_filename("dirid.c9r");
        let decrypted = self.decrypt_file_with_context(encrypted_data, master_key, context)?;
        String::from_utf8(decrypted.content).map_err(|e| FileDecryptionError::InvalidHeader {
            reason: format!("Directory ID is not valid UTF-8: {e}"),
            context: FileContext::new().with_filename("dirid.c9r"),
        })
    }
}

/// Claims contained in the vault configuration JWT (`vault.cryptomator`).
///
/// # Reference Implementation
/// - Java: [`VaultConfig`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/VaultConfig.java)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfigurationClaims {
    format: i32,
    #[serde(default = "default_shortening_threshold")]
    shortening_threshold: i32,
    jti: String,
    cipher_combo: String,
}

fn default_shortening_threshold() -> i32 {
    // Safe cast: DEFAULT_SHORTENING_THRESHOLD (220) is well within i32 range
    i32::try_from(DEFAULT_SHORTENING_THRESHOLD)
        .expect("DEFAULT_SHORTENING_THRESHOLD (220) fits in i32")
}

impl VaultConfigurationClaims {
    /// Returns the vault format version.
    pub fn format(&self) -> i32 {
        self.format
    }

    /// Returns the cipher combination string used by this vault.
    pub fn cipher_combo_str(&self) -> &str {
        &self.cipher_combo
    }

    /// Returns the parsed cipher combination used by this vault.
    pub fn cipher_combo(&self) -> Option<CipherCombo> {
        self.cipher_combo.parse().ok()
    }

    /// Returns the shortening threshold for filenames.
    ///
    /// Encrypted filenames longer than this value will be shortened using
    /// the .c9s format (SHA-1 hash of the encrypted name).
    pub fn shortening_threshold(&self) -> usize {
        // Safe cast: .max(0) ensures non-negative, and typical values are 220-1024 (well within usize)
        usize::try_from(self.shortening_threshold.max(0))
            .expect("shortening_threshold is ensured to be non-negative")
    }
}

/// Vault configuration for creating new vaults.
///
/// # Reference Implementation
/// - Java: [`VaultConfig`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/VaultConfig.java)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub jti: String,
    pub format: i32,
    /// Shortening threshold for filenames (defaults to 220 if not specified)
    #[serde(default = "default_shortening_threshold")]
    pub shortening_threshold: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_dir: Option<CiphertextDir>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Payload>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CiphertextDir(pub String);

#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    pub key: String,
    #[serde(flatten)]
    pub other_fields: HashMap<String, Value>,
}

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Error extracting master key: {0}")]
    MasterKeyExtraction(#[from] MasterKeyExtractionError),

    #[error("Error validating vault claims: {0}")]
    ClaimValidation(#[from] ClaimValidationError),

    #[error("Error cloning master key: {0}")]
    KeyClone(#[from] KeyAccessError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum MasterKeyExtractionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT header decode error: {0}")]
    JwtHeader(#[from] jsonwebtoken::errors::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Missing kid in header")]
    MissingKid,

    #[error("Invalid masterkey file scheme")]
    InvalidScheme,

    #[error("Master key file not found at path: {0}")]
    MasterKeyFileNotFound(PathBuf),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Error, Debug)]
pub enum ClaimValidationError {
    #[error("JWT decode error: {0}")]
    JwtDecode(#[from] jsonwebtoken::errors::Error),

    #[error("JWT validation error: {0}")]
    JwtValidation(#[from] JwtValidationError),

    #[error("Unsupported cipher combo: {0}")]
    UnsupportedCipherCombo(String),

    #[error("Unsupported vault format: {0}")]
    UnsupportedVaultFormat(i32),
}

/// Extract the master key from a vault using the passphrase.
///
/// Reads the vault configuration JWT, locates the master key file,
/// and unlocks it with the provided passphrase.
///
/// # Reference Implementation
/// - Java: [`MasterkeyFileAccess.load()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/MasterkeyFileAccess.java)
pub fn extract_master_key(
    vault_path: &Path,
    passphrase: &str,
) -> Result<MasterKey, MasterKeyExtractionError> {
    let vault_config_path = vault_path.join("vault.cryptomator");
    let vault_config = fs::read_to_string(&vault_config_path)?;
    let header = jsonwebtoken::decode_header(&vault_config)?;

    let kid = header.kid.ok_or(MasterKeyExtractionError::MissingKid)?;
    let masterkey_uri = Url::parse(&kid)?;

    if masterkey_uri.scheme() != "masterkeyfile" {
        return Err(MasterKeyExtractionError::InvalidScheme);
    }

    let master_key_path = vault_path.join(Path::new(masterkey_uri.path()));
    if !master_key_path.exists() {
        return Err(MasterKeyExtractionError::MasterKeyFileNotFound(
            master_key_path,
        ));
    }

    let master_key_data_json = fs::read_to_string(&master_key_path)?;
    let master_key_data: MasterKeyFile = serde_json::from_str(&master_key_data_json)?;

    Ok(master_key_data.unlock(passphrase)?)
}

/// Validate and decode the vault configuration JWT claims.
///
/// Verifies the JWT signature using the master key and extracts the vault
/// configuration claims (format version, cipher combo, etc.).
///
/// # Reference Implementation
/// - Java: [`VaultConfig.decode()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/VaultConfig.java)
pub fn validate_vault_claims(
    vault_config: &str,
    master_key: &MasterKey,
) -> Result<VaultConfigurationClaims, ClaimValidationError> {
    let header = jsonwebtoken::decode_header(vault_config)?;

    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.algorithms = vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];

    // Use the new validate_jwt method which handles key access securely
    let claims = master_key.validate_jwt::<VaultConfigurationClaims>(vault_config, &validation)?;

    // Validate cipher combo - support both SIV_GCM and SIV_CTRMAC
    if claims.cipher_combo().is_none() {
        return Err(ClaimValidationError::UnsupportedCipherCombo(
            claims.cipher_combo.clone(),
        ));
    }

    if claims.format != 8 {
        return Err(ClaimValidationError::UnsupportedVaultFormat(claims.format));
    }

    Ok(claims)
}

/// Error type for vault config creation
#[derive(Error, Debug)]
pub enum VaultConfigCreationError {
    #[error("JWT encoding error: {0}")]
    JwtEncode(#[from] jsonwebtoken::errors::Error),

    #[error("Key access error: {0}")]
    KeyAccess(#[from] KeyAccessError),
}

/// Create a vault configuration JWT.
///
/// # Reference Implementation
/// - Java: [`VaultConfig.createNew()`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/VaultConfig.java)
pub fn create_vault_config(
    config: &VaultConfig,
    master_key: &MasterKey,
) -> Result<String, VaultConfigCreationError> {
    let claims = VaultConfigurationClaims {
        format: config.format,
        shortening_threshold: config.shortening_threshold,
        jti: config.jti.clone(),
        cipher_combo: "SIV_GCM".to_string(),
    };

    let encoding_key = master_key.create_jwt_encoding_key()?;
    let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
    header.kid = Some("masterkeyfile:masterkey/masterkey.cryptomator".to_string());

    Ok(jsonwebtoken::encode(&header, &claims, &encoding_key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;
    use uuid::Uuid;

    #[test]
    fn test_claim_validation() {
        let master_key = MasterKey::random().unwrap();
        let claims = VaultConfigurationClaims {
            format: 8,
            shortening_threshold: 200,
            jti: Uuid::new_v4().to_string(),
            cipher_combo: "SIV_GCM".to_string(),
        };

        let encoding_key = master_key.create_jwt_encoding_key().unwrap();
        let token = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &encoding_key);

        let validated_claims = validate_vault_claims(&token.unwrap(), &master_key).unwrap();
        assert_eq!(claims, validated_claims);
    }

    #[test]
    fn test_tampered_claim_validation() {
        let master_key = MasterKey::random().unwrap();
        let claims = VaultConfigurationClaims {
            format: 8,
            shortening_threshold: 200,
            jti: Uuid::new_v4().to_string(),
            cipher_combo: "SIV_GCM".to_string(),
        };

        let encoding_key = master_key.create_jwt_encoding_key().unwrap();
        let token =
            jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &encoding_key).unwrap();

        // Replace the base64 encoded cipher combo with a different one
        let tampered_token = {
            let mut parts = token.split('.').collect::<Vec<&str>>();
            let claims_json =
                String::from_utf8(BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
            let tampered_claims_json = claims_json.replace("SIV_GCM", "SIV_CBC");
            let tampered_payload = BASE64URL_NOPAD.encode(tampered_claims_json.as_bytes());
            parts[1] = &tampered_payload;
            parts.join(".")
        };

        println!("{tampered_token}");
        let result = validate_vault_claims(&tampered_token, &master_key);
        println!("{result:?}");
        match result {
            Err(ClaimValidationError::JwtDecode(_) | ClaimValidationError::JwtValidation(_)) => (),
            Ok(_) => panic!("Tampered token was validated successfully"),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_shortening_threshold_getter() {
        let master_key = MasterKey::random().unwrap();
        let claims = VaultConfigurationClaims {
            format: 8,
            shortening_threshold: 150, // Custom threshold
            jti: Uuid::new_v4().to_string(),
            cipher_combo: "SIV_GCM".to_string(),
        };

        let encoding_key = master_key.create_jwt_encoding_key().unwrap();
        let token =
            jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &encoding_key).unwrap();

        let validated_claims = validate_vault_claims(&token, &master_key).unwrap();
        assert_eq!(validated_claims.shortening_threshold(), 150);
    }

    #[test]
    fn test_default_shortening_threshold() {
        assert_eq!(DEFAULT_SHORTENING_THRESHOLD, 220);
    }

    #[test]
    fn test_vault_config_with_custom_threshold() {
        let master_key = MasterKey::random().unwrap();
        let config = VaultConfig {
            jti: Uuid::new_v4().to_string(),
            format: 8,
            shortening_threshold: 100, // Custom threshold
            ciphertext_dir: None,
            payload: None,
        };

        let jwt = create_vault_config(&config, &master_key).unwrap();
        let validated_claims = validate_vault_claims(&jwt, &master_key).unwrap();

        // The JWT should preserve the custom threshold
        assert_eq!(validated_claims.shortening_threshold(), 100);
    }
}
