#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use url::Url;

use crate::{crypto::keys::{MasterKey, JwtValidationError, KeyAccessError}, crypto::CryptoError, vault::master_key::MasterKeyFile};

use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Default shortening threshold for filenames (in characters of encrypted name)
pub const DEFAULT_SHORTENING_THRESHOLD: usize = 220;

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
    DEFAULT_SHORTENING_THRESHOLD as i32
}

impl VaultConfigurationClaims {
    /// Returns the shortening threshold for filenames.
    ///
    /// Encrypted filenames longer than this value will be shortened using
    /// the .c9s format (SHA-1 hash of the encrypted name).
    pub fn shortening_threshold(&self) -> usize {
        self.shortening_threshold.max(0) as usize
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

    if claims.cipher_combo != "SIV_GCM" {
        return Err(ClaimValidationError::UnsupportedCipherCombo(
            claims.cipher_combo,
        ));
    }

    if claims.format != 8 {
        return Err(ClaimValidationError::UnsupportedVaultFormat(
            claims.format,
        ));
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
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &encoding_key,
        );

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
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &encoding_key,
        )
        .unwrap();

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
            Err(ClaimValidationError::JwtDecode(_)) | Err(ClaimValidationError::JwtValidation(_)) => (),
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
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &encoding_key,
        )
        .unwrap();

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
