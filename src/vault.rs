#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use url::Url;

use crate::{master_key::MasterKey, master_key_file::MasterKeyFile};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfigurationClaims {
    format: i32,
    shortening_threshold: i32,
    jti: String,
    cipher_combo: String,
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
}

#[derive(Error, Debug)]
pub enum ClaimValidationError {
    #[error("JWT decode error: {0}")]
    JwtDecode(#[from] jsonwebtoken::errors::Error),

    #[error("Unsupported cipher combo: {0}")]
    UnsupportedCipherCombo(String),

    #[error("Unsupported vault format: {0}")]
    UnsupportedVaultFormat(i32),
}

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

    Ok(master_key_data.unlock(passphrase))
}

pub fn validate_vault_claims(
    vault_config: &str,
    master_key: &MasterKey,
) -> Result<VaultConfigurationClaims, ClaimValidationError> {
    let header = jsonwebtoken::decode_header(vault_config)?;
    let jwt_secret = DecodingKey::from_secret(master_key.raw_key().to_vec().as_slice());

    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.algorithms = vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];

    let token =
        jsonwebtoken::decode::<VaultConfigurationClaims>(vault_config, &jwt_secret, &validation)?;

    if token.claims.cipher_combo != "SIV_GCM" {
        return Err(ClaimValidationError::UnsupportedCipherCombo(
            token.claims.cipher_combo,
        ));
    }

    if token.claims.format != 8 {
        return Err(ClaimValidationError::UnsupportedVaultFormat(
            token.claims.format,
        ));
    }

    Ok(token.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;
    use jsonwebtoken::EncodingKey;
    use uuid::Uuid;

    #[test]
    fn test_claim_validation() {
        let master_key = MasterKey::random();
        let claims = VaultConfigurationClaims {
            format: 8,
            shortening_threshold: 200,
            jti: Uuid::new_v4().to_string(),
            cipher_combo: "SIV_GCM".to_string(),
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(master_key.raw_key().to_vec().as_slice()),
        );

        let validated_claims = validate_vault_claims(&token.unwrap(), &master_key).unwrap();
        assert_eq!(claims, validated_claims);
    }

    #[test]
    fn test_tampered_claim_validation() {
        let master_key = MasterKey::random();
        let claims = VaultConfigurationClaims {
            format: 8,
            shortening_threshold: 200,
            jti: Uuid::new_v4().to_string(),
            cipher_combo: "SIV_GCM".to_string(),
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(master_key.raw_key().to_vec().as_slice()),
        )
        .unwrap();

        // Replace the base64 encoded cipher combo with a different one
        let tampered_token = {
            let mut parts = token.split('.').collect::<Vec<&str>>();
            let claims_json =
                String::from_utf8(BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
            let tampered_claims_json = claims_json.replace("SIV_GCM", "SIV_CBC");
            let tampered_payload = BASE64URL_NOPAD.encode(&tampered_claims_json.as_bytes());
            parts[1] = &tampered_payload;
            parts.join(".")
        };

        println!("{}", tampered_token);
        let result = validate_vault_claims(&tampered_token, &master_key);
        println!("{:?}", result);
        match result {
            Err(ClaimValidationError::JwtDecode(_)) => (),
            Ok(_) => panic!("Tampered token was validated successfully"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
