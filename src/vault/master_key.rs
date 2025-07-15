#![forbid(unsafe_code)]

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, Secret};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use unicode_normalization::UnicodeNormalization;

use crate::crypto::{keys::MasterKey, rfc3394};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterKeyFile {
    // Deprecated
    version: u32,
    // Scrypt parameters
    #[serde_as(as = "Base64")]
    pub scrypt_salt: Vec<u8>,
    pub scrypt_cost_param: i32,
    pub scrypt_block_size: i32,
    #[serde_as(as = "Base64")]
    // The wrapped Encryption Master key
    // TODO: Probably make a secret?
    pub primary_master_key: Vec<u8>,
    // The wrapped MAC key
    #[serde_as(as = "Base64")]
    pub hmac_master_key: Vec<u8>,
    // HMAC-256 of the vault version
    #[serde_as(as = "Base64")]
    pub version_mac: Vec<u8>,
}

impl MasterKeyFile {
    pub fn derive_key(&self, passphrase: &str) -> Secret<[u8; 32]> {
        // We use NFC normalization on the passphrase
        let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());

        // Define the scrypt parameters
        let log2_n: u8 = log_2(self.scrypt_cost_param) as u8;
        let r: u32 = self.scrypt_block_size as u32;
        let p: u32 = 1;

        let scrypt_params =
            scrypt::Params::new(log2_n, r, p, 32).expect("Failed to create scrypt parameters");

        // Initialize kek to 256-bit empty array
        let mut kek = Zeroizing::new([0u8; 32]);

        // Derive the kek from the normalized passphrase
        scrypt::scrypt(
            normalized_passphrase.as_bytes(),
            &self.scrypt_salt,
            &scrypt_params,
            &mut kek[..],
        )
        .expect("Failed to derive kek");

        Secret::new(*kek)
    }

    pub fn unlock(&self, passphrase: &str) -> MasterKey {
        let kek = self.derive_key(passphrase);
        self.unlock_with_kek(&kek)
    }

    fn unlock_with_kek(&self, kek: &Secret<[u8; 32]>) -> MasterKey {
        // Unwrap the primary master key
        let aes_key =
            rfc3394::unwrap_key(&self.primary_master_key, kek).expect("Failed to unwrap AES key.");
        let aes_key: [u8; 32] = aes_key.try_into().unwrap();
        // Unwrap the Hmac key
        let hmac_key = rfc3394::unwrap_key(&self.hmac_master_key, kek).unwrap();
        let hmac_key: Secret<[u8; 32]> =
            Secret::new(hmac_key.try_into().expect("Failed to unwrap HMAC key."));

        // Cross-reference versions
        self.check_vault_version(&hmac_key);

        // Construct key
        MasterKey {
            aes_master_key: Secret::new(aes_key),
            mac_master_key: hmac_key,
        }
    }

    fn check_vault_version(&self, mac_key: &Secret<[u8; 32]>) {
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key.expose_secret());

        hmac::verify(&key, &self.version.to_be_bytes(), &self.version_mac)
            .expect("HMAC check failed");
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

/// Create a master key file content for testing
pub fn create_masterkey_file(
    master_key: &MasterKey,
    passphrase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use crate::crypto::rfc3394::wrap_key;
    
    // Generate salt
    let mut salt = vec![0u8; 32];
    SystemRandom::new().fill(&mut salt)?;
    
    // Scrypt parameters (matching Cryptomator defaults)
    let log2_n = 16;
    let r = 8;
    let p = 1;
    
    // Derive KEK from passphrase
    let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());
    let scrypt_params = scrypt::Params::new(log2_n as u8, r, p, 32)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(
        normalized_passphrase.as_bytes(),
        &salt,
        &scrypt_params,
        &mut kek[..],
    )?;
    let kek_secret = Secret::new(*kek);
    
    // Wrap the keys
    let wrapped_aes = master_key.with_aes_key(|key| wrap_key(key, &kek_secret))?;
    let wrapped_mac = master_key.with_mac_key(|key| wrap_key(key, &kek_secret))?;
    
    // Create version MAC
    let version = 999u32;
    let version_mac = master_key.with_mac_key(|key| {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, &version.to_be_bytes());
        tag.as_ref().to_vec()
    });
    
    // Create MasterKeyFile structure
    let masterkey_file = MasterKeyFile {
        version,
        scrypt_salt: salt,
        scrypt_cost_param: 1 << log2_n,
        scrypt_block_size: r as i32,
        primary_master_key: wrapped_aes,
        hmac_master_key: wrapped_mac,
        version_mac,
    };
    
    // Serialize to JSON
    Ok(serde_json::to_string_pretty(&masterkey_file)?)
}

pub fn derive_keys(passphrase: &str) -> (MasterKey, Secret<[u8; 32]>) {
    let master_key = MasterKey::random();
    
    // Generate salt
    let mut salt = vec![0u8; 32];
    SystemRandom::new()
        .fill(&mut salt)
        .expect("Failed to generate salt");
    
    // Scrypt parameters
    let log2_n = 16;
    let r = 8;
    let p = 1;
    
    // Derive KEK from passphrase
    let normalized_passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());
    let scrypt_params = scrypt::Params::new(log2_n as u8, r, p, 32)
        .expect("Failed to create scrypt parameters");
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(
        normalized_passphrase.as_bytes(),
        &salt,
        &scrypt_params,
        &mut kek[..],
    )
    .expect("Failed to derive KEK");
    
    (master_key, Secret::new(*kek))
}
