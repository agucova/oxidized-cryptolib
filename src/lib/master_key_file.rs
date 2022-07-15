#![forbid(unsafe_code)]

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::base64::Base64;
use unicode_normalization::{UnicodeNormalization};

use super::master_key::MasterKey;

#[serde(rename_all = "camelCase")]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
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
    pub primary_master_key: Vec<u8>,
    // The wrapped MAC key
    #[serde_as(as = "Base64")]
    pub hmac_master_key: Vec<u8>,
    // HMAC-256 of the vault version
    #[serde_as(as = "Base64")]
    pub version_mac: Vec<u8>,
}

impl MasterKeyFile {
    #![allow(dead_code)]
    fn derive_key(&self, passphrase: &str) -> Vec<u8> {
        // We use NFC normalization on the passphrase
        let normalized_passphrase = passphrase.nfc().collect::<String>();

        // Define the scrypt parameters
        let log2_n: u8 = log_2(self.scrypt_cost_param) as u8;
        let r: u32 = self.scrypt_block_size as u32;
        let p: u32 = 1;

        let scrypt_params = scrypt::Params::new(log2_n, r, p).unwrap();

        // Initialize kek to an empty vector
        // TODO: Check size
        let k_cckey_size_aes256 = 32;
        let mut kek = vec![0; k_cckey_size_aes256];

        // Derive the kek from the normalized passphrase
        scrypt::scrypt(
            normalized_passphrase.as_bytes(),
            &self.scrypt_salt,
            &scrypt_params,
            &mut kek,
        )
        .unwrap();

        kek
    }

    // pub fn unlock(&self, passphrase: String) -> MasterKey {
    //     let kek = self.derive_key(&passphrase);
    //     self.unlock_with_kek(kek)
    // }

    // fn unlock_with_kek(&self, kek: Vec<u8>) -> MasterKey {
    //     // Unwrap the primary master key
    //     let aes_key = self.unwrap_key(&self.primary_master_key, &kek);
    //     // Unwrap the Hmac key
    //     let hmac_key = self.unwrap_key(&self.hmac_master_key, &kek);

    //     // Cross-reference versions

    //     self.check_vault_version(&hmac_key);

    //     // Construct key
    //     MasterKey {
    //         aes_master_key: aes_key,
    //         mac_master_key: hmac_key,
    //     }
    // }

    fn check_vault_version(&self, mac_key: &Vec<u8>) {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);

        hmac::verify(&key, &self.version.to_be_bytes(), &self.version_mac).expect("HMAC check failed");
    }

    // #[allow(unused_variables)]
    // fn unwrap_key(&self, wrapped_key: &Vec<u8>, kek: &Vec<u8>) -> Vec<u8> {
    //     // TODO: Key unwrapping
    //     wrapped_key
    // }
}

// From: https://users.rust-lang.org/t/logarithm-of-integers/8506/5
const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: i32) -> u32 {
    assert!(x > 0);
    num_bits::<i32>() as u32 - x.leading_zeros() - 1
}
