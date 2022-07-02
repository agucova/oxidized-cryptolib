use aes_keywrap_rs::aes_unwrap_key;
use scrypt::ScryptParams::scrypt;
use unicode_normalization::is_nfc;
use ring::{hmac};
use serde::{Deserialize, Serialize, serde};
use serde_with::{serde_as};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde_as]
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
    fn deriveKey(passphrase: &str) -> Vec<u8> {
        if (!is_nfc(passphrase)) {
            // We use NFC normalization on the passphrase
            passphrase = passphrase.nfc().collect::<String>().as_str();
        }
        // Define the scrypt parameters
        let log2_n: u8 = log_2(self.scrypt_cost_param) as u8;
        let r: u32 = self.scrypt_block_size as u32;
        let p: u32 = 1;

        let scrypt_params = ScryptParams::new(log2_N, r, p);

        // Initialize kek to an empty vector
        // TODO: Check size
        let kCCKeySizeAES256 = 32;
        let mut kek = vec![0; kCCKeySizeAES256];

        // Derive the kek from the passphrase
        scrypt::scrypt(
            passphrase.as_bytes(),
            &self.scrypt_salt,
            &scrypt_params,
            &mut kek,
        )
        .unwrap();

        kek
    }

    pub fn unlock(&self, passphrase: String) -> MasterKey {
        let kek = self.deriveKey(&passphrase);
        unlock(&kek)
    }

    fn unlock(&self, kek: Vec<u8>) -> MasterKey {
        // Unwrap the primary master key
        let aes_key = self.unwrap_key(&self.primary_master_key, &kek);
        // Unwrap the Hmac key
        let hmac_key = self.unwrap_key(&self.hmac_master_key, &kek);

        // Cross-reference versions
        assert!(self.check_vault_version(&hmac_key), "Vault version check failed");

        // Construct key

    }

    fn check_vault_version(macKey: &Vec<u8>) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &macKey);

        hmac::verify(&key, &self.version, &self.version_mac).unwrap()
    }

    fn unwrap_key(&self, wrapped_key: &Vec<u8>, kek: &Vec<u8>) -> Vec<u8> {
        aes_unwrap_key(kek, wrapped_key).unwrap()
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
