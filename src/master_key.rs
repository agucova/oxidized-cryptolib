#![forbid(unsafe_code)]

use rand_core::{OsRng, RngCore};

#[derive(Debug)]
pub struct MasterKey {
    pub aes_master_key: [u8; 32],
    pub mac_master_key: [u8; 32],
}

use generic_array::{typenum::U64, GenericArray};

impl MasterKey {
    pub fn random() -> Self {
        let mut aes_master_key = [0u8; 32];
        let mut mac_master_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_master_key);
        OsRng.fill_bytes(&mut mac_master_key);
        MasterKey {
            aes_master_key,
            mac_master_key,
        }
    }

    pub fn raw_key(&self) -> GenericArray<u8, U64> {
        // Combine the AES and MAC keys into a single key through copying
        let mut key = GenericArray::default();
        key[..32].copy_from_slice(&self.aes_master_key);
        key[32..].copy_from_slice(&self.mac_master_key);
        key
    }
}
