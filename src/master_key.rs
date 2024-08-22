#![forbid(unsafe_code)]

use rand_core::{OsRng, RngCore};

use secrecy::{ExposeSecret, Secret};

#[derive(Debug)]
pub struct MasterKey {
    pub aes_master_key: Secret<[u8; 32]>,
    pub mac_master_key: Secret<[u8; 32]>,
}

use generic_array::{typenum::U64, GenericArray};

impl MasterKey {
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

    pub fn raw_key(&self) -> GenericArray<u8, U64> {
        let mut key = GenericArray::default();
        key[..32].copy_from_slice(self.aes_master_key.expose_secret());
        key[32..].copy_from_slice(self.mac_master_key.expose_secret());
        key
    }
}
