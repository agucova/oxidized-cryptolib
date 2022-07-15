#![forbid(unsafe_code)]

use generic_array::{GenericArray, typenum::U32};


pub struct MasterKey {
    pub aes_master_key: GenericArray<u8, U32>,
    pub mac_master_key: GenericArray<u8, U32>,
}

impl MasterKey {
    #![allow(dead_code)]
    pub fn raw_key(&self) -> Vec<u8>{
        // Combine the AES and MAC keys into a single key through copying
        [self.aes_master_key, self.mac_master_key].concat()
    }
}
