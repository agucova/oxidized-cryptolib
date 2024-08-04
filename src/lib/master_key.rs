#![forbid(unsafe_code)]

#[derive(Debug)]
pub struct MasterKey {
    pub aes_master_key: [u8; 32],
    pub mac_master_key: [u8; 32],
}

impl MasterKey {
    #![allow(dead_code)]
    pub fn raw_key(&self) -> Vec<u8>{
        [self.aes_master_key, self.mac_master_key].concat()
    }
}
