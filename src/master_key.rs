pub struct MasterKey {
    aes_master_key: Vec<u8>,
    mac_master_key: Vec<u8>,
}

impl MasterKey {
    pub fn raw_key(&self) -> &Vec<u8> {
        &self.aes_master_key + &self.mac_master_key
    }
}
