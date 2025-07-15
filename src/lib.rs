#![feature(test)]
#![feature(int_roundings)]

pub mod crypto;
pub mod error;
pub mod fs;
pub mod vault;

// Temporary re-exports for backward compatibility
// These can be removed once all code is updated to use the new module paths
pub use crypto::keys as master_key;
pub use crypto::rfc3394 as rfc_3394;
pub use fs::directory;
pub use fs::file as files;
pub use fs::name as names;
pub use vault::master_key as master_key_file;
pub use vault::operations as vault_ops;