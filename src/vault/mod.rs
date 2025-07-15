//! Vault-level abstractions and operations

pub mod config;
pub mod master_key;
pub mod operations;

// Re-export commonly used types
pub use config::{extract_master_key, validate_vault_claims, VaultConfigurationClaims};
pub use master_key::MasterKeyFile;
pub use operations::{VaultOperations, debug_read_files_in_tree};