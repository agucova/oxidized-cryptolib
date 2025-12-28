//! Vault-level abstractions and operations

pub mod config;
pub mod creator;
pub mod master_key;
pub mod operations;
pub mod path;

// Re-export commonly used types
pub use config::{
    create_vault_config, extract_master_key, validate_vault_claims, CiphertextDir, VaultConfig,
    VaultConfigurationClaims,
};
pub use creator::{VaultCreationError, VaultCreator};
pub use master_key::{create_masterkey_file, MasterKeyCreationError, MasterKeyFile};
pub use operations::{debug_read_files_in_tree, VaultOperationError, VaultOperations, VaultWriteError};
pub use path::{DirId, VaultPath};