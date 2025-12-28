//! Vault-level abstractions and operations

pub mod config;
pub mod creator;
pub mod master_key;
pub mod operations;
pub mod path;

#[cfg(feature = "async")]
pub mod handles;
#[cfg(feature = "async")]
pub mod locks;
#[cfg(feature = "async")]
pub mod operations_async;

#[cfg(feature = "async")]
pub use handles::{OpenHandle, VaultHandleTable};
#[cfg(feature = "async")]
pub use locks::{VaultLockManager, VaultLockRegistry};
#[cfg(feature = "async")]
pub use operations_async::VaultOperationsAsync;

// Re-export commonly used types
pub use config::{
    create_vault_config, extract_master_key, validate_vault_claims, CipherCombo, CiphertextDir,
    VaultConfig, VaultConfigurationClaims, VaultError,
};
pub use creator::{VaultCreationError, VaultCreator};
pub use master_key::{
    create_masterkey_file, create_masterkey_file_with_pepper, MasterKeyCreationError, MasterKeyFile,
};
pub use operations::{debug_read_files_in_tree, VaultOperationError, VaultOperations, VaultWriteError};
pub use path::{DirId, EntryType, VaultPath};