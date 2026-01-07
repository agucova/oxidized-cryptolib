//! Vault-level abstractions and operations

pub mod cache;
pub mod config;
pub mod creator;
pub mod master_key;
pub mod operations;
pub mod ops;
pub mod password;
pub mod path;

#[cfg(feature = "async")]
pub mod handles;
#[cfg(feature = "async")]
pub mod locks;
#[cfg(feature = "async")]
pub mod lock_metrics;
#[cfg(feature = "async")]
pub mod operations_async;

#[cfg(feature = "async")]
pub use handles::{OpenHandle, VaultHandleTable};
#[cfg(feature = "async")]
pub use locks::{VaultLockManager, VaultLockRegistry};
#[cfg(feature = "async")]
pub use operations_async::{change_password_async, ChangePasswordAsyncError, VaultOperationsAsync};

// Re-export commonly used types
pub use cache::{CacheStats, VaultCache};
pub use config::{
    create_vault_config, extract_master_key, validate_vault_claims, CipherCombo, CiphertextDir,
    VaultConfig, VaultConfigurationClaims, VaultError,
};
pub use creator::{VaultCreationError, VaultCreator};
pub use master_key::{
    change_password, change_password_with_pepper, create_masterkey_file,
    create_masterkey_file_with_pepper, ChangePasswordError, MasterKeyCreationError, MasterKeyFile,
};
pub use password::{
    PasswordValidationError, PasswordValidator, ValidatedPassword, DEFAULT_VALIDATION_TIMEOUT,
};
pub use operations::{
    DirEntry, VaultDirectoryInfo, VaultFileInfo, VaultOperationError, VaultOperations,
    VaultSymlinkInfo, VaultWriteError,
};
pub use path::{DirId, EntryType, VaultPath};

// Re-export shared operations infrastructure
pub use ops::{VaultCore, StoragePathError};
