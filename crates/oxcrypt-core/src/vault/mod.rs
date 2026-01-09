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
pub mod lock_metrics;
#[cfg(feature = "async")]
pub mod locks;
#[cfg(feature = "async")]
pub mod operations_async;

#[cfg(feature = "async")]
pub use handles::{OpenHandle, VaultHandleTable};
#[cfg(feature = "async")]
pub use locks::{VaultLockManager, VaultLockRegistry};
#[cfg(feature = "async")]
pub use operations_async::{
    ChangePasswordAsyncError, SyncFirstResult, VaultOperationsAsync, change_password_async,
};

// Re-export commonly used types
pub use cache::{CacheStats, VaultCache};
pub use config::{
    CipherCombo, CiphertextDir, VaultConfig, VaultConfigurationClaims, VaultError,
    create_vault_config, extract_master_key, validate_vault_claims,
};
pub use creator::{VaultCreationError, VaultCreator};
pub use master_key::{
    ChangePasswordError, MasterKeyCreationError, MasterKeyFile, change_password,
    change_password_with_pepper, create_masterkey_file, create_masterkey_file_with_pepper,
};
pub use operations::{
    DirEntry, VaultDirectoryInfo, VaultFileInfo, VaultOperationError, VaultOperations,
    VaultSymlinkInfo, VaultWriteError,
};
pub use password::{
    DEFAULT_VALIDATION_TIMEOUT, PasswordValidationError, PasswordValidator, ValidatedPassword,
};
pub use path::{DirId, EntryType, VaultPath};

// Re-export shared operations infrastructure
pub use ops::{StoragePathError, VaultCore};
