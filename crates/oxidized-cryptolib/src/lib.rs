#![cfg_attr(test, feature(test))]

pub mod crypto;
pub mod error;
pub mod fs;
pub mod mount;
pub mod vault;

// Re-export commonly used types at crate root
pub use mount::{
    BackendInfo, BackendType, MountBackend, MountError, MountHandle,
    first_available_backend, list_backend_info, select_backend,
};

#[cfg(feature = "async")]
pub use vault::VaultOperationsAsync;

#[cfg(feature = "async")]
pub use fs::file_async::{decrypt_file_async, decrypt_file_with_context_async};