#![cfg_attr(test, feature(test))]

pub mod crypto;
pub mod error;
pub mod fs;
pub mod vault;

#[cfg(feature = "async")]
pub use vault::VaultOperationsAsync;

#[cfg(feature = "async")]
pub use fs::file_async::{decrypt_file_async, decrypt_file_with_context_async};
