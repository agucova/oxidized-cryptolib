//! Error types for the cryptolib crate
//!
//! This module provides all error types and their context structures for
//! detailed error messages throughout the crate.

// Re-export error types from submodules
pub use crate::fs::file::{FileContext, FileDecryptionError, FileEncryptionError, FileError};
pub use crate::fs::name::{NameContext, NameError};
pub use crate::vault::config::{ClaimValidationError, MasterKeyExtractionError, VaultError};
pub use crate::vault::operations::{VaultOpContext, VaultOperationError, VaultWriteError};
