//! Error types for the cryptolib crate
//!
//! This module provides all error types and their context structures for
//! detailed error messages throughout the crate.

// Re-export error types from submodules
pub use crate::fs::file::{FileContext, FileError, FileDecryptionError, FileEncryptionError};
pub use crate::fs::name::{NameContext, NameError};
pub use crate::vault::config::{VaultError, MasterKeyExtractionError, ClaimValidationError};
pub use crate::vault::operations::{VaultOperationError, VaultWriteError, VaultOpContext};