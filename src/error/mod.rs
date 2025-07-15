//! Error types for the cryptolib crate

// Re-export error types from submodules
pub use crate::fs::file::{FileError, FileDecryptionError, FileEncryptionError};
pub use crate::vault::config::{VaultError, MasterKeyExtractionError, ClaimValidationError};
pub use crate::vault::operations::VaultOperationError;