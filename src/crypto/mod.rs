//! Cryptographic primitives for Cryptomator vault operations

pub mod keys;
pub mod key_wrap;

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
///
/// # Security Classification
///
/// Some errors indicate potential **adversarial tampering** or **integrity violations**.
/// These should be treated as security events and may warrant logging, alerting,
/// or aborting the operation entirely. They are marked with `[INTEGRITY VIOLATION]`.
///
/// Other errors indicate **user errors** (wrong password) or **programming errors**
/// (invalid parameters). These are marked accordingly.
#[derive(Error, Debug)]
pub enum CryptoError {
    // =========================================================================
    // INTEGRITY VIOLATIONS - Potential adversarial tampering
    // =========================================================================
    /// The master key file's integrity check failed during unwrapping.
    ///
    /// **[INTEGRITY VIOLATION]** This indicates the encrypted master key has been
    /// tampered with, corrupted, or the wrong key encryption key was derived
    /// (possibly due to wrong password, but also possibly due to malicious modification).
    #[error("[INTEGRITY VIOLATION] Key unwrap integrity check failed - possible tampering")]
    KeyUnwrapIntegrityFailed,

    /// HMAC verification of the vault configuration failed.
    ///
    /// **[INTEGRITY VIOLATION]** This indicates the vault's JWT configuration has been
    /// tampered with or corrupted. The vault should not be trusted.
    #[error("[INTEGRITY VIOLATION] HMAC verification failed - vault configuration tampered")]
    HmacVerificationFailed,

    // =========================================================================
    // USER ERRORS - Typically wrong password or corrupted input
    // =========================================================================
    /// Key derivation failed, typically due to scrypt computation error.
    ///
    /// **[USER ERROR]** This usually means the password was rejected during
    /// key derivation, or system resources were exhausted.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    // =========================================================================
    // PROGRAMMING ERRORS - Invalid parameters or implementation bugs
    // =========================================================================
    /// Invalid scrypt parameters in the master key file.
    ///
    /// **[PROGRAMMING ERROR]** The scrypt cost parameters (N, r, p) are invalid.
    /// This indicates a corrupted master key file or implementation bug.
    #[error("Invalid scrypt parameters: {0}")]
    InvalidScryptParams(String),

    /// The ciphertext length is invalid for AES key unwrapping.
    ///
    /// **[PROGRAMMING ERROR]** The ciphertext must be a multiple of 64 bits.
    #[error("Invalid ciphertext length for key unwrap")]
    InvalidCiphertextLength,

    /// Array conversion failed due to unexpected length.
    ///
    /// **[PROGRAMMING ERROR]** Internal error during key material handling.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Key access failed due to memory protection error or borrow conflict.
    ///
    /// **[SYSTEM ERROR]** This indicates a failure in the memory protection
    /// subsystem (mlock, mprotect) or a concurrent access attempt.
    #[error("Key access failed: {0}")]
    KeyAccess(#[from] keys::KeyAccessError),
}

impl From<key_wrap::UnwrapError> for CryptoError {
    fn from(err: key_wrap::UnwrapError) -> Self {
        match err {
            key_wrap::UnwrapError::InvalidCiphertextLength => CryptoError::InvalidCiphertextLength,
            key_wrap::UnwrapError::CiphertextTooShort => CryptoError::InvalidCiphertextLength,
            key_wrap::UnwrapError::InvalidIntegrityCheck => CryptoError::KeyUnwrapIntegrityFailed,
        }
    }
}

// Re-export commonly used types
pub use keys::{KeyAccessError, MasterKey};