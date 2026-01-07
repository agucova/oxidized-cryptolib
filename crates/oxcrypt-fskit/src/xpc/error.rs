//! Error types for FSKit XPC operations.

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur when interacting with the FSKit extension.
#[derive(Debug, Error)]
pub enum FskitError {
    /// FSKit extension is not available (not installed, not running, or macOS version too old)
    #[error("FSKit extension not available")]
    ExtensionNotAvailable,

    /// Failed to establish XPC connection to the extension
    #[error("XPC connection failed: {0}")]
    ConnectionFailed(String),

    /// XPC connection was invalidated (extension crashed or restarted)
    #[error("XPC connection invalidated")]
    ConnectionInvalidated,

    /// The provided vault path is invalid or not a valid Cryptomator vault
    #[error("invalid vault path: {0}")]
    InvalidVault(PathBuf),

    /// Authentication failed (wrong password or vault corrupted)
    #[error("authentication failed")]
    AuthFailed,

    /// Mount operation failed
    #[error("mount failed: {0}")]
    MountFailed(String),

    /// Unmount operation failed
    #[error("unmount failed: {0}")]
    UnmountFailed(String),

    /// The requested mount was not found
    #[error("mount not found: {0}")]
    NotFound(PathBuf),

    /// Permission denied for the requested operation
    #[error("permission denied")]
    PermissionDenied,

    /// Rate limit exceeded (too many requests)
    #[error("rate limit exceeded, try again later")]
    RateLimitExceeded,

    /// XPC protocol error (message serialization/deserialization failed)
    #[error("XPC protocol error: {0}")]
    Protocol(String),

    /// Operation timed out
    #[error("operation timed out")]
    Timeout,

    /// Internal error from the extension
    #[error("internal error: {0}")]
    Internal(String),
}

impl FskitError {
    /// Create an error from an XPC NSError code.
    pub fn from_nserror_code(code: i64, domain: &str, message: &str) -> Self {
        // Map common error codes from OxVaultServiceError (Swift)
        match (domain, code) {
            ("com.agucova.oxcrypt.service", 1) => Self::InvalidVault(PathBuf::new()),
            ("com.agucova.oxcrypt.service", 2) => Self::AuthFailed,
            ("com.agucova.oxcrypt.service", 3) => Self::MountFailed(message.to_string()),
            ("com.agucova.oxcrypt.service", 4) => Self::NotFound(PathBuf::new()),
            ("com.agucova.oxcrypt.service", 5) => Self::PermissionDenied,
            ("com.agucova.oxcrypt.service", 6) => Self::RateLimitExceeded,
            ("com.agucova.oxcrypt.service", 7) => Self::Internal(message.to_string()),
            ("NSPOSIXErrorDomain", _) => Self::Internal(format!("POSIX error {code}: {message}")),
            _ => Self::Internal(format!("{domain} ({code}): {message}")),
        }
    }

    /// Returns true if this is a retryable error.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ConnectionFailed(_)
                | Self::ConnectionInvalidated
                | Self::RateLimitExceeded
                | Self::Timeout
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_nserror_code() {
        let err = FskitError::from_nserror_code(2, "com.agucova.oxcrypt.service", "Bad password");
        assert!(matches!(err, FskitError::AuthFailed));

        let err = FskitError::from_nserror_code(5, "com.agucova.oxcrypt.service", "Access denied");
        assert!(matches!(err, FskitError::PermissionDenied));
    }

    #[test]
    fn test_is_retryable() {
        assert!(FskitError::RateLimitExceeded.is_retryable());
        assert!(FskitError::ConnectionInvalidated.is_retryable());
        assert!(!FskitError::AuthFailed.is_retryable());
        assert!(!FskitError::InvalidVault(PathBuf::new()).is_retryable());
    }
}
