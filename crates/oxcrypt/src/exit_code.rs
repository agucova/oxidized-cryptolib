//! Exit codes for the CLI.
//!
//! These follow common Unix conventions and provide meaningful
//! status information for scripting and automation.

/// Successful execution
pub const SUCCESS: u8 = 0;

/// General/unspecified error
pub const GENERAL_ERROR: u8 = 1;

/// Command-line usage error (bad arguments)
pub const USAGE_ERROR: u8 = 2;

/// Authentication failed (bad password, invalid keyfile)
pub const AUTH_FAILED: u8 = 3;

/// Vault not found or invalid/corrupt
pub const VAULT_INVALID: u8 = 4;

/// Permission denied (filesystem or vault access)
pub const PERMISSION_DENIED: u8 = 5;

/// Mount or unmount operation failed
pub const MOUNT_FAILED: u8 = 6;

/// File or directory not found (within vault)
pub const NOT_FOUND: u8 = 7;

/// Operation cancelled or interrupted
pub const CANCELLED: u8 = 8;
