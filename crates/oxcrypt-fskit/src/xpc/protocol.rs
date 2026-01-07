//! XPC protocol types for FSKit extension communication.
//!
//! These types mirror the Swift `OxVaultServiceProtocol` interface and are used
//! for message serialization over XPC.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// XPC messages sent to the FSKit extension.
#[derive(Debug, Clone)]
pub enum XpcMessage {
    /// Mount a vault with the given path and password.
    Mount {
        /// Absolute path to the vault directory.
        vault_path: PathBuf,
        /// Vault password (will be zeroized after use).
        password: String,
    },

    /// Unmount a mounted vault by its mountpoint.
    Unmount {
        /// Mountpoint to unmount.
        mountpoint: PathBuf,
    },

    /// List all active mounts.
    ListMounts,

    /// Get statistics for a specific mount.
    GetStats {
        /// Mountpoint to get stats for.
        mountpoint: PathBuf,
    },

    /// Ping to check if extension is alive.
    Ping,
}

/// XPC responses from the FSKit extension.
#[derive(Debug, Clone)]
pub enum XpcResponse {
    /// Mount succeeded, returns the mountpoint.
    MountSuccess {
        /// The path where the vault is mounted.
        mountpoint: PathBuf,
    },

    /// Unmount succeeded.
    UnmountSuccess,

    /// List of active mounts.
    MountList {
        /// All currently active mount entries.
        mounts: Vec<MountEntry>,
    },

    /// Statistics for a mount.
    Stats {
        /// Key-value pairs of statistics data.
        stats: HashMap<String, XpcValue>,
    },

    /// Ping response.
    Pong {
        /// Whether the extension is alive and responding.
        alive: bool,
    },

    /// Operation failed with an error.
    Error {
        /// Error code from NSError.
        code: i64,
        /// Error domain from NSError.
        domain: String,
        /// Localized error message.
        message: String,
    },
}

/// A mount entry returned from ListMounts.
#[derive(Debug, Clone)]
pub struct MountEntry {
    /// Path to the vault directory.
    pub vault_path: PathBuf,
    /// Mountpoint where the vault is mounted.
    pub mountpoint: PathBuf,
    /// When the vault was mounted.
    pub mounted_at: SystemTime,
}

/// Dynamic XPC value types (for stats dictionaries).
#[derive(Debug, Clone)]
pub enum XpcValue {
    /// String value.
    String(String),
    /// Integer value.
    Int(i64),
    /// Unsigned integer value.
    UInt(u64),
    /// Boolean value.
    Bool(bool),
    /// Floating point value.
    Double(f64),
}

impl XpcValue {
    /// Try to get as a string.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get as an integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::UInt(u) if i64::try_from(*u).is_ok() => {
                // Safe cast: We've already validated that u fits in i64 via try_from check
                #[allow(clippy::cast_possible_wrap)]
                Some(*u as i64)
            }
            _ => None,
        }
    }

    /// Try to get as an unsigned integer.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::UInt(u) => Some(*u),
            Self::Int(i) if *i >= 0 => {
                // Safe cast: We've already validated that i is non-negative
                #[allow(clippy::cast_sign_loss)]
                Some(*i as u64)
            }
            _ => None,
        }
    }
}

impl From<String> for XpcValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i64> for XpcValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<u64> for XpcValue {
    fn from(u: u64) -> Self {
        Self::UInt(u)
    }
}

impl From<bool> for XpcValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<f64> for XpcValue {
    fn from(d: f64) -> Self {
        Self::Double(d)
    }
}
