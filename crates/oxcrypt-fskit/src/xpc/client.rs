//! High-level FSKit XPC client.
//!
//! This module provides a user-friendly API for interacting with the FSKit extension.
//! It handles connection management, message serialization, and provides type-safe
//! methods for all XPC operations.

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::msg_send;
use objc2_foundation::{NSArray, NSDictionary, NSError, NSNumber, NSString};
use secrecy::{ExposeSecret, SecretString};

use super::connection::{
    is_extension_available, OxVaultXPC_mount, OxVaultXPC_ping, OxVaultXPC_unmount, XpcConnection,
};
use super::error::FskitError;

/// High-level client for the FSKit XPC service.
///
/// This client provides a simple, type-safe interface for mounting and managing
/// Cryptomator vaults via the FSKit extension.
///
/// # Thread Safety
///
/// The client is thread-safe and can be shared across threads. The underlying
/// XPC connection is managed internally with proper synchronization.
///
/// # Example
///
/// ```no_run
/// use oxcrypt_fskit::xpc::FskitClient;
/// use secrecy::SecretString;
///
/// let client = FskitClient::connect()?;
/// let password = SecretString::from("my-password");
/// let mount = client.mount(std::path::Path::new("/path/to/vault"), password)?;
/// println!("Mounted at: {}", mount.mountpoint.display());
/// # Ok::<(), oxcrypt_fskit::xpc::FskitError>(())
/// ```
pub struct FskitClient {
    /// The XPC connection (lazily created).
    connection: Arc<Mutex<Option<XpcConnection>>>,
}

/// Information about an active mount.
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Path to the vault directory.
    pub vault_path: PathBuf,
    /// Mountpoint where the vault is accessible.
    pub mountpoint: PathBuf,
    /// When the mount was created.
    pub mounted_at: SystemTime,
    /// The backend identifier.
    pub backend: &'static str,
}

/// Statistics for a mounted vault.
#[derive(Debug, Clone, Default)]
pub struct VaultStats {
    /// Path to the vault directory.
    pub vault_path: PathBuf,
    /// Mountpoint.
    pub mountpoint: PathBuf,
    /// When the vault was mounted.
    pub mounted_at: Option<SystemTime>,
    /// Bytes read from the vault.
    pub bytes_read: u64,
    /// Bytes written to the vault.
    pub bytes_written: u64,
    /// Number of files opened.
    pub files_opened: u64,
    /// Total number of operations.
    pub ops_count: u64,
}

impl FskitClient {
    /// Check if the FSKit extension is available.
    ///
    /// This performs a quick check without establishing a connection:
    /// - Verifies macOS version (15.4+ required)
    /// - Checks if extension is registered with the system
    ///
    /// Use this before attempting to connect to provide a better user experience.
    pub fn is_available() -> bool {
        is_extension_available()
    }

    /// Connect to the FSKit extension.
    ///
    /// This establishes a connection to the extension's XPC service. The connection
    /// is lazily created on first use and will automatically reconnect if invalidated.
    ///
    /// # Errors
    ///
    /// Returns `FskitError::ExtensionNotAvailable` if the extension is not installed
    /// or the macOS version is too old.
    pub fn connect() -> Result<Self, FskitError> {
        if !Self::is_available() {
            return Err(FskitError::ExtensionNotAvailable);
        }

        // XpcConnection isn't Send/Sync (Objective-C object), but the FskitClient
        // is wrapped in ThreadSafeClient when used from backends. Arc is used for
        // lazy initialization, not cross-thread sharing.
        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            connection: Arc::new(Mutex::new(None)),
        })
    }

    /// Ensure we have a valid connection, creating one if needed.
    fn ensure_connection(&self) -> Result<(), FskitError> {
        let mut conn_guard = self.connection.lock();

        // Check if we need a new connection
        let needs_new = match &*conn_guard {
            Some(conn) => !conn.is_valid(),
            None => true,
        };

        if needs_new {
            *conn_guard = Some(XpcConnection::new()?);
        }

        Ok(())
    }

    /// Get a reference to the XPC connection.
    fn with_connection<F, T>(&self, f: F) -> Result<T, FskitError>
    where
        F: FnOnce(&mut XpcConnection) -> Result<T, FskitError>,
    {
        self.ensure_connection()?;

        let mut conn_guard = self.connection.lock();

        let conn = conn_guard
            .as_mut()
            .ok_or(FskitError::ConnectionInvalidated)?;

        f(conn)
    }

    /// Mount a vault.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Absolute path to the vault directory
    /// * `password` - Vault password (will be zeroized after use)
    ///
    /// # Returns
    ///
    /// Returns `MountInfo` with the mountpoint and other details on success.
    ///
    /// # Errors
    ///
    /// - `FskitError::InvalidVault` - Path is not a valid Cryptomator vault
    /// - `FskitError::AuthFailed` - Wrong password
    /// - `FskitError::MountFailed` - Mount operation failed
    pub fn mount(&self, vault_path: &Path, password: &SecretString) -> Result<MountInfo, FskitError> {
        let vault_path_str = vault_path
            .to_str()
            .ok_or_else(|| FskitError::InvalidVault(vault_path.to_path_buf()))?;

        // Use a channel to receive the async result
        let (tx, rx) = std::sync::mpsc::channel::<Result<PathBuf, FskitError>>();

        self.with_connection(|conn| {
            // Get the proxy - we use a simple error handler here since the ObjC wrapper
            // will handle errors via the callback
            let proxy = conn.get_proxy_with_error_handler(|_err| {
                // XPC connection errors will be caught by the callback or timeout
            })?;

            // Convert strings to C strings for the ObjC wrapper
            let vault_c = CString::new(vault_path_str)
                .map_err(|_| FskitError::InvalidVault(vault_path.to_path_buf()))?;
            let password_c = CString::new(password.expose_secret())
                .map_err(|_| FskitError::AuthFailed)?;

            // Create context with the sender - box it so it lives until the callback
            let context = Box::into_raw(Box::new(tx.clone()));

            // Call the ObjC wrapper which creates properly-typed blocks
            unsafe {
                OxVaultXPC_mount(
                    &raw const *proxy as *const c_void,
                    vault_c.as_ptr(),
                    password_c.as_ptr(),
                    mount_callback,
                    context as *mut c_void,
                );
            }

            Ok(())
        })?;

        // Wait for reply with timeout
        let mountpoint = rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| FskitError::Timeout)??;

        Ok(MountInfo {
            vault_path: vault_path.to_path_buf(),
            mountpoint,
            mounted_at: SystemTime::now(),
            backend: "fskit",
        })
    }

    /// Unmount a mounted vault.
    ///
    /// # Arguments
    ///
    /// * `mountpoint` - The mountpoint to unmount
    ///
    /// # Errors
    ///
    /// - `FskitError::NotFound` - Mount not found
    /// - `FskitError::PermissionDenied` - Not authorized to unmount this mount
    pub fn unmount(&self, mountpoint: &Path) -> Result<(), FskitError> {
        let mountpoint_str = mountpoint
            .to_str()
            .ok_or_else(|| FskitError::NotFound(mountpoint.to_path_buf()))?;

        let (tx, rx) = std::sync::mpsc::channel::<Result<(), FskitError>>();

        self.with_connection(|conn| {
            let proxy = conn.get_proxy_with_error_handler(|_err| {})?;

            let mountpoint_c = CString::new(mountpoint_str)
                .map_err(|_| FskitError::NotFound(mountpoint.to_path_buf()))?;

            let context = Box::into_raw(Box::new(tx.clone()));

            unsafe {
                OxVaultXPC_unmount(
                    &raw const *proxy as *const c_void,
                    mountpoint_c.as_ptr(),
                    unmount_callback,
                    context as *mut c_void,
                );
            }

            Ok(())
        })?;

        rx.recv_timeout(Duration::from_secs(30))
            .map_err(|_| FskitError::Timeout)?
    }

    /// List all active mounts.
    ///
    /// Returns mounts owned by the current process or any process signed by the same team.
    pub fn list_mounts(&self) -> Result<Vec<MountInfo>, FskitError> {
        let (tx, rx) = std::sync::mpsc::channel();

        self.with_connection(|conn| {
            // Use error handler proxy to catch XPC failures without ObjC exceptions
            let tx_error = tx.clone();
            let proxy = conn.get_proxy_with_error_handler(move |err| {
                let code: i64 = unsafe { msg_send![err, code] };
                let domain: Retained<NSString> = unsafe { msg_send![err, domain] };
                let message: Retained<NSString> = unsafe { msg_send![err, localizedDescription] };
                let _ = tx_error.send(Err(FskitError::from_nserror_code(
                    code,
                    &domain.to_string(),
                    &message.to_string(),
                )));
            })?;

            let tx_clone = tx.clone();
            let reply_block = RcBlock::new(
                move |mounts: *const NSArray<NSDictionary<NSString, AnyObject>>,
                      error: *const NSError| {
                    let result = if !error.is_null() {
                        unsafe {
                            let err = &*error;
                            let code: i64 = msg_send![err, code];
                            let domain: Retained<NSString> = msg_send![err, domain];
                            let message: Retained<NSString> =
                                msg_send![err, localizedDescription];
                            Err(FskitError::from_nserror_code(
                                code,
                                &domain.to_string(),
                                &message.to_string(),
                            ))
                        }
                    } else if !mounts.is_null() {
                        Ok(parse_mount_list(unsafe { &*mounts }))
                    } else {
                        Ok(vec![])
                    };
                    let _ = tx_clone.send(result);
                },
            );

            unsafe {
                let _: () = msg_send![&*proxy, listMountsWithReply: &*reply_block];
            }

            Ok(())
        })?;

        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| FskitError::Timeout)?
    }

    /// Get statistics for a specific mount.
    ///
    /// # Arguments
    ///
    /// * `mountpoint` - The mountpoint to get stats for
    pub fn get_stats(&self, mountpoint: &Path) -> Result<VaultStats, FskitError> {
        let mountpoint_str = mountpoint
            .to_str()
            .ok_or_else(|| FskitError::NotFound(mountpoint.to_path_buf()))?;

        let (tx, rx) = std::sync::mpsc::channel();

        self.with_connection(|conn| {
            // Use error handler proxy to catch XPC failures without ObjC exceptions
            let tx_error = tx.clone();
            let proxy = conn.get_proxy_with_error_handler(move |err| {
                let code: i64 = unsafe { msg_send![err, code] };
                let domain: Retained<NSString> = unsafe { msg_send![err, domain] };
                let message: Retained<NSString> = unsafe { msg_send![err, localizedDescription] };
                let _ = tx_error.send(Err(FskitError::from_nserror_code(
                    code,
                    &domain.to_string(),
                    &message.to_string(),
                )));
            })?;
            let mountpoint_ns = NSString::from_str(mountpoint_str);

            let tx_clone = tx.clone();
            let reply_block = RcBlock::new(
                move |stats: *const NSDictionary<NSString, AnyObject>, error: *const NSError| {
                    let result = if !error.is_null() {
                        unsafe {
                            let err = &*error;
                            let code: i64 = msg_send![err, code];
                            let domain: Retained<NSString> = msg_send![err, domain];
                            let message: Retained<NSString> =
                                msg_send![err, localizedDescription];
                            Err(FskitError::from_nserror_code(
                                code,
                                &domain.to_string(),
                                &message.to_string(),
                            ))
                        }
                    } else if !stats.is_null() {
                        Ok(parse_stats(unsafe { &*stats }))
                    } else {
                        Ok(VaultStats::default())
                    };
                    let _ = tx_clone.send(result);
                },
            );

            unsafe {
                let _: () = msg_send![
                    &*proxy,
                    getStatsWithMountpoint: &*mountpoint_ns,
                    reply: &*reply_block
                ];
            }

            Ok(())
        })?;

        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| FskitError::Timeout)?
    }

    /// Ping the extension to check if it's alive.
    ///
    /// This is a lightweight check that doesn't require any vault operations.
    pub fn ping(&self) -> Result<bool, FskitError> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<bool, FskitError>>();

        self.with_connection(|conn| {
            let proxy = conn.get_proxy_with_error_handler(|_err| {})?;

            let context = Box::into_raw(Box::new(tx.clone()));

            unsafe {
                OxVaultXPC_ping(
                    &raw const *proxy as *const c_void,
                    ping_callback,
                    context as *mut c_void,
                );
            }

            Ok(())
        })?;

        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| FskitError::Timeout)?
    }
}

// C callbacks for XPC wrapper functions

/// Callback for mount results.
unsafe extern "C" fn mount_callback(
    mountpoint: *const c_char,
    error_code: i64,
    error_msg: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: context was created by Box::into_raw in mount()
    let tx = unsafe {
        Box::from_raw(context as *mut std::sync::mpsc::Sender<Result<PathBuf, FskitError>>)
    };

    let result = if error_code != 0 {
        let msg = if !error_msg.is_null() {
            // SAFETY: error_msg is a valid C string from ObjC
            unsafe { CStr::from_ptr(error_msg).to_string_lossy().to_string() }
        } else {
            format!("Error code {error_code}")
        };
        Err(FskitError::MountFailed(msg))
    } else if !mountpoint.is_null() {
        // SAFETY: mountpoint is a valid C string from ObjC
        let mp = unsafe { CStr::from_ptr(mountpoint).to_string_lossy().to_string() };
        Ok(PathBuf::from(mp))
    } else {
        Err(FskitError::MountFailed("No mountpoint returned".to_string()))
    };

    let _ = tx.send(result);
}

/// Callback for unmount results.
unsafe extern "C" fn unmount_callback(
    error_code: i64,
    error_msg: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: context was created by Box::into_raw in unmount()
    let tx =
        unsafe { Box::from_raw(context as *mut std::sync::mpsc::Sender<Result<(), FskitError>>) };

    let result = if error_code != 0 {
        let msg = if !error_msg.is_null() {
            // SAFETY: error_msg is a valid C string from ObjC
            unsafe { CStr::from_ptr(error_msg).to_string_lossy().to_string() }
        } else {
            format!("Error code {error_code}")
        };
        Err(FskitError::UnmountFailed(msg))
    } else {
        Ok(())
    };

    let _ = tx.send(result);
}

/// Callback for ping results.
unsafe extern "C" fn ping_callback(alive: bool, context: *mut c_void) {
    // SAFETY: context was created by Box::into_raw in ping()
    let tx =
        unsafe { Box::from_raw(context as *mut std::sync::mpsc::Sender<Result<bool, FskitError>>) };
    let _ = tx.send(Ok(alive));
}

/// Parse a mount list from NSArray of NSDictionary.
fn parse_mount_list(
    array: &NSArray<NSDictionary<NSString, AnyObject>>,
) -> Vec<MountInfo> {
    let mut mounts = Vec::new();

    for dict in array {
        if let Some(info) = parse_mount_dict(&dict) {
            mounts.push(info);
        }
    }

    mounts
}

/// Parse a single mount dictionary.
fn parse_mount_dict(dict: &NSDictionary<NSString, AnyObject>) -> Option<MountInfo> {
    let vault_path = get_string_value(dict, "vaultPath")?;
    let mountpoint = get_string_value(dict, "mountpoint")?;
    let _mounted_at = get_string_value(dict, "mountedAt"); // ISO8601 string

    Some(MountInfo {
        vault_path: PathBuf::from(vault_path),
        mountpoint: PathBuf::from(mountpoint),
        mounted_at: SystemTime::now(), // TODO: Parse ISO8601
        backend: "fskit",
    })
}

/// Parse stats dictionary.
fn parse_stats(dict: &NSDictionary<NSString, AnyObject>) -> VaultStats {
    VaultStats {
        vault_path: get_string_value(dict, "vaultPath")
            .map(PathBuf::from)
            .unwrap_or_default(),
        mountpoint: get_string_value(dict, "mountpoint")
            .map(PathBuf::from)
            .unwrap_or_default(),
        mounted_at: None, // TODO: Parse ISO8601
        bytes_read: get_uint_value(dict, "bytesRead").unwrap_or(0),
        bytes_written: get_uint_value(dict, "bytesWritten").unwrap_or(0),
        files_opened: get_uint_value(dict, "filesOpened").unwrap_or(0),
        ops_count: get_uint_value(dict, "opsCount").unwrap_or(0),
    }
}

/// Get a string value from a dictionary.
fn get_string_value(dict: &NSDictionary<NSString, AnyObject>, key: &str) -> Option<String> {
    unsafe {
        let key_ns = NSString::from_str(key);
        let value: Option<Retained<AnyObject>> = msg_send![dict, objectForKey: &*key_ns];
        value.and_then(|v| {
            // Check if it's an NSString
            if msg_send![&*v, isKindOfClass: objc2::class!(NSString)] {
                let s: Retained<NSString> = std::mem::transmute(v);
                Some(s.to_string())
            } else {
                None
            }
        })
    }
}

/// Get an unsigned integer value from a dictionary.
fn get_uint_value(dict: &NSDictionary<NSString, AnyObject>, key: &str) -> Option<u64> {
    unsafe {
        let key_ns = NSString::from_str(key);
        let value: Option<Retained<AnyObject>> = msg_send![dict, objectForKey: &*key_ns];
        value.and_then(|v| {
            // Check if it's an NSNumber
            if msg_send![&*v, isKindOfClass: objc2::class!(NSNumber)] {
                let n: Retained<NSNumber> = std::mem::transmute(v);
                Some(n.as_u64())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_info_backend() {
        let info = MountInfo {
            vault_path: PathBuf::from("/path/to/vault"),
            mountpoint: PathBuf::from("/Volumes/vault"),
            mounted_at: SystemTime::now(),
            backend: "fskit",
        };
        assert_eq!(info.backend, "fskit");
    }

    #[test]
    fn test_vault_stats_default() {
        let stats = VaultStats::default();
        assert_eq!(stats.bytes_read, 0);
        assert_eq!(stats.bytes_written, 0);
    }
}
