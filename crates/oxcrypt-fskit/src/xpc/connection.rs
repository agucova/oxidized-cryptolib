//! Low-level XPC connection management.
//!
//! This module provides the low-level connection to the FSKit extension's XPC service.
//! It handles connection lifecycle, reconnection, and Objective-C interop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{class, msg_send};
use objc2_foundation::{NSError, NSString};

use super::error::FskitError;

// Link to the ObjC protocol getter and XPC wrapper functions.
// These force the linker to include the OxVaultServiceProtocol symbols
// and provide properly-typed blocks for XPC calls.
unsafe extern "C" {
    pub(crate) fn OxVaultServiceProtocol_get() -> *const std::ffi::c_void;

    // XPC wrapper functions that create properly-encoded blocks for XPC serialization
    pub(crate) fn OxVaultXPC_mount(
        proxy: *const std::ffi::c_void,
        vault_path: *const std::ffi::c_char,
        password: *const std::ffi::c_char,
        callback: MountCallback,
        context: *mut std::ffi::c_void,
    );
    pub(crate) fn OxVaultXPC_unmount(
        proxy: *const std::ffi::c_void,
        mountpoint: *const std::ffi::c_char,
        callback: UnmountCallback,
        context: *mut std::ffi::c_void,
    );
    pub(crate) fn OxVaultXPC_ping(
        proxy: *const std::ffi::c_void,
        callback: PingCallback,
        context: *mut std::ffi::c_void,
    );
}

/// Callback for mount results.
pub(crate) type MountCallback = unsafe extern "C" fn(
    mountpoint: *const std::ffi::c_char,
    error_code: i64,
    error_msg: *const std::ffi::c_char,
    context: *mut std::ffi::c_void,
);

/// Callback for unmount results.
pub(crate) type UnmountCallback = unsafe extern "C" fn(
    error_code: i64,
    error_msg: *const std::ffi::c_char,
    context: *mut std::ffi::c_void,
);

/// Callback for ping results.
pub(crate) type PingCallback = unsafe extern "C" fn(alive: bool, context: *mut std::ffi::c_void);

/// The XPC service name for the Host App.
/// Note: XPC service is now hosted by the main app (not the extension)
/// because FSKit extensions are demand-loaded and not always running.
const SERVICE_NAME: &str = "com.agucova.oxcrypt.desktop.xpc";

/// Maximum number of connection retry attempts.
const MAX_RETRIES: u32 = 3;

/// Initial retry delay (doubles with each attempt).
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Low-level XPC connection to the FSKit extension.
pub struct XpcConnection {
    /// The underlying NSXPCConnection.
    inner: Retained<AnyObject>,
    /// Whether the connection is currently valid.
    valid: Arc<AtomicBool>,
}

impl XpcConnection {
    /// Create a new XPC connection to the FSKit extension.
    ///
    /// This attempts to connect to the extension's XPC service. If the extension
    /// is not available, returns `FskitError::ExtensionNotAvailable`.
    pub fn new() -> Result<Self, FskitError> {
        Self::new_with_retries(MAX_RETRIES)
    }

    /// Create a connection with a specific number of retries.
    fn new_with_retries(max_retries: u32) -> Result<Self, FskitError> {
        let mut last_error = None;
        let mut delay = INITIAL_RETRY_DELAY;

        for attempt in 0..=max_retries {
            match Self::try_connect() {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < max_retries {
                        std::thread::sleep(delay);
                        delay *= 2;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(FskitError::ExtensionNotAvailable))
    }

    /// Attempt a single connection.
    fn try_connect() -> Result<Self, FskitError> {
        let valid = Arc::new(AtomicBool::new(true));

        // Create NSXPCConnection with Mach service name
        let connection = unsafe {
            let service_name = NSString::from_str(SERVICE_NAME);
            let nsxpc_class = class!(NSXPCConnection);

            // Use default options (0) for regular user-level XPC service
            // Note: NSXPCConnectionOptions.Privileged (1 << 12) is only for
            // privileged helper tools registered in /Library/LaunchDaemons
            let options: u64 = 0;

            // initWithMachServiceName:options:
            let conn: Option<Retained<AnyObject>> = msg_send![
                msg_send![nsxpc_class, alloc],
                initWithMachServiceName: &*service_name,
                options: options
            ];

            conn.ok_or_else(|| {
                FskitError::ConnectionFailed("Failed to create NSXPCConnection".to_string())
            })?
        };

        // Set up invalidation handler
        let valid_clone = valid.clone();
        let invalidation_handler = RcBlock::new(move || {
            valid_clone.store(false, Ordering::SeqCst);
            tracing::warn!("XPC connection invalidated");
        });

        unsafe {
            let _: () = msg_send![&*connection, setInvalidationHandler: &*invalidation_handler];
        }

        // Set up interruption handler
        let valid_clone = valid.clone();
        let interruption_handler = RcBlock::new(move || {
            valid_clone.store(false, Ordering::SeqCst);
            tracing::warn!("XPC connection interrupted");
        });

        unsafe {
            let _: () = msg_send![&*connection, setInterruptionHandler: &*interruption_handler];
        }

        // Set up the remote object interface (OxVaultServiceProtocol)
        // Note: We use our own C function to get the protocol, which forces the linker
        // to include the ObjC protocol symbols in the final binary.
        unsafe {
            // Get the protocol using our C function (forces linker to include symbols)
            let protocol = OxVaultServiceProtocol_get();

            if !protocol.is_null() {
                let interface_class = class!(NSXPCInterface);
                let interface: Option<Retained<AnyObject>> =
                    msg_send![interface_class, interfaceWithProtocol: protocol];

                if let Some(iface) = interface {
                    let _: () = msg_send![&*connection, setRemoteObjectInterface: &*iface];
                } else {
                    tracing::warn!("Failed to create NSXPCInterface from protocol");
                }
            } else {
                tracing::warn!("OxVaultServiceProtocol_get returned null");
            }
        }

        // Resume the connection
        unsafe {
            let _: () = msg_send![&*connection, resume];
        }

        // Wait a short time to allow connection invalidation to propagate
        // This helps detect if the XPC service isn't running
        std::thread::sleep(Duration::from_millis(50));

        // Check if connection was immediately invalidated (service not running)
        if !valid.load(Ordering::SeqCst) {
            return Err(FskitError::ExtensionNotAvailable);
        }

        Ok(Self {
            inner: connection,
            valid,
        })
    }

    /// Check if the connection is still valid.
    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::SeqCst)
    }

    /// Get a proxy with error handler for async calls.
    ///
    /// This returns a proxy that will call the error handler if the XPC call fails.
    pub fn get_proxy_with_error_handler<F>(
        &self,
        error_handler: F,
    ) -> Result<Retained<AnyObject>, FskitError>
    where
        F: Fn(&NSError) + Send + 'static,
    {
        if !self.is_valid() {
            return Err(FskitError::ConnectionInvalidated);
        }

        let error_block = RcBlock::new(move |error: &NSError| {
            error_handler(error);
        });

        unsafe {
            let proxy: Option<Retained<AnyObject>> = msg_send![
                &*self.inner,
                remoteObjectProxyWithErrorHandler: &*error_block
            ];
            proxy.ok_or(FskitError::ConnectionFailed(
                "Failed to get remote object proxy with error handler".to_string(),
            ))
        }
    }

    /// Invalidate and close the connection.
    pub fn invalidate(&self) {
        unsafe {
            let _: () = msg_send![&*self.inner, invalidate];
        }
        self.valid.store(false, Ordering::SeqCst);
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        self.invalidate();
    }
}

/// Check if the FSKit extension is available.
///
/// This performs a quick check:
/// 1. Checks macOS version (requires 15.4+)
/// 2. Checks if extension is registered via pluginkit
///
/// Note: This does NOT verify the XPC service is running. The extension
/// must be activated by FSKit (e.g., by loading a vault resource) before
/// CLI can connect. Use `XpcConnection::new()` to verify connectivity.
pub fn is_extension_available() -> bool {
    // Check macOS version
    if !check_macos_version() {
        return false;
    }

    // Check if extension is registered
    check_extension_registered()
}

/// Check if we're running on macOS 15.4+.
fn check_macos_version() -> bool {
    use std::process::Command;

    // Use sw_vers to get macOS version
    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok();

    let Some(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = version_str.trim().split('.').collect();

    if parts.len() < 2 {
        return false;
    }

    let major: i64 = parts[0].parse().unwrap_or(0);
    let minor: i64 = parts[1].parse().unwrap_or(0);

    // Require macOS 15.4+
    major > 15 || (major == 15 && minor >= 4)
}

/// Check if the FSKit extension is registered with pluginkit.
fn check_extension_registered() -> bool {
    use std::process::Command;

    // Use pluginkit to check if extension is registered
    let output = Command::new("pluginkit")
        .args(["-m", "-i", "com.agucova.oxcrypt.desktop.fsextension"])
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name() {
        assert_eq!(SERVICE_NAME, "com.agucova.oxcrypt.desktop.xpc");
    }

    #[test]
    fn test_retry_delay_calculation() {
        let initial = Duration::from_millis(100);
        assert_eq!(initial * 2, Duration::from_millis(200));
        assert_eq!(initial * 4, Duration::from_millis(400));
    }
}
