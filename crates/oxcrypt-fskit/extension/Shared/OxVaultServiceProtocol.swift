// OxVaultServiceProtocol.swift
// XPC protocol for CLI/Desktop communication with the FSKit extension.

import Foundation

/// XPC protocol for external clients (CLI, Desktop app) to control the FSKit extension.
///
/// Security: All connections are validated using audit tokens to ensure only
/// binaries signed by our team ID can communicate with the extension.
@objc protocol OxVaultServiceProtocol {
    /// Mount a vault at the specified path.
    ///
    /// - Parameters:
    ///   - vaultPath: Absolute path to the vault directory (must contain vault.cryptomator)
    ///   - password: The vault password (zeroized after use)
    ///   - reply: Callback with mountpoint on success, or error
    func mount(
        vaultPath: String,
        password: String,
        reply: @escaping (String?, NSError?) -> Void
    )

    /// Unmount a vault by its mountpoint.
    ///
    /// - Parameters:
    ///   - mountpoint: The mountpoint path to unmount
    ///   - reply: Callback with nil on success, or error
    func unmount(
        mountpoint: String,
        reply: @escaping (NSError?) -> Void
    )

    /// List all active mounts owned by the caller or same team.
    ///
    /// - Parameter reply: Callback with array of mount info dictionaries, or error
    ///   Each dictionary contains: vaultPath, mountpoint, mountedAt (ISO8601), backend
    func listMounts(
        reply: @escaping ([[String: Any]]?, NSError?) -> Void
    )

    /// Get statistics for a specific mount.
    ///
    /// - Parameters:
    ///   - mountpoint: The mountpoint to get stats for
    ///   - reply: Callback with stats dictionary, or error
    ///   Stats include: bytesRead, bytesWritten, filesOpened, opsCount
    func getStats(
        mountpoint: String,
        reply: @escaping ([String: Any]?, NSError?) -> Void
    )

    /// Ping to check if extension is alive and ready.
    ///
    /// - Parameter reply: Callback with true if ready
    func ping(reply: @escaping (Bool) -> Void)
}

/// Error codes for XPC operations.
/// These map to categorized error responses (no internal details exposed).
enum OxVaultServiceError: Int, Error {
    case invalidVault = 1
    case authFailed = 2
    case mountFailed = 3
    case notFound = 4
    case permissionDenied = 5
    case alreadyMounted = 6
    case resourceExhausted = 7
    case internalError = 99

    var nsError: NSError {
        let domain = "com.agucova.oxcrypt.xpc"
        let message: String
        switch self {
        case .invalidVault:
            message = "Invalid vault path"
        case .authFailed:
            message = "Authentication failed"
        case .mountFailed:
            message = "Mount operation failed"
        case .notFound:
            message = "Mount not found"
        case .permissionDenied:
            message = "Permission denied"
        case .alreadyMounted:
            message = "Vault already mounted"
        case .resourceExhausted:
            message = "Too many mounts"
        case .internalError:
            message = "Internal error"
        }
        return NSError(domain: domain, code: rawValue, userInfo: [
            NSLocalizedDescriptionKey: message
        ])
    }
}
