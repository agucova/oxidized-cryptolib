// OxVaultFilesystem.swift
// FSKit Unary File System implementation for Cryptomator vaults.

import FSKit
import Foundation
import os
// OxVaultFFI types are included directly in target sources via swift-bridge

/// Debug file logging for troubleshooting FSKit extension issues.
func debugLog(_ message: String) {
    let logPath = "/tmp/oxvault_fskit_debug.log"
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let entry = "[\(timestamp)] \(message)\n"

    if let data = entry.data(using: .utf8) {
        if FileManager.default.fileExists(atPath: logPath) {
            if let handle = FileHandle(forWritingAtPath: logPath) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        } else {
            FileManager.default.createFile(atPath: logPath, contents: data)
        }
    }
}

/// FSKit extension entry point - required by UnaryFileSystemExtension protocol.
@main
struct OxVaultFSExtension: UnaryFileSystemExtension {
    init() {
        debugLog("OxVaultFSExtension.init() called")
    }

    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        debugLog("OxVaultFSExtension.fileSystem property accessed")
        return OxVaultExtension()
    }
}

/// Main FSKit filesystem implementation.
final class OxVaultExtension: FSUnaryFileSystem, FSUnaryFileSystemOperations {
    static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "Extension")

    /// Vault path being managed.
    private var vaultPath: String?

    /// The Rust filesystem handle.
    private var cryptoFS: CryptoFilesystem?

    /// The volume instance.
    private var volume: OxVaultVolume?

    override init() {
        debugLog("OxVaultExtension.init() starting")
        super.init()
        debugLog("OxVaultExtension.init() completed, super.init() done")
        Self.logger.info("OxVaultFS extension initialized")

        // Note: XPC service is now hosted by the main app (OxVaultFSApp),
        // not the extension. This allows CLI/Desktop to connect even when
        // the extension isn't running (FSKit extensions are demand-loaded).
    }

    // MARK: - FSUnaryFileSystemOperations

    func probeResource(
        resource: FSResource,
        replyHandler reply: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        debugLog("probeResource() called with resource type: \(type(of: resource))")

        // Handle block resources (trigger disk images)
        if let blockResource = resource as? FSBlockDeviceResource {
            debugLog("probeResource() - handling block resource")
            probeBlockResource(blockResource, reply: reply)
            return
        }

        guard let url = extractURL(from: resource) else {
            debugLog("probeResource() - failed to extract URL")
            reply(nil, posixError(EINVAL))
            return
        }

        debugLog("probeResource() - extracted URL: \(url.path)")
        Self.logger.info("Probing resource: \(url.path)")

        // Check if this is a trigger volume with our marker file
        if TriggerMarker.exists(at: url) {
            debugLog("probeResource() - found trigger marker at \(url.path)")
            Self.logger.info("Found trigger marker at: \(url.path)")
            let containerID = FSContainerIdentifier(uuid: UUID())
            reply(FSProbeResult.usable(name: "OxCryptTrigger", containerID: containerID), nil)
            return
        }

        // Check if this looks like a Cryptomator vault
        let vaultConfigURL = url.appendingPathComponent("vault.cryptomator")
        let masterkeyURL = url.appendingPathComponent("masterkey.cryptomator")

        let fileManager = FileManager.default
        let hasVaultConfig = fileManager.fileExists(atPath: vaultConfigURL.path)
        let hasMasterkey = fileManager.fileExists(atPath: masterkeyURL.path)

        // Create a container identifier for the probe result
        let containerID = FSContainerIdentifier(uuid: UUID())

        if hasVaultConfig && hasMasterkey {
            let result = FSProbeResult.usable(name: url.lastPathComponent, containerID: containerID)
            reply(result, nil)
        } else if hasVaultConfig || hasMasterkey {
            // Partial match - maybe corrupted vault, but recognized
            let result = FSProbeResult.recognized(name: url.lastPathComponent, containerID: containerID)
            reply(result, nil)
        } else {
            // Not a vault
            reply(FSProbeResult.notRecognized, nil)
        }
    }

    /// Probe a block device resource.
    /// With the raw disk image approach (FSKitBridge style), we accept any
    /// block device since the vault path comes from mount options, not the device.
    private func probeBlockResource(
        _ resource: FSBlockDeviceResource,
        reply: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        debugLog("probeBlockResource() called - accepting raw trigger device")
        Self.logger.info("Block device probe - accepting as trigger (vault path from mount options)")

        // With raw disk images, the device contains no filesystem.
        // The vault path is passed via mount options (-o vaultPath=...).
        // Always report as usable so fskitd proceeds to loadResource.
        let containerID = FSContainerIdentifier(uuid: UUID())
        reply(FSProbeResult.usable(name: "OxCryptMount", containerID: containerID), nil)
    }

    /// Parse mount options from FSTaskOptions.
    /// Mount options are passed via `-o key=value,key2=value2`
    /// FSTaskOptions.taskOptions contains the raw command-line options array.
    private func parseMountOptions(_ options: FSTaskOptions) -> [String: String] {
        var result: [String: String] = [:]

        let taskOpts = options.taskOptions
        Self.logger.info("parseMountOptions() - taskOptions count: \(taskOpts.count)")
        for (i, opt) in taskOpts.enumerated() {
            Self.logger.info("parseMountOptions() - opt[\(i)]: \(opt)")
        }
        debugLog("parseMountOptions() - taskOptions: \(taskOpts)")

        // Look for -o or options that look like key=value
        var nextIsOptionValue = false
        for opt in taskOpts {
            if opt == "-o" || opt == "o" {
                nextIsOptionValue = true
                continue
            }

            if nextIsOptionValue || opt.contains("=") {
                // Parse comma-separated key=value pairs
                let pairs = opt.split(separator: ",")
                for pair in pairs {
                    if let equalsIndex = pair.firstIndex(of: "=") {
                        let key = String(pair[..<equalsIndex])
                        let value = String(pair[pair.index(after: equalsIndex)...])
                        result[key] = value
                        debugLog("parseMountOptions() - parsed \(key)=\(value)")
                    }
                }
                nextIsOptionValue = false
            }
        }

        return result
    }

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        debugLog("loadResource() called with resource type: \(type(of: resource))")
        Self.logger.info("loadResource() called with resource type: \(type(of: resource))")

        var actualVaultPath: String
        var volumeDisplayName: String

        // Determine the vault path - either from pending mount file or direct path
        if resource is FSBlockDeviceResource {
            debugLog("loadResource() - handling block resource (raw trigger)")
            Self.logger.info("Block resource - checking pending mount file")

            // Block resource with raw disk image: vault path comes from pending mount file
            guard let pending = PendingMountManager.consumePending() else {
                debugLog("loadResource() - ERROR: no pending mount found")
                Self.logger.error("Block resource but no pending mount found")
                reply(nil, posixError(EINVAL))
                return
            }

            actualVaultPath = pending.vaultPath
            volumeDisplayName = pending.volumeName
            debugLog("loadResource() - vaultPath from pending: \(actualVaultPath)")
            Self.logger.info("Block-triggered mount: vault=\(actualVaultPath), name=\(volumeDisplayName)")

        } else if let url = extractURL(from: resource) {
            debugLog("loadResource() - extracted URL: \(url.path)")

            // Direct vault path (e.g., from oxcrypt:// URL or FSPathURLResource)
            actualVaultPath = url.path
            volumeDisplayName = url.lastPathComponent
            debugLog("loadResource() - direct path: \(actualVaultPath)")
            Self.logger.info("Direct path mount: vault=\(actualVaultPath)")

        } else {
            debugLog("loadResource() - failed to extract URL or handle resource")
            reply(nil, posixError(EINVAL))
            return
        }

        Self.logger.info("Loading vault: \(actualVaultPath)")
        self.vaultPath = actualVaultPath

        // Try to get password from Keychain using the ACTUAL vault path
        let password: String
        do {
            password = try KeychainHelper.retrieve(for: actualVaultPath)
            Self.logger.info("Retrieved password from Keychain")
        } catch KeychainError.notFound {
            // Password not in Keychain - FSKit should prompt user
            // Return EAUTH to trigger authentication flow
            Self.logger.warning("Password not found in Keychain for: \(actualVaultPath)")
            reply(nil, posixError(EAUTH))
            return
        } catch {
            Self.logger.error("Keychain error: \(error)")
            reply(nil, posixError(EIO))
            return
        }

        // Create the Rust filesystem with the password
        let result = create(actualVaultPath, password)

        guard result.isOk() else {
            let errno = result.getError()

            // If password was wrong, remove from Keychain
            if errno == EACCES || errno == EINVAL {
                Self.logger.warning("Invalid password, removing from Keychain")
                try? KeychainHelper.delete(for: actualVaultPath)
            }

            Self.logger.error("Failed to create filesystem, errno: \(errno)")
            reply(nil, posixError(errno))
            return
        }

        self.cryptoFS = result.unwrap()

        let rootItemId = cryptoFS!.get_root_item_id()
        Self.logger.info("Vault loaded successfully, root item ID: \(rootItemId)")

        // Create the volume
        let volumeID = FSVolume.Identifier(uuid: UUID())
        let volumeName = FSFileName(string: volumeDisplayName)
        let vol = OxVaultVolume(
            volumeID: volumeID,
            volumeName: volumeName,
            cryptoFS: cryptoFS!
        )
        self.volume = vol

        reply(vol, nil)
    }

    /// Extract URL from an FSResource.
    /// For generic URL resources with oxcrypt:// scheme, convert to file:// URL
    private func extractURL(from resource: FSResource) -> URL? {
        if let genericResource = resource as? FSGenericURLResource {
            let url = genericResource.url
            Self.logger.info("Generic URL resource: \(url)")

            // Convert oxcrypt:// to file:// URL
            // oxcrypt:///path/to/vault?mount=/mountpoint -> file:///path/to/vault
            if url.scheme == "oxcrypt" {
                var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
                components?.scheme = "file"
                components?.query = nil  // Remove query parameters (mount info)
                if let fileURL = components?.url {
                    Self.logger.info("Converted oxcrypt URL to file URL: \(fileURL)")
                    return fileURL
                }
            }
            return url
        } else if let pathResource = resource as? FSPathURLResource {
            return pathResource.url
        }
        return nil
    }

    func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        Self.logger.info("Unloading resource")

        cryptoFS?.shutdown()
        cryptoFS = nil
        volume = nil
        vaultPath = nil

        reply(nil)
    }

    func didFinishLoading() {
        debugLog("didFinishLoading() called")
        Self.logger.info("Extension finished loading")
    }
}

// MARK: - Error Helpers

/// Creates an NSError from a POSIX errno value.
func posixError(_ errno: Int32) -> NSError {
    return NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
}
