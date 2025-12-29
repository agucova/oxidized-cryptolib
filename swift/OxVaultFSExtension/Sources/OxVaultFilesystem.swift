// OxVaultFilesystem.swift
// FSKit Unary File System implementation for Cryptomator vaults.

import FSKit
import Foundation
import os
import OxVaultFFI

/// Main FSKit filesystem extension entry point.
final class OxVaultExtension: FSUnaryFileSystem, FSUnaryFileSystemOperations {
    /// Entry point for the file system extension.
    static func main() {
        // FSKit extension lifecycle is managed by the system
        RunLoop.main.run()
    }
    static let logger = Logger(subsystem: "com.agucova.oxidized", category: "Extension")

    /// Vault path being managed.
    private var vaultPath: String?

    /// The Rust filesystem handle.
    private var cryptoFS: CryptoFilesystem?

    /// The volume instance.
    private var volume: OxVaultVolume?

    override init() {
        super.init()
        Self.logger.info("OxVaultFS extension initialized")
    }

    // MARK: - FSUnaryFileSystemOperations

    func probeResource(
        resource: FSResource,
        replyHandler reply: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        // Extract URL from resource (FSPathURLResource or FSGenericURLResource)
        let url: URL?
        if let pathResource = resource as? FSPathURLResource {
            url = pathResource.url
        } else if let genericResource = resource as? FSGenericURLResource {
            url = genericResource.url
        } else {
            url = nil
        }

        Self.logger.info("Probing resource: \(url?.path ?? "unknown")")

        guard let url = url else {
            reply(nil, posixError(EINVAL))
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

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        // Extract URL from resource
        let url: URL?
        if let pathResource = resource as? FSPathURLResource {
            url = pathResource.url
        } else if let genericResource = resource as? FSGenericURLResource {
            url = genericResource.url
        } else {
            url = nil
        }

        Self.logger.info("Loading resource: \(url?.path ?? "unknown")")

        guard let url = url else {
            reply(nil, posixError(EINVAL))
            return
        }

        self.vaultPath = url.path

        // TODO: Get password from user via FSKit authentication
        // For now, use empty password - in production FSKit handles auth UI
        let password = ""

        // Create the Rust filesystem
        let result = create(url.path, password)

        guard result.isOk() else {
            let errno = result.getError()
            Self.logger.error("Failed to create filesystem, errno: \(errno)")
            reply(nil, posixError(errno))
            return
        }

        self.cryptoFS = result.unwrap()

        let rootItemId = cryptoFS!.get_root_item_id()
        Self.logger.info("Vault loaded successfully, root item ID: \(rootItemId)")

        // Create the volume
        let volumeID = FSVolume.Identifier(uuid: UUID())
        let volumeName = FSFileName(string: url.lastPathComponent)
        let vol = OxVaultVolume(
            volumeID: volumeID,
            volumeName: volumeName,
            cryptoFS: cryptoFS!
        )
        self.volume = vol

        reply(vol, nil)
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
        Self.logger.info("Extension finished loading")
    }
}

// MARK: - Error Helpers

/// Creates an NSError from a POSIX errno value.
func posixError(_ errno: Int32) -> NSError {
    return NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
}
