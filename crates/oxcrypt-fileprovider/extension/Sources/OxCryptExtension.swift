// OxCryptExtension.swift
// Main File Provider extension implementing NSFileProviderReplicatedExtension.

import FileProvider
import Foundation
import os.log

/// Logger for extension operations.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "Extension")

/// Debug logging - writes to file since system logs redact content
private func debugLog(_ message: String) {
    NSLog("[OxCrypt:Ext] %@", message)
    // Also write to file for debugging
    let logFile = FileManager.default.temporaryDirectory.appendingPathComponent("oxcrypt_extension.log")
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let line = "[\(timestamp)] \(message)\n"
    if let data = line.data(using: .utf8) {
        if FileManager.default.fileExists(atPath: logFile.path) {
            if let handle = try? FileHandle(forWritingTo: logFile) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        } else {
            try? data.write(to: logFile)
        }
    }
}

/// Main File Provider extension for OxCrypt vaults.
///
/// This class implements `NSFileProviderReplicatedExtension` to expose
/// Cryptomator vaults as native macOS cloud storage volumes.
class OxCryptExtension: NSObject, NSFileProviderReplicatedExtension {
    let domain: NSFileProviderDomain
    var filesystem: FileProviderFilesystem?
    let manager: NSFileProviderManager
    /// URL to the vault with security scope (must stop accessing on invalidate)
    private var vaultURL: URL?

    /// Lock for thread-safe initialization.
    private let initLock = NSLock()
    /// Flag indicating initialization is complete (filesystem is ready).
    private var isInitialized = false
    /// Unique instance ID for debugging multiple extension instances
    private let instanceId = UUID().uuidString.prefix(8)

    /// Initialize the extension for a domain.
    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        self.manager = NSFileProviderManager(for: domain)!
        super.init()

        // Acquire lock during initialization to prevent race with protocol methods
        initLock.lock()
        defer { initLock.unlock() }

        // Load password from Keychain and resolve vault path
        let domainId = domain.identifier.rawValue
        debugLog("[\(self.instanceId)] Initializing extension for domain: \(domainId)")

        // Retrieve password from shared Keychain
        let password: String
        do {
            password = try KeychainHelper.retrieve(for: domainId)
            debugLog("[\(self.instanceId)] Successfully retrieved password from Keychain")
        } catch {
            debugLog("[\(self.instanceId)] Failed to retrieve password from Keychain: \(error)")
            return
        }

        // Get vault path from domain identifier (base64url-encoded)
        guard let vaultPath = KeychainHelper.vaultPath(from: domainId) else {
            debugLog("[\(self.instanceId)] Failed to decode vault path from domain identifier")
            return
        }
        debugLog("[\(self.instanceId)] Vault path: \(vaultPath)")

        // Try direct path access first (using temp exception entitlement)
        debugLog("[\(self.instanceId)] Calling FFI create() with vault path...")
        let result = create(vaultPath, password)
        debugLog("[\(self.instanceId)] FFI create() returned, isOk=\(result.isOk())")
        if result.isOk() {
            self.filesystem = result.unwrap()
            isInitialized = true
            debugLog("[\(self.instanceId)] Filesystem initialized successfully, isInitialized=\(self.isInitialized)")
            return
        } else {
            debugLog("[\(self.instanceId)] Failed to initialize filesystem: \(result.getErrorDomain()) (\(result.getErrorCode()))")

            // If direct access fails, try security-scoped bookmark as fallback
            logger.info("Attempting bookmark-based access as fallback")
            do {
                let (url, isStale) = try BookmarkHelper.resolve(for: domainId)
                if isStale {
                    logger.warning("Bookmark is stale - may need re-registration")
                }

                // Note: Bookmarks are created by the unsandboxed host app, so they're not
                // security-scoped. The extension accesses via its entitlements.
                self.vaultURL = url
                let bookmarkPath = url.path
                logger.info("Resolved bookmark to: \(bookmarkPath)")

                let bookmarkResult = create(bookmarkPath, password)
                if bookmarkResult.isOk() {
                    self.filesystem = bookmarkResult.unwrap()
                    isInitialized = true
                    logger.info("[\(self.instanceId)] Filesystem initialized successfully via bookmark, isInitialized=\(self.isInitialized)")
                } else {
                    logger.error(
                        "Bookmark access failed: \(bookmarkResult.getErrorDomain()) (\(bookmarkResult.getErrorCode()))")
                    self.vaultURL = nil
                }
            } catch {
                logger.error("Failed to resolve vault bookmark: \(error.localizedDescription)")
            }
        }
    }

    /// Clean up when the extension is invalidated.
    func invalidate() {
        logger.info("[\(self.instanceId)] Invalidating extension")
        filesystem?.shutdown()
        filesystem = nil
        vaultURL = nil
    }

    // MARK: - Item Operations

    /// Get an item by identifier.
    func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)

        debugLog("[\(self.instanceId)] item(for: \(identifier.rawValue)) called, acquiring lock...")
        initLock.lock()
        debugLog("[\(self.instanceId)] Lock acquired, isInitialized=\(self.isInitialized), filesystem=\(self.filesystem != nil ? "present" : "nil")")
        guard isInitialized, let fs = filesystem else {
            debugLog("[\(self.instanceId)] Guard FAILED: isInitialized=\(self.isInitialized), filesystem=\(self.filesystem != nil ? "present" : "nil")")
            initLock.unlock()
            completionHandler(nil, NSFileProviderError(.notAuthenticated))
            return progress
        }
        debugLog("[\(self.instanceId)] Guard passed, proceeding with item lookup")
        initLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async {
            let rustId = self.translateIdentifier(identifier)
            debugLog("[\(self.instanceId)] Calling fs.item(\(rustId)) [original: \(identifier.rawValue)]")
            let result = fs.item(rustId)
            if result.isOk() {
                let item = OxCryptItem(from: result.unwrap())
                debugLog("[\(self.instanceId)] fs.item() succeeded for \(rustId)")
                completionHandler(item, nil)
            } else {
                let errorCode = result.getErrorCode()
                debugLog("[\(self.instanceId)] fs.item() FAILED for \(rustId): error code \(errorCode)")
                completionHandler(nil, self.mapError(code: errorCode))
            }
            progress.completedUnitCount = 1
        }

        return progress
    }

    /// Fetch file contents to a destination URL.
    func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 100)

        initLock.lock()
        guard isInitialized, let fs = filesystem else {
            initLock.unlock()
            completionHandler(nil, nil, NSFileProviderError(.notAuthenticated))
            return progress
        }
        initLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async {
            // Create temporary file for content
            let tempDir = FileManager.default.temporaryDirectory
            let tempFile = tempDir.appendingPathComponent(UUID().uuidString)

            let rustId = self.translateIdentifier(itemIdentifier)
            let result = fs.fetchContents(rustId, tempFile.path)

            if result.isOk() {
                // Get updated item info
                let itemResult = fs.item(rustId)
                if itemResult.isOk() {
                    let item = OxCryptItem(from: itemResult.unwrap())
                    completionHandler(tempFile, item, nil)
                } else {
                    completionHandler(tempFile, nil, nil)
                }
            } else {
                completionHandler(nil, nil, self.mapError(code: result.getErrorCode()))
            }
            progress.completedUnitCount = 100
        }

        return progress
    }

    /// Create a new item.
    func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) ->
            Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 100)

        initLock.lock()
        guard isInitialized, let fs = filesystem else {
            initLock.unlock()
            completionHandler(nil, [], false, NSFileProviderError(.notAuthenticated))
            return progress
        }
        initLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async {
            let itemType: UInt8 =
                switch itemTemplate.contentType {
                case .folder, .directory:
                    1  // Directory
                case .symbolicLink:
                    2  // Symlink
                default:
                    0  // File
                }

            let contentsPath: String? =
                if let url = url {
                    url.path
                } else if itemType == 2, let symlinkTarget = itemTemplate.symlinkTargetPath {
                    symlinkTarget
                } else {
                    nil
                }

            let parentRustId = self.translateIdentifier(itemTemplate.parentItemIdentifier)
            let result = fs.createItem(
                parentRustId,
                itemTemplate.filename,
                itemType,
                contentsPath)

            if result.isOk() {
                let item = OxCryptItem(from: result.unwrap())
                completionHandler(item, [], false, nil)
            } else {
                completionHandler(nil, [], false, self.mapError(code: result.getErrorCode()))
            }
            progress.completedUnitCount = 100
        }

        return progress
    }

    /// Modify an existing item.
    func modifyItem(
        _ item: NSFileProviderItem,
        baseVersion version: NSFileProviderItemVersion,
        changedFields: NSFileProviderItemFields,
        contents newContents: URL?,
        options: NSFileProviderModifyItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) ->
            Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 100)

        initLock.lock()
        guard isInitialized, let fs = filesystem else {
            initLock.unlock()
            completionHandler(nil, [], false, NSFileProviderError(.notAuthenticated))
            return progress
        }
        initLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async {
            var newParent: String? = nil
            var newName: String? = nil
            var contentsPath: String? = nil

            if changedFields.contains(.parentItemIdentifier) {
                newParent = self.translateIdentifier(item.parentItemIdentifier)
            }

            if changedFields.contains(.filename) {
                newName = item.filename
            }

            if changedFields.contains(.contents), let url = newContents {
                contentsPath = url.path
            }

            let itemRustId = self.translateIdentifier(item.itemIdentifier)
            let result = fs.modifyItem(
                itemRustId,
                newParent,
                newName,
                contentsPath)

            if result.isOk() {
                let modifiedItem = OxCryptItem(from: result.unwrap())
                completionHandler(modifiedItem, [], false, nil)
            } else {
                completionHandler(nil, [], false, self.mapError(code: result.getErrorCode()))
            }
            progress.completedUnitCount = 100
        }

        return progress
    }

    /// Delete an item.
    func deleteItem(
        identifier: NSFileProviderItemIdentifier,
        baseVersion version: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)

        initLock.lock()
        guard isInitialized, let fs = filesystem else {
            initLock.unlock()
            completionHandler(NSFileProviderError(.notAuthenticated))
            return progress
        }
        initLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async {
            let rustId = self.translateIdentifier(identifier)
            let result = fs.deleteItem(rustId)

            if result.isOk() {
                completionHandler(nil)
            } else {
                completionHandler(self.mapError(code: result.getErrorCode()))
            }
            progress.completedUnitCount = 1
        }

        return progress
    }

    // MARK: - Enumeration

    /// Create an enumerator for a container.
    func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> NSFileProviderEnumerator {
        debugLog("[\(self.instanceId)] enumerator(for: \(containerItemIdentifier.rawValue)) called, acquiring lock...")
        initLock.lock()
        defer { initLock.unlock() }

        debugLog("[\(self.instanceId)] enumerator: Lock acquired, isInitialized=\(self.isInitialized), filesystem=\(self.filesystem != nil ? "present" : "nil")")
        guard isInitialized, filesystem != nil else {
            debugLog("[\(self.instanceId)] enumerator guard FAILED")
            throw NSFileProviderError(.notAuthenticated)
        }

        if containerItemIdentifier == .workingSet {
            debugLog("[\(self.instanceId)] Returning WorkingSetEnumerator")
            return WorkingSetEnumerator(extension: self)
        }

        debugLog("[\(self.instanceId)] Returning DirectoryEnumerator for \(containerItemIdentifier.rawValue)")
        return DirectoryEnumerator(extension: self, container: containerItemIdentifier)
    }

    // MARK: - Identifier Translation

    /// Translate Apple's File Provider identifiers to Rust's expected format.
    ///
    /// Swift's File Provider framework uses special constants like `.rootContainer`
    /// that map to literal strings like "NSFileProviderRootContainerItemIdentifier".
    /// Rust expects custom base64url-encoded identifiers.
    func translateIdentifier(_ identifier: NSFileProviderItemIdentifier) -> String {
        switch identifier {
        case .rootContainer:
            return ROOT_ITEM_IDENTIFIER  // matches Rust ROOT_ITEM_IDENTIFIER
        case .trashContainer:
            return ".trash"  // matches Rust TRASH_IDENTIFIER
        case .workingSet:
            return ".workingset"  // matches Rust WORKING_SET_IDENTIFIER
        default:
            return identifier.rawValue
        }
    }

    // MARK: - Error Mapping

    /// Map errno-like error codes to NSFileProviderError.
    func mapError(code: Int32) -> NSError {
        switch code {
        case 2:  // ENOENT
            return NSFileProviderError(.noSuchItem) as NSError
        case 13:  // EACCES
            return NSFileProviderError(.notAuthenticated) as NSError
        case 17:  // EEXIST
            return NSFileProviderError(.filenameCollision) as NSError
        case 28:  // ENOSPC
            return NSFileProviderError(.insufficientQuota) as NSError
        case 66:  // ENOTEMPTY
            return NSFileProviderError(.directoryNotEmpty) as NSError
        default:
            return NSFileProviderError(.serverUnreachable) as NSError
        }
    }
}

// MARK: - Materializing Items (required by protocol)

extension OxCryptExtension {
    /// Called when an item needs to be materialized.
    func materializedItemsDidChange(completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
