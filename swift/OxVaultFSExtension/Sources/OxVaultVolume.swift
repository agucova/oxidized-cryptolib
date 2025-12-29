// OxVaultVolume.swift
// FSVolume implementation delegating to Rust CryptoFilesystem.

import FSKit
import Foundation
import os
import OxVaultFFI

/// FSVolume implementation for a Cryptomator vault.
final class OxVaultVolume: FSVolume, FSVolume.Operations {
    static let logger = Logger(subsystem: "com.agucova.oxidized", category: "Volume")

    /// Rust filesystem handle.
    private let cryptoFS: CryptoFilesystem

    /// Item ID to FSItem mapping (FSKit manages FSItem lifecycle).
    private var itemCache: [UInt64: FSItem] = [:]
    private let itemCacheLock = NSLock()

    /// Root item, lazily created.
    private var _rootItem: FSItem?

    init(volumeID: FSVolume.Identifier, volumeName: FSFileName, cryptoFS: CryptoFilesystem) {
        self.cryptoFS = cryptoFS
        super.init(volumeID: volumeID, volumeName: volumeName)
    }

    // MARK: - FSVolumeOperations Properties

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let caps = FSVolume.SupportedCapabilities()
        caps.supportsSymbolicLinks = true
        caps.supportsHardLinks = false
        caps.supports2TBFiles = true
        caps.supports64BitObjectIDs = true
        caps.caseFormat = .sensitive
        return caps
    }

    var volumeStatistics: FSStatFSResult {
        let stats = FSStatFSResult(fileSystemTypeName: "oxvault")
        let result = cryptoFS.getVolumeStats()

        if result.isOk() {
            let rustStats = result.unwrap()
            stats.blockSize = Int(rustStats.getBlockSize())
            stats.ioSize = Int(rustStats.getBlockSize())
            stats.totalBytes = rustStats.getTotalBytes()
            stats.availableBytes = rustStats.getAvailableBytes()
            stats.freeBytes = rustStats.getAvailableBytes()
            stats.usedBytes = rustStats.getUsedBytes()
            stats.totalFiles = rustStats.getTotalInodes()
            stats.freeFiles = rustStats.getAvailableInodes()
        } else {
            // Default values on error
            stats.blockSize = 4096
            stats.ioSize = 4096
            stats.totalBytes = 0
            stats.availableBytes = 0
            stats.freeBytes = 0
            stats.usedBytes = 0
            stats.totalFiles = 0
            stats.freeFiles = 0
        }

        return stats
    }

    // MARK: - FSVolumePathConfOperations

    var maximumLinkCount: Int { 1 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { false }
    var truncatesLongNames: Bool { false }

    // MARK: - FSVolumeOperations Methods

    func mount(
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        Self.logger.info("Mounting volume")
        reply(nil)
    }

    func unmount(replyHandler reply: @escaping () -> Void) {
        Self.logger.info("Unmounting volume")
        cryptoFS.shutdown()
        itemCacheLock.lock()
        itemCache.removeAll()
        itemCacheLock.unlock()
        reply()
    }

    func synchronize(
        flags: FSSyncFlags,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        // No-op for read-only filesystem
        reply(nil)
    }

    func getAttributes(
        _ request: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, (any Error)?) -> Void
    ) {
        let itemId = getItemId(for: item)

        let result = cryptoFS.getAttributes(itemId)

        guard result.isOk() else {
            reply(nil, posixError(result.getError()))
            return
        }

        let rustAttrs = result.unwrap()
        let attrs = toFSItemAttributes(rustAttrs)
        reply(attrs, nil)
    }

    func setAttributes(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, (any Error)?) -> Void
    ) {
        // Read-only filesystem
        reply(nil, posixError(EROFS))
    }

    func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void
    ) {
        let parentId = getItemId(for: directory)
        let nameStr = name.string ?? ""

        let result = cryptoFS.lookup(parentId, nameStr)

        guard result.isOk() else {
            reply(nil, nil, posixError(result.getError()))
            return
        }

        let attrs = result.unwrap()
        let childId = attrs.getItemId()

        let childItem = getOrCreateItem(for: childId)
        reply(childItem, name, nil)
    }

    func reclaimItem(
        _ item: FSItem,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        let itemId = getItemId(for: item)
        cryptoFS.reclaim(itemId)

        itemCacheLock.lock()
        itemCache.removeValue(forKey: itemId)
        itemCacheLock.unlock()

        reply(nil)
    }

    func readSymbolicLink(
        _ item: FSItem,
        replyHandler reply: @escaping (FSFileName?, (any Error)?) -> Void
    ) {
        let itemId = getItemId(for: item)

        let result = cryptoFS.readSymlink(itemId)

        guard result.isOk() else {
            reply(nil, posixError(result.getError()))
            return
        }

        let targetBytes = result.unwrap()
        let target = String(bytes: targetBytes, encoding: .utf8) ?? ""
        reply(FSFileName(string: target), nil)
    }

    func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes: FSItem.SetAttributesRequest,
        replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void
    ) {
        // Read-only filesystem
        reply(nil, nil, posixError(EROFS))
    }

    func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName,
        replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void
    ) {
        // Read-only filesystem
        reply(nil, nil, posixError(EROFS))
    }

    func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSFileName?, (any Error)?) -> Void
    ) {
        // No hard links supported
        reply(nil, posixError(ENOTSUP))
    }

    func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler reply: @escaping @Sendable ((any Error)?) -> Void
    ) {
        // Read-only filesystem
        reply(posixError(EROFS))
    }

    func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?,
        replyHandler reply: @escaping @Sendable (FSFileName?, (any Error)?) -> Void
    ) {
        // Read-only filesystem
        reply(nil, posixError(EROFS))
    }

    func activate(
        options: FSTaskOptions,
        replyHandler reply: @escaping @Sendable (FSItem?, (any Error)?) -> Void
    ) {
        Self.logger.info("Activating volume")
        let rootItem = getRootItem()
        reply(rootItem, nil)
    }

    func deactivate(
        options: FSDeactivateOptions,
        replyHandler reply: @escaping @Sendable ((any Error)?) -> Void
    ) {
        Self.logger.info("Deactivating volume")
        reply(nil)
    }

    func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker,
        replyHandler reply: @escaping @Sendable (FSDirectoryVerifier, (any Error)?) -> Void
    ) {
        let itemId = getItemId(for: directory)

        let result = cryptoFS.enumerateDirectory(itemId, cookie.rawValue)

        guard result.isOk() else {
            reply(verifier, posixError(result.getError()))
            return
        }

        let entries = result.unwrap()

        for entry in entries {
            let nameBytes = entry.getName()
            let name = FSFileName(rustBytes: nameBytes)
            let childId = entry.getItemId()

            let itemType: FSItem.ItemType
            if entry.isDirectory() {
                itemType = .directory
            } else if entry.isSymlink() {
                itemType = .symlink
            } else {
                itemType = .file
            }

            let entryAttrs = FSItem.Attributes()
            entryAttrs.size = entry.getSize()
            entryAttrs.type = itemType
            entryAttrs.fileID = FSItem.Identifier(rawValue: childId) ?? .invalid

            let nextCookie = FSDirectoryCookie(rawValue: childId)

            let added = packer.packEntry(
                name: name,
                itemType: itemType,
                itemID: FSItem.Identifier(rawValue: childId) ?? .invalid,
                nextCookie: nextCookie,
                attributes: entryAttrs
            )

            if !added {
                break // Packer is full
            }
        }

        reply(verifier, nil)
    }

    // MARK: - Item Management

    /// Get the item ID for an FSItem.
    private func getItemId(for item: FSItem) -> UInt64 {
        // Look up in reverse cache
        itemCacheLock.lock()
        defer { itemCacheLock.unlock() }

        for (id, cachedItem) in itemCache {
            if cachedItem === item {
                return id
            }
        }

        // If not in cache, it's the root item
        return cryptoFS.get_root_item_id()
    }

    /// Get or create an FSItem for the given item ID.
    private func getOrCreateItem(for itemId: UInt64) -> FSItem {
        itemCacheLock.lock()
        defer { itemCacheLock.unlock() }

        if let existing = itemCache[itemId] {
            return existing
        }

        let item = FSItem()
        itemCache[itemId] = item
        return item
    }

    /// Get the root item.
    func getRootItem() -> FSItem {
        if let root = _rootItem {
            return root
        }

        let rootId = cryptoFS.get_root_item_id()
        let root = getOrCreateItem(for: rootId)
        _rootItem = root
        return root
    }

    // MARK: - Helper Methods

    private func toFSItemAttributes(_ attrs: FileAttributes) -> FSItem.Attributes {
        let fsAttrs = FSItem.Attributes()
        fsAttrs.size = attrs.getSize()
        fsAttrs.mode = attrs.getMode()
        fsAttrs.uid = attrs.getUid()
        fsAttrs.gid = attrs.getGid()
        fsAttrs.fileID = FSItem.Identifier(rawValue: attrs.getItemId()) ?? .invalid

        if attrs.isDirectory() {
            fsAttrs.type = .directory
        } else if attrs.isSymlink() {
            fsAttrs.type = .symlink
        } else {
            fsAttrs.type = .file
        }

        return fsAttrs
    }
}

// MARK: - FSFileName Extension

extension FSFileName {
    convenience init(bytes: [UInt8]) {
        let data = Data(bytes)
        self.init(data: data)
    }

    convenience init(rustBytes: RustVec<UInt8>) {
        var bytes: [UInt8] = []
        for byte in rustBytes {
            bytes.append(byte)
        }
        self.init(bytes: bytes)
    }
}
