// OxCryptEnumerator.swift
// NSFileProviderEnumerator implementations for directory and working set enumeration.

import FileProvider
import Foundation
import os.log

/// Logger for enumerator operations.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "Enumerator")

/// Debug logging - writes to file since system logs redact content
private func debugLog(_ message: String) {
    NSLog("[OxCrypt:Enum] %@", message)
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

// MARK: - Directory Enumerator

/// Enumerates items within a specific directory.
class DirectoryEnumerator: NSObject, NSFileProviderEnumerator {
    private weak var ext: OxCryptExtension?
    private let containerIdentifier: NSFileProviderItemIdentifier

    init(extension ext: OxCryptExtension, container: NSFileProviderItemIdentifier) {
        self.ext = ext
        self.containerIdentifier = container
        super.init()
        debugLog("DirectoryEnumerator created for container: \(container.rawValue)")
    }

    func invalidate() {
        debugLog("DirectoryEnumerator invalidated for container: \(containerIdentifier.rawValue)")
    }

    func enumerateItems(
        for observer: NSFileProviderEnumerationObserver,
        startingAt page: NSFileProviderPage
    ) {
        debugLog("enumerateItems called for container: \(containerIdentifier.rawValue)")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("enumerateItems: ext or fs is nil, returning notAuthenticated")
            observer.finishEnumeratingWithError(NSFileProviderError(.notAuthenticated))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            // Parse page number from data
            let pageNum: UInt32
            if page == NSFileProviderPage.initialPageSortedByDate as NSFileProviderPage
                || page == NSFileProviderPage.initialPageSortedByName as NSFileProviderPage
            {
                pageNum = 0
            } else {
                pageNum = page.rawValue.withUnsafeBytes { ptr in
                    ptr.load(as: UInt32.self)
                }
            }

            // Translate container identifier to Rust format
            let containerId = ext.translateIdentifier(self.containerIdentifier)

            debugLog("Calling fs.enumerate(\(containerId), page=\(pageNum))")

            let result = fs.enumerate(containerId, pageNum)

            if result.isOk() {
                // Filter out items with empty identifiers to prevent File Provider crashes
                let allItems = result.getItems()
                var validItems: [OxCryptItem] = []
                for item in allItems {
                    let identifier = item.identifier().toString()
                    if !identifier.isEmpty {
                        validItems.append(OxCryptItem(from: item))
                    } else {
                        debugLog("Skipping item with empty identifier in container: \(containerId)")
                    }
                }

                debugLog("fs.enumerate succeeded: \(validItems.count) items")
                observer.didEnumerate(validItems)

                if result.hasMore() {
                    // Create next page token
                    var nextPage = result.getNextPage()
                    let nextPageData = withUnsafeBytes(of: &nextPage) { Data($0) }
                    observer.finishEnumerating(upTo: NSFileProviderPage(nextPageData))
                } else {
                    observer.finishEnumerating(upTo: nil)
                }
            } else {
                let errorCode = result.getErrorCode()
                let error = ext.mapError(code: errorCode)
                debugLog("fs.enumerate FAILED: error code \(errorCode)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }

    func enumerateChanges(
        for observer: NSFileProviderChangeObserver,
        from anchor: NSFileProviderSyncAnchor
    ) {
        debugLog("DirectoryEnumerator.enumerateChanges called for container: \(containerIdentifier.rawValue)")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("DirectoryEnumerator.enumerateChanges: ext or fs is nil")
            observer.finishEnumeratingWithError(NSFileProviderError(.notAuthenticated))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let anchorStr = String(data: anchor.rawValue, encoding: .utf8) ?? ""

            // Translate container identifier to Rust format
            let containerId = ext.translateIdentifier(self.containerIdentifier)

            debugLog("DirectoryEnumerator: Enumerating changes for container: \(containerId), anchor: \(anchorStr)")

            let result = fs.changesSince(anchorStr)

            if result.isOk() {
                // Get updated items, filtering out any with empty identifiers
                let allUpdated = result.getUpdatedItems()
                var validUpdated: [OxCryptItem] = []
                for item in allUpdated {
                    let identifier = item.identifier().toString()
                    if !identifier.isEmpty {
                        validUpdated.append(OxCryptItem(from: item))
                    } else {
                        debugLog("DirectoryEnumerator: Skipping updated item with empty identifier in container: \(containerId)")
                    }
                }
                if !validUpdated.isEmpty {
                    observer.didUpdate(validUpdated)
                }

                // Get deleted item identifiers, filtering out empty ones
                let allDeleted = result.getDeletedIdentifiers()
                var validDeleted: [NSFileProviderItemIdentifier] = []
                for idRef in allDeleted {
                    let idStr = idRef.as_str().toString()
                    if !idStr.isEmpty {
                        validDeleted.append(NSFileProviderItemIdentifier(rawValue: idStr))
                    }
                }
                if !validDeleted.isEmpty {
                    observer.didDeleteItems(withIdentifiers: validDeleted)
                }

                // Create new anchor from result
                let newAnchorStr = result.getNewAnchor().toString()
                let newAnchor = NSFileProviderSyncAnchor(newAnchorStr.data(using: .utf8)!)

                observer.finishEnumeratingChanges(upTo: newAnchor, moreComing: false)

                debugLog("DirectoryEnumerator: enumerated \(validUpdated.count) updates, \(validDeleted.count) deletions for container: \(containerId)")
            } else {
                let errorCode = result.getErrorCode()
                let error = ext.mapError(code: errorCode)
                debugLog("DirectoryEnumerator: change enumeration FAILED with error code \(errorCode)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        debugLog("DirectoryEnumerator.currentSyncAnchor called for container: \(containerIdentifier.rawValue)")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("DirectoryEnumerator.currentSyncAnchor: ext or fs is nil, returning nil anchor")
            completionHandler(nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let anchor = fs.currentAnchor().toString()
            debugLog("DirectoryEnumerator.currentSyncAnchor returning anchor: \(anchor)")
            let anchorData = anchor.data(using: .utf8) ?? Data()
            completionHandler(NSFileProviderSyncAnchor(anchorData))
        }
    }
}

// MARK: - Working Set Enumerator

/// Enumerates the working set (recently accessed/modified items across the entire vault).
class WorkingSetEnumerator: NSObject, NSFileProviderEnumerator {
    private weak var ext: OxCryptExtension?

    init(extension ext: OxCryptExtension) {
        self.ext = ext
        super.init()
        debugLog("WorkingSetEnumerator created")
    }

    func invalidate() {
        debugLog("WorkingSetEnumerator invalidated")
    }

    func enumerateItems(
        for observer: NSFileProviderEnumerationObserver,
        startingAt page: NSFileProviderPage
    ) {
        debugLog("WorkingSetEnumerator.enumerateItems called")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("WorkingSetEnumerator.enumerateItems: ext or fs is nil")
            observer.finishEnumeratingWithError(NSFileProviderError(.notAuthenticated))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            debugLog("WorkingSetEnumerator: Enumerating working set items")

            // For working set, enumerate recent/important items
            // For now, just enumerate root to provide basic coverage
            let result = fs.enumerateWorkingSet()

            if result.isOk() {
                // Filter out items with empty identifiers to prevent File Provider crashes
                let allItems = result.getItems()
                var validItems: [OxCryptItem] = []
                for item in allItems {
                    let identifier = item.identifier().toString()
                    if !identifier.isEmpty {
                        let oxItem = OxCryptItem(from: item)
                        // Log each item's identifier and parent for debugging
                        debugLog("WorkingSetEnumerator: Item '\(oxItem.filename)' id=\(oxItem.itemIdentifier.rawValue) parent=\(oxItem.parentItemIdentifier.rawValue)")
                        validItems.append(oxItem)
                    } else {
                        debugLog("WorkingSetEnumerator: Skipping item with empty identifier")
                    }
                }

                debugLog("WorkingSetEnumerator: enumerated \(validItems.count) items, calling didEnumerate")
                observer.didEnumerate(validItems)
                debugLog("WorkingSetEnumerator: calling finishEnumerating")
                observer.finishEnumerating(upTo: nil)
                debugLog("WorkingSetEnumerator: enumeration complete")
            } else {
                let errorCode = result.getErrorCode()
                let error = ext.mapError(code: errorCode)
                debugLog("WorkingSetEnumerator: enumeration FAILED with error code \(errorCode)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }

    func enumerateChanges(
        for observer: NSFileProviderChangeObserver,
        from anchor: NSFileProviderSyncAnchor
    ) {
        debugLog("WorkingSetEnumerator.enumerateChanges called")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("WorkingSetEnumerator.enumerateChanges: ext or fs is nil")
            observer.finishEnumeratingWithError(NSFileProviderError(.notAuthenticated))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let anchorStr = String(data: anchor.rawValue, encoding: .utf8) ?? ""

            debugLog("WorkingSetEnumerator: Enumerating changes from anchor: \(anchorStr)")

            let result = fs.workingSetChangesSince(anchorStr)

            if result.isOk() {
                // Get updated items, filtering out any with empty identifiers
                let allUpdated = result.getUpdatedItems()
                var validUpdated: [OxCryptItem] = []
                for item in allUpdated {
                    let identifier = item.identifier().toString()
                    if !identifier.isEmpty {
                        validUpdated.append(OxCryptItem(from: item))
                    } else {
                        debugLog("WorkingSetEnumerator: Skipping updated item with empty identifier")
                    }
                }
                if !validUpdated.isEmpty {
                    observer.didUpdate(validUpdated)
                }

                // Get deleted item identifiers, filtering out empty ones
                let allDeleted = result.getDeletedIdentifiers()
                var validDeleted: [NSFileProviderItemIdentifier] = []
                for idRef in allDeleted {
                    let idStr = idRef.as_str().toString()
                    if !idStr.isEmpty {
                        validDeleted.append(NSFileProviderItemIdentifier(rawValue: idStr))
                    }
                }
                if !validDeleted.isEmpty {
                    observer.didDeleteItems(withIdentifiers: validDeleted)
                }

                // Create new anchor from result
                let newAnchorStr = result.getNewAnchor().toString()
                let newAnchor = NSFileProviderSyncAnchor(newAnchorStr.data(using: .utf8)!)

                observer.finishEnumeratingChanges(upTo: newAnchor, moreComing: false)

                debugLog("WorkingSetEnumerator: enumerated \(validUpdated.count) updates, \(validDeleted.count) deletions")
            } else {
                let errorCode = result.getErrorCode()
                let error = ext.mapError(code: errorCode)
                debugLog("WorkingSetEnumerator: change enumeration FAILED with error code \(errorCode)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        debugLog("WorkingSetEnumerator.currentSyncAnchor called")
        guard let ext = ext, let fs = ext.filesystem else {
            debugLog("WorkingSetEnumerator.currentSyncAnchor: ext or fs is nil, returning nil")
            completionHandler(nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let anchor = fs.currentAnchor().toString()
            debugLog("WorkingSetEnumerator.currentSyncAnchor returning anchor: \(anchor)")
            let anchorData = anchor.data(using: .utf8) ?? Data()
            completionHandler(NSFileProviderSyncAnchor(anchorData))
        }
    }
}
