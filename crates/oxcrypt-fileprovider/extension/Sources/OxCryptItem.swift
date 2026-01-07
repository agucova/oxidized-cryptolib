// OxCryptItem.swift
// NSFileProviderItem adapter for FileProviderItem (Rust FFI).

import FileProvider
import Foundation
import UniformTypeIdentifiers

/// Root item identifier - base64url("root"), must match Rust's ROOT_ITEM_IDENTIFIER
let ROOT_ITEM_IDENTIFIER = "cm9vdA"

/// Adapts a Rust FileProviderItem to NSFileProviderItem protocol.
/// Uses FileProviderItemRef to work with both owned items and vector element references.
class OxCryptItem: NSObject, NSFileProviderItem {
    private let rustItem: FileProviderItemRef

    init(from rustItem: FileProviderItemRef) {
        self.rustItem = rustItem
        super.init()
    }

    // MARK: - Required Properties

    var itemIdentifier: NSFileProviderItemIdentifier {
        let id = rustItem.identifier().toString()
        // Translate root identifier to special constant
        if id == ROOT_ITEM_IDENTIFIER {
            return .rootContainer
        }
        return NSFileProviderItemIdentifier(rawValue: id)
    }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        let parentId = rustItem.parentIdentifier().toString()
        // Rust returns ROOT_ITEM_IDENTIFIER for items in root container
        if parentId.isEmpty || parentId == ROOT_ITEM_IDENTIFIER {
            return .rootContainer
        }
        return NSFileProviderItemIdentifier(rawValue: parentId)
    }

    var filename: String {
        // Convert UTF-8 bytes to String
        let bytes = rustItem.filename()
        let name = String(decoding: bytes, as: UTF8.self)
        // Root container should have "/" as filename
        if name.isEmpty && rustItem.identifier().toString() == ROOT_ITEM_IDENTIFIER {
            return "/"
        }
        return name
    }

    var capabilities: NSFileProviderItemCapabilities {
        let itemType = rustItem.itemType()

        var caps: NSFileProviderItemCapabilities = [
            .allowsReading,
            .allowsDeleting,
            .allowsRenaming,
            .allowsReparenting
        ]

        if itemType == 1 {
            // Directory - must have .allowsContentEnumerating for File Provider to enumerate contents
            caps.insert(.allowsAddingSubItems)
            caps.insert(.allowsContentEnumerating)
        } else if itemType == 0 {
            // File
            caps.insert(.allowsWriting)
        }

        return caps
    }

    // MARK: - Content Properties

    var contentType: UTType {
        let itemType = rustItem.itemType()

        switch itemType {
        case 1:  // Directory
            return .folder
        case 2:  // Symlink
            return .symbolicLink
        default:  // File
            // Try to infer from extension
            let ext = (filename as NSString).pathExtension
            if !ext.isEmpty, let type = UTType(filenameExtension: ext) {
                return type
            }
            return .data
        }
    }

    var documentSize: NSNumber? {
        let size = rustItem.size()
        // Only return size for files
        if rustItem.itemType() == 0 {
            return NSNumber(value: size)
        }
        return nil
    }

    // MARK: - Timestamps

    var creationDate: Date? {
        let timestamp = rustItem.creationDate()
        if timestamp > 0 {
            return Date(timeIntervalSince1970: timestamp)
        }
        return nil
    }

    var contentModificationDate: Date? {
        let timestamp = rustItem.contentModificationDate()
        if timestamp > 0 {
            return Date(timeIntervalSince1970: timestamp)
        }
        return nil
    }

    // MARK: - Versioning

    var itemVersion: NSFileProviderItemVersion {
        // Use modification timestamp as version
        let timestamp = rustItem.contentModificationDate()
        let versionData = withUnsafeBytes(of: timestamp) { Data($0) }

        return NSFileProviderItemVersion(
            contentVersion: versionData,
            metadataVersion: versionData
        )
    }

    // MARK: - Symlink Support

    var symlinkTargetPath: String? {
        // Symlinks store their target in a special property
        // We'll need to add this to the Rust FFI if symlinks are supported
        if rustItem.itemType() == 2 {
            // For now, return nil - we'd need to extend the Rust FFI
            return nil
        }
        return nil
    }

    // MARK: - Sync State

    var isDownloaded: Bool {
        // Files are NOT downloaded until fetchContents is called
        // This tells File Provider it needs to call fetchContents before opening
        false
    }

    var isDownloading: Bool {
        false
    }

    var isUploaded: Bool {
        true
    }

    var isUploading: Bool {
        false
    }
}

// MARK: - Root Container Item

/// Special item representing the root container.
class OxCryptRootItem: NSObject, NSFileProviderItem {
    var itemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
    var parentItemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
    var filename: String { "/" }

    var capabilities: NSFileProviderItemCapabilities {
        [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems]
    }

    var contentType: UTType { .folder }
    var documentSize: NSNumber? { nil }
    var creationDate: Date? { nil }
    var contentModificationDate: Date? { nil }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(contentVersion: Data(), metadataVersion: Data())
    }

    var isDownloaded: Bool { true }
    var isDownloading: Bool { false }
    var isUploaded: Bool { true }
    var isUploading: Bool { false }
}
