// BookmarkHelper.swift
// Security-scoped bookmark storage for sharing vault access between host app and extension.

import Foundation
import os.log

/// Logger for bookmark operations.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "BookmarkHelper")

/// Errors that can occur during bookmark operations.
enum BookmarkError: Error {
    case creationFailed(Error)
    case resolutionFailed(Error)
    case stale
    case notFound
    case accessDenied
}

/// Helper for storing and retrieving security-scoped bookmarks.
/// Bookmarks allow the sandboxed extension to access vault paths selected by the host app.
struct BookmarkHelper {
    /// The shared app group container for storing bookmarks.
    /// Must match the application-groups in entitlements.
    static let appGroupIdentifier = "2LR4AGRZW3.group.com.agucova.oxcrypt.fileprovider"

    /// Get the shared container URL for storing bookmarks.
    private static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
    }

    /// Get the bookmarks directory within the shared container.
    private static var bookmarksDirectory: URL? {
        guard let container = containerURL else { return nil }
        let dir = container.appendingPathComponent("Bookmarks", isDirectory: true)

        // Create directory if needed
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        return dir
    }

    /// Create and store a security-scoped bookmark for a vault path.
    /// - Parameters:
    ///   - url: The URL to the vault directory.
    ///   - domainIdentifier: The File Provider domain identifier.
    /// - Throws: BookmarkError if bookmark creation fails.
    static func store(url: URL, for domainIdentifier: String) throws {
        guard let bookmarksDir = bookmarksDirectory else {
            throw BookmarkError.accessDenied
        }

        // Start accessing security-scoped resource if needed
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            // Create a bookmark (host app is unsandboxed, so .withSecurityScope has no effect)
            // The sandboxed extension will access via its entitlements
            let bookmarkData = try url.bookmarkData(
                options: [],
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )

            // Store bookmark data in shared container
            let bookmarkFile = bookmarksDir.appendingPathComponent(sanitizeFilename(domainIdentifier))
            try bookmarkData.write(to: bookmarkFile)

            logger.info("Stored bookmark for domain: \(domainIdentifier)")
        } catch {
            logger.error("Failed to create bookmark: \(error.localizedDescription)")
            throw BookmarkError.creationFailed(error)
        }
    }

    /// Resolve a stored bookmark and return the URL with security scope.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    /// - Returns: A tuple of (URL, isStale) - caller must call startAccessingSecurityScopedResource().
    /// - Throws: BookmarkError if resolution fails.
    static func resolve(for domainIdentifier: String) throws -> (url: URL, isStale: Bool) {
        guard let bookmarksDir = bookmarksDirectory else {
            throw BookmarkError.accessDenied
        }

        let bookmarkFile = bookmarksDir.appendingPathComponent(sanitizeFilename(domainIdentifier))

        guard FileManager.default.fileExists(atPath: bookmarkFile.path) else {
            logger.warning("No bookmark found for domain: \(domainIdentifier)")
            throw BookmarkError.notFound
        }

        do {
            let bookmarkData = try Data(contentsOf: bookmarkFile)

            var isStale = false
            let url = try URL(
                resolvingBookmarkData: bookmarkData,
                options: [.withoutUI],
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            )

            if isStale {
                logger.warning("Bookmark is stale for domain: \(domainIdentifier)")
            }

            logger.debug("Resolved bookmark for domain: \(domainIdentifier) -> \(url.path)")
            return (url, isStale)
        } catch {
            logger.error("Failed to resolve bookmark: \(error.localizedDescription)")
            throw BookmarkError.resolutionFailed(error)
        }
    }

    /// Delete a stored bookmark.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    static func delete(for domainIdentifier: String) {
        guard let bookmarksDir = bookmarksDirectory else { return }

        let bookmarkFile = bookmarksDir.appendingPathComponent(sanitizeFilename(domainIdentifier))
        try? FileManager.default.removeItem(at: bookmarkFile)

        logger.info("Deleted bookmark for domain: \(domainIdentifier)")
    }

    /// Check if a bookmark exists for a domain.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    /// - Returns: true if a bookmark is stored.
    static func exists(for domainIdentifier: String) -> Bool {
        guard let bookmarksDir = bookmarksDirectory else { return false }

        let bookmarkFile = bookmarksDir.appendingPathComponent(sanitizeFilename(domainIdentifier))
        return FileManager.default.fileExists(atPath: bookmarkFile.path)
    }

    /// Sanitize a domain identifier for use as a filename.
    private static func sanitizeFilename(_ identifier: String) -> String {
        // Domain identifiers are already base64url which is filename-safe
        // Just add a .bookmark extension
        return identifier + ".bookmark"
    }
}
