// PendingMount.swift
// File-based pending mount state shared between host app and FSKit extension.

import Foundation
import os

/// Pending mount information stored in a shared file.
struct PendingMount: Codable {
    /// Path to the vault directory.
    let vaultPath: String

    /// Desired volume name.
    let volumeName: String

    /// When the mount was requested.
    let requestedAt: Date

    /// Unique ID for this mount request.
    let requestId: UUID
}

/// Manager for pending mount state.
/// Uses a file in Application Support that both host app and extension can access.
enum PendingMountManager {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "PendingMount")

    /// Shared directory for pending mounts.
    private static var pendingDir: URL {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        return appSupport.appendingPathComponent("com.agucova.oxcrypt/pending")
    }

    /// File for pending mount info.
    private static var pendingFile: URL {
        return pendingDir.appendingPathComponent("pending_mount.json")
    }

    /// Write a pending mount request (called by host app before triggering mount).
    static func writePending(vaultPath: String, volumeName: String) throws -> UUID {
        try FileManager.default.createDirectory(at: pendingDir, withIntermediateDirectories: true)

        let pending = PendingMount(
            vaultPath: vaultPath,
            volumeName: volumeName,
            requestedAt: Date(),
            requestId: UUID()
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(pending)
        try data.write(to: pendingFile, options: .atomic)

        logger.info("Wrote pending mount: \(vaultPath) as \(volumeName)")
        return pending.requestId
    }

    /// Read and consume a pending mount request (called by extension in loadResource).
    /// Returns nil if no pending mount or if it's stale (> 30 seconds old).
    static func consumePending() -> PendingMount? {
        guard FileManager.default.fileExists(atPath: pendingFile.path) else {
            logger.info("No pending mount file found")
            return nil
        }

        do {
            let data = try Data(contentsOf: pendingFile)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let pending = try decoder.decode(PendingMount.self, from: data)

            // Check if stale (> 30 seconds old)
            let age = Date().timeIntervalSince(pending.requestedAt)
            if age > 30 {
                logger.warning("Pending mount is stale (\(age)s old), ignoring")
                try? FileManager.default.removeItem(at: pendingFile)
                return nil
            }

            // Consume by deleting
            try FileManager.default.removeItem(at: pendingFile)
            logger.info("Consumed pending mount: \(pending.vaultPath)")
            return pending

        } catch {
            logger.error("Failed to read pending mount: \(error)")
            try? FileManager.default.removeItem(at: pendingFile)
            return nil
        }
    }

    /// Clear any pending mount (for cleanup).
    static func clearPending() {
        try? FileManager.default.removeItem(at: pendingFile)
    }
}
