// MountRegistry.swift
// Thread-safe registry for tracking active FSKit mounts with ownership.

import Foundation
import os

/// Information about an active mount.
struct MountInfo: Sendable {
    /// Unique identifier for this mount.
    let mountId: UUID

    /// Path to the vault directory.
    let vaultPath: String

    /// Mountpoint where the vault is mounted.
    let mountpoint: String

    /// When the mount was created.
    let mountedAt: Date

    /// Audit token of the process that requested the mount (for ownership).
    let ownerAuditToken: Data

    /// Team ID of the process that requested the mount.
    let ownerTeamId: String

    /// Convert to dictionary for XPC response.
    func toDictionary() -> [String: Any] {
        return [
            "mountId": mountId.uuidString,
            "vaultPath": vaultPath,
            "mountpoint": mountpoint,
            "mountedAt": ISO8601DateFormatter().string(from: mountedAt),
            "backend": "fskit"
        ]
    }
}

/// Thread-safe registry for active mounts.
/// Tracks mount ownership to ensure only the creator (or same team) can query/unmount.
actor MountRegistry {
    /// Singleton instance.
    static let shared = MountRegistry()

    /// Active mounts by mountpoint.
    private var mounts: [String: MountInfo] = [:]

    /// Mounts by vault path (for detecting duplicate mount attempts).
    private var mountsByVault: [String: String] = [:]  // vaultPath -> mountpoint

    /// Maximum number of concurrent mounts (resource exhaustion protection).
    private let maxMounts = 10

    private let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "MountRegistry")

    private init() {}

    /// Register a new mount.
    /// - Throws: If vault is already mounted or max mounts reached.
    func register(
        vaultPath: String,
        mountpoint: String,
        ownerAuditToken: Data,
        ownerTeamId: String
    ) throws -> MountInfo {
        // Check if vault is already mounted
        if let existingMountpoint = mountsByVault[vaultPath] {
            logger.warning("Vault already mounted: \(vaultPath) at \(existingMountpoint)")
            throw OxVaultServiceError.alreadyMounted
        }

        // Check max mounts
        if mounts.count >= maxMounts {
            logger.warning("Maximum mounts reached (\(self.maxMounts))")
            throw OxVaultServiceError.resourceExhausted
        }

        let info = MountInfo(
            mountId: UUID(),
            vaultPath: vaultPath,
            mountpoint: mountpoint,
            mountedAt: Date(),
            ownerAuditToken: ownerAuditToken,
            ownerTeamId: ownerTeamId
        )

        mounts[mountpoint] = info
        mountsByVault[vaultPath] = mountpoint

        logger.info("Registered mount: \(mountpoint) for vault \(vaultPath)")
        return info
    }

    /// Unregister a mount.
    /// - Returns: The removed mount info, or nil if not found.
    func unregister(mountpoint: String) -> MountInfo? {
        guard let info = mounts.removeValue(forKey: mountpoint) else {
            return nil
        }

        mountsByVault.removeValue(forKey: info.vaultPath)
        logger.info("Unregistered mount: \(mountpoint)")
        return info
    }

    /// Get mount info by mountpoint.
    func get(mountpoint: String) -> MountInfo? {
        return mounts[mountpoint]
    }

    /// Get mount info by vault path.
    func getByVaultPath(_ vaultPath: String) -> MountInfo? {
        guard let mountpoint = mountsByVault[vaultPath] else {
            return nil
        }
        return mounts[mountpoint]
    }

    /// List all mounts visible to the given client.
    /// A mount is visible if:
    /// 1. The client is the owner (same audit token), OR
    /// 2. The client has the same team ID
    func listMounts(forClientWithTeamId teamId: String) -> [MountInfo] {
        return Array(mounts.values.filter { mount in
            mount.ownerTeamId == teamId
        })
    }

    /// Check if a client can access a mount.
    /// Access is allowed if:
    /// 1. The client is the owner, OR
    /// 2. The client has the same team ID
    func canAccess(
        mountpoint: String,
        clientAuditToken: Data,
        clientTeamId: String
    ) -> Bool {
        guard let mount = mounts[mountpoint] else {
            return false
        }

        return mount.ownerAuditToken == clientAuditToken ||
               mount.ownerTeamId == clientTeamId
    }

    /// Get all mountpoints (for cleanup on extension termination).
    func allMountpoints() -> [String] {
        return Array(mounts.keys)
    }

    /// Clear all mounts (for cleanup).
    func clear() {
        mounts.removeAll()
        mountsByVault.removeAll()
        logger.info("Cleared all mounts")
    }
}
