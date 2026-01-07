// HostAppService.swift
// XPC service implementation for the Host App.
// Handles mount requests by storing passwords in Keychain and triggering FSKit.

import AppKit
import Foundation
import FSKit
import Security
import os

/// XPC service for CLI/Desktop communication hosted in the main app.
/// Unlike the extension-hosted version, this doesn't have direct access to
/// the Rust filesystem. Instead, it stores passwords in Keychain and triggers
/// FSKit to load the extension which reads the password.
final class HostAppService: NSObject, OxVaultServiceProtocol {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "HostAppService")

    /// The audit token of the connected client (for ownership tracking).
    private let clientAuditToken: Data

    /// The team ID of the connected client.
    private let clientTeamId: String

    /// Rate limiting: last request time per operation.
    private var lastRequestTime: Date = .distantPast
    private let minRequestInterval: TimeInterval = 0.1  // 100ms between requests

    init(auditToken: Data, teamId: String) {
        self.clientAuditToken = auditToken
        self.clientTeamId = teamId
        super.init()
        Self.logger.info("HostAppService initialized for client with team ID: \(teamId)")
    }

    // MARK: - OxVaultServiceProtocol

    func mount(
        vaultPath: String,
        password: String,
        reply: @escaping (String?, NSError?) -> Void
    ) {
        fputs("HostAppService: Mount request received for: \(vaultPath)\n", stderr)
        Self.logger.info("Mount request for: \(vaultPath)")

        // Rate limiting
        guard checkRateLimit() else {
            Self.logger.warning("Rate limit exceeded")
            reply(nil, OxVaultServiceError.resourceExhausted.nsError)
            return
        }

        // Input validation
        guard let validatedPath = validateVaultPath(vaultPath) else {
            fputs("HostAppService: Invalid vault path: \(vaultPath)\n", stderr)
            Self.logger.warning("Invalid vault path: \(vaultPath)")
            reply(nil, OxVaultServiceError.invalidVault.nsError)
            return
        }
        fputs("HostAppService: Vault path validated: \(validatedPath)\n", stderr)

        guard !password.isEmpty, password.count <= 10240 else {
            Self.logger.warning("Invalid password (empty or too long)")
            reply(nil, OxVaultServiceError.authFailed.nsError)
            return
        }

        Task {
            do {
                fputs("HostAppService: [Task] Starting mount task...\n", stderr)

                // 1. Store password in Keychain for FSKit extension to use
                fputs("HostAppService: [Task] Storing password in Keychain...\n", stderr)
                try KeychainHelper.store(password: password, for: validatedPath)
                fputs("HostAppService: [Task] Password stored in Keychain\n", stderr)
                Self.logger.info("Password stored in Keychain")

                // Generate mountpoint in user-accessible location (~/Vaults)
                // /Volumes requires root to create directories
                let volumeName = URL(fileURLWithPath: validatedPath).lastPathComponent
                let vaultsDir = FileManager.default.homeDirectoryForCurrentUser
                    .appendingPathComponent("Vaults")
                let mountpoint = vaultsDir.appendingPathComponent(volumeName).path
                fputs("HostAppService: [Task] Mountpoint will be: \(mountpoint)\n", stderr)

                // Register the mount
                fputs("HostAppService: [Task] Registering mount in registry...\n", stderr)
                _ = try await MountRegistry.shared.register(
                    vaultPath: validatedPath,
                    mountpoint: mountpoint,
                    ownerAuditToken: clientAuditToken,
                    ownerTeamId: clientTeamId
                )
                fputs("HostAppService: [Task] Mount registered\n", stderr)

                Self.logger.info("Triggering FSKit mount via trigger DMG: vault=\(validatedPath)")
                fputs("HostAppService: [Task] Triggering FSKit mount via trigger DMG...\n", stderr)

                // 2. Mount using RAW trigger disk image approach (FSKitBridge style)
                // - Create a raw disk image (no filesystem)
                // - Attach with CRawDiskImage + -nomount (no driver claims it)
                // - Call mount -F -t oxcrypt to trigger fskitd probing
                var devicePath: String = ""
                do {
                    // Create raw trigger DMG
                    fputs("HostAppService: [Task] Creating RAW trigger DMG...\n", stderr)
                    let dmgPath = try TriggerImageManager.createTrigger(
                        vaultPath: validatedPath,
                        volumeName: volumeName
                    )
                    fputs("HostAppService: [Task] Created trigger at: \(dmgPath.path)\n", stderr)

                    // Attach trigger with CRawDiskImage/-nomount
                    fputs("HostAppService: [Task] Attaching RAW trigger (no mount)...\n", stderr)
                    devicePath = try TriggerImageManager.attachTrigger(dmgPath)
                    fputs("HostAppService: [Task] Attached at device: \(devicePath)\n", stderr)
                    Self.logger.info("Trigger attached at: \(devicePath)")

                    // Write pending mount info for extension to read
                    fputs("HostAppService: [Task] Writing pending mount info...\n", stderr)
                    _ = try PendingMountManager.writePending(
                        vaultPath: validatedPath,
                        volumeName: volumeName
                    )
                    fputs("HostAppService: [Task] Pending mount info written\n", stderr)

                    // Now trigger FSKit by calling mount -F
                    fputs("HostAppService: [Task] Calling mount -F -t oxcrypt...\n", stderr)
                    try TriggerImageManager.mountFSKit(
                        device: devicePath,
                        mountpoint: mountpoint,
                        vaultPath: validatedPath
                    )
                    fputs("HostAppService: [Task] FSKit mount command succeeded\n", stderr)
                    Self.logger.info("FSKit mount triggered for: \(mountpoint)")

                } catch {
                    fputs("HostAppService: [Task] Trigger mount failed: \(error.localizedDescription)\n", stderr)
                    Self.logger.error("Trigger mount failed: \(error)")
                    // Clean up device if attached
                    if !devicePath.isEmpty {
                        TriggerImageManager.detachTrigger(devicePath)
                    }
                    _ = await MountRegistry.shared.unregister(mountpoint: mountpoint)
                    throw OxVaultServiceError.mountFailed
                }

                // 3. Verify mount appeared
                fputs("HostAppService: [Task] Waiting for mount to appear...\n", stderr)
                let mounted = await waitForMount(mountpoint: mountpoint, timeout: 10.0)

                if mounted {
                    fputs("HostAppService: [Task] Mount successful: \(mountpoint)\n", stderr)
                    Self.logger.info("Mount successful: \(mountpoint)")
                    reply(mountpoint, nil)
                } else {
                    fputs("HostAppService: [Task] Mount did not appear within timeout\n", stderr)
                    Self.logger.warning("Mount did not appear within timeout")
                    _ = await MountRegistry.shared.unregister(mountpoint: mountpoint)
                    throw OxVaultServiceError.mountFailed
                }

            } catch let error as OxVaultServiceError {
                fputs("HostAppService: [Task] Mount failed with OxVaultServiceError: \(error.nsError.localizedDescription)\n", stderr)
                Self.logger.error("Mount failed: \(error.nsError.localizedDescription)")
                try? KeychainHelper.delete(for: validatedPath)
                reply(nil, error.nsError)

            } catch {
                fputs("HostAppService: [Task] Mount failed with unexpected error: \(error)\n", stderr)
                Self.logger.error("Mount failed with error: \(error)")
                try? KeychainHelper.delete(for: validatedPath)
                reply(nil, OxVaultServiceError.mountFailed.nsError)
            }
        }
    }

    func unmount(
        mountpoint: String,
        reply: @escaping (NSError?) -> Void
    ) {
        Self.logger.info("Unmount request for: \(mountpoint)")

        // Rate limiting
        guard checkRateLimit() else {
            reply(OxVaultServiceError.resourceExhausted.nsError)
            return
        }

        // Validate mountpoint
        guard validateMountpoint(mountpoint) else {
            Self.logger.warning("Invalid mountpoint: \(mountpoint)")
            reply(OxVaultServiceError.invalidVault.nsError)
            return
        }

        Task {
            // Check access permission
            let canAccess = await MountRegistry.shared.canAccess(
                mountpoint: mountpoint,
                clientAuditToken: clientAuditToken,
                clientTeamId: clientTeamId
            )

            guard canAccess else {
                Self.logger.warning("Permission denied for unmount: \(mountpoint)")
                reply(OxVaultServiceError.permissionDenied.nsError)
                return
            }

            // Get mount info
            guard let mountInfo = await MountRegistry.shared.get(mountpoint: mountpoint) else {
                Self.logger.warning("Mount not found: \(mountpoint)")
                reply(OxVaultServiceError.notFound.nsError)
                return
            }

            do {
                // Unmount via diskutil (FSKit volumes can be unmounted this way)
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
                process.arguments = ["unmount", mountpoint]

                try process.run()
                process.waitUntilExit()

                if process.terminationStatus != 0 {
                    Self.logger.warning("diskutil unmount failed with status: \(process.terminationStatus)")
                    // Try force unmount
                    let forceProcess = Process()
                    forceProcess.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
                    forceProcess.arguments = ["unmount", "force", mountpoint]
                    try forceProcess.run()
                    forceProcess.waitUntilExit()
                }

                // Clean up
                _ = await MountRegistry.shared.unregister(mountpoint: mountpoint)
                try? KeychainHelper.delete(for: mountInfo.vaultPath)

                Self.logger.info("Unmount successful: \(mountpoint)")
                reply(nil)

            } catch {
                Self.logger.error("Unmount failed: \(error)")
                reply(OxVaultServiceError.mountFailed.nsError)
            }
        }
    }

    func listMounts(
        reply: @escaping ([[String: Any]]?, NSError?) -> Void
    ) {
        Self.logger.info("List mounts request")

        Task {
            let mounts = await MountRegistry.shared.listMounts(forClientWithTeamId: clientTeamId)
            let dicts = mounts.map { $0.toDictionary() }
            reply(dicts, nil)
        }
    }

    func getStats(
        mountpoint: String,
        reply: @escaping ([String: Any]?, NSError?) -> Void
    ) {
        Self.logger.info("Get stats request for: \(mountpoint)")

        Task {
            // Check access permission
            let canAccess = await MountRegistry.shared.canAccess(
                mountpoint: mountpoint,
                clientAuditToken: clientAuditToken,
                clientTeamId: clientTeamId
            )

            guard canAccess else {
                Self.logger.warning("Permission denied for stats: \(mountpoint)")
                reply(nil, OxVaultServiceError.permissionDenied.nsError)
                return
            }

            guard let mountInfo = await MountRegistry.shared.get(mountpoint: mountpoint) else {
                reply(nil, OxVaultServiceError.notFound.nsError)
                return
            }

            // Return basic mount info
            // TODO: Could query the mount for actual FS stats via statfs
            let stats: [String: Any] = [
                "vaultPath": mountInfo.vaultPath,
                "mountpoint": mountInfo.mountpoint,
                "mountedAt": ISO8601DateFormatter().string(from: mountInfo.mountedAt),
                "bytesRead": 0,
                "bytesWritten": 0,
                "filesOpened": 0,
                "opsCount": 0
            ]

            reply(stats, nil)
        }
    }

    func ping(reply: @escaping (Bool) -> Void) {
        Self.logger.debug("Ping received")
        reply(true)
    }

    // MARK: - Helpers

    /// Wait for a mount to appear at the given mountpoint.
    private func waitForMount(mountpoint: String, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        let checkInterval: UInt64 = 200_000_000  // 200ms

        while Date() < deadline {
            // Check if mountpoint is mounted
            var statBuf = statfs()
            if statfs(mountpoint, &statBuf) == 0 {
                // Check it's not just the directory
                let mountPath = withUnsafePointer(to: &statBuf.f_mntonname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { cString in
                        String(cString: cString)
                    }
                }
                if mountPath == mountpoint {
                    return true
                }
            }

            try? await Task.sleep(nanoseconds: checkInterval)
        }

        return false
    }

    /// Validate and canonicalize a vault path.
    private func validateVaultPath(_ path: String) -> String? {
        guard path.hasPrefix("/") else {
            return nil
        }

        let url = URL(fileURLWithPath: path).standardized
        let canonicalPath = url.path

        let vaultConfigPath = url.appendingPathComponent("vault.cryptomator").path
        guard FileManager.default.fileExists(atPath: vaultConfigPath) else {
            Self.logger.warning("No vault.cryptomator found at: \(canonicalPath)")
            return nil
        }

        return canonicalPath
    }

    /// Validate a mountpoint path.
    private func validateMountpoint(_ path: String) -> Bool {
        guard path.hasPrefix("/") else {
            return false
        }

        let allowedPrefixes = ["/Volumes/", "/tmp/", NSHomeDirectory() + "/"]
        return allowedPrefixes.contains { path.hasPrefix($0) }
    }

    /// Generate a mountpoint for a vault.
    /// Uses ~/Vaults/ to avoid needing admin privileges for /Volumes/
    private func generateMountpoint(for vaultPath: String) -> String {
        let vaultName = URL(fileURLWithPath: vaultPath).lastPathComponent
        let sanitizedName = vaultName.replacingOccurrences(of: " ", with: "_")
        let vaultsDir = NSHomeDirectory() + "/Vaults"
        return "\(vaultsDir)/\(sanitizedName)"
    }

    /// Check rate limiting.
    private func checkRateLimit() -> Bool {
        let now = Date()
        guard now.timeIntervalSince(lastRequestTime) >= minRequestInterval else {
            return false
        }
        lastRequestTime = now
        return true
    }
}
