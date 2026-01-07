import Foundation
import os.log

/// Manages trigger disk images for FSKit mounting.
/// When a trigger disk image is attached, fskitd automatically probes registered
/// FSKit extensions, allowing us to bootstrap vault mounting without private APIs.
class TriggerImageManager {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "TriggerImageManager")

    /// Directory where trigger DMGs are stored
    private static var triggerDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("com.agucova.oxcrypt/triggers")
    }

    /// Creates a RAW trigger disk image (no filesystem).
    /// FSKitBridge approach: raw image won't be claimed by any driver,
    /// allowing our FSKit extension to be probed.
    /// - Parameters:
    ///   - vaultPath: Absolute path to the Cryptomator vault
    ///   - volumeName: Desired name for the mounted volume
    /// - Returns: URL to the created raw image file
    static func createTrigger(vaultPath: String, volumeName: String) throws -> URL {
        logger.info("Creating RAW trigger for vault: \(vaultPath)")

        // Ensure trigger directory exists
        try FileManager.default.createDirectory(at: triggerDir, withIntermediateDirectories: true)

        // Create unique image filename based on vault path
        let imageName = "trigger-\(abs(vaultPath.hashValue)).dmg"
        let imagePath = triggerDir.appendingPathComponent(imageName)

        // Remove existing image if present
        try? FileManager.default.removeItem(at: imagePath)

        // Create a small raw disk image (1MB)
        // This is just an empty file that hdiutil will attach as CRawDiskImage
        let imageSize = 1024 * 1024  // 1MB
        let emptyData = Data(count: imageSize)
        try emptyData.write(to: imagePath)

        logger.info("Created RAW trigger image at: \(imagePath.path)")
        return imagePath
    }

    /// Attaches a RAW trigger disk image WITHOUT mounting it.
    /// Uses CRawDiskImage class so no filesystem driver claims the device.
    /// - Parameter imagePath: Path to the raw image file
    /// - Returns: The device path (e.g., /dev/disk4) for FSKit mounting
    static func attachTrigger(_ imagePath: URL) throws -> String {
        logger.info("Attaching RAW trigger (no-mount): \(imagePath.path)")

        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = [
            "attach",
            "-imagekey", "diskimage-class=CRawDiskImage",  // Treat as raw disk image
            "-nomount",                                      // Don't auto-mount!
            "-plist",                                        // Output as plist for parsing
            imagePath.path
        ]
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorMsg = String(data: errorData, encoding: .utf8) ?? "Unknown error"
            logger.error("hdiutil attach failed: \(errorMsg)")
            throw TriggerError.attachFailed(errorMsg)
        }

        // Parse plist output to get device path
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let entities = plist["system-entities"] as? [[String: Any]],
              let entity = entities.first,
              let devicePath = entity["dev-entry"] as? String else {
            throw TriggerError.parseError("Failed to parse hdiutil output")
        }

        logger.info("Attached RAW trigger at device: \(devicePath)")
        return devicePath
    }

    /// Mounts the FSKit filesystem using the attached device.
    /// This triggers fskitd to probe our FSKit extension.
    /// - Parameters:
    ///   - device: The device path from attachTrigger (e.g., /dev/disk4)
    ///   - mountpoint: Where to mount the filesystem
    ///   - vaultPath: Path to the vault (passed as mount option)
    static func mountFSKit(device: String, mountpoint: String, vaultPath: String) throws {
        logger.info("Mounting FSKit: device=\(device) mountpoint=\(mountpoint) vault=\(vaultPath)")

        // Ensure mountpoint exists
        try FileManager.default.createDirectory(
            atPath: mountpoint,
            withIntermediateDirectories: true,
            attributes: nil
        )

        let process = Process()
        let errorPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/sbin/mount")
        process.arguments = [
            "-F",                           // Force FSKit
            "-t", "oxcrypt",                // Our filesystem type
            "-o", "vaultPath=\(vaultPath)", // Pass vault path as option
            device,                         // Device to mount
            mountpoint                      // Mount point
        ]
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorMsg = String(data: errorData, encoding: .utf8) ?? "Unknown error"
            logger.error("mount -F failed: \(errorMsg)")
            throw TriggerError.mountFailed(errorMsg)
        }

        logger.info("FSKit mount successful at: \(mountpoint)")
    }

    /// Detaches a trigger disk image.
    /// - Parameter devicePath: The device path returned from attachTrigger
    static func detachTrigger(_ devicePath: String) {
        logger.info("Detaching trigger: \(devicePath)")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = ["detach", devicePath, "-force"]

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus != 0 {
                logger.warning("hdiutil detach returned non-zero status for \(devicePath)")
            }
        } catch {
            logger.error("Failed to detach trigger: \(error.localizedDescription)")
        }
    }

    /// Detaches a trigger by its mount point in /Volumes.
    /// - Parameter volumePath: Path to the mounted volume (e.g., /Volumes/OxCryptTrigger)
    static func detachTriggerByVolume(_ volumePath: String) {
        logger.info("Detaching trigger by volume: \(volumePath)")

        // Use diskutil to get the device identifier
        let infoProcess = Process()
        let infoPipe = Pipe()
        infoProcess.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
        infoProcess.arguments = ["info", "-plist", volumePath]
        infoProcess.standardOutput = infoPipe

        do {
            try infoProcess.run()
            infoProcess.waitUntilExit()

            if infoProcess.terminationStatus == 0 {
                let data = infoPipe.fileHandleForReading.readDataToEndOfFile()
                if let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                   let deviceId = plist["DeviceIdentifier"] as? String {
                    detachTrigger("/dev/\(deviceId)")
                    return
                }
            }
        } catch {
            logger.warning("diskutil info failed, attempting direct unmount")
        }

        // Fallback: try unmounting directly
        let unmountProcess = Process()
        unmountProcess.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
        unmountProcess.arguments = ["unmount", "force", volumePath]
        try? unmountProcess.run()
        unmountProcess.waitUntilExit()
    }

    /// Cleans up old trigger disk images.
    /// - Parameter interval: Maximum age for trigger images (default: 24 hours)
    static func cleanup(olderThan interval: TimeInterval = 86400) {
        logger.info("Cleaning up old trigger images")

        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: triggerDir,
            includingPropertiesForKeys: [.creationDateKey]
        ) else {
            return
        }

        let cutoff = Date().addingTimeInterval(-interval)
        var cleanedCount = 0

        for url in contents where url.pathExtension == "dmg" {
            if let values = try? url.resourceValues(forKeys: [.creationDateKey]),
               let creationDate = values.creationDate,
               creationDate < cutoff {
                do {
                    try FileManager.default.removeItem(at: url)
                    cleanedCount += 1
                } catch {
                    logger.warning("Failed to remove old trigger: \(url.lastPathComponent)")
                }
            }
        }

        if cleanedCount > 0 {
            logger.info("Cleaned up \(cleanedCount) old trigger image(s)")
        }
    }

    /// Finds and detaches all currently mounted trigger volumes.
    static func detachAllTriggers() {
        let volumesDir = URL(fileURLWithPath: "/Volumes")
        guard let volumes = try? FileManager.default.contentsOfDirectory(at: volumesDir, includingPropertiesForKeys: nil) else {
            return
        }

        for volumeURL in volumes {
            if TriggerMarker.exists(at: volumeURL) {
                logger.info("Found mounted trigger at \(volumeURL.path), detaching...")
                detachTriggerByVolume(volumeURL.path)
            }
        }
    }
}

/// Errors that can occur during trigger operations
enum TriggerError: LocalizedError {
    case createFailed(String)
    case attachFailed(String)
    case parseError(String)
    case mountFailed(String)

    var errorDescription: String? {
        switch self {
        case .createFailed(let msg): return "Failed to create trigger DMG: \(msg)"
        case .attachFailed(let msg): return "Failed to attach trigger DMG: \(msg)"
        case .parseError(let msg): return "Failed to parse hdiutil output: \(msg)"
        case .mountFailed(let msg): return "Failed to mount FSKit filesystem: \(msg)"
        }
    }
}
