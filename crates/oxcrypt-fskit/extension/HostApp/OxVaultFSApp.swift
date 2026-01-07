// OxVaultFSApp.swift
// Container app for the OxVault FSKit extension.
//
// This app serves dual roles:
// 1. Hosts the FSKit extension (embedded in bundle)
// 2. Hosts the XPC service for CLI/Desktop communication
//
// The app runs as a background process (LSUIElement) when launched
// via launchd for XPC, or shows UI when launched directly.

import AppKit
import Foundation
import FSKit
import os

/// Logger for the host app.
private let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "HostApp")

/// Entry point - runs as either UI or background XPC host.
@main
struct OxVaultFSApp {
    static func main() {
        // Check if launched for XPC service (via launchd)
        // Launchd sets environment when activating for Mach service
        let isXPCMode = ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] != nil
            || CommandLine.arguments.contains("--xpc")

        if isXPCMode {
            logger.info("Starting in XPC service mode")
            runAsXPCService()
        } else {
            logger.info("Starting in UI mode")
            runAsUIApp()
        }
    }

    /// Run as background XPC service host.
    static func runAsXPCService() {
        fputs("OxVaultFS: Starting XPC listener setup...\n", stderr)

        // Start XPC listener for CLI/Desktop communication
        let xpcDelegate = HostAppXPCDelegate()
        let listener = NSXPCListener(machServiceName: "com.agucova.oxcrypt.desktop.xpc")
        listener.delegate = xpcDelegate
        listener.resume()

        fputs("OxVaultFS: XPC listener started on com.agucova.oxcrypt.desktop.xpc\n", stderr)
        logger.info("XPC listener started on com.agucova.oxcrypt.desktop.xpc")

        // Run without UI (background mode)
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)  // No dock icon

        // Create a minimal delegate for URL handling in XPC mode
        let appDelegate = XPCModeAppDelegate()
        app.delegate = appDelegate

        // Keep running to handle XPC requests
        app.run()
    }
}

// MARK: - XPC Mode App Delegate (for URL handling in background)

/// Minimal app delegate for XPC mode that handles URL events.
final class XPCModeAppDelegate: NSObject, NSApplicationDelegate {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "XPCModeDelegate")

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.logger.info("XPC mode app delegate initialized")
        // Also write to stderr for debugging
        fputs("OxVaultFS: XPC mode app delegate initialized\n", stderr)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false  // Keep running in XPC mode
    }

    /// Modern URL handling via NSApplicationDelegate - preferred over AppleEvent handler
    func application(_ application: NSApplication, open urls: [URL]) {
        fputs("OxVaultFS: application(_:open:) called with \(urls.count) URLs\n", stderr)
        Self.logger.info("Received \(urls.count) URLs via application(_:open:)")

        for url in urls {
            handleURL(url)
        }
    }

    /// Handle a single oxcrypt:// URL
    private func handleURL(_ url: URL) {
        fputs("OxVaultFS: Handling URL: \(url)\n", stderr)
        Self.logger.info("Handling URL: \(url)")

        guard url.scheme == "oxcrypt" else {
            Self.logger.warning("Ignoring non-oxcrypt URL: \(url.scheme ?? "nil")")
            return
        }

        let vaultPath = url.path
        guard !vaultPath.isEmpty else {
            Self.logger.error("Empty vault path in URL")
            return
        }

        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let mountpoint = components?.queryItems?.first(where: { $0.name == "mount" })?.value

        fputs("OxVaultFS: Mount request - vault=\(vaultPath), mountpoint=\(mountpoint ?? "auto")\n", stderr)
        Self.logger.info("URL mount request: vault=\(vaultPath), mountpoint=\(mountpoint ?? "auto")")

        // Trigger FSKit mount
        Task {
            await triggerFSKitMount(vaultPath: vaultPath, mountpoint: mountpoint)
        }
    }

    /// Trigger FSKit mount using the disk image trigger approach.
    /// Password must already be stored in Keychain (via XPC mount call).
    private func triggerFSKitMount(vaultPath: String, mountpoint: String?) async {
        Self.logger.info("Triggering FSKit mount for: \(vaultPath)")
        fputs("OxVaultFS: Triggering FSKit mount for: \(vaultPath)\n", stderr)

        // Verify password is in Keychain (should have been stored by XPC mount call)
        guard KeychainHelper.exists(for: vaultPath) else {
            fputs("OxVaultFS: Password not found in Keychain - use 'oxcrypt mount' CLI first\n", stderr)
            Self.logger.error("Password not in Keychain for: \(vaultPath)")

            NotificationCenter.default.post(
                name: .oxcryptMountFailed,
                object: nil,
                userInfo: [
                    "vaultPath": vaultPath,
                    "error": "Password not found in Keychain. Use 'oxcrypt mount' CLI command instead."
                ]
            )
            return
        }

        // Use the trigger disk image approach
        let volumeName = URL(fileURLWithPath: vaultPath).lastPathComponent

        do {
            // Create trigger DMG
            fputs("OxVaultFS: Creating trigger DMG...\n", stderr)
            let dmgPath = try TriggerImageManager.createTrigger(
                vaultPath: vaultPath,
                volumeName: volumeName
            )
            fputs("OxVaultFS: Created trigger at: \(dmgPath.path)\n", stderr)

            // Attach trigger - this causes fskitd to probe our extension
            fputs("OxVaultFS: Attaching trigger...\n", stderr)
            let devicePath = try TriggerImageManager.attachTrigger(dmgPath)
            fputs("OxVaultFS: Attached at device: \(devicePath)\n", stderr)

            Self.logger.info("Trigger attached at: \(devicePath)")

            // Post success notification
            NotificationCenter.default.post(
                name: .oxcryptMountRequested,
                object: nil,
                userInfo: [
                    "vaultPath": vaultPath,
                    "mountpoint": mountpoint ?? "/Volumes/\(volumeName)",
                    "status": "trigger_attached",
                    "devicePath": devicePath
                ]
            )

            fputs("OxVaultFS: Mount triggered successfully - FSKit will handle the rest\n", stderr)

        } catch {
            fputs("OxVaultFS: Trigger failed: \(error.localizedDescription)\n", stderr)
            Self.logger.error("Trigger mount failed: \(error.localizedDescription)")

            NotificationCenter.default.post(
                name: .oxcryptMountFailed,
                object: nil,
                userInfo: [
                    "vaultPath": vaultPath,
                    "error": error.localizedDescription
                ]
            )
        }
    }
}

/// Run as UI application showing setup instructions.
private func runAsUIApp() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}

// MARK: - UI App Delegate

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "AppDelegate")

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Register for URL events
        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleURLEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(kInternetEventClass),
            andEventID: AEEventID(kAEGetURL)
        )

        // Create main window with setup instructions
        let contentView = SetupViewController()
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 520),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "OxVault File System"
        window.contentViewController = contentView
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window

        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Handle oxcrypt:// URL events.
    /// These are triggered by the mount flow to activate FSKit.
    @objc func handleURLEvent(_ event: NSAppleEventDescriptor, withReplyEvent replyEvent: NSAppleEventDescriptor) {
        guard let urlString = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue,
              let url = URL(string: urlString) else {
            Self.logger.error("Failed to parse URL from Apple Event")
            return
        }

        Self.logger.info("Received URL: \(url)")

        // oxcrypt:///path/to/vault?mount=/path/to/mountpoint
        guard url.scheme == "oxcrypt" else {
            Self.logger.warning("Ignoring non-oxcrypt URL: \(url.scheme ?? "nil")")
            return
        }

        // The URL path is the vault path
        let vaultPath = url.path
        guard !vaultPath.isEmpty else {
            Self.logger.error("Empty vault path in URL")
            return
        }

        // Extract mountpoint from query parameter
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let mountpoint = components?.queryItems?.first(where: { $0.name == "mount" })?.value

        Self.logger.info("URL mount request: vault=\(vaultPath), mountpoint=\(mountpoint ?? "auto")")

        // Trigger FSKit mount via FSClient
        // FSKit will receive this as FSGenericURLResource and call probeResource/loadResource
        Task {
            await triggerFSKitMount(vaultPath: vaultPath, mountpoint: mountpoint)
        }
    }

    /// Trigger FSKit mount using disk image trigger approach.
    /// Password must already be in Keychain (via XPC mount flow).
    private func triggerFSKitMount(vaultPath: String, mountpoint: String?) async {
        Self.logger.info("Triggering FSKit mount for: \(vaultPath)")

        // Verify password is in Keychain
        guard KeychainHelper.exists(for: vaultPath) else {
            Self.logger.error("Password not in Keychain for: \(vaultPath)")
            NotificationCenter.default.post(
                name: .oxcryptMountFailed,
                object: nil,
                userInfo: [
                    "vaultPath": vaultPath,
                    "error": "Password not found. Use 'oxcrypt mount' CLI command."
                ]
            )
            return
        }

        let volumeName = URL(fileURLWithPath: vaultPath).lastPathComponent

        do {
            // Create and attach trigger DMG
            let dmgPath = try TriggerImageManager.createTrigger(
                vaultPath: vaultPath,
                volumeName: volumeName
            )
            let devicePath = try TriggerImageManager.attachTrigger(dmgPath)

            Self.logger.info("Trigger attached at: \(devicePath)")

            NotificationCenter.default.post(
                name: .oxcryptMountRequested,
                object: nil,
                userInfo: [
                    "vaultPath": vaultPath,
                    "mountpoint": mountpoint ?? "/Volumes/\(volumeName)",
                    "status": "trigger_attached"
                ]
            )
        } catch {
            Self.logger.error("Trigger mount failed: \(error.localizedDescription)")
            NotificationCenter.default.post(
                name: .oxcryptMountFailed,
                object: nil,
                userInfo: ["vaultPath": vaultPath, "error": error.localizedDescription]
            )
        }
    }
}

extension Notification.Name {
    static let oxcryptMountRequested = Notification.Name("oxcryptMountRequested")
    static let oxcryptMountFailed = Notification.Name("oxcryptMountFailed")
}

// MARK: - Setup View Controller

final class SetupViewController: NSViewController {
    override func loadView() {
        let stackView = NSStackView()
        stackView.orientation = .vertical
        stackView.spacing = 20
        stackView.edgeInsets = NSEdgeInsets(top: 40, left: 40, bottom: 40, right: 40)

        // Icon
        let icon = NSImageView()
        icon.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Lock Shield")
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 64, weight: .regular)
        icon.contentTintColor = .controlAccentColor

        // Title
        let titleLabel = NSTextField(labelWithString: "OxVault File System")
        titleLabel.font = .boldSystemFont(ofSize: 24)
        titleLabel.alignment = .center

        // Subtitle
        let subtitleLabel = NSTextField(labelWithString: "Cryptomator Vault Support")
        subtitleLabel.font = .systemFont(ofSize: 18)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.alignment = .center

        // Instructions
        let instructions = """
        To enable the OxVault file system extension:

        1. Open System Settings
        2. Go to General > Login Items & Extensions
        3. Enable "OxVault File System" under File System Extensions

        Once enabled, you can mount Cryptomator vaults using:
        - The oxcrypt CLI: oxcrypt mount <vault> -b fskit
        - The Desktop app (when available)
        """

        let instructionsLabel = NSTextField(wrappingLabelWithString: instructions)
        instructionsLabel.font = .systemFont(ofSize: 13)
        instructionsLabel.textColor = .labelColor

        // Button
        let button = NSButton(
            title: "Open System Settings",
            target: self,
            action: #selector(openSystemSettings)
        )
        button.bezelStyle = .rounded
        button.controlSize = .large

        stackView.addArrangedSubview(icon)
        stackView.addArrangedSubview(titleLabel)
        stackView.addArrangedSubview(subtitleLabel)
        stackView.addArrangedSubview(NSBox()) // Divider
        stackView.addArrangedSubview(instructionsLabel)
        stackView.addArrangedSubview(button)

        stackView.setCustomSpacing(8, after: titleLabel)
        stackView.setCustomSpacing(30, after: subtitleLabel)
        stackView.setCustomSpacing(20, after: instructionsLabel)

        self.view = stackView
    }

    @objc func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - XPC Listener Delegate for Host App

/// Delegate for the Host App's XPC listener.
/// Validates incoming connections and creates service instances.
final class HostAppXPCDelegate: NSObject, NSXPCListenerDelegate {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "HostAppXPC")

    /// Our team ID for code signature validation.
    private static let ourTeamId = "2LR4AGRZW3"

    /// Whether to allow unsigned connections (for development).
    /// Set OXCRYPT_ALLOW_UNSIGNED=1 environment variable to enable.
    private static var allowUnsigned: Bool {
        ProcessInfo.processInfo.environment["OXCRYPT_ALLOW_UNSIGNED"] == "1"
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        fputs("OxVaultFS: XPC connection request from PID \(newConnection.processIdentifier)\n", stderr)
        Self.logger.info("New XPC connection request from PID \(newConnection.processIdentifier)")

        // Get audit token
        var auditToken = audit_token_t()
        let tokenSize = MemoryLayout<audit_token_t>.size
        var auditTokenData = Data(count: tokenSize)

        auditTokenData.withUnsafeMutableBytes { ptr in
            if let baseAddress = ptr.baseAddress {
                memcpy(baseAddress, &auditToken, tokenSize)
            }
        }

        // Validate code signature (or bypass in dev mode)
        let teamId: String
        fputs("OxVaultFS: allowUnsigned=\(Self.allowUnsigned)\n", stderr)
        if let validatedTeamId = validateCodeSignature(for: newConnection) {
            fputs("OxVaultFS: Code signature validated, teamId=\(validatedTeamId)\n", stderr)
            teamId = validatedTeamId
        } else if Self.allowUnsigned {
            fputs("OxVaultFS: Dev mode - accepting unsigned connection\n", stderr)
            Self.logger.warning("Development mode: accepting unsigned connection from PID \(newConnection.processIdentifier)")
            teamId = "unsigned"
        } else {
            fputs("OxVaultFS: Connection REJECTED - invalid code signature\n", stderr)
            Self.logger.warning("Connection rejected: invalid code signature")
            return false
        }

        // Must be signed by our team (or in dev mode)
        guard teamId == Self.ourTeamId || Self.allowUnsigned else {
            fputs("OxVaultFS: Connection REJECTED - wrong team ID (\(teamId))\n", stderr)
            Self.logger.warning("Connection rejected: wrong team ID (\(teamId))")
            return false
        }

        fputs("OxVaultFS: Connection ACCEPTED from team: \(teamId)\n", stderr)
        Self.logger.info("Connection accepted from team: \(teamId)")

        // Configure connection
        newConnection.exportedInterface = NSXPCInterface(with: OxVaultServiceProtocol.self)
        newConnection.exportedObject = HostAppService(
            auditToken: auditTokenData,
            teamId: teamId
        )

        // Handle connection invalidation
        newConnection.invalidationHandler = {
            Self.logger.info("XPC connection invalidated")
        }

        newConnection.interruptionHandler = {
            Self.logger.warning("XPC connection interrupted")
        }

        newConnection.resume()
        return true
    }

    /// Validate code signature of connecting process.
    private func validateCodeSignature(for connection: NSXPCConnection) -> String? {
        let pid = connection.processIdentifier

        var code: SecCode?
        var attributes = [String: Any]()
        attributes[kSecGuestAttributePid as String] = pid

        let status = SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            [],
            &code
        )

        guard status == errSecSuccess, let secCode = code else {
            Self.logger.error("Failed to get SecCode for PID \(pid): \(status)")
            return nil
        }

        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(secCode, [], &staticCode)
        guard staticStatus == errSecSuccess, let secStaticCode = staticCode else {
            Self.logger.error("Failed to get static code: \(staticStatus)")
            return nil
        }

        var info: CFDictionary?
        // Must pass kSecCSSigningInformation to get team identifier
        let infoStatus = SecCodeCopySigningInformation(secStaticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)

        guard infoStatus == errSecSuccess, let signingInfo = info as? [String: Any] else {
            Self.logger.error("Failed to get signing info: \(infoStatus)")
            return nil
        }

        guard let teamId = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String else {
            Self.logger.warning("No team ID in signing info")
            return nil
        }

        // Verify the code is validly signed
        let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(Self.ourTeamId)\""
        var secRequirement: SecRequirement?

        guard SecRequirementCreateWithString(requirement as CFString, [], &secRequirement) == errSecSuccess,
              let req = secRequirement else {
            Self.logger.error("Failed to create security requirement")
            return nil
        }

        let validityStatus = SecCodeCheckValidity(secCode, [], req)
        guard validityStatus == errSecSuccess else {
            Self.logger.warning("Code signature validation failed: \(validityStatus)")
            return nil
        }

        return teamId
    }
}
