// OxCryptFileProviderApp.swift
// Main entry point for the File Provider host application.
// This app hosts the File Provider extension and provides CLI/XPC for domain management.
//
// Supports three modes:
// 1. CLI mode: `OxCryptFileProvider register|unregister|list|status ...`
// 2. Daemon mode: `OxCryptFileProvider --daemon` or `--xpc` (background service, no GUI)
// 3. GUI mode: Launch without arguments (shows window for debugging)

import AppKit
import FileProvider
import Foundation
import os.log
import Security
import SwiftUI

// MARK: - Private API Access for Audit Token

/// Extension to access the private auditToken property on NSXPCConnection
/// This is necessary for secure caller verification to prevent PID reuse attacks
/// See: https://knight.sc/reverse%20engineering/2020/03/20/audit-tokens-explained.html
extension NSXPCConnection {
    var auditToken: audit_token_t {
        // Access the private property using key-value coding
        // Returns NSValue wrapping the audit_token_t struct
        var token = audit_token_t()
        if let value = self.value(forKey: "auditToken") as? NSValue {
            value.getValue(&token)
        }
        return token
    }
}

/// Logger for the host app.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "HostApp")

// MARK: - Entry Point

/// Main entry point - handles CLI, daemon, and GUI modes before SwiftUI initializes.
@main
enum AppMain {
    static func main() {
        let args = CommandLine.arguments

        // CLI mode: handle commands and exit
        if args.count > 1 {
            let command = args[1]

            // CLI commands
            if command == "register" || command == "unregister" || command == "list" || command == "status" {
                runCLI()
                exit(0)
            }

            // Daemon mode: run pure NSApplication without GUI
            if command == "--daemon" || command == "--xpc" {
                runDaemon()
                // Never returns
            }
        }

        // GUI mode: launch SwiftUI app (for debugging/manual use)
        OxCryptFileProviderApp.main()
    }
}

/// Run as a background daemon with XPC services but no GUI.
private func runDaemon() {
    logger.info("Starting OxCrypt File Provider in daemon mode")

    let app = NSApplication.shared
    let delegate = AppDelegate()

    app.delegate = delegate
    app.setActivationPolicy(.accessory)  // No dock icon, no menu bar

    // Run the event loop (blocks forever)
    app.run()
}

// MARK: - SwiftUI App (GUI Mode)

struct OxCryptFileProviderApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .commands {
            CommandGroup(replacing: .appTermination) {
                Button("Quit OxCrypt File Provider") {
                    NSApplication.shared.terminate(nil)
                }
                .keyboardShortcut("q")
            }
        }
    }
}

/// Run the CLI commands without launching the full app.
private func runCLI() {
    let args = CommandLine.arguments
    guard args.count > 1 else {
        printUsage()
        return
    }

    let command = args[1]

    switch command {
    case "register":
        cliRegister(args: Array(args.dropFirst(2)))
    case "unregister":
        cliUnregister(args: Array(args.dropFirst(2)))
    case "list":
        cliList()
    case "status":
        cliStatus(args: Array(args.dropFirst(2)))
    default:
        printUsage()
    }
}

private func printUsage() {
    fputs("""
        Usage: OxCryptFileProvider <command> [options]

        Commands:
          register --vault <path> --name <name>
              Register a vault as a File Provider domain.
              Password is read from OXCRYPT_PASSWORD environment variable.

          unregister --domain <id>
              Unregister a File Provider domain.

          list
              List all registered domains.

          status --domain <id>
              Check if a domain is active.

        Daemon Mode:
          --daemon  Run as background service (no GUI, XPC services only)
          --xpc     Alias for --daemon

        GUI Mode:
          Launch without arguments to show the management window.

        """, stderr)
}

private func cliRegister(args: [String]) {
    var vaultPath: String?
    var displayName: String?

    // Parse arguments
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--vault":
            if i + 1 < args.count {
                vaultPath = args[i + 1]
                i += 2
            } else {
                fputs("Error: --vault requires a path\n", stderr)
                exit(1)
            }
        case "--name":
            if i + 1 < args.count {
                displayName = args[i + 1]
                i += 2
            } else {
                fputs("Error: --name requires a value\n", stderr)
                exit(1)
            }
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
            exit(1)
        }
    }

    guard let vault = vaultPath else {
        fputs("Error: --vault is required\n", stderr)
        exit(1)
    }

    // Get password from environment
    guard let password = ProcessInfo.processInfo.environment["OXCRYPT_PASSWORD"] else {
        fputs("Error: OXCRYPT_PASSWORD environment variable not set\n", stderr)
        exit(1)
    }

    // Use vault name if display name not provided
    let name = displayName ?? URL(fileURLWithPath: vault).lastPathComponent

    // Run the registration
    let semaphore = DispatchSemaphore(value: 0)
    var result: (success: Bool, message: String?) = (false, nil)

    Task {
        do {
            let domainId = try await DomainManager.registerDomain(
                vaultPath: vault,
                displayName: name,
                password: password
            )
            result = (true, domainId)
        } catch {
            result = (false, error.localizedDescription)
        }
        semaphore.signal()
    }

    semaphore.wait()

    if result.success {
        print("OK:\(result.message ?? "")")
    } else {
        fputs("Error: \(result.message ?? "Unknown error")\n", stderr)
        exit(1)
    }
}

private func cliUnregister(args: [String]) {
    var domainId: String?

    // Parse arguments
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--domain":
            if i + 1 < args.count {
                domainId = args[i + 1]
                i += 2
            } else {
                fputs("Error: --domain requires an ID\n", stderr)
                exit(1)
            }
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
            exit(1)
        }
    }

    guard let domain = domainId else {
        fputs("Error: --domain is required\n", stderr)
        exit(1)
    }

    let semaphore = DispatchSemaphore(value: 0)
    var error: Error?

    Task {
        do {
            try await DomainManager.unregisterDomain(domain)
        } catch let e {
            error = e
        }
        semaphore.signal()
    }

    semaphore.wait()

    if let err = error {
        fputs("Error: \(err.localizedDescription)\n", stderr)
        exit(1)
    } else {
        print("OK")
    }
}

private func cliList() {
    let semaphore = DispatchSemaphore(value: 0)
    var domains: [(identifier: String, displayName: String)] = []
    var error: Error?

    Task {
        do {
            domains = try await DomainManager.listDomains()
        } catch let e {
            error = e
        }
        semaphore.signal()
    }

    semaphore.wait()

    if let err = error {
        fputs("Error: \(err.localizedDescription)\n", stderr)
        exit(1)
    }

    if domains.isEmpty {
        print("No domains registered")
    } else {
        for domain in domains {
            print("\(domain.identifier)\t\(domain.displayName)")
        }
    }
}

private func cliStatus(args: [String]) {
    var domainId: String?

    // Parse arguments
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--domain":
            if i + 1 < args.count {
                domainId = args[i + 1]
                i += 2
            } else {
                fputs("Error: --domain requires an ID\n", stderr)
                exit(1)
            }
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
            exit(1)
        }
    }

    guard let domain = domainId else {
        fputs("Error: --domain is required\n", stderr)
        exit(1)
    }

    let semaphore = DispatchSemaphore(value: 0)
    var isActive = false

    Task {
        isActive = await DomainManager.isDomainActive(domain)
        semaphore.signal()
    }

    semaphore.wait()

    if isActive {
        print("ACTIVE")
    } else {
        print("INACTIVE")
    }
}

/// Application delegate for handling XPC service and lifecycle.
class AppDelegate: NSObject, NSApplicationDelegate {
    private var xpcListener: NSXPCListener?
    private let xpcService = HostAppService()
    private var passwordServiceListener: NSXPCListener?
    private let passwordLogger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "XPC")

    func applicationDidFinishLaunching(_ notification: Notification) {
        let isDaemonMode = CommandLine.arguments.contains("--daemon") || CommandLine.arguments.contains("--xpc")

        if isDaemonMode {
            logger.info("OxCrypt File Provider starting in daemon mode")
        } else {
            logger.info("OxCrypt File Provider starting in GUI mode")
        }

        // Set up XPC listener for CLI/GUI communication (daemon mode only needs this)
        if isDaemonMode {
            setupXPCListener()
        }

        // Start XPC listener for secure password retrieval (always needed)
        startPasswordServiceListener()

        // Register existing domains if needed
        Task {
            await registerExistingDomains()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        logger.info("OxCrypt File Provider Host App terminating")
    }

    /// Start XPC listener for secure password retrieval service
    private func startPasswordServiceListener() {
        // Write to file for debugging (bypass stdout issues)
        try? "startPasswordServiceListener called\n".write(toFile: "/tmp/oxcrypt_debug.log", atomically: false, encoding: .utf8)
        print("DEBUG: startPasswordServiceListener called")
        passwordLogger.info("startPasswordServiceListener called")

        guard #available(macOS 13.0, *) else {
            print("DEBUG: macOS version too old")
            passwordLogger.error("Password retrieval service requires macOS 13.0+")
            return
        }

        print("DEBUG: Creating NSXPCListener")
        let listener = NSXPCListener(machServiceName: "com.agucova.oxcrypt.fileprovider.password-service")
        print("DEBUG: Created listener: \(listener)")
        passwordLogger.info("Created NSXPCListener with service name: com.agucova.oxcrypt.fileprovider.password-service")

        print("DEBUG: Setting delegate")
        listener.delegate = self
        print("DEBUG: Delegate set to: \(self)")
        passwordLogger.info("Set delegate to self: \(self)")

        print("DEBUG: Calling resume()")
        listener.resume()
        print("DEBUG: Resume called")
        passwordLogger.info("Called resume() on listener")

        self.passwordServiceListener = listener
        print("DEBUG: Listener stored in passwordServiceListener")
        passwordLogger.info("XPC listener started for password retrieval service - stored in passwordServiceListener")
    }

    /// Create code signing requirement for password retrieval authorization
    ///
    /// Requirements:
    /// 1. Valid Apple signing (anchor apple generic)
    /// 2. Team ID 2LR4AGRZW3
    /// 3. Bundle ID matching com.agucova.oxcrypt.*
    /// 4. Entitlement: com.agucova.oxcrypt.password-retrieval
    ///
    /// See: https://developer.apple.com/forums/thread/681053 (Validating Signature Of XPC Process)
    @available(macOS 13.0, *)
    private func createPasswordRetrievalRequirement() -> String {
        """
        anchor apple generic
        and certificate leaf[subject.OU] = "2LR4AGRZW3"
        and entitlement["com.agucova.oxcrypt.password-retrieval"]
        """
    }

    /// Verify caller's code signature manually using Security framework
    ///
    /// This implements the security checks that setCodeSigningRequirement() would do,
    /// but manually so we can debug what's failing.
    ///
    /// Verify that the connecting process is authorized to retrieve passwords.
    ///
    /// Security checks (defense-in-depth):
    /// 1. Signature is valid (not revoked, not corrupted)
    /// 2. Team ID matches 2LR4AGRZW3
    /// 3. Bundle ID matches com.agucova.oxcrypt.* pattern
    ///
    /// Uses audit token (not PID) to prevent race condition attacks.
    /// See: https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
    private func verifyCallerAuthorized(_ connection: NSXPCConnection) -> Bool {
        passwordLogger.debug("Verifying caller authorization")

        // Get audit token (private property, accessed via extension)
        // This prevents PID reuse attacks - see https://knight.sc/reverse%20engineering/2020/03/20/audit-tokens-explained.html
        var auditToken = connection.auditToken
        let auditData = Data(bytes: &auditToken, count: MemoryLayout<audit_token_t>.size)

        // Check if audit token is all zeros (indicates KVC extraction failed)
        let isZero = auditData.allSatisfy { $0 == 0 }
        if isZero {
            passwordLogger.error("Audit token is all zeros - KVC extraction failed")
            return false
        }

        passwordLogger.debug("Audit token retrieved successfully")

        // Create SecCode from audit token (NOT PID - that's vulnerable to race conditions)
        var code: SecCode?
        let attributes: [String: Any] = [kSecGuestAttributeAudit as String: auditData]
        var status = SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            [],
            &code
        )

        guard status == errSecSuccess, let secCode = code else {
            passwordLogger.error("Failed to get caller's SecCode: \(status)")
            return false
        }

        // CRITICAL: Check signature validity FIRST
        // This prevents revoked/corrupted signatures from passing
        status = SecCodeCheckValidity(secCode, [], nil)
        guard status == errSecSuccess else {
            passwordLogger.error("Caller code signature is invalid or revoked: \(status)")
            return false
        }

        passwordLogger.debug("Code signature is valid")

        // Convert to static code for signing information
        var staticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(secCode, [], &staticCode)
        guard status == errSecSuccess, let secStaticCode = staticCode else {
            passwordLogger.error("Failed to get static code: \(status)")
            return false
        }

        // Get signing information with Team ID
        var signingInfo: CFDictionary?
        status = SecCodeCopySigningInformation(
            secStaticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInfo
        )

        guard status == errSecSuccess,
              let info = signingInfo as? [String: Any] else {
            passwordLogger.error("Failed to get signing information: \(status)")
            return false
        }

        // Check Team ID
        let foundTeamID = info[kSecCodeInfoTeamIdentifier as String] as? String ?? "none"
        guard let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String,
              teamID == "2LR4AGRZW3" else {
            passwordLogger.error("Caller Team ID (\(foundTeamID)) does not match expected (2LR4AGRZW3)")
            return false
        }

        // Check bundle ID matches allowed pattern (defense-in-depth)
        // Instead of custom entitlement (which requires notarization), we verify bundle ID
        let bundleID = info[kSecCodeInfoIdentifier as String] as? String ?? "unknown"

        // Allow com.agucova.oxcrypt.* pattern (desktop, CLI, etc.)
        let isAllowed = bundleID.hasPrefix("com.agucova.oxcrypt.") ||
                        bundleID == "com.agucova.oxcrypt"
        guard isAllowed else {
            passwordLogger.error("Caller bundle ID (\(bundleID)) does not match allowed pattern")
            return false
        }

        // Log successful authorization
        passwordLogger.info("Caller authorized: Bundle ID \(bundleID), Team ID \(teamID)")

        return true
    }

    /// Set up XPC listener for CLI/GUI communication.
    private func setupXPCListener() {
        // Use a Mach service name that matches Info.plist
        let listener = NSXPCListener(machServiceName: "com.agucova.oxcrypt.fileprovider.xpc")
        listener.delegate = self
        listener.resume()

        self.xpcListener = listener
        logger.info("XPC listener started on com.agucova.oxcrypt.fileprovider.xpc")
    }

    /// Re-register domains that have stored passwords.
    private func registerExistingDomains() async {
        do {
            let domains = try await NSFileProviderManager.domains()
            logger.info("Found \(domains.count) existing File Provider domains")

            for domain in domains {
                let domainId = domain.identifier.rawValue

                // Check if we have a password for this domain
                if KeychainHelper.exists(for: domainId) {
                    logger.info("Domain \(domain.displayName) has stored credentials")
                } else {
                    logger.warning(
                        "Domain \(domain.displayName) has no stored credentials - may need re-authentication"
                    )
                }
            }
        } catch {
            logger.error("Failed to enumerate existing domains: \(error.localizedDescription)")
        }
    }
}

// MARK: - XPC Listener Delegate

extension AppDelegate: NSXPCListenerDelegate {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Write to file for debugging
        try? "shouldAcceptNewConnection called\n".write(toFile: "/tmp/oxcrypt_debug.log", atomically: true, encoding: .utf8)
        print("DEBUG: shouldAcceptNewConnection called")
        passwordLogger.info("shouldAcceptNewConnection called")

        // Determine which listener this is for
        if listener === passwordServiceListener {
            print("DEBUG: This is the password service listener")
            // Handle password service connection with security verification
            passwordLogger.info("New XPC connection request for password service")

            // CRITICAL SECURITY: Verify caller using manual SecCode verification
            // This replaces setCodeSigningRequirement() which was preventing delegate invocation
            guard verifyCallerAuthorized(newConnection) else {
                passwordLogger.error("XPC connection rejected: Caller not authorized")
                return false
            }

            // Configure connection with service instance (rate limiting is tracked globally per audit token)
            newConnection.exportedInterface = NSXPCInterface(with: PasswordRetrievalProtocol.self)
            newConnection.exportedObject = PasswordRetrievalService(auditToken: newConnection.auditToken)

            newConnection.invalidationHandler = {
                self.passwordLogger.info("Password service XPC connection invalidated")
            }

            newConnection.interruptionHandler = {
                self.passwordLogger.warning("Password service XPC connection interrupted")
            }

            newConnection.resume()
            passwordLogger.info("Password service XPC connection accepted from authorized caller")
            return true
        } else {
            // Handle regular XPC connection (CLI/GUI)
            logger.debug("Accepting new XPC connection")

            // Set up the exported interface
            newConnection.exportedInterface = NSXPCInterface(with: OxCryptFileProviderXPC.self)
            newConnection.exportedObject = xpcService

            // Set up interruption and invalidation handlers
            newConnection.interruptionHandler = {
                logger.warning("XPC connection interrupted")
            }

            newConnection.invalidationHandler = {
                logger.info("XPC connection invalidated")
            }

            newConnection.resume()
            return true
        }
    }
}

// MARK: - XPC Protocol

/// XPC protocol for CLI/GUI to communicate with the File Provider host app.
@objc protocol OxCryptFileProviderXPC {
    /// Register a new vault as a File Provider domain.
    func registerDomain(
        vaultPath: String,
        displayName: String,
        password: String,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Unregister a File Provider domain.
    func unregisterDomain(
        identifier: String,
        reply: @escaping (Bool, String?) -> Void
    )

    /// List all registered domains.
    func listDomains(
        reply: @escaping ([String], [String]) -> Void
    )

    /// Signal the working set enumerator to refresh (called by FSEvents watcher).
    func signalChanges(
        domainIdentifier: String,
        reply: @escaping (Bool) -> Void
    )

    /// Check if a domain is currently active.
    func isDomainActive(
        identifier: String,
        reply: @escaping (Bool) -> Void
    )

    /// Get the mount path for a domain.
    func getMountPath(
        domainIdentifier: String,
        reply: @escaping (String?) -> Void
    )
}
