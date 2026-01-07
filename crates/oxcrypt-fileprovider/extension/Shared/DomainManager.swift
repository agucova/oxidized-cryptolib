// DomainManager.swift
// Wrapper for NSFileProviderManager domain operations.

import FileProvider
import Foundation
import os.log

/// Logger for domain management operations.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "DomainManager")

/// Manages File Provider domain registration and lifecycle.
struct DomainManager {
    private static func cloudStoragePath(for displayName: String) -> URL {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        return homeDir
            .appendingPathComponent("Library/CloudStorage")
            .appendingPathComponent(displayName)
    }

    /// Register a vault as a File Provider domain.
    /// - Parameters:
    ///   - vaultPath: The path to the vault directory.
    ///   - displayName: The name to show in Finder (e.g., "My Vault").
    ///   - password: The vault password (stored in Keychain).
    /// - Returns: The domain identifier on success.
    static func registerDomain(
        vaultPath: String,
        displayName: String,
        password: String
    ) async throws -> String {
        // Generate domain identifier from vault path (base64url encoding)
        let domainId = vaultPath.data(using: .utf8)!
            .base64EncodedString()
            .base64ToBase64url()

        logger.info("Registering File Provider domain: \(displayName) (\(domainId))")

        // Store password in Keychain first
        try KeychainHelper.store(password: password, for: domainId)

        // Create security-scoped bookmark for the vault path
        // This allows the sandboxed extension to access the vault
        let vaultURL = URL(fileURLWithPath: vaultPath)
        try BookmarkHelper.store(url: vaultURL, for: domainId)

        // Create domain
        // Note: The vault path is encoded in the domain identifier and can be
        // retrieved via KeychainHelper.vaultPath(from:) in the extension
        let domainIdentifier = NSFileProviderDomainIdentifier(rawValue: domainId)
        let domain = NSFileProviderDomain(
            identifier: domainIdentifier,
            displayName: displayName
        )

        // We don't support trash, so disable it to prevent macOS from trying to enumerate it
        domain.supportsSyncingTrash = false

        // Register with the system
        do {
            try await NSFileProviderManager.add(domain)
            logger.info("Successfully registered domain: \(domainId)")
            return domainId
        } catch {
            // Clean up Keychain and bookmark on failure
            try? KeychainHelper.delete(for: domainId)
            BookmarkHelper.delete(for: domainId)
            logger.error("Failed to register domain: \(error.localizedDescription)")
            throw error
        }
    }

    /// Unregister a File Provider domain.
    /// - Parameter domainIdentifier: The domain identifier to remove.
    static func unregisterDomain(_ domainIdentifier: String) async throws {
        logger.info("Unregistering File Provider domain: \(domainIdentifier)")

        let domainId = NSFileProviderDomainIdentifier(rawValue: domainIdentifier)

        // Find the domain
        let domains = try await NSFileProviderManager.domains()
        guard let domain = domains.first(where: { $0.identifier == domainId }) else {
            logger.warning("Domain not found: \(domainIdentifier)")
            // Still clean up Keychain and bookmark
            try? KeychainHelper.delete(for: domainIdentifier)
            BookmarkHelper.delete(for: domainIdentifier)
            return
        }

        // Remove from system
        try await NSFileProviderManager.remove(domain)

        // Clean up Keychain and bookmark
        try? KeychainHelper.delete(for: domainIdentifier)
        BookmarkHelper.delete(for: domainIdentifier)

        let cloudStoragePath = cloudStoragePath(for: domain.displayName)
        if FileManager.default.fileExists(atPath: cloudStoragePath.path) {
            do {
                try FileManager.default.removeItem(at: cloudStoragePath)
                logger.info("Removed stale CloudStorage folder: \(cloudStoragePath.path)")
            } catch {
                logger.warning("Failed to remove CloudStorage folder: \(error.localizedDescription)")
            }
        }

        logger.info("Successfully unregistered domain: \(domainIdentifier)")
    }

    /// List all registered domains.
    /// - Returns: Array of (identifier, displayName) tuples.
    static func listDomains() async throws -> [(identifier: String, displayName: String)] {
        let domains = try await NSFileProviderManager.domains()
        return domains.map { ($0.identifier.rawValue, $0.displayName) }
    }

    /// Get the manager for a specific domain.
    /// - Parameter domainIdentifier: The domain identifier.
    /// - Returns: The NSFileProviderManager for this domain, or nil if not found.
    static func manager(for domainIdentifier: String) async -> NSFileProviderManager? {
        let domainId = NSFileProviderDomainIdentifier(rawValue: domainIdentifier)

        do {
            let domains = try await NSFileProviderManager.domains()
            guard let domain = domains.first(where: { $0.identifier == domainId }) else {
                return nil
            }
            return NSFileProviderManager(for: domain)
        } catch {
            logger.error("Failed to get manager for domain: \(error.localizedDescription)")
            return nil
        }
    }

    /// Signal the working set enumerator to refresh.
    /// Called when vault contents change (via FSEvents watcher).
    /// - Parameter domainIdentifier: The domain identifier.
    static func signalChanges(for domainIdentifier: String) async throws {
        guard let manager = await manager(for: domainIdentifier) else {
            logger.warning("Cannot signal changes: domain not found: \(domainIdentifier)")
            return
        }

        try await manager.signalEnumerator(for: .workingSet)
        logger.debug("Signaled working set for domain: \(domainIdentifier)")
    }

    /// Check if a domain is currently mounted/active.
    /// - Parameter domainIdentifier: The domain identifier.
    /// - Returns: true if the domain is registered and active.
    static func isDomainActive(_ domainIdentifier: String) async -> Bool {
        let domainId = NSFileProviderDomainIdentifier(rawValue: domainIdentifier)

        do {
            let domains = try await NSFileProviderManager.domains()
            return domains.contains(where: { $0.identifier == domainId })
        } catch {
            return false
        }
    }

    /// Get the CloudStorage mount path for a display name.
    static func mountPath(for displayName: String) -> URL {
        cloudStoragePath(for: displayName)
    }
}

// MARK: - Base64URL helpers

private extension String {
    /// Convert standard base64 to base64url.
    func base64ToBase64url() -> String {
        self
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
