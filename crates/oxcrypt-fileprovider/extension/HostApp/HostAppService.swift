// HostAppService.swift
// XPC service implementation for File Provider domain management.

import FileProvider
import Foundation
import os.log

/// Logger for the XPC service.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "XPCService")

/// Implements the XPC service protocol for domain management.
class HostAppService: NSObject, OxCryptFileProviderXPC {
    // MARK: - Domain Registration

    func registerDomain(
        vaultPath: String,
        displayName: String,
        password: String,
        reply: @escaping (Bool, String?) -> Void
    ) {
        Task {
            do {
                let domainId = try await DomainManager.registerDomain(
                    vaultPath: vaultPath,
                    displayName: displayName,
                    password: password
                )
                logger.info("Successfully registered domain: \(domainId)")
                reply(true, domainId)
            } catch {
                logger.error("Failed to register domain: \(error.localizedDescription)")
                reply(false, error.localizedDescription)
            }
        }
    }

    func unregisterDomain(
        identifier: String,
        reply: @escaping (Bool, String?) -> Void
    ) {
        Task {
            do {
                try await DomainManager.unregisterDomain(identifier)
                logger.info("Successfully unregistered domain: \(identifier)")
                reply(true, nil)
            } catch {
                logger.error("Failed to unregister domain: \(error.localizedDescription)")
                reply(false, error.localizedDescription)
            }
        }
    }

    // MARK: - Domain Listing

    func listDomains(
        reply: @escaping ([String], [String]) -> Void
    ) {
        Task {
            do {
                let domains = try await DomainManager.listDomains()
                let identifiers = domains.map { $0.identifier }
                let displayNames = domains.map { $0.displayName }
                reply(identifiers, displayNames)
            } catch {
                logger.error("Failed to list domains: \(error.localizedDescription)")
                reply([], [])
            }
        }
    }

    // MARK: - Change Signaling

    func signalChanges(
        domainIdentifier: String,
        reply: @escaping (Bool) -> Void
    ) {
        Task {
            do {
                try await DomainManager.signalChanges(for: domainIdentifier)
                reply(true)
            } catch {
                logger.error("Failed to signal changes: \(error.localizedDescription)")
                reply(false)
            }
        }
    }

    // MARK: - Status

    func isDomainActive(
        identifier: String,
        reply: @escaping (Bool) -> Void
    ) {
        Task {
            let isActive = await DomainManager.isDomainActive(identifier)
            reply(isActive)
        }
    }

    func getMountPath(
        domainIdentifier: String,
        reply: @escaping (String?) -> Void
    ) {
        Task {
            // File Provider mounts appear in ~/Library/CloudStorage/
            // The exact path depends on the domain display name
            do {
                let domains = try await NSFileProviderManager.domains()
                guard let domain = domains.first(where: { $0.identifier.rawValue == domainIdentifier })
                else {
                    reply(nil)
                    return
                }

                let path = DomainManager.mountPath(for: domain.displayName)
                if FileManager.default.fileExists(atPath: path.path) {
                    reply(path.path)
                } else {
                    reply(nil)
                }
            } catch {
                logger.error("Failed to get mount path: \(error.localizedDescription)")
                reply(nil)
            }
        }
    }
}
