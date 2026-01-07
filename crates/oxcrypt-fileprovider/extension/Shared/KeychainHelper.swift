// KeychainHelper.swift
// Secure storage for vault passwords using macOS Keychain.
// Shared between the File Provider host app and extension.

import Foundation
import Security
import os.log

/// Logger for keychain operations.
private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "Keychain")

/// Errors that can occur during Keychain operations.
enum KeychainError: Error {
    case notFound
    case unexpectedData
    case unhandled(OSStatus)
}

/// Helper for storing and retrieving vault passwords from the macOS Keychain.
struct KeychainHelper {
    /// The Keychain service name for File Provider vault passwords.
    static let serviceName = "com.agucova.oxcrypt.fileprovider"

    /// The shared Keychain access group for host app and extension.
    /// Must match the keychain-access-groups in entitlements.
    /// Format: TEAMID.bundleid (note: NOT the app group format with "group.")
    /// Only used when app is properly signed with a developer certificate.
    static let accessGroup = "2LR4AGRZW3.com.agucova.oxcrypt.fileprovider"

    /// Detect if the app is properly signed with a team ID.
    /// Returns true if running with a valid developer certificate, false for adhoc signing.
    private static var isProperlyCodeSigned: Bool = {
        // Check if we have a valid team identifier
        // For adhoc-signed apps, kSecAttrAccessGroup will be rejected
        let bundleURL = Bundle.main.bundleURL as CFURL
        var codeRef: SecStaticCode?

        guard SecStaticCodeCreateWithPath(bundleURL, [], &codeRef) == errSecSuccess,
              let code = codeRef else {
            logger.info("Could not get code signature - assuming adhoc")
            return false
        }

        var signingInfo: CFDictionary?
        let status = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)

        guard status == errSecSuccess,
              let info = signingInfo as? [String: Any],
              let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamID.isEmpty else {
            logger.info("Running with adhoc code signature - keychain access groups disabled")
            return false
        }

        logger.info("Running with valid code signature - team ID: \(teamID)")
        return true
    }()

    /// Store a password for a vault/domain identifier.
    /// - Parameters:
    ///   - password: The password to store.
    ///   - domainIdentifier: The File Provider domain identifier (base64url-encoded vault path).
    static func store(password: String, for domainIdentifier: String) throws {
        guard let passwordData = password.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        logger.info("Storing password for domain: \(domainIdentifier)")
        if isProperlyCodeSigned {
            logger.info("Using access group: \(accessGroup)")
        } else {
            logger.info("Using default keychain (no access group - adhoc build)")
        }

        // Build delete query
        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier
        ]
        if isProperlyCodeSigned {
            // Use Data Protection keychain with access group for signed builds
            deleteQuery[kSecAttrAccessGroup as String] = accessGroup
            deleteQuery[kSecUseDataProtectionKeychain as String] = true
        }
        // For adhoc builds, use legacy file-based keychain (no Data Protection)

        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        logger.debug("Delete status: \(deleteStatus)")

        // Also try deleting from legacy file-based keychain (cleanup)
        let deleteLegacyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier
        ]
        SecItemDelete(deleteLegacyQuery as CFDictionary)

        // Build add query
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier,
            kSecValueData as String: passwordData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        if isProperlyCodeSigned {
            // Use Data Protection keychain with access group for signed builds
            // kSecUseDataProtectionKeychain is REQUIRED for kSecAttrAccessGroup to work
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }
        // For adhoc builds, use legacy file-based keychain (no Data Protection)

        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            let message = SecCopyErrorMessageString(status, nil) ?? "Unknown" as CFString
            logger.error("Keychain store error: \(status) - \(message as String)")
            throw KeychainError.unhandled(status)
        }
        logger.info("Successfully stored password for domain: \(domainIdentifier)")
    }

    /// Retrieve a password for a domain identifier.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    /// - Returns: The stored password.
    /// - Throws: `KeychainError.notFound` if no password is stored for this domain.
    static func retrieve(for domainIdentifier: String) throws -> String {
        logger.info("Retrieving password for domain: \(domainIdentifier)")
        if isProperlyCodeSigned {
            logger.info("Using access group: \(accessGroup)")
        } else {
            logger.info("Using default keychain (no access group - adhoc build)")
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if isProperlyCodeSigned {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                logger.error("No password found for domain: \(domainIdentifier)")
                throw KeychainError.notFound
            }
            let message = SecCopyErrorMessageString(status, nil) ?? "Unknown" as CFString
            logger.error("Keychain retrieve error: \(status) - \(message as String)")
            throw KeychainError.unhandled(status)
        }

        guard let data = item as? Data,
              let password = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }

        logger.info("Successfully retrieved password for domain: \(domainIdentifier)")
        return password
    }

    /// Delete a password for a domain identifier.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    static func delete(for domainIdentifier: String) throws {
        // Delete from keychain
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier
        ]
        if isProperlyCodeSigned {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }

        let status = SecItemDelete(query as CFDictionary)

        // Also try deleting from legacy file-based keychain
        let legacyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier
        ]
        SecItemDelete(legacyQuery as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandled(status)
        }
        logger.debug("Deleted password for domain: \(domainIdentifier)")
    }

    /// Check if a password exists for a domain identifier.
    /// - Parameter domainIdentifier: The File Provider domain identifier.
    /// - Returns: `true` if a password is stored, `false` otherwise.
    static func exists(for domainIdentifier: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: domainIdentifier,
            kSecReturnData as String: false,
            kSecUseDataProtectionKeychain as String: true
        ]
        if isProperlyCodeSigned {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Get the vault path from a domain identifier.
    /// - Parameter domainIdentifier: The File Provider domain identifier (base64url-encoded).
    /// - Returns: The decoded vault path, or nil if decoding fails.
    static func vaultPath(from domainIdentifier: String) -> String? {
        // Domain identifiers are base64url-encoded vault paths
        guard let data = Data(base64Encoded: domainIdentifier.base64urlToBase64()) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

// MARK: - Base64URL helpers

private extension String {
    /// Convert base64url to standard base64.
    func base64urlToBase64() -> String {
        var result = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let remainder = result.count % 4
        if remainder > 0 {
            result += String(repeating: "=", count: 4 - remainder)
        }

        return result
    }
}
