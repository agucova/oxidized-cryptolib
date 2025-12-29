// KeychainHelper.swift
// Secure storage for vault passwords using macOS Keychain.

import Foundation
import Security

/// Errors that can occur during Keychain operations.
enum KeychainError: Error {
    case notFound
    case unexpectedData
    case unhandled(OSStatus)
}

/// Helper for storing and retrieving vault passwords from the macOS Keychain.
struct KeychainHelper {
    /// The Keychain service name for vault passwords.
    static let serviceName = "com.agucova.oxidized.vault"

    /// Store a password for a vault path.
    /// - Parameters:
    ///   - password: The password to store.
    ///   - vaultPath: The path to the vault (used as the account identifier).
    static func store(password: String, for vaultPath: String) throws {
        guard let passwordData = password.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: vaultPath,
            kSecValueData as String: passwordData
        ]

        // Delete existing item if present
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status)
        }
    }

    /// Retrieve a password for a vault path.
    /// - Parameter vaultPath: The path to the vault.
    /// - Returns: The stored password.
    /// - Throws: `KeychainError.notFound` if no password is stored for this vault.
    static func retrieve(for vaultPath: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: vaultPath,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.notFound
            }
            throw KeychainError.unhandled(status)
        }

        guard let data = item as? Data,
              let password = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }

        return password
    }

    /// Delete a password for a vault path.
    /// - Parameter vaultPath: The path to the vault.
    static func delete(for vaultPath: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: vaultPath
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandled(status)
        }
    }

    /// Check if a password exists for a vault path.
    /// - Parameter vaultPath: The path to the vault.
    /// - Returns: `true` if a password is stored, `false` otherwise.
    static func exists(for vaultPath: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: vaultPath,
            kSecReturnData as String: false
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
