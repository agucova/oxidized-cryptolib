import Foundation

/// Protocol for secure password retrieval from Keychain
@objc public protocol PasswordRetrievalProtocol: NSObjectProtocol {
    /// Retrieve password for a domain from Keychain
    ///
    /// - Parameter domainId: Base64url-encoded vault path (domain identifier)
    /// - Parameter reply: Completion handler with password or error (NSError for XPC serialization)
    func getPassword(
        forDomain domainId: String,
        withReply reply: @escaping (String?, NSError?) -> Void
    )
}

/// Errors that can occur during password retrieval
public enum PasswordRetrievalError: Int, Error {
    case passwordNotFound = 1
    case keychainLocked = 2
    case accessDenied = 3
    case invalidDomainId = 4
    case rateLimitExceeded = 5

    var localizedDescription: String {
        switch self {
        case .passwordNotFound:
            return "Password not found in Keychain"
        case .keychainLocked:
            return "Keychain is locked. Please unlock and try again"
        case .accessDenied:
            return "Keychain access denied"
        case .invalidDomainId:
            return "Invalid domain identifier"
        case .rateLimitExceeded:
            return "Rate limit exceeded. Too many password requests in a short time"
        }
    }
}
