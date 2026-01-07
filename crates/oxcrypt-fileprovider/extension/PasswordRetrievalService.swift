import Foundation
import os.log

/// XPC service for secure password retrieval
class PasswordRetrievalService: NSObject, PasswordRetrievalProtocol {
    private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "PasswordRetrieval")
    private let auditToken: audit_token_t

    // Rate limiting to prevent password enumeration from compromised authorized apps
    // Shared state across all service instances (one per connection)
    private static var requestCounts: [Data: (count: Int, resetTime: Date)] = [:]
    private static let maxRequestsPerMinute = 10
    private static let lock = NSLock()

    /// Initialize with the connection's audit token
    init(auditToken: audit_token_t) {
        self.auditToken = auditToken
        super.init()
    }

    /// Check if the caller has exceeded rate limit
    private func checkRateLimit() -> Bool {
        Self.lock.lock()
        defer { Self.lock.unlock() }

        // Use audit token as key (more secure than PID)
        let tokenData = withUnsafeBytes(of: auditToken) { Data($0) }
        let now = Date()

        if let entry = Self.requestCounts[tokenData] {
            // Check if we need to reset the counter (>60 seconds elapsed)
            if now.timeIntervalSince(entry.resetTime) > 60 {
                Self.requestCounts[tokenData] = (1, now)
                return true
            }

            // Check if limit exceeded
            if entry.count >= Self.maxRequestsPerMinute {
                logger.warning("Rate limit exceeded for caller")
                return false
            }

            // Increment counter
            Self.requestCounts[tokenData] = (entry.count + 1, entry.resetTime)
        } else {
            // First request from this caller
            Self.requestCounts[tokenData] = (1, now)
        }

        return true
    }

    func getPassword(forDomain domainId: String, withReply reply: @escaping (String?, Error?) -> Void) {
        logger.info("Password retrieval request for domain: \(domainId)")

        // Check rate limit before processing to prevent enumeration attacks
        guard checkRateLimit() else {
            logger.warning("Rate limit exceeded, rejecting password request")
            reply(nil, PasswordRetrievalError.rateLimitExceeded)
            return
        }

        // Validate domain ID format and length before processing
        guard domainId.count > 0 && domainId.count <= 4096 else {
            logger.warning("Domain ID length out of bounds: \(domainId.count)")
            reply(nil, PasswordRetrievalError.invalidDomainId)
            return
        }

        // Domain IDs are base64url-encoded vault paths, validate character set
        let validCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_="))
        guard domainId.unicodeScalars.allSatisfy({ validCharacters.contains($0) }) else {
            logger.warning("Domain ID contains invalid characters")
            reply(nil, PasswordRetrievalError.invalidDomainId)
            return
        }

        // Retrieve from keychain
        do {
            let password = try KeychainHelper.retrieve(for: domainId)
            logger.info("Password retrieved successfully")

            // Add random delay to mask timing differences in keychain access
            let randomDelay = useconds_t.random(in: 1000...5000) // 1-5ms
            usleep(randomDelay)

            reply(password, nil)
        } catch {
            logger.error("Failed to retrieve password: \(error.localizedDescription)")

            // Map error to PasswordRetrievalError
            let retrievalError: PasswordRetrievalError
            let errorDesc = error.localizedDescription.lowercased()

            if errorDesc.contains("not found") {
                retrievalError = .passwordNotFound
            } else if errorDesc.contains("locked") {
                retrievalError = .keychainLocked
            } else if errorDesc.contains("access") || errorDesc.contains("denied") {
                retrievalError = .accessDenied
            } else {
                retrievalError = .accessDenied
            }

            // Add same random delay on error path (constant-time)
            let randomDelay = useconds_t.random(in: 1000...5000)
            usleep(randomDelay)

            reply(nil, retrievalError)
        }
    }
}
