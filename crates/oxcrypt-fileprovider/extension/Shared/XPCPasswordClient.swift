import Foundation
import os.log

/// Swift wrapper for XPC password retrieval.
///
/// This class bridges between Rust and NSXPCConnection for secure password
/// retrieval from the host app's Keychain. It manages the XPC connection
/// lifecycle and provides async methods for password retrieval.
///
/// Memory Safety:
/// - Connection is properly invalidated in deinit
/// - Errors are propagated with formatted strings for robust FFI parsing
/// - Uses async/await to avoid blocking and callback leaks
public class XPCPasswordClient {
    private var connection: NSXPCConnection?
    private let logger = Logger(subsystem: "com.agucova.oxcrypt.fileprovider", category: "XPCClient")

    public init() {
        logger.debug("XPCPasswordClient initialized")
    }

    /// Connect to the XPC password retrieval service.
    ///
    /// Establishes connection to the Mach service and sets up lifecycle handlers.
    /// Must be called before getPassword().
    public func connect() {
        let connection = NSXPCConnection(machServiceName: "com.agucova.oxcrypt.fileprovider.password-service")
        connection.remoteObjectInterface = NSXPCInterface(with: PasswordRetrievalProtocol.self)

        connection.invalidationHandler = {
            self.logger.warning("XPC connection invalidated")
            self.connection = nil
        }

        connection.interruptionHandler = {
            self.logger.warning("XPC connection interrupted")
        }

        connection.resume()
        self.connection = connection
        logger.info("Connected to XPC password service")
    }

    /// Retrieve password for a domain from Keychain via XPC (synchronous).
    ///
    /// This method calls the XPC service which validates the caller's code signature
    /// before returning the password. Errors are formatted as "CODE:message" where
    /// CODE is the PasswordRetrievalError.rawValue for robust parsing in Rust.
    ///
    /// Uses a semaphore to make the async XPC call synchronous for FFI compatibility.
    ///
    /// - Parameter domain_id: Base64url-encoded vault path (domain identifier)
    /// - Returns: The password string if found, or error message with code prefix
    public func getPassword(domain_id: RustString) -> RustString {
        let domainId = domain_id.toString()

        guard let connection = connection else {
            return "ERROR:-1:Not connected to XPC service".intoRustString()
        }

        let semaphore = DispatchSemaphore(value: 0)
        var result: String = "ERROR:-3:No password or error returned"

        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            self.logger.error("XPC proxy error: \(error.localizedDescription)")
            result = "ERROR:-1:\(error.localizedDescription)"
            semaphore.signal()
        }

        guard let service = proxy as? PasswordRetrievalProtocol else {
            return "ERROR:-2:Invalid proxy type".intoRustString()
        }

        service.getPassword(forDomain: domainId) { (password: String?, error: Error?) in
            if let error = error {
                // Format error with code prefix for robust Rust parsing
                // Format: "ERROR:CODE:message" where CODE is PasswordRetrievalError.rawValue
                let nsError: NSError = error as NSError
                let errorCode = nsError.code
                let errorMessage = nsError.localizedDescription
                result = "ERROR:\(errorCode):\(errorMessage)"
            } else if let password = password {
                result = "OK:\(password)"
            } else {
                result = "ERROR:-3:No password or error returned"
            }
            semaphore.signal()
        }

        // Wait for XPC response with 30 second timeout
        let timeout = DispatchTime.now() + .seconds(30)
        if semaphore.wait(timeout: timeout) == .timedOut {
            logger.error("XPC request timed out after 30 seconds")
            return "ERROR:-4:XPC request timed out".intoRustString()
        }

        return result.intoRustString()
    }

    /// Disconnect from the XPC service.
    ///
    /// Invalidates the connection and cleans up resources. Called automatically
    /// in deinit, but can be called explicitly for immediate cleanup.
    public func disconnect() {
        connection?.invalidate()
        connection = nil
        logger.info("Disconnected from XPC service")
    }

    deinit {
        // Ensure connection is cleaned up to prevent leaks
        disconnect()
    }
}
