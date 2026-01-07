import Foundation

/// Marker file format used in trigger disk images to point to the real vault.
/// When fskitd probes a trigger disk image, the extension reads this marker
/// to determine which vault to actually mount.
struct TriggerMarker: Codable {
    /// Absolute path to the real Cryptomator vault
    let vaultPath: String

    /// Desired volume name for the mounted vault
    let volumeName: String

    /// Creation timestamp for cleanup of stale triggers
    let timestamp: Date

    /// Standard filename for the marker file
    static let filename = ".oxcrypt-trigger"

    /// Writes this marker to a directory
    /// - Parameter url: Directory URL to write the marker file into
    func write(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(self)
        try data.write(to: url.appendingPathComponent(Self.filename))
    }

    /// Reads a marker from a directory
    /// - Parameter url: Directory URL containing the marker file
    /// - Returns: The decoded TriggerMarker
    static func read(from url: URL) throws -> TriggerMarker {
        let data = try Data(contentsOf: url.appendingPathComponent(filename))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TriggerMarker.self, from: data)
    }

    /// Checks if a directory contains a trigger marker
    /// - Parameter url: Directory URL to check
    /// - Returns: true if the marker file exists
    static func exists(at url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.appendingPathComponent(filename).path)
    }
}
