// OxVaultFSExtensionTests.swift
// Integration tests for the FSKit extension using the Rust FFI.

import XCTest
import OxVaultFFI
@testable import OxVaultFSExtension

/// Integration tests for the OxVault FSKit extension.
/// These tests use the Rust FFI directly to test filesystem operations.
final class OxVaultFSExtensionTests: XCTestCase {

    // SHARED_VAULT_PASSWORD from oxidized-mount-common::testing
    static let testPassword = "123456789"

    var cryptoFS: CryptoFilesystem!

    /// Compute the absolute path to test_vault from source file location.
    /// Structure: Tests/OxVaultFSExtensionTests.swift -> Tests/ -> OxVaultFSExtension/ -> swift/ -> repo root
    static func testVaultPath() -> String {
        let fileURL = URL(fileURLWithPath: #file)
        let repoRoot = fileURL
            .deletingLastPathComponent()  // Remove OxVaultFSExtensionTests.swift
            .deletingLastPathComponent()  // Remove Tests/
            .deletingLastPathComponent()  // Remove OxVaultFSExtension/
            .deletingLastPathComponent()  // Remove swift/
        return repoRoot.appendingPathComponent("test_vault").standardized.path
    }

    override func setUp() {
        super.setUp()

        let vaultPath = Self.testVaultPath()
        let result = create(vaultPath, Self.testPassword)
        XCTAssertTrue(result.isOk(), "Failed to create filesystem: errno \(result.getError()) at path \(vaultPath)")
        cryptoFS = result.unwrap()
    }

    override func tearDown() {
        cryptoFS?.shutdown()
        cryptoFS = nil
        super.tearDown()
    }

    // MARK: - File I/O Tests

    func testOpenReadClose() throws {
        let rootId = cryptoFS.get_root_item_id()

        // Create a test file
        let fileName = "test_read_\(UUID().uuidString).txt"
        let createResult = cryptoFS.createFile(rootId, fileName)
        XCTAssertTrue(createResult.isOk(), "Failed to create file")
        let attrs = createResult.unwrap()
        let itemId = attrs.getItemId()

        defer {
            // Cleanup
            _ = cryptoFS.remove(rootId, fileName, itemId)
        }

        // Open for write
        let openWrite = cryptoFS.openFile(itemId, true)
        XCTAssertTrue(openWrite.isOk(), "Failed to open for write")
        let writeHandle = openWrite.unwrap()

        // Write data
        let testString = "Hello, FSKit!"
        let testBytes = Array(testString.utf8)
        let rustVec = RustVec<UInt8>()
        for byte in testBytes {
            rustVec.push(value: byte)
        }
        let writeResult = cryptoFS.writeFile(writeHandle, 0, rustVec)
        XCTAssertTrue(writeResult.isOk(), "Failed to write")
        XCTAssertEqual(writeResult.unwrap(), Int64(testBytes.count))

        // Close write handle
        let closeWrite = cryptoFS.closeFile(writeHandle)
        XCTAssertTrue(closeWrite.isOk(), "Failed to close write handle")

        // Open for read
        let openRead = cryptoFS.openFile(itemId, false)
        XCTAssertTrue(openRead.isOk(), "Failed to open for read")
        let readHandle = openRead.unwrap()

        // Read data
        let readResult = cryptoFS.readFile(readHandle, 0, 100)
        XCTAssertTrue(readResult.isOk(), "Failed to read")

        let rustBytes = readResult.unwrap()
        var readBytes: [UInt8] = []
        for byte in rustBytes {
            readBytes.append(byte)
        }
        let readString = String(bytes: readBytes, encoding: .utf8)
        XCTAssertEqual(readString, testString)

        // Close read handle
        _ = cryptoFS.closeFile(readHandle)
    }

    func testCreateDirectory() throws {
        let rootId = cryptoFS.get_root_item_id()
        let dirName = "test_dir_\(UUID().uuidString)"

        let result = cryptoFS.createDirectory(rootId, dirName)
        XCTAssertTrue(result.isOk(), "Failed to create directory")

        let attrs = result.unwrap()
        XCTAssertTrue(attrs.isDirectory(), "Created item is not a directory")

        // Cleanup
        let removeResult = cryptoFS.remove(rootId, dirName, attrs.getItemId())
        XCTAssertTrue(removeResult.isOk(), "Failed to remove directory")
    }

    func testCreateSymlink() throws {
        let rootId = cryptoFS.get_root_item_id()
        let linkName = "test_link_\(UUID().uuidString)"
        let target = "/path/to/target"

        let result = cryptoFS.createSymlink(rootId, linkName, target)
        XCTAssertTrue(result.isOk(), "Failed to create symlink")

        let attrs = result.unwrap()
        XCTAssertTrue(attrs.isSymlink(), "Created item is not a symlink")

        // Read symlink target
        let readResult = cryptoFS.readSymlink(attrs.getItemId())
        XCTAssertTrue(readResult.isOk(), "Failed to read symlink")

        let rustBytes = readResult.unwrap()
        var targetBytes: [UInt8] = []
        for byte in rustBytes {
            targetBytes.append(byte)
        }
        let readTarget = String(bytes: targetBytes, encoding: .utf8)
        XCTAssertEqual(readTarget, target)

        // Cleanup
        _ = cryptoFS.remove(rootId, linkName, attrs.getItemId())
    }

    func testRename() throws {
        let rootId = cryptoFS.get_root_item_id()
        let originalName = "original_\(UUID().uuidString).txt"
        let newName = "renamed_\(UUID().uuidString).txt"

        // Create file
        let createResult = cryptoFS.createFile(rootId, originalName)
        XCTAssertTrue(createResult.isOk(), "Failed to create file")
        let attrs = createResult.unwrap()
        let itemId = attrs.getItemId()

        defer {
            // Cleanup - try both names
            _ = cryptoFS.remove(rootId, newName, itemId)
            _ = cryptoFS.remove(rootId, originalName, itemId)
        }

        // Rename
        let renameResult = cryptoFS.rename(rootId, originalName, rootId, newName, itemId)
        XCTAssertTrue(renameResult.isOk(), "Failed to rename")

        // Verify old name is gone
        let oldLookup = cryptoFS.lookup(rootId, originalName)
        XCTAssertFalse(oldLookup.isOk(), "Old name should not exist")

        // Verify new name exists
        let newLookup = cryptoFS.lookup(rootId, newName)
        XCTAssertTrue(newLookup.isOk(), "New name should exist")
    }

    func testTruncate() throws {
        let rootId = cryptoFS.get_root_item_id()
        let fileName = "truncate_test_\(UUID().uuidString).txt"

        // Create file with content
        let createResult = cryptoFS.createFile(rootId, fileName)
        XCTAssertTrue(createResult.isOk(), "Failed to create file")
        let itemId = createResult.unwrap().getItemId()

        defer {
            _ = cryptoFS.remove(rootId, fileName, itemId)
        }

        // Write some data
        let openResult = cryptoFS.openFile(itemId, true)
        XCTAssertTrue(openResult.isOk(), "Failed to open for write")
        let handle = openResult.unwrap()

        let testString = "Hello, World!"
        let testBytes = Array(testString.utf8)
        let rustVec2 = RustVec<UInt8>()
        for byte in testBytes {
            rustVec2.push(value: byte)
        }
        _ = cryptoFS.writeFile(handle, 0, rustVec2)
        _ = cryptoFS.closeFile(handle)

        // Truncate to 5 bytes
        let truncateResult = cryptoFS.truncate(itemId, 5)
        XCTAssertTrue(truncateResult.isOk(), "Failed to truncate")

        // Verify size
        let attrsResult = cryptoFS.getAttributes(itemId)
        XCTAssertTrue(attrsResult.isOk(), "Failed to get attributes")
        XCTAssertEqual(attrsResult.unwrap().getSize(), 5)
    }

    func testDirectoryEnumeration() throws {
        let rootId = cryptoFS.get_root_item_id()

        // Create a few test files
        let fileNames = (0..<3).map { "enum_test_\($0)_\(UUID().uuidString).txt" }
        var itemIds: [UInt64] = []

        for name in fileNames {
            let result = cryptoFS.createFile(rootId, name)
            XCTAssertTrue(result.isOk(), "Failed to create file \(name)")
            itemIds.append(result.unwrap().getItemId())
        }

        defer {
            // Cleanup
            for (name, itemId) in zip(fileNames, itemIds) {
                _ = cryptoFS.remove(rootId, name, itemId)
            }
        }

        // Enumerate directory
        let enumResult = cryptoFS.enumerateDirectory(rootId, 0)
        XCTAssertTrue(enumResult.isOk(), "Failed to enumerate directory")

        let entries = enumResult.unwrap()
        XCTAssertGreaterThanOrEqual(entries.count, fileNames.count)

        // Verify our files are in the listing
        var foundCount = 0
        for entry in entries {
            let nameBytes = entry.getName()
            var bytes: [UInt8] = []
            for byte in nameBytes {
                bytes.append(byte)
            }
            let name = String(bytes: bytes, encoding: .utf8) ?? ""
            if fileNames.contains(name) {
                foundCount += 1
            }
        }
        XCTAssertEqual(foundCount, fileNames.count, "Not all created files found in enumeration")
    }

    func testVolumeStats() throws {
        let result = cryptoFS.getVolumeStats()
        XCTAssertTrue(result.isOk(), "Failed to get volume stats")

        let stats = result.unwrap()

        // Basic sanity checks
        XCTAssertGreaterThan(stats.getBlockSize(), 0)
        XCTAssertGreaterThan(stats.getTotalBytes(), 0)
    }

    func testLookupNonexistent() throws {
        let rootId = cryptoFS.get_root_item_id()

        let result = cryptoFS.lookup(rootId, "nonexistent_file_\(UUID()).txt")
        XCTAssertFalse(result.isOk(), "Lookup should fail for nonexistent file")
        XCTAssertEqual(result.getError(), ENOENT)
    }

    func testCreateDuplicateFile() throws {
        let rootId = cryptoFS.get_root_item_id()
        let fileName = "duplicate_test_\(UUID().uuidString).txt"

        // Create first file
        let result1 = cryptoFS.createFile(rootId, fileName)
        XCTAssertTrue(result1.isOk(), "Failed to create first file")
        let itemId = result1.unwrap().getItemId()

        defer {
            _ = cryptoFS.remove(rootId, fileName, itemId)
        }

        // Try to create duplicate
        let result2 = cryptoFS.createFile(rootId, fileName)
        XCTAssertFalse(result2.isOk(), "Should not be able to create duplicate file")
        XCTAssertEqual(result2.getError(), EEXIST)
    }

    func testRemoveNonEmptyDirectory() throws {
        let rootId = cryptoFS.get_root_item_id()
        let dirName = "nonempty_dir_\(UUID().uuidString)"

        // Create directory
        let dirResult = cryptoFS.createDirectory(rootId, dirName)
        XCTAssertTrue(dirResult.isOk(), "Failed to create directory")
        let dirId = dirResult.unwrap().getItemId()

        // Create file inside
        let fileName = "file.txt"
        let fileResult = cryptoFS.createFile(dirId, fileName)
        XCTAssertTrue(fileResult.isOk(), "Failed to create file in directory")
        let fileId = fileResult.unwrap().getItemId()

        // Try to remove non-empty directory
        let removeResult = cryptoFS.remove(rootId, dirName, dirId)
        XCTAssertFalse(removeResult.isOk(), "Should not be able to remove non-empty directory")
        XCTAssertEqual(removeResult.getError(), ENOTEMPTY)

        // Cleanup: remove file first, then directory
        _ = cryptoFS.remove(dirId, fileName, fileId)
        _ = cryptoFS.remove(rootId, dirName, dirId)
    }
}
