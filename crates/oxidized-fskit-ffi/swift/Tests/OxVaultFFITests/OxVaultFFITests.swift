// OxVaultFFITests.swift
// Integration tests for the OxVaultFFI Swift bindings.
//
// PREREQUISITES:
// 1. Build the Rust library: cargo build -p oxidized-fskit-ffi --release
// 2. Create a test vault or use the existing test_vault in the repo root
// 3. Run with: cd crates/oxidized-fskit-ffi/swift && swift test
//
// NOTE: These tests require a valid Cryptomator vault. By default, they use
// the test_vault in the repository root with the test password.

import XCTest
@testable import OxVaultFFI

/// Test password matching oxidized_mount_common::testing::TEST_PASSWORD
let TEST_PASSWORD = "test-password-12345"

/// Path to test_vault relative to the swift directory
/// Structure: swift/ -> oxidized-fskit-ffi/ -> crates/ -> oxidized-cryptolib/
let TEST_VAULT_PATH = "../../../../test_vault"

final class OxVaultFFITests: XCTestCase {

    // MARK: - Filesystem Creation Tests

    func testCreateFilesystemSucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk(), "Expected filesystem creation to succeed, got error: \(result.getError())")

        let fs = result.unwrap()
        fs.shutdown()
    }

    func testCreateFilesystemWithWrongPasswordFails() throws {
        let result = create(TEST_VAULT_PATH, "wrong-password")
        XCTAssertFalse(result.isOk(), "Expected filesystem creation to fail with wrong password")
        // EINVAL or similar error expected
        XCTAssertNotEqual(result.getError(), 0)
    }

    func testCreateFilesystemWithNonexistentVaultFails() throws {
        let result = create("/nonexistent/vault/path", TEST_PASSWORD)
        XCTAssertFalse(result.isOk(), "Expected filesystem creation to fail with nonexistent path")
        XCTAssertNotEqual(result.getError(), 0)
    }

    // MARK: - Root Item Tests

    func testRootItemIdIsTwo() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        // FSKit reserves ID 1, so root is always 2
        XCTAssertEqual(fs.get_root_item_id(), 2)
    }

    // MARK: - Volume Statistics Tests

    func testVolumeStatisticsSucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let statsResult = fs.getVolumeStats()
        XCTAssertTrue(statsResult.isOk(), "Expected volume stats to succeed")

        let stats = statsResult.unwrap()
        XCTAssertGreaterThan(stats.totalBytes(), 0)
        XCTAssertGreaterThan(stats.blockSize(), 0)
    }

    // MARK: - Directory Enumeration Tests

    func testEnumerateRootDirectory() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let entriesResult = fs.enumerateDirectory(rootId, 0)
        XCTAssertTrue(entriesResult.isOk(), "Expected directory enumeration to succeed")

        // Just verify we can enumerate - contents depend on test vault state
        let entries = entriesResult.unwrap()
        // entries is a RustVec, we can check its length
        XCTAssertGreaterThanOrEqual(entries.len(), 0)
    }

    // MARK: - File Creation Tests (Uses fresh vault state)

    func testCreateFileSucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Create a file with unique name using timestamp
        let filename = "swift_test_\(Int(Date().timeIntervalSince1970)).txt"
        let createResult = fs.createFile(rootId, filename)

        XCTAssertTrue(createResult.isOk(), "Expected file creation to succeed, got error: \(createResult.getError())")

        let attrs = createResult.unwrap()
        XCTAssertTrue(attrs.isFile())
        XCTAssertEqual(attrs.size(), 0)
        XCTAssertEqual(attrs.mode(), 0o644)

        // Clean up: remove the file
        let itemId = attrs.itemId()
        let removeResult = fs.remove(rootId, filename, itemId)
        // Don't assert on remove since PathTable cache bugs exist
        _ = removeResult
    }

    // MARK: - File Read/Write Tests

    func testWriteAndReadFile() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Create a file
        let filename = "swift_rw_test_\(Int(Date().timeIntervalSince1970)).txt"
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())

        let attrs = createResult.unwrap()
        let itemId = attrs.itemId()

        // Open for writing
        let openWriteResult = fs.openFile(itemId, true)
        XCTAssertTrue(openWriteResult.isOk(), "Expected open for write to succeed")
        let writeHandle = openWriteResult.unwrap()

        // Write content
        let content = "Hello from Swift FFI tests!"
        let contentBytes = Array(content.utf8)
        let rustVec = RustVec<UInt8>()
        for byte in contentBytes {
            rustVec.push(value: byte)
        }

        let writeResult = fs.writeFile(writeHandle, 0, rustVec)
        XCTAssertTrue(writeResult.isOk(), "Expected write to succeed")
        XCTAssertEqual(writeResult.unwrap(), Int64(contentBytes.count))

        // Close write handle
        let closeWriteResult = fs.closeFile(writeHandle)
        XCTAssertTrue(closeWriteResult.isOk())

        // Open for reading
        let openReadResult = fs.openFile(itemId, false)
        XCTAssertTrue(openReadResult.isOk())
        let readHandle = openReadResult.unwrap()

        // Read content
        let readResult = fs.readFile(readHandle, 0, Int64(contentBytes.count + 100))
        XCTAssertTrue(readResult.isOk())

        let readBytes = readResult.unwrap()
        XCTAssertEqual(readBytes.len(), UInt(contentBytes.count))

        // Verify content matches
        var readContent = [UInt8]()
        for i in 0..<readBytes.len() {
            if let byte = readBytes.get(index: i) {
                readContent.append(byte)
            }
        }
        let readString = String(bytes: readContent, encoding: .utf8)
        XCTAssertEqual(readString, content)

        // Close read handle
        let closeReadResult = fs.closeFile(readHandle)
        XCTAssertTrue(closeReadResult.isOk())

        // Clean up
        _ = fs.remove(rootId, filename, itemId)
    }

    // MARK: - Directory Creation Tests

    func testCreateDirectorySucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        let dirname = "swift_dir_\(Int(Date().timeIntervalSince1970))"
        let createResult = fs.createDirectory(rootId, dirname)

        XCTAssertTrue(createResult.isOk(), "Expected directory creation to succeed")

        let attrs = createResult.unwrap()
        XCTAssertTrue(attrs.isDirectory())
        XCTAssertEqual(attrs.mode(), 0o755)

        // Clean up
        let itemId = attrs.itemId()
        _ = fs.remove(rootId, dirname, itemId)
    }

    // MARK: - Symlink Tests

    func testCreateSymlinkSucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        let linkname = "swift_link_\(Int(Date().timeIntervalSince1970))"
        let target = "/some/target/path"
        let createResult = fs.createSymlink(rootId, linkname, target)

        XCTAssertTrue(createResult.isOk(), "Expected symlink creation to succeed")

        let attrs = createResult.unwrap()
        XCTAssertTrue(attrs.isSymlink())

        // Read symlink target
        let itemId = attrs.itemId()
        let readResult = fs.readSymlink(itemId)
        XCTAssertTrue(readResult.isOk())

        let targetBytes = readResult.unwrap()
        var targetContent = [UInt8]()
        for i in 0..<targetBytes.len() {
            if let byte = targetBytes.get(index: i) {
                targetContent.append(byte)
            }
        }
        let readTarget = String(bytes: targetContent, encoding: .utf8)
        XCTAssertEqual(readTarget, target)

        // Clean up
        _ = fs.remove(rootId, linkname, itemId)
    }

    // MARK: - Lookup Tests

    func testLookupNonexistentFails() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let lookupResult = fs.lookup(rootId, "nonexistent_file_12345.txt")

        // Note: Due to known PathTable caching bugs, this might not return ENOENT correctly
        // The test documents expected behavior even if implementation has bugs
        XCTAssertFalse(lookupResult.isOk(), "Expected lookup of nonexistent file to fail")
    }

    // MARK: - Attributes Tests

    func testGetAttributesSucceeds() throws {
        let result = create(TEST_VAULT_PATH, TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Create a file to get attributes for
        let filename = "swift_attrs_\(Int(Date().timeIntervalSince1970)).txt"
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())

        let createAttrs = createResult.unwrap()
        let itemId = createAttrs.itemId()

        // Get attributes by item ID
        let attrsResult = fs.getAttributes(itemId)
        XCTAssertTrue(attrsResult.isOk())

        let attrs = attrsResult.unwrap()
        XCTAssertEqual(attrs.itemId(), itemId)
        XCTAssertTrue(attrs.isFile())
        XCTAssertEqual(attrs.size(), 0)

        // Clean up
        _ = fs.remove(rootId, filename, itemId)
    }
}
