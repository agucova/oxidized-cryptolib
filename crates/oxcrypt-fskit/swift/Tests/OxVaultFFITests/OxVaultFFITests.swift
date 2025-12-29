// OxVaultFFITests.swift
// Integration tests for the OxVaultFFI Swift bindings.
//
// PREREQUISITES:
// 1. Build the Rust library: cargo build -p oxcrypt-fskit --release
// 2. Create a test vault or use the existing test_vault in the repo root
// 3. Run with: cd crates/oxcrypt-fskit/swift && swift test
//
// NOTE: These tests require a valid Cryptomator vault. By default, they use
// the test_vault in the repository root with the test password.

import XCTest
@testable import OxVaultFFI

/// Test password matching oxcrypt_mount::testing::SHARED_VAULT_PASSWORD
let TEST_PASSWORD = "123456789"

/// Returns the absolute path to test_vault computed from source file location.
/// Structure: Tests/OxVaultFFITests/ -> swift/ -> oxcrypt-fskit/ -> crates/ -> repo root
func testVaultPath() -> String {
    let fileURL = URL(fileURLWithPath: #file)
    let packagePath = fileURL
        .deletingLastPathComponent()  // Remove OxVaultFFITests.swift
        .deletingLastPathComponent()  // Remove OxVaultFFITests/
        .deletingLastPathComponent()  // Remove Tests/
        .deletingLastPathComponent()  // Remove swift/
        .deletingLastPathComponent()  // Remove oxcrypt-fskit/
        .deletingLastPathComponent()  // Remove crates/
    return packagePath.appendingPathComponent("test_vault").standardized.path
}

final class OxVaultFFITests: XCTestCase {

    // MARK: - Filesystem Creation Tests

    func testCreateFilesystemSucceeds() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk(), "Expected filesystem creation to succeed, got error: \(result.getError())")

        let fs = result.unwrap()
        fs.shutdown()
    }

    func testCreateFilesystemWithWrongPasswordFails() throws {
        let result = create(testVaultPath(), "wrong-password")
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
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        // FSKit reserves ID 1, so root is always 2
        XCTAssertEqual(fs.get_root_item_id(), 2)
    }

    // MARK: - Volume Statistics Tests

    func testVolumeStatisticsSucceeds() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let statsResult = fs.getVolumeStats()
        XCTAssertTrue(statsResult.isOk(), "Expected volume stats to succeed")

        let stats = statsResult.unwrap()
        XCTAssertGreaterThan(stats.getTotalBytes(), 0)
        XCTAssertGreaterThan(stats.getBlockSize(), 0)
    }

    // MARK: - Directory Enumeration Tests

    func testEnumerateRootDirectory() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
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
        let result = create(testVaultPath(), TEST_PASSWORD)
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
        XCTAssertEqual(attrs.getSize(), 0)
        XCTAssertEqual(attrs.getMode(), 0o644)

        // Clean up: remove the file
        let itemId = attrs.getItemId()
        let removeResult = fs.remove(rootId, filename, itemId)
        XCTAssertTrue(removeResult.isOk(), "Remove should succeed")
    }

    // MARK: - File Read/Write Tests

    func testWriteAndReadFile() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Create a file
        let filename = "swift_rw_test_\(Int(Date().timeIntervalSince1970)).txt"
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())

        let attrs = createResult.unwrap()
        let itemId = attrs.getItemId()

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
        XCTAssertEqual(Int(readBytes.len()), contentBytes.count)

        // Verify content matches
        var readContent = [UInt8]()
        for i in 0..<Int(readBytes.len()) {
            if let byte = readBytes.get(index: UInt(i)) {
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
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        let dirname = "swift_dir_\(Int(Date().timeIntervalSince1970))"
        let createResult = fs.createDirectory(rootId, dirname)

        XCTAssertTrue(createResult.isOk(), "Expected directory creation to succeed")

        let attrs = createResult.unwrap()
        XCTAssertTrue(attrs.isDirectory())
        XCTAssertEqual(attrs.getMode(), 0o755)

        // Clean up
        let itemId = attrs.getItemId()
        _ = fs.remove(rootId, dirname, itemId)
    }

    // MARK: - Symlink Tests

    func testCreateSymlinkSucceeds() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
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
        let itemId = attrs.getItemId()
        let readResult = fs.readSymlink(itemId)
        XCTAssertTrue(readResult.isOk())

        let targetBytes = readResult.unwrap()
        var targetContent = [UInt8]()
        for i in 0..<Int(targetBytes.len()) {
            if let byte = targetBytes.get(index: UInt(i)) {
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
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let lookupResult = fs.lookup(rootId, "nonexistent_file_12345.txt")

        XCTAssertFalse(lookupResult.isOk(), "Expected lookup of nonexistent file to fail")
        XCTAssertEqual(lookupResult.getError(), ENOENT, "Should return ENOENT for nonexistent file")
    }

    // MARK: - Attributes Tests

    func testGetAttributesSucceeds() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Create a file to get attributes for
        let filename = "swift_attrs_\(Int(Date().timeIntervalSince1970)).txt"
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())

        let createAttrs = createResult.unwrap()
        let itemId = createAttrs.getItemId()

        // Get attributes by item ID
        let attrsResult = fs.getAttributes(itemId)
        XCTAssertTrue(attrsResult.isOk())

        let attrs = attrsResult.unwrap()
        XCTAssertEqual(attrs.getItemId(), itemId)
        XCTAssertTrue(attrs.isFile())
        XCTAssertEqual(attrs.getSize(), 0)

        // Clean up
        _ = fs.remove(rootId, filename, itemId)
    }

    // MARK: - Unicode Filename Tests

    func testUnicodeFilename() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()

        // Test various Unicode filenames
        let unicodeNames = [
            "café_☕.txt",           // Latin with diacritics + emoji
            "日本語ファイル.txt",      // Japanese
            "中文文件.txt",            // Chinese
            "файл_кириллица.txt",    // Cyrillic
            "αρχείο_ελληνικά.txt",   // Greek
            "קובץ_עברית.txt",         // Hebrew (RTL)
            "🎉🎊🎄.txt"              // Pure emoji
        ]

        for name in unicodeNames {
            let createResult = fs.createFile(rootId, name)
            XCTAssertTrue(createResult.isOk(), "Failed to create file: \(name)")

            let attrs = createResult.unwrap()
            let itemId = attrs.getItemId()

            // Lookup should work
            let lookupResult = fs.lookup(rootId, name)
            XCTAssertTrue(lookupResult.isOk(), "Failed to lookup Unicode file: \(name)")
            XCTAssertEqual(lookupResult.unwrap().getItemId(), itemId)

            // Clean up
            let removeResult = fs.remove(rootId, name, itemId)
            XCTAssertTrue(removeResult.isOk(), "Failed to remove Unicode file: \(name)")
        }
    }

    func testUnicodeDirectoryName() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let dirName = "документы_📁"

        let createResult = fs.createDirectory(rootId, dirName)
        XCTAssertTrue(createResult.isOk(), "Failed to create Unicode directory")

        let dirId = createResult.unwrap().getItemId()

        // Create a file inside the Unicode-named directory
        let fileResult = fs.createFile(dirId, "test_inside.txt")
        XCTAssertTrue(fileResult.isOk(), "Failed to create file in Unicode directory")
        let fileId = fileResult.unwrap().getItemId()

        // Clean up
        _ = fs.remove(dirId, "test_inside.txt", fileId)
        _ = fs.remove(rootId, dirName, dirId)
    }

    // MARK: - Large File Tests

    func testLargeFileMultiChunk() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let filename = "large_file_\(Int(Date().timeIntervalSince1970)).bin"

        // Create file
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())
        let itemId = createResult.unwrap().getItemId()

        // Cryptomator uses 32KB chunks, write 100KB to span multiple chunks
        let fileSize = 100 * 1024
        var testData = [UInt8](repeating: 0, count: fileSize)
        for i in 0..<fileSize {
            testData[i] = UInt8(i & 0xFF)  // Predictable pattern
        }

        // Open for write
        let openResult = fs.openFile(itemId, true)
        XCTAssertTrue(openResult.isOk())
        let writeHandle = openResult.unwrap()

        // Write data
        let rustVec = RustVec<UInt8>()
        for byte in testData {
            rustVec.push(value: byte)
        }
        let writeResult = fs.writeFile(writeHandle, 0, rustVec)
        XCTAssertTrue(writeResult.isOk())
        XCTAssertEqual(writeResult.unwrap(), Int64(fileSize))

        _ = fs.closeFile(writeHandle)

        // Verify size
        let attrsResult = fs.getAttributes(itemId)
        XCTAssertTrue(attrsResult.isOk())
        XCTAssertEqual(attrsResult.unwrap().getSize(), UInt64(fileSize))

        // Read back and verify
        let openReadResult = fs.openFile(itemId, false)
        XCTAssertTrue(openReadResult.isOk())
        let readHandle = openReadResult.unwrap()

        let readResult = fs.readFile(readHandle, 0, Int64(fileSize))
        XCTAssertTrue(readResult.isOk())

        let readBytes = readResult.unwrap()
        XCTAssertEqual(Int(readBytes.len()), fileSize)

        // Verify content
        for i in 0..<fileSize {
            if let byte = readBytes.get(index: UInt(i)) {
                XCTAssertEqual(byte, UInt8(i & 0xFF), "Mismatch at byte \(i)")
            }
        }

        _ = fs.closeFile(readHandle)
        _ = fs.remove(rootId, filename, itemId)
    }

    func testPartialReadAcrossChunks() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let filename = "partial_read_\(Int(Date().timeIntervalSince1970)).bin"

        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())
        let itemId = createResult.unwrap().getItemId()

        // Write 64KB (2 chunks)
        let fileSize = 64 * 1024
        var testData = [UInt8](repeating: 0, count: fileSize)
        for i in 0..<fileSize {
            testData[i] = UInt8(i & 0xFF)
        }

        let openResult = fs.openFile(itemId, true)
        XCTAssertTrue(openResult.isOk())
        let writeHandle = openResult.unwrap()

        let rustVec = RustVec<UInt8>()
        for byte in testData {
            rustVec.push(value: byte)
        }
        _ = fs.writeFile(writeHandle, 0, rustVec)
        _ = fs.closeFile(writeHandle)

        // Read from middle of first chunk to middle of second chunk (crossing boundary)
        let readOffset = Int64(30 * 1024)  // 30KB into file
        let readLength = Int64(8 * 1024)   // 8KB read

        let openReadResult = fs.openFile(itemId, false)
        XCTAssertTrue(openReadResult.isOk())
        let readHandle = openReadResult.unwrap()

        let readResult = fs.readFile(readHandle, readOffset, readLength)
        XCTAssertTrue(readResult.isOk())

        let readBytes = readResult.unwrap()
        XCTAssertEqual(Int(readBytes.len()), Int(readLength))

        // Verify the read content matches expected
        for i in 0..<Int(readLength) {
            let expectedByte = UInt8((Int(readOffset) + i) & 0xFF)
            if let byte = readBytes.get(index: UInt(i)) {
                XCTAssertEqual(byte, expectedByte, "Mismatch at offset \(Int(readOffset) + i)")
            }
        }

        _ = fs.closeFile(readHandle)
        _ = fs.remove(rootId, filename, itemId)
    }

    // MARK: - Concurrent Access Tests

    func testConcurrentFileCreation() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let expectation = XCTestExpectation(description: "Concurrent file creation")
        expectation.expectedFulfillmentCount = 10

        var createdIds: [UInt64] = []
        let lock = NSLock()
        let timestamp = Int(Date().timeIntervalSince1970)

        // Create 10 files concurrently
        for i in 0..<10 {
            DispatchQueue.global().async {
                let filename = "concurrent_\(timestamp)_\(i).txt"
                let createResult = fs.createFile(rootId, filename)

                if createResult.isOk() {
                    let itemId = createResult.unwrap().getItemId()
                    lock.lock()
                    createdIds.append(itemId)
                    lock.unlock()
                }

                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)

        // All files should have been created
        XCTAssertEqual(createdIds.count, 10, "All 10 files should be created")

        // All IDs should be unique
        let uniqueIds = Set(createdIds)
        XCTAssertEqual(uniqueIds.count, 10, "All item IDs should be unique")

        // Clean up
        lock.lock()
        for (i, itemId) in createdIds.enumerated() {
            _ = fs.remove(rootId, "concurrent_\(timestamp)_\(i).txt", itemId)
        }
        lock.unlock()
    }

    func testConcurrentReadWrite() throws {
        let result = create(testVaultPath(), TEST_PASSWORD)
        XCTAssertTrue(result.isOk())

        let fs = result.unwrap()
        defer { fs.shutdown() }

        let rootId = fs.get_root_item_id()
        let filename = "concurrent_rw_\(Int(Date().timeIntervalSince1970)).txt"

        // Create file with initial content
        let createResult = fs.createFile(rootId, filename)
        XCTAssertTrue(createResult.isOk())
        let itemId = createResult.unwrap().getItemId()

        // Write initial content
        let initialContent = "Initial content for concurrent test"
        let openResult = fs.openFile(itemId, true)
        XCTAssertTrue(openResult.isOk())
        let writeHandle = openResult.unwrap()

        let rustVec = RustVec<UInt8>()
        for byte in initialContent.utf8 {
            rustVec.push(value: byte)
        }
        _ = fs.writeFile(writeHandle, 0, rustVec)
        _ = fs.closeFile(writeHandle)

        // Concurrent reads
        let expectation = XCTestExpectation(description: "Concurrent reads")
        expectation.expectedFulfillmentCount = 5

        var readResults: [Bool] = []
        let lock = NSLock()

        for _ in 0..<5 {
            DispatchQueue.global().async {
                let openReadResult = fs.openFile(itemId, false)
                if openReadResult.isOk() {
                    let handle = openReadResult.unwrap()
                    let readResult = fs.readFile(handle, 0, 100)

                    lock.lock()
                    readResults.append(readResult.isOk())
                    lock.unlock()

                    _ = fs.closeFile(handle)
                }
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)

        // All reads should succeed
        XCTAssertEqual(readResults.count, 5)
        XCTAssertTrue(readResults.allSatisfy { $0 }, "All concurrent reads should succeed")

        // Clean up
        _ = fs.remove(rootId, filename, itemId)
    }
}
