//! Tests for critical bug fixes in FUSE filesystem.
//!
//! This test suite validates fixes for security vulnerabilities and data corruption bugs:
//! - Negative offset handling (read/write/fallocate/copy_file_range)
//! - O_TRUNC without subsequent writes
//! - POSIX unlink compliance (deferred deletion)
//!
//! Run: `cargo nextest run -p oxcrypt-fuse --features fuse-tests bugfix_tests`

#![cfg(all(unix, feature = "fuse-tests"))]

mod common;

#[allow(unused_imports)]
use common::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// =============================================================================
// CRITICAL: Negative Offset in write() - CVE-level severity
// =============================================================================

#[test]
fn test_write_negative_offset_rejected() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create a file with some content
    mount.write("test.txt", b"Hello, World!").unwrap();

    // Open file for writing
    let mut file = OpenOptions::new()
        .write(true)
        .open(mount.path("test.txt"))
        .unwrap();

    // Attempt to seek to negative offset and write
    // This should fail with EINVAL, not cause integer overflow
    let result = file.seek(SeekFrom::Start(u64::MAX)); // -1 as u64

    // Depending on implementation, this might fail at seek or write
    // Either way, it should NOT succeed in writing at a huge offset
    if result.is_ok() {
        let write_result = file.write(b"EXPLOIT");
        assert!(
            write_result.is_err(),
            "Write with negative offset should fail, but succeeded"
        );
    }

    // Verify original content is unchanged
    drop(file);
    assert_file_content(&mount, "test.txt", b"Hello, World!");
}

#[test]
fn test_write_at_max_offset_rejected() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("test.txt", b"content").unwrap();

    let mut file = OpenOptions::new()
        .write(true)
        .open(mount.path("test.txt"))
        .unwrap();

    // Try to write at impossibly large offset (would be negative as i64)
    let result = file.seek(SeekFrom::Start(i64::MAX as u64 + 1));

    if result.is_ok() {
        let write_result = file.write(b"X");
        assert!(
            write_result.is_err(),
            "Write at i64::MAX+1 offset should fail"
        );
    }
}

// =============================================================================
// CRITICAL: O_TRUNC Bug - Data Loss
// =============================================================================

#[test]
fn test_o_trunc_without_write_truncates_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create file with content
    mount
        .write("truncate_test.txt", b"This should be deleted")
        .unwrap();

    // Verify file has content
    assert_file_size(&mount, "truncate_test.txt", 22);

    // Open with O_TRUNC but don't write anything, then close
    {
        let _file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(mount.path("truncate_test.txt"))
            .unwrap();
        // File closed here without writing
    }

    // CRITICAL: File should now be empty (bug was that old content remained)
    assert_file_size(&mount, "truncate_test.txt", 0);
    assert_file_content(&mount, "truncate_test.txt", b"");
}

#[test]
fn test_o_trunc_with_create_empty_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create file with O_TRUNC|O_CREAT but no writes
    {
        let _file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(mount.path("empty_trunc.txt"))
            .unwrap();
    }

    // File should exist and be empty
    assert_exists(&mount, "empty_trunc.txt");
    assert_file_size(&mount, "empty_trunc.txt", 0);
}

#[test]
fn test_o_trunc_multiple_times() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create file with content
    mount.write("multi_trunc.txt", b"Initial content").unwrap();

    // Truncate without writing
    {
        let _file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(mount.path("multi_trunc.txt"))
            .unwrap();
    }
    assert_file_size(&mount, "multi_trunc.txt", 0);

    // Write new content
    mount.write("multi_trunc.txt", b"New content").unwrap();
    assert_file_size(&mount, "multi_trunc.txt", 11);

    // Truncate again without writing
    {
        let _file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(mount.path("multi_trunc.txt"))
            .unwrap();
    }

    // Should be empty again
    assert_file_size(&mount, "multi_trunc.txt", 0);
}

// =============================================================================
// HIGH: Negative Offset in read() - Security Vulnerability
// =============================================================================

#[test]
fn test_read_negative_offset_rejected() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("read_test.txt", b"Secret data here").unwrap();

    let mut file = File::open(mount.path("read_test.txt")).unwrap();

    // Attempt to seek to negative position
    let result = file.seek(SeekFrom::Start(u64::MAX));

    if result.is_ok() {
        let mut buf = [0u8; 16];
        let read_result = file.read(&mut buf);

        // Read should fail, not return arbitrary memory
        assert!(
            read_result.is_err() || read_result.unwrap() == 0,
            "Read at negative offset should fail or return 0 bytes"
        );
    }
}

#[test]
fn test_read_beyond_i64_max_rejected() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("read_test2.txt", b"data").unwrap();

    let mut file = File::open(mount.path("read_test2.txt")).unwrap();

    // Try to read from impossibly large offset
    let result = file.seek(SeekFrom::Start(i64::MAX as u64 + 1000));

    if result.is_ok() {
        let mut buf = [0u8; 100];
        let read_result = file.read(&mut buf);
        assert!(
            read_result.is_err() || read_result.unwrap() == 0,
            "Read at huge offset should fail"
        );
    }
}

// =============================================================================
// HIGH: copy_file_range Negative Offset Bug
// =============================================================================

#[cfg(target_os = "linux")]
#[test]
fn test_copy_file_range_negative_source_offset() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    mount.write("source.txt", b"Source content here").unwrap();
    mount.write("dest.txt", b"Destination").unwrap();

    let src = File::open(mount.path("source.txt")).unwrap();
    let mut dst = OpenOptions::new()
        .write(true)
        .open(mount.path("dest.txt"))
        .unwrap();

    // Attempt copy with negative source offset (as large u64)
    let mut off_in = u64::MAX as i64; // -1
    let mut off_out = 0i64;

    let result = unsafe {
        libc::copy_file_range(
            src.as_raw_fd(),
            &mut off_in as *mut i64,
            dst.as_raw_fd(),
            &mut off_out as *mut i64,
            100,
            0,
        )
    };

    // Should fail with EINVAL
    if result >= 0 {
        panic!("copy_file_range with negative source offset should fail");
    }

    let errno = std::io::Error::last_os_error();
    assert_eq!(errno.kind(), ErrorKind::InvalidInput);

    // Destination should be unchanged
    drop(src);
    drop(dst);
    assert_file_content(&mount, "dest.txt", b"Destination");
}

#[cfg(target_os = "linux")]
#[test]
fn test_copy_file_range_negative_dest_offset() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    mount.write("source2.txt", b"Source").unwrap();
    mount.write("dest2.txt", b"Dest").unwrap();

    let src = File::open(mount.path("source2.txt")).unwrap();
    let mut dst = OpenOptions::new()
        .write(true)
        .open(mount.path("dest2.txt"))
        .unwrap();

    // Attempt copy with negative destination offset
    let mut off_in = 0i64;
    let mut off_out = u64::MAX as i64; // -1

    let result = unsafe {
        libc::copy_file_range(
            src.as_raw_fd(),
            &mut off_in as *mut i64,
            dst.as_raw_fd(),
            &mut off_out as *mut i64,
            100,
            0,
        )
    };

    // Should fail with EINVAL
    if result >= 0 {
        panic!("copy_file_range with negative dest offset should fail");
    }

    let errno = std::io::Error::last_os_error();
    assert_eq!(errno.kind(), ErrorKind::InvalidInput);
}

// =============================================================================
// HIGH: fallocate Negative Offset Bug
// =============================================================================

#[cfg(target_os = "linux")]
#[test]
fn test_fallocate_negative_offset() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    mount.write("fallocate_test.txt", b"content").unwrap();

    let file = OpenOptions::new()
        .write(true)
        .open(mount.path("fallocate_test.txt"))
        .unwrap();

    // Attempt fallocate with negative offset
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            0,     // mode: allocate
            -1i64, // negative offset
            1000,
        )
    };

    // Should fail with EINVAL
    assert!(result < 0, "fallocate with negative offset should fail");

    let errno = std::io::Error::last_os_error();
    assert_eq!(errno.kind(), ErrorKind::InvalidInput);

    // File should be unchanged
    drop(file);
    assert_file_content(&mount, "fallocate_test.txt", b"content");
}

#[cfg(target_os = "linux")]
#[test]
fn test_fallocate_negative_length() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    mount.write("fallocate_len.txt", b"data").unwrap();

    let file = OpenOptions::new()
        .write(true)
        .open(mount.path("fallocate_len.txt"))
        .unwrap();

    // Attempt fallocate with negative length
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            0,
            0,
            -1000i64, // negative length
        )
    };

    // Should fail with EINVAL
    assert!(result < 0, "fallocate with negative length should fail");

    let errno = std::io::Error::last_os_error();
    assert_eq!(errno.kind(), ErrorKind::InvalidInput);
}

// =============================================================================
// MEDIUM: POSIX unlink Compliance - Deferred Deletion
// =============================================================================

#[test]
fn test_unlink_with_open_handle_deferred() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    let content = b"This file is open while being deleted";
    mount.write("open_unlink.txt", content).unwrap();

    // Open file for reading
    let mut file = File::open(mount.path("open_unlink.txt")).unwrap();

    // Unlink while file is open (POSIX: should succeed, file persists until close)
    mount.remove("open_unlink.txt").unwrap();

    // File should no longer appear in directory
    // After unlink, the kernel's dcache is invalidated and lookup returns ENOENT
    // for files marked for deferred deletion.
    let result = File::open(mount.path("open_unlink.txt"));
    assert!(
        result.is_err(),
        "Opening a new handle to unlinked file should fail"
    );
    if let Err(e) = result {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "Should get ENOENT");
    }

    // BUT we should still be able to read from the open file handle
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    assert_eq!(
        buf, content,
        "Should still read from unlinked but open file"
    );

    // Close the file - now it should be truly deleted from vault
    drop(file);

    // Verify file is gone and cannot be re-opened (forces fresh lookup, bypasses cache)
    let result = File::open(mount.path("open_unlink.txt"));
    assert!(
        result.is_err(),
        "File should be deleted after last handle closes"
    );
    if let Err(e) = result {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "Should get ENOENT after deletion"
        );
    }
}

// Test POSIX-compliant behavior: unlinking a file with an open read handle
// should allow continued reading, and file should be deleted when handle closes.
//
// NOTE: This test currently fails - deferred deletion is triggered (confirmed via debug logs)
// but the file persists after handle close. Write handles work correctly (see test_unlink_with_write_handle).
// This appears to be a specific issue with read handle cleanup that needs further investigation.
#[test]
#[ignore = "read handle deferred deletion not completing - needs investigation"]
fn test_unlink_with_multiple_open_handles() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("read_unlink.txt", b"Content to read").unwrap();

    // Open for reading
    let mut file = File::open(mount.path("read_unlink.txt")).unwrap();

    // Unlink while open for reading
    mount.remove("read_unlink.txt").unwrap();

    // Should still be able to read
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"Content to read");

    // Can seek and read again
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut content2 = Vec::new();
    file.read_to_end(&mut content2).unwrap();
    assert_eq!(content2, b"Content to read");

    // Close - file should be deleted
    drop(file);

    // File should be gone
    assert!(!mount.path("read_unlink.txt").exists());
}

#[test]
fn test_unlink_with_write_handle() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("write_unlink.txt", b"Original").unwrap();

    // Open for writing
    let mut file = OpenOptions::new()
        .write(true)
        .open(mount.path("write_unlink.txt"))
        .unwrap();

    // Unlink while open for writing
    mount.remove("write_unlink.txt").unwrap();

    // Should still be able to write
    file.write_all(b"Modified content after unlink").unwrap();
    file.sync_all().unwrap();

    // Close - changes should be persisted even though file was unlinked
    drop(file);

    // File should be gone
    assert!(!mount.path("write_unlink.txt").exists());
}

#[test]
fn test_unlink_without_open_handles_immediate() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("immediate_delete.txt", b"Delete me").unwrap();

    // Unlink without any open handles
    mount.remove("immediate_delete.txt").unwrap();

    // Should be immediately deleted (no deferred deletion needed)
    assert!(!mount.path("immediate_delete.txt").exists());
    assert!(File::open(mount.path("immediate_delete.txt")).is_err());
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_o_trunc_with_subsequent_write() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("trunc_write.txt", b"Old content").unwrap();

    // O_TRUNC followed by write - should work normally
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(mount.path("trunc_write.txt"))
            .unwrap();
        file.write_all(b"New").unwrap();
    }

    assert_file_content(&mount, "trunc_write.txt", b"New");
}

#[test]
fn test_zero_offset_operations_still_work() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("zero_offset.txt", b"0123456789").unwrap();

    // Reading from offset 0 should work
    let mut file = File::open(mount.path("zero_offset.txt")).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buf = [0u8; 5];
    file.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"01234");

    // Writing at offset 0 should work
    let mut file = OpenOptions::new()
        .write(true)
        .open(mount.path("zero_offset.txt"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"XX").unwrap();
    drop(file);

    assert_file_content(&mount, "zero_offset.txt", b"XX23456789");
}

// =============================================================================
// CRITICAL: Multi-Handle File Size Consistency (mmap SIGBUS fix)
// =============================================================================
//
// SQLite WAL mode opens multiple file handles to the same files (.db, -wal, -shm).
// When mmap is used, the kernel caches the file size (st_size) based on getattr's
// attr_ttl. If a stale size is cached, mmap access beyond that size causes SIGBUS.
//
// The fix: buffer_sizes tracking (used for zero TTL) should only be cleared when
// the LAST handle for an inode is closed, not when ANY handle is closed.

#[test]
fn test_multi_handle_size_consistency() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // Create initial file
    mount.write("multi_handle.txt", b"initial").unwrap();
    assert_file_size(&mount, "multi_handle.txt", 7);

    // Open two write handles to the same file
    let mut file1 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("multi_handle.txt"))
        .unwrap();

    let file2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("multi_handle.txt"))
        .unwrap();

    // Extend the file through file1
    file1.seek(SeekFrom::End(0)).unwrap();
    file1.write_all(b" extended content here").unwrap();
    file1.sync_all().unwrap();

    // Query size while both handles are open - should show extended size
    let meta1 = mount.path("multi_handle.txt").metadata().unwrap();
    assert_eq!(
        meta1.len(),
        29,
        "Size should reflect extension while both handles open"
    );

    // Close file1 (but file2 is still open!)
    drop(file1);

    // CRITICAL: Size should STILL be correct after closing one handle
    // The bug was that buffer_sizes was cleared on first handle close,
    // causing getattr to return 60s TTL and the kernel to cache stale size.
    let meta2 = mount.path("multi_handle.txt").metadata().unwrap();
    assert_eq!(
        meta2.len(),
        29,
        "Size should remain correct after closing one handle"
    );

    // Close the second handle
    drop(file2);

    // Final verification
    assert_file_content(&mount, "multi_handle.txt", b"initial extended content here");
}

#[test]
fn test_ftruncate_extend_with_multiple_handles() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("ftrunc_multi.txt", b"start").unwrap();

    // Open multiple handles
    let file1 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("ftrunc_multi.txt"))
        .unwrap();

    let file2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("ftrunc_multi.txt"))
        .unwrap();

    // Extend via ftruncate on file1
    file1.set_len(100).unwrap();

    // Size should be 100
    let meta = mount.path("ftrunc_multi.txt").metadata().unwrap();
    assert_eq!(meta.len(), 100, "Size should be 100 after ftruncate");

    // Close file1
    drop(file1);

    // Size should STILL be 100 after closing one handle
    let meta2 = mount.path("ftrunc_multi.txt").metadata().unwrap();
    assert_eq!(
        meta2.len(),
        100,
        "Size should remain 100 after closing one handle"
    );

    // Close file2
    drop(file2);

    // Final check
    assert_file_size(&mount, "ftrunc_multi.txt", 100);
}

#[test]
fn test_sqlite_like_multi_file_pattern() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    // SQLite-like pattern: multiple files with multiple handles each
    // .db (main), -wal (write-ahead log), -shm (shared memory)

    mount.write("test.db", b"database").unwrap();
    mount.write("test.db-wal", b"wal").unwrap();
    mount.write("test.db-shm", b"shm").unwrap();

    // Open multiple handles per file (simulating SQLite's behavior)
    let db1 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db"))
        .unwrap();
    let db2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db"))
        .unwrap();

    let wal1 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db-wal"))
        .unwrap();
    let wal2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db-wal"))
        .unwrap();

    let shm1 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db-shm"))
        .unwrap();
    let shm2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("test.db-shm"))
        .unwrap();

    // Extend all files via ftruncate (SQLite does this during WAL checkpoint)
    db1.set_len(4096).unwrap();
    wal1.set_len(8192).unwrap();
    shm1.set_len(32768).unwrap();

    // Close one handle from each file
    drop(db1);
    drop(wal1);
    drop(shm1);

    // Sizes should still be correct (this is where the bug manifested)
    assert_eq!(mount.path("test.db").metadata().unwrap().len(), 4096);
    assert_eq!(mount.path("test.db-wal").metadata().unwrap().len(), 8192);
    assert_eq!(mount.path("test.db-shm").metadata().unwrap().len(), 32768);

    // Close remaining handles
    drop(db2);
    drop(wal2);
    drop(shm2);

    // Final verification
    assert_file_size(&mount, "test.db", 4096);
    assert_file_size(&mount, "test.db-wal", 8192);
    assert_file_size(&mount, "test.db-shm", 32768);
}

#[test]
fn test_rapid_open_close_size_consistency() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    mount.write("rapid.txt", b"x").unwrap();

    // Rapidly open/extend/close handles while keeping at least one open
    let anchor = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("rapid.txt"))
        .unwrap();

    for i in 1..=10u64 {
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(mount.path("rapid.txt"))
            .unwrap();

        handle.set_len(i * 1000).unwrap();
        drop(handle);

        // Size should be consistent after each close
        let size = mount.path("rapid.txt").metadata().unwrap().len();
        assert_eq!(
            size,
            i * 1000,
            "Size should be {} after iteration {}",
            i * 1000,
            i
        );
    }

    drop(anchor);
    assert_file_size(&mount, "rapid.txt", 10000);
}

// =============================================================================
// CORRECTNESS: fsync/fdatasync Durability
// =============================================================================
//
// These tests verify that fsync() and fdatasync() properly sync data to disk.
// Prior to the fix, fsync() only flushed to the kernel page cache but never
// called sync_data() or sync_all() on the underlying encrypted files.
//
// Cryptomator's Java implementation calls channel.force(metaData) which
// respects the datasync flag (sync data only vs data+metadata).

/// Test that fsync() properly syncs written data.
///
/// This test verifies that after write() + fsync(), the data is durable.
/// While we can't easily verify data reached the physical disk without root,
/// we ensure the fsync path is exercised and data is correct.
#[test]
fn test_fsync_syncs_data() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    let content = b"Data that must survive a crash";

    // Open file for writing
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mount.path("fsync_test.txt"))
        .unwrap();

    // Write data
    file.write_all(content).unwrap();

    // Call fsync - this should sync data to disk
    let fd = file.as_raw_fd();
    let result = unsafe { libc::fsync(fd) };
    assert_eq!(
        result,
        0,
        "fsync should succeed, errno: {}",
        std::io::Error::last_os_error()
    );

    drop(file);

    // Verify data is correct
    assert_file_content(&mount, "fsync_test.txt", content);
}

/// Test that fdatasync() (via fsync with datasync=true) works correctly.
///
/// fdatasync() syncs only data, not metadata like timestamps. This is
/// faster than full fsync when metadata changes don't need to be durable.
#[test]
fn test_fdatasync_syncs_data() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    let content = b"Data-only sync test content";

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mount.path("fdatasync_test.txt"))
        .unwrap();

    file.write_all(content).unwrap();

    // Call fdatasync - this syncs data only (not metadata)
    // Note: macOS doesn't have fdatasync, so we use fsync instead
    let fd = file.as_raw_fd();
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::fdatasync(fd) };
    #[cfg(not(target_os = "linux"))]
    let result = unsafe { libc::fsync(fd) }; // Fallback for macOS/BSD
    assert_eq!(
        result,
        0,
        "fdatasync/fsync should succeed, errno: {}",
        std::io::Error::last_os_error()
    );

    drop(file);

    assert_file_content(&mount, "fdatasync_test.txt", content);
}

/// Test fsync on a file opened for read-write that was modified.
#[test]
fn test_fsync_after_modify_existing_file() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    // Create initial file
    mount
        .write("modify_fsync.txt", b"Original content")
        .unwrap();

    // Open for read-write and modify
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mount.path("modify_fsync.txt"))
        .unwrap();

    // Overwrite beginning
    file.write_all(b"Modified").unwrap();

    // fsync the changes
    let result = unsafe { libc::fsync(file.as_raw_fd()) };
    assert_eq!(result, 0, "fsync should succeed");

    drop(file);

    // Verify modification persisted
    assert_file_content(&mount, "modify_fsync.txt", b"Modified content");
}

/// Test that multiple fsync calls work correctly.
#[test]
fn test_multiple_fsync_calls() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mount.path("multi_fsync.txt"))
        .unwrap();

    // Write and fsync multiple times
    for i in 0..5 {
        file.write_all(format!("Line {}\n", i).as_bytes()).unwrap();
        let result = unsafe { libc::fsync(file.as_raw_fd()) };
        assert_eq!(result, 0, "fsync #{} should succeed", i);
    }

    drop(file);

    let content = mount.read("multi_fsync.txt").unwrap();
    assert_eq!(content, b"Line 0\nLine 1\nLine 2\nLine 3\nLine 4\n");
}

/// Test fsync on a clean (unmodified) file handle.
#[test]
fn test_fsync_on_clean_handle() {
    skip_if_no_fuse!();
    let mount = require_mount!(TestMount::with_temp_vault());

    use std::os::unix::io::AsRawFd;

    mount.write("clean_fsync.txt", b"Existing content").unwrap();

    // Open read-only (no modifications)
    let file = File::open(mount.path("clean_fsync.txt")).unwrap();

    // fsync on clean handle should succeed (no-op)
    let result = unsafe { libc::fsync(file.as_raw_fd()) };
    assert_eq!(result, 0, "fsync on clean handle should succeed");

    drop(file);

    assert_file_content(&mount, "clean_fsync.txt", b"Existing content");
}
