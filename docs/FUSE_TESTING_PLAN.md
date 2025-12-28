# Filesystem Test Suite for oxidized-fuse

## Current Testing Status

The oxidized-fuse crate has solid unit and integration testing:
- **51 unit tests**: inode table, caches (attr/dir), handles, error mapping
- **18 integration tests**: simulated FUSE operations, concurrency, edge cases
- **Benchmarks**: performance testing with real vault operations

**Key Gap**: No tests for the actual mounted FUSE filesystem. Current tests simulate components but don't verify behavior through the kernel FUSE interface.

## Available Filesystem Test Suites

### 1. pjdfstest (Recommended)
- **GitHub**: https://github.com/pjd/pjdfstest
- **What it tests**: POSIX compliance - chmod, chown, link, mkdir, mkfifo, open, rename, rmdir, symlink, truncate, unlink
- **Platforms**: FreeBSD, Linux, Solaris (macOS via secfs.test port)
- **Requires**: Root access, mounted filesystem
- **Pros**:
  - Industry standard for FUSE filesystems
  - Well-documented, actively maintained
  - Tests real filesystem behavior through kernel
  - Easy to run: `prove -r /path/to/pjdfstest`
- **Cons**: Requires root, C-based (not Rust-native)

### 2. xfstests
- **GitHub**: https://github.com/kdave/xfstests
- **What it tests**: Comprehensive stress testing, metadata operations, data integrity
- **Requires**: Patching for FUSE support (see bhumitattarde/XFSTESTS-FUSE-patch)
- **Pros**: Most comprehensive test suite available
- **Cons**: Complex setup, originally for kernel filesystems, requires patching

### 3. secfs.test (macOS)
- **GitHub**: https://github.com/billziss-gh/secfs.test
- **What it tests**: Port of pjdfstest to macOS
- **Pros**: Works on macOS (darwin platform)
- **Cons**: Less actively maintained than pjdfstest

### 4. Custom Rust Integration Tests
- **Approach**: Write tests that mount the filesystem, perform operations via std::fs, verify results
- **Examples**: AWS mountpoint-s3, fuser's own mount_tests (uses Docker)
- **Pros**: Rust-native, can integrate with cargo test
- **Cons**: Need to build from scratch, won't catch edge cases that established suites would

## Recommendation

**Primary: pjdfstest** for POSIX compliance testing
- Catches real-world filesystem bugs that unit tests miss
- Validates errno codes, permission handling, edge cases
- Used by ntfs-3g, ZFS, and many other FUSE filesystems

**Secondary: Custom Rust integration tests** for Cryptomator-specific scenarios
- Test encrypted file read/write roundtrip via mounted filesystem
- Verify symlink handling
- Test concurrent access patterns

## Detailed Implementation Plan

### Part 1: Custom Rust Mount Tests

**File**: `crates/oxidized-fuse/tests/mount_tests.rs`

```rust
// Pattern from fuser's own tests:
// 1. Create temp directory for mountpoint
// 2. Spawn filesystem in background thread
// 3. Perform std::fs operations on mounted path
// 4. Verify results
// 5. Unmount and cleanup
```

**Tests to include**:
- `test_mount_and_list_root` - basic mount, readdir
- `test_read_file_content` - read encrypted file, verify decryption
- `test_write_new_file` - create file, write, flush, verify via CLI
- `test_mkdir_and_rmdir` - directory operations
- `test_rename_file` - move within vault
- `test_symlink_roundtrip` - create/read symlinks
- `test_file_attributes` - verify size, timestamps
- `test_concurrent_reads` - multi-threaded file access
- `test_large_file` - test chunked encryption (>32KB)

**Dev dependencies to add**:
```toml
[dev-dependencies]
tempfile = "3"
```

**Test gating**: `#[cfg(target_os = "linux")]` or `#[cfg(unix)]` since macOS FUSE has different behavior.

### Part 2: pjdfstest Integration

**File**: `scripts/run-pjdfstest.sh`
```bash
#!/bin/bash
# Build and run pjdfstest against mounted vault
# Requires: root, FUSE installed

VAULT_PATH="$1"
MOUNT_POINT="$2"

# Mount the vault
./target/release/oxmount "$VAULT_PATH" "$MOUNT_POINT" &
MOUNT_PID=$!
sleep 2

# Run pjdfstest (skip unsupported: mkfifo, mknod, special files)
cd /path/to/pjdfstest
prove -r tests/chmod tests/chown tests/link tests/mkdir \
         tests/open tests/rename tests/rmdir tests/symlink \
         tests/truncate tests/unlink

# Cleanup
umount "$MOUNT_POINT"
wait $MOUNT_PID
```

**CI Integration** (`.github/workflows/ci.yml`):
```yaml
pjdfstest:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install FUSE
      run: sudo apt-get install -y fuse3 libfuse3-dev
    - name: Build pjdfstest
      run: |
        git clone https://github.com/pjd/pjdfstest
        cd pjdfstest && autoreconf -ifs && ./configure && make
    - name: Build oxidized-fuse
      run: cargo build --release -p oxidized-fuse
    - name: Run pjdfstest
      run: sudo ./scripts/run-pjdfstest.sh test_vault /tmp/mnt
```

### Part 3: Test Categories

| Category | pjdfstest | Rust Tests |
|----------|-----------|------------|
| POSIX syscall semantics | ✓ | |
| Error codes (errno) | ✓ | |
| Permission bits | ✓ | |
| Crypto roundtrip | | ✓ |
| Large files | | ✓ |
| Concurrent access | | ✓ |
| Symlinks | ✓ | ✓ |

## Files to Create/Modify

| File | Action |
|------|--------|
| `crates/oxidized-fuse/tests/mount_tests.rs` | Create |
| `crates/oxidized-fuse/Cargo.toml` | Add tempfile dev-dep |
| `scripts/run-pjdfstest.sh` | Create |
| `.github/workflows/ci.yml` | Add pjdfstest job |

## Execution Order

1. Add Rust mount tests first (can develop/test locally)
2. Verify tests pass on Linux
3. Add pjdfstest CI job
4. Document test requirements in README

---

## Implementation Status (Completed)

### Files Created

| File | Description |
|------|-------------|
| `crates/oxidized-fuse/tests/mount_tests.rs` | 10 Rust mount tests covering read, write, mkdir, rename, symlinks, large files, concurrent access |
| `crates/oxidized-fuse/tests/pjdfstest.rs` | Rust wrapper for pjdfstest POSIX compliance tests (7 test categories) |
| `scripts/run-pjdfstest.sh` | Wrapper script to run pjdfstest against mounted vault |

### CI Workflows Updated

Added to `.github/workflows/rust.yml`:
- **fuse_tests** job: Runs Rust mount tests on Ubuntu with FUSE
- **pjdfstest_rust** job: Runs Rust pjdfstest wrapper (mkdir, open, symlink tests - no sudo needed)
- **pjdfstest_shell** job: Runs full pjdfstest suite via shell script (on main branch or with `run-pjdfstest` label)

### Running Tests Locally

```bash
# Run mount tests (requires FUSE)
cargo test -p oxidized-fuse --test mount_tests -- --ignored --test-threads=1

# Run pjdfstest Rust wrapper (requires FUSE and pjdfstest binary)
# In devenv, pjdfstest is available automatically
cargo test -p oxidized-fuse --test pjdfstest "mkdir" -- --ignored --test-threads=1
cargo test -p oxidized-fuse --test pjdfstest "open" -- --ignored --test-threads=1
cargo test -p oxidized-fuse --test pjdfstest "symlink" -- --ignored --test-threads=1

# Run full pjdfstest suite (requires sudo for chown/chmod tests)
sudo ./scripts/run-pjdfstest.sh --quick
```

### pjdfstest Test Status

| Test Category | Status | Notes |
|---------------|--------|-------|
| mkdir | ✅ 100% pass | Directory create/remove operations |
| open | ✅ 100% pass | File create with O_CREAT |
| symlink | ✅ 100% pass | Symlink create/unlink (readlink not supported by pjdfstest on macOS) |
| unlink | ⚠️ Known issues | File visibility after create (cache issue) |
| rename | ⚠️ Known issues | File visibility after create (cache issue) |
| truncate | ❌ Not implemented | setattr returns ENOSYS |

### Mount Tests Coverage

| Test | Purpose |
|------|---------|
| `test_mount_and_list_root` | Basic mount and readdir |
| `test_read_file_content` | Read encrypted file, verify decryption |
| `test_file_attributes` | Verify file metadata |
| `test_concurrent_reads` | Multi-threaded directory access |
| `test_write_new_file` | Create and write file |
| `test_mkdir_and_rmdir` | Directory operations |
| `test_rename_file` | Move/rename within vault |
| `test_symlink_roundtrip` | Create and read symlinks |
| `test_large_file` | Multi-chunk file (>32KB) |
| `test_rapid_open_close` | Stress test for handle management |

### FSX (File System eXerciser) Tests

Added in `crates/oxidized-fuse/tests/fsx_tests.rs`. FSX generates pseudorandom read/write/truncate operations and verifies data integrity on every read.

**Installation**: Installed automatically by devenv.

**Run**: `cargo test -p oxidized-fuse --test fsx_tests -- --ignored --nocapture`

| Test | Operations | Status | Notes |
|------|------------|--------|-------|
| `test_fsx_quick` | 100 | ❌ Known bug | File visibility issue after create |
| `test_fsx_medium` | 1000 | ❌ Known bug | Same issue |
| `test_fsx_stress` | 10000 | ❌ Known bug | Same issue |
| `test_fsx_multiple_seeds` | 5x500 | ❌ Known bug | Same issue |
| `test_fsx_small_file` | 500, 4KB max | ❌ Known bug | Same issue |
| `test_fsx_large_file` | 500, 128KB max | ❌ Known bug | Same issue |

**Root Cause**: Created files are not immediately visible for subsequent operations. This is the same cache invalidation bug that affects pjdfstest's unlink/rename tests.

### fsstress Tests (Linux only)

Added in `crates/oxidized-fuse/tests/fsstress_tests.rs`. fsstress performs concurrent filesystem operations across multiple processes to find race conditions.

**Available via**: devenv (Linux only)

**Run**: `cargo test -p oxidized-fuse --test fsstress_tests -- --ignored --nocapture`

| Test | Operations | Processes | Notes |
|------|------------|-----------|-------|
| `test_fsstress_quick` | 50 | 1 | Single-process smoke test |
| `test_fsstress_concurrent` | 100 | 4 | Concurrency test |
| `test_fsstress_stress` | 500 | 8 | Full stress test |
| `test_fsstress_multiple_seeds` | 5x100 | 2 | Multiple seeds for coverage |

### Additional Test Suites (Research)

Other test suites considered for future integration:

| Suite | Purpose | Integration Status |
|-------|---------|-------------------|
| [pjdfstest-rs](https://github.com/musikid/pjdfstest) | Rust rewrite of pjdfstest, no root required | Candidate |
| [fsracer](https://github.com/billziss-gh/secfs.test) | Race condition detection | Candidate |
| [Google fs-stress](https://github.com/google/file-system-stress-testing) | Monkey testing | Candidate |
| [CrashMonkey](https://github.com/utsaslab/crashmonkey) | Crash consistency | Lower priority |

