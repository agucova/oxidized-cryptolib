# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Structure

This is a Cargo workspace with six crates:

```
crates/
├── oxidized-cryptolib/    # Core cryptographic library
│   ├── src/
│   │   ├── crypto/        # MasterKey, RFC 3394 key wrapping
│   │   ├── vault/         # VaultOperations, config, master key extraction
│   │   ├── fs/            # File/directory/symlink encryption
│   │   ├── mount/         # MountBackend trait for filesystem backends
│   │   └── error/         # Unified error types
│   ├── benches/           # Performance and timing leak benchmarks
│   └── tests/             # Integration tests
├── oxidized-cli/          # CLI tool (oxcrypt binary)
│   └── src/
│       └── commands/      # ls, cat, tree, mkdir, rm, cp, mv, info
├── oxidized-fuse/         # FUSE filesystem (oxmount binary)
│   ├── src/
│   │   ├── filesystem.rs  # FUSE Filesystem trait implementation
│   │   ├── inode.rs       # Inode table management
│   │   ├── backend.rs     # MountBackend implementation
│   │   ├── attr.rs        # Attribute and directory caching
│   │   └── error.rs       # Error mapping to errno
│   ├── benches/           # Performance benchmarks
│   └── tests/             # Integration tests
├── oxidized-fskit/        # FSKit filesystem (oxmount-fskit binary, macOS 15.4+)
│   ├── src/
│   │   ├── filesystem.rs  # FSKit Filesystem trait implementation
│   │   ├── item_table.rs  # Item ID management (like inodes)
│   │   ├── backend.rs     # MountBackend implementation
│   │   ├── handles.rs     # File handle and write buffer management
│   │   └── error.rs       # Error mapping to errno
│   └── tests/             # Unit tests
├── oxidized-gui/          # Desktop GUI (oxvault binary)
│   └── src/
│       ├── backend/       # FUSE/FSKit backend integration
│       ├── state/         # App state and vault management
│       └── components/    # Dioxus UI components
└── oxidized-bench/        # Cross-implementation benchmark harness (oxbench binary)
    └── src/
        ├── bench/         # Benchmark definitions, runner, suites
        ├── mount/         # Uses MountBackend from oxidized-fuse/fskit
        ├── results/       # Statistics, tables, and charts
        └── platform/      # Platform-specific utilities (macOS version detection)
```

## Commands

### Build and Development
- **Build all**: `cargo build` (builds entire workspace)
- **Build library**: `cargo build -p oxidized-cryptolib`
- **Build CLI**: `cargo build -p oxidized-cli`
- **Build FUSE**: `cargo build -p oxidized-fuse`
- **Build FSKit**: `cargo build -p oxidized-fskit` (macOS 15.4+ only, requires `protoc`)
- **Build GUI**: `cargo build -p oxidized-gui`
- **Build GUI with FSKit**: `cargo build -p oxidized-gui --features fskit`
- **Check**: `cargo check` (fast compile check without generating binaries)
- **Format**: `cargo fmt` (format all Rust code using rustfmt)
- **Lint**: `cargo clippy` (static analysis and linting)
- **Clean**: `cargo clean` (remove target directory)

### Running the CLI
- **Run CLI**: `cargo run -p oxidized-cli -- --vault <path> <command>`
- **Install CLI**: `cargo install --path crates/oxidized-cli`
- **Example**: `oxcrypt --vault test_vault ls`

### Running the FUSE Mount
- **Run mount**: `cargo run -p oxidized-fuse -- <vault_path> <mountpoint>`
- **Install mount**: `cargo install --path crates/oxidized-fuse`
- **Example**: `oxmount ~/my_vault /mnt/vault`
- **Unmount (macOS)**: `umount /mnt/vault`
- **Unmount (Linux)**: `fusermount -u /mnt/vault`

### Running the FSKit Mount (macOS 15.4+)
Requires FSKitBridge.app installed and enabled in System Settings.
- **Run mount**: `cargo run -p oxidized-fskit -- <vault_path> --mount-point <mountpoint>`
- **Install mount**: `cargo install --path crates/oxidized-fskit`
- **Example**: `oxmount-fskit ~/my_vault --mount-point /tmp/vault`
- **Unmount**: `umount /tmp/vault` or Ctrl+C

**Prerequisites**:
1. macOS 15.4 (Sequoia) or later
2. `protoc` installed (for building fskit-rs)
3. FSKitBridge.app from [releases](https://github.com/debox-network/FSKitBridge/releases)
4. Enable in System Settings → General → Login Items & Extensions → File System Extensions

### Running the GUI
- **Run GUI**: `cargo run -p oxidized-gui`
- **Run GUI with FSKit**: `cargo run -p oxidized-gui --features fskit`
- **Install GUI**: `cargo install --path crates/oxidized-gui`
- **Binary name**: `oxvault`

### Running the Benchmark Harness
Cross-implementation benchmark tool for comparing FUSE, FSKit, and official Cryptomator performance.
- **Run benchmarks**: `cargo run -p oxidized-bench --release -- /path/to/vault`
- **Install**: `cargo install --path crates/oxidized-bench`
- **Binary name**: `oxbench`

**Basic usage**:
```bash
# Benchmark FUSE implementation only (default)
oxbench /path/to/vault

# Benchmark specific implementations
oxbench /path/to/vault fuse fskit

# Compare with official Cryptomator (user-mounted)
oxbench /path/to/vault fuse --cryptomator /Volumes/MyVault
```

**Options**:
- `-m, --mount-prefix <PATH>` - Mount point prefix (default: /tmp/oxbench)
- `-c, --cryptomator <PATH>` - Path to already-mounted Cryptomator vault
- `-p, --password <PASSWORD>` - Vault password (or OXBENCH_PASSWORD env)
- `-s, --suite <SUITE>` - Benchmark suite: quick, read, write, full (default: full)
- `--iterations <N>` - Iterations per benchmark (default: 10)
- `-v, --verbose` - Verbose output

**Cache clearing**: When benchmarking multiple implementations, oxbench will prompt for sudo access to clear OS caches between implementations for accurate results. Falls back to extended waits if sudo is unavailable.

### Testing
Uses `cargo-nextest` for faster parallel test execution (installed automatically by devenv):
- **All tests**: `cargo nextest run` (runs all tests in parallel with better output)
- **Library tests**: `cargo nextest run -p oxidized-cryptolib`
- **CLI tests**: `cargo nextest run -p oxidized-cli`
- **FUSE unit tests**: `cargo nextest run -p oxidized-fuse` (unit tests only)
- **FSKit tests**: `cargo nextest run -p oxidized-fskit`
- **GUI tests**: `cargo nextest run -p oxidized-gui`
- **Integration tests**: `cargo nextest run -p oxidized-cryptolib -E 'test(crypto_tests)'`
- **Specific test**: `cargo nextest run [test_name]`
- **CI profile**: `cargo nextest run --profile ci` (used in GitHub Actions)
- **List tests**: `cargo nextest list` (show all available tests)
- **Retry flaky**: `cargo nextest run --retries 2` (retry failed tests)

### FUSE Integration Tests
Requires FUSE installed and external test tools (pjdfstest, fsx). Enable with `--features fuse-tests`:
- **All FUSE tests**: `cargo nextest run -p oxidized-fuse --features fuse-tests`
- **pjdfstest** (POSIX compliance): tests mkdir, open, symlink, rename, unlink, etc.
- **fsx** (data integrity): random read/write/truncate with verification
- **fsstress** (concurrency, Linux only): multi-process stress testing
- **mount_tests**: basic mount/read/write operations

Legacy `cargo test` still works but nextest is preferred:
- **Fallback**: `cargo test` (standard test runner)
- **With output**: `cargo test -- --nocapture`

### Code Coverage
Uses `cargo-llvm-cov` (installed automatically by devenv):
- **Text summary**: `cargo llvm-cov nextest --workspace`
- **HTML report**: `cargo llvm-cov nextest --workspace --html` (output in `target/llvm-cov/html/`)
- **LCOV format**: `cargo llvm-cov nextest --workspace --lcov --output-path lcov.info`
- **Open HTML report**: `cargo llvm-cov nextest --workspace --open`

### Benchmarking
- **All benchmarks**: `cargo bench -p oxidized-cryptolib` (runs all criterion-based performance benchmarks)
- **FUSE benchmarks**: `cargo bench -p oxidized-fuse` (inode table, caches, end-to-end I/O)
- **Quick benchmarks**: `cargo bench -p oxidized-cryptolib -- --quick` (faster execution for development)
- **Baseline benchmarks**: `cargo bench -p oxidized-cryptolib -- --save-baseline [name]` (save performance baseline)
- **Compare benchmarks**: `cargo bench -p oxidized-cryptolib -- --baseline [name]` (compare against saved baseline)

### Timing Leak Detection (Constant-Time Verification)
Uses dudect statistical methodology to detect timing side-channels in cryptographic operations:
- **Run all tests**: `cargo bench -p oxidized-cryptolib --bench timing_leaks` (runs all timing tests)
- **Run specific test**: `cargo bench -p oxidized-cryptolib --bench timing_leaks -- --filter <name>` (e.g., `--filter key_unwrap`)
- **Continuous mode**: `cargo bench -p oxidized-cryptolib --bench timing_leaks -- --continuous <name>` (runs until Ctrl+C)

**Interpretation**: t-value < 4.5 = PASS (no timing leak detected), t-value > 4.5 = FAIL (potential timing leak)

**Tests include**:
- RFC 3394 key unwrap integrity check
- HMAC verification (via ring)
- AES-GCM file header/content decryption
- AES-SIV filename decryption

### Async Debugging with tokio-console
Both `oxidized-fuse` and `oxidized-fskit` support [tokio-console](https://github.com/tokio-rs/console) for real-time async task introspection during development. The `tokio-console` CLI is installed automatically by devenv.

**Usage**:
```bash
# Build with console support (FUSE)
cargo build -p oxidized-fuse --features tokio-console

# Build with console support (FSKit)
cargo build -p oxidized-fskit --features tokio-console

# Run the mount (terminal 1)
./target/debug/oxmount ~/vault /mnt/point

# Connect console (terminal 2)
tokio-console
```

**What you can observe**:
- Active async tasks and their states
- Task poll times and waker counts
- Resource contention (mutexes, semaphores)
- `spawn_blocking` threads for CPU-bound crypto

**Note**: The `tokio-console` feature is opt-in and adds zero overhead to normal builds. The workspace `.cargo/config.toml` enables `tokio_unstable` required for task instrumentation.

## Architecture Overview

### oxidized-cryptolib (Core Library)

Implements the Cryptomator encryption protocol with modern cryptographic practices.

#### Cryptographic Modules (`crates/oxidized-cryptolib/src/crypto/`)
- **`keys.rs`**: Core MasterKey struct with AES and MAC keys (32 bytes each), uses `memsafe` crate for memory protection (mlock, mprotect)
- **`key_wrap.rs`**: Pure Rust implementation of AES Key Wrap algorithm per RFC 3394

#### Vault Modules (`crates/oxidized-cryptolib/src/vault/`)
- **`master_key.rs`**: Scrypt-based key derivation from passphrases with RFC 3394 AES key wrapping
- **`config.rs`**: JWT-based vault configuration parsing and master key extraction
- **`operations.rs`**: High-level VaultOperations API for file/directory operations
- **`path.rs`**: DirId and VaultPath types for vault navigation

#### Filesystem Modules (`crates/oxidized-cryptolib/src/fs/`)
- **`name.rs`**: Filename encryption/decryption using AES-SIV with directory ID as associated data
- **`file.rs`**: File content encryption/decryption using AES-GCM with 32KB chunk processing
- **`directory.rs`**: Directory traversal and tree building
- **`symlink.rs`**: Symlink target encryption/decryption

### oxidized-cli (CLI Tool)

Command-line interface for interacting with Cryptomator vaults.

#### Commands (`crates/oxidized-cli/src/commands/`)
- **`ls`**: List directory contents
- **`cat`**: Read and output file contents
- **`tree`**: Show directory tree
- **`mkdir`**: Create a directory
- **`rm`**: Remove a file or directory
- **`cp`**: Copy a file within the vault
- **`mv`**: Move or rename a file or directory
- **`info`**: Show vault information

### oxidized-fuse (FUSE Filesystem)

FUSE implementation for mounting Cryptomator vaults as native filesystems.

#### Core Modules (`crates/oxidized-fuse/src/`)
- **`filesystem.rs`**: `CryptomatorFS` struct implementing fuser's `Filesystem` trait
- **`inode.rs`**: `InodeTable` for bidirectional path↔inode mapping with `nlookup` tracking
- **`attr.rs`**: `AttrCache` (TTL-based file attributes) and `DirCache` (directory listings)
- **`error.rs`**: Conversion from `VaultOperationError`/`VaultWriteError` to libc errno codes

#### Architecture
```
CryptomatorFS (implements fuser::Filesystem)
        │
        ├── InodeTable (DashMap, lock-free)
        ├── AttrCache (TTL-based, 1s default)
        └── VaultOperationsAsync (from oxidized-cryptolib)
                │
                ├── HandleTable (file I/O handles)
                └── Crypto (AES-GCM, AES-SIV)
```

#### Performance Characteristics
- Inode lookup: ~10 ns (in-memory hash)
- Attribute cache hit: ~26 ns
- Vault unlock: ~37 ms (one-time scrypt)
- Directory listing: ~80 µs (filename decryption)
- File read: ~82 µs (content decryption)

### oxidized-fskit (FSKit Filesystem, macOS 15.4+)

Native macOS filesystem using Apple's FSKit framework via [fskit-rs](https://github.com/debox-network/fskit-rs).

#### Why FSKit?
- FUSE on macOS is unmaintained (fuser maintainer [stopped macOS support](https://github.com/cberner/fuser/issues/306#issuecomment-2107438748))
- FSKit provides better macOS integration (native Finder support, no kernel extension)
- Requires FSKitBridge.app to bridge FSKit's XPC to Rust via TCP+Protobuf

#### Architecture
```
VFS (Kernel)
     │ XPC
     ▼
FSKitBridge.app/FSKitExt.appex (Swift, sandboxed)
     │ TCP + Protobuf (127.0.0.1:35367)
     ▼
CryptomatorFSKit (implements fskit_rs::Filesystem)
     │
     ├── ItemTable (item_id ↔ VaultPath mapping)
     ├── HandleTable (open file handles)
     └── VaultOperationsAsync (from oxidized-cryptolib)
```

#### Core Modules (`crates/oxidized-fskit/src/`)
- **`filesystem.rs`**: `CryptomatorFSKit` struct implementing fskit_rs's `Filesystem` trait
- **`item_table.rs`**: `ItemTable` for bidirectional item_id↔path mapping (like FUSE inodes)
- **`handles.rs`**: `HandleTable` and `WriteBuffer` for file I/O with random-access write support
- **`backend.rs`**: `FSKitBackend` implementing `MountBackend` trait for GUI integration
- **`error.rs`**: Conversion from vault errors to POSIX errno codes

### oxidized-gui (Desktop GUI)

Cross-platform desktop application using [Dioxus](https://dioxuslabs.com/) for vault management.

#### Features
- Vault creation, opening, and management
- Backend selection (FUSE by default, FSKit on macOS 15.4+ with `--features fskit`)
- Mount/unmount operations via MountManager

#### Architecture
```
oxvault (Dioxus desktop app)
     │
     ├── MountManager (coordinates backends)
     │        │
     │        ├── FuseBackend (from oxidized-fuse)
     │        └── FSKitBackend (stub or real from oxidized-fskit)
     │
     └── VaultState (app state management)
```

#### Core Modules (`crates/oxidized-gui/src/`)
- **`backend/mod.rs`**: `MountManager` for coordinating filesystem backends
- **`backend/fuse.rs`**: Re-exports `FuseBackend` from oxidized-fuse
- **`backend/fskit.rs`**: Conditional `FSKitBackend` (real when `fskit` feature enabled, stub otherwise)
- **`state/`**: Application state and vault management

### oxidized-bench (Benchmark Harness)

Cross-implementation benchmark tool for comparing filesystem performance across FUSE, FSKit, and official Cryptomator.

#### Architecture
```
oxbench (BenchmarkRunner)
     │
     ├── mount_implementation()
     │        │
     │        ├── FuseBackend (from oxidized-fuse, via MountBackend trait)
     │        ├── FSKitBackend (from oxidized-fskit, via MountBackend trait)
     │        └── ExternalMount (validates user-mounted Cryptomator)
     │
     ├── CacheClearStrategy (Sudo or WaitOnly)
     │
     └── Benchmark suite (read/write/metadata operations)
```

#### Core Modules (`crates/oxidized-bench/src/`)
- **`bench/runner.rs`**: `BenchmarkRunner` for sequential benchmark execution with cache clearing
- **`bench/suite.rs`**: Suite definitions (quick, read, write, full)
- **`bench/read.rs`**, **`write.rs`**, **`metadata.rs`**: Individual benchmark implementations
- **`mount/mod.rs`**: Uses `MountBackend` trait from oxidized-fuse/fskit for unified mount handling
- **`mount/external.rs`**: Validates external Cryptomator mounts
- **`results/`**: Statistics calculation, table rendering, and chart output

#### Sequential Mounting
Benchmarks run one implementation at a time to avoid:
- Concurrent access conflicts on the same vault
- OS page cache cross-contamination between implementations
- Write conflicts that could corrupt vault data

### Security Features
- Uses `#![forbid(unsafe_code)]` in critical crypto modules
- Memory protection via `memsafe` crate (mlock, mprotect, zeroization on drop)
- Authenticated encryption (AES-GCM, AES-SIV) preventing tampering
- JWT signature validation for vault integrity
- Property-based testing with 1000 test cases for crypto operations
- Constant-time operations verified via dudect timing analysis
- Uses `subtle` crate for constant-time comparisons in key unwrap

### Dependencies
Key cryptographic dependencies include:
- `aes-gcm`, `aes-siv` for authenticated encryption
- `ring` for cryptographic primitives (HMAC, SHA)
- `scrypt` for key derivation
- `jsonwebtoken` for vault configuration validation
- `proptest` for property-based testing
- `memsafe` for memory-protected key storage (mlock, mprotect)
- `zeroize` for secure memory zeroization
- `subtle` for constant-time primitives
- `dudect-bencher` for timing leak detection (dev-dependency)
- `fuser` for FUSE filesystem implementation (oxidized-fuse)
- `fskit-rs` for FSKit filesystem implementation (oxidized-fskit, macOS 15.4+)
- `dioxus` for desktop GUI framework (oxidized-gui)
- `dashmap` for lock-free concurrent data structures (oxidized-fuse, oxidized-fskit)

### Development Notes
- Property-based tests use 1000 test cases to verify cryptographic correctness
- Code follows Rust 2024 edition (requires Rust 1.90+)
- Test vault in `test_vault/` for integration testing

## Cryptomator Protocol Reference

### Vault Format 8 (Current)
The implementation follows Cryptomator Vault Format 8, introduced in Cryptomator 1.6.0:
- **JWT-based vault configuration**: `vault.cryptomator` contains vault metadata signed with master keys
- **Cipher combo**: `SIV_GCM` (AES-SIV for filenames, AES-GCM for file contents)
- **Filename threshold**: 220 characters before shortening to `.c9s` format
- **Directory structure**: Flattened under `/d/` with 2-character subdirectories

### Key Cryptographic Components
- **Master keys**: 256-bit encryption + 256-bit MAC keys derived via scrypt
- **File headers**: 68 bytes (12-byte nonce + 40-byte AES-GCM payload + 16-byte tag)
- **File content**: 32KB chunks with AES-GCM, chunk number + header nonce as AAD
- **Filename encryption**: AES-SIV with parent directory ID as associated data
- **Directory IDs**: Random UUIDs (root directory uses empty string)

### File Structure Patterns
- **Regular files**: `{base64url-encrypted-name}.c9r`
- **Directories**: `{encrypted-name}.c9r/dir.c9r` (contains directory ID)
- **Symlinks**: `{encrypted-name}.c9r/symlink.c9r` (contains link target)
- **Long names**: `{sha1-hash}.c9s/name.c9s` + `contents.c9r`/`dir.c9r`/`symlink.c9r`

### Security Considerations
- **Accepted risk**: Filename swapping within same directory (performance vs security tradeoff)
- **Protected**: File contents, filenames, directory structure obfuscation
- **Not protected**: File sizes, timestamps, number of files per directory

Refer to `.claude/cryptomator_docs/` for complete protocol specifications.
