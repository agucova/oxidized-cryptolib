# oxidized-cryptolib

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

A Rust implementation for reading and writing [Cryptomator](https://cryptomator.org/) vaults (Vault Format 8).

This monorepo contains ten crates:

**Applications:**
- **[oxidized-cli](crates/oxidized-cli/)** (`oxcrypt`) - Command-line interface for vault operations and mounting
- **[oxidized-gui](crates/oxidized-gui/)** (`oxvault`) - Desktop GUI for vault management
- **[oxidized-bench](crates/oxidized-bench/)** (`oxbench`) - Cross-implementation filesystem benchmark harness

**Libraries:**
- **oxidized-cryptolib** - Core library implementing all cryptographic and vault operations
- **[oxidized-mount-common](crates/oxidized-mount-common/)** - Shared utilities for mount backends (caching, handles, WriteBuffer)

**Mount Backends:**
- **[oxidized-fuse](crates/oxidized-fuse/)** - FUSE filesystem (Linux/macOS with macFUSE)
- **[oxidized-fskit-legacy](crates/oxidized-fskit-legacy/)** - FSKit via FSKitBridge.app (macOS 15.4+, deprecated)
- **[oxidized-fskit-ffi](crates/oxidized-fskit-ffi/)** - Native FSKit via Swift FFI (macOS 15.4+)
- **[oxidized-webdav](crates/oxidized-webdav/)** - WebDAV server backend (cross-platform, no kernel extensions)
- **[oxidized-nfs](crates/oxidized-nfs/)** - NFS server backend (Linux/macOS, no kernel extensions)

The goal is to build a full-featured, high-performance Cryptomator client in Rust. The library implements master key derivation, file and filename encryption/decryption, directory traversal, and file operations including symlinks.

Cryptographic operations use established RustCrypto libraries (aes-gcm, aes-siv, scrypt) rather than custom implementations. Keys are memory-protected using `memsafe` (mlock, mprotect) and zeroized on drop. Timing-sensitive operations use constant-time comparisons via the `subtle` crate, verified with dudect. The codebase includes property-based tests, Wycheproof test vectors, and fuzz targets.

## CLI Usage

```bash
# Build and install (choose backends based on your platform)
cargo install --path crates/oxidized-cli --features fuse,webdav  # Linux/macOS
cargo install --path crates/oxidized-cli --features webdav       # Windows

# List vault contents
oxcrypt --vault /path/to/vault ls

# Show directory tree
oxcrypt --vault /path/to/vault tree

# Read a file
oxcrypt --vault /path/to/vault cat documents/secret.txt

# Create a directory
oxcrypt --vault /path/to/vault mkdir my_folder

# Create an empty file
oxcrypt --vault /path/to/vault touch newfile.txt

# Write stdin to a file
echo "Hello" | oxcrypt --vault /path/to/vault write greeting.txt

# Copy, move, remove files
oxcrypt --vault /path/to/vault cp source.txt dest.txt
oxcrypt --vault /path/to/vault mv old.txt new.txt
oxcrypt --vault /path/to/vault rm unwanted.txt

# Show vault info
oxcrypt --vault /path/to/vault info

# Initialize a new vault
oxcrypt init /path/to/new-vault

# Mount commands (requires backend features)
oxcrypt backends                        # List available backends
oxcrypt mount /path/to/vault /mnt/vault # Mount using best available backend
oxcrypt mount /path/to/vault -b webdav  # Mount using specific backend
oxcrypt mounts                          # List active mounts
oxcrypt unmount /mnt/vault              # Unmount a vault
oxcrypt stats                           # Show vault statistics
```

Set `OXCRYPT_VAULT` to avoid passing `--vault` every time.

See the [CLI README](crates/oxidized-cli/README.md) for full documentation.

## FUSE Mount Usage

```bash
# Build and install
cargo install --path crates/oxidized-fuse

# Mount a vault
oxmount /path/to/vault /mnt/vault
# Enter password when prompted

# Access files normally
ls /mnt/vault
cat /mnt/vault/documents/secret.txt

# Unmount
umount /mnt/vault  # macOS
fusermount -u /mnt/vault  # Linux
```

See the [FUSE README](crates/oxidized-fuse/README.md) for full documentation.

## FSKit Mount Usage (macOS 15.4+)

FSKit provides better macOS integration than FUSE (native Finder support, no kernel extension).

**Prerequisites**:
1. macOS 15.4 (Sequoia) or later
2. `protoc` installed
3. FSKitBridge.app from [releases](https://github.com/debox-network/FSKitBridge/releases)
4. Enable in System Settings → General → Login Items & Extensions → File System Extensions

```bash
# Build and install
cargo install --path crates/oxidized-fskit-legacy

# Mount a vault
oxmount-fskit /path/to/vault --mount-point /tmp/vault
# Enter password when prompted

# Unmount
umount /tmp/vault  # or Ctrl+C
```

See the [FSKit README](crates/oxidized-fskit-legacy/README.md) for full documentation.

## WebDAV Mount Usage

WebDAV provides cross-platform mounting without kernel extensions - ideal for Windows or when FUSE/FSKit aren't available.

```bash
# Start WebDAV server for a vault
oxcrypt --vault /path/to/vault mount -b webdav /tmp/webdav-mount

# Connect via:
# - macOS: Finder → Go → Connect to Server → http://127.0.0.1:PORT
# - Windows: Explorer → Map network drive → http://127.0.0.1:PORT
# - Linux: File manager → Connect to Server → dav://127.0.0.1:PORT
```

## NFS Mount Usage

NFS provides userspace mounting on Unix systems without kernel extensions.

```bash
# Start NFS server for a vault
oxcrypt --vault /path/to/vault mount -b nfs /mnt/vault

# The vault is automatically mounted via system mount command
```

## GUI Usage

```bash
# Build with FUSE backend (Linux/macOS)
cargo build -p oxidized-gui --release --features fuse
./target/release/oxvault

# Build with WebDAV backend (cross-platform)
cargo build -p oxidized-gui --release --features webdav
./target/release/oxvault

# Build with multiple backends (macOS)
cargo build -p oxidized-gui --release --features fuse,webdav,nfs
./target/release/oxvault
```

The GUI includes:
- Vault browser with unlock/lock
- Mount management with backend selection
- System tray for background operation
- Real-time vault statistics

## Benchmark Usage

Compare filesystem performance across FUSE, FSKit, WebDAV, NFS, and official Cryptomator:

```bash
# Build and install
cargo install --path crates/oxidized-bench

# Benchmark FUSE implementation only
oxbench /path/to/vault fuse

# Benchmark multiple backends
oxbench /path/to/vault fuse webdav nfs

# Benchmark all available backends (macOS 15.4+)
oxbench /path/to/vault fuse fskit webdav nfs

# Compare with official Cryptomator (mount it first, then provide path)
oxbench /path/to/vault fuse --cryptomator /Volumes/MyVault

# Quick benchmark (fewer iterations, smaller files)
oxbench /path/to/vault fuse -s quick

# Full benchmark suite with all tests
oxbench /path/to/vault fuse -s full
```

See the [Benchmark README](crates/oxidized-bench/README.md) for full documentation.

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
oxidized-cryptolib = { git = "https://github.com/agucova/oxidized-cryptolib" }
```

### Opening a vault and listing contents

```rust
use oxidized_cryptolib::vault::{
    config::extract_master_key,
    operations::VaultOperations,
    path::DirId,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new("my_vault");
    let password = "my_password";

    // Extract master key from vault using passphrase
    let master_key = extract_master_key(vault_path, password)?;

    // Create vault operations handle
    let vault = VaultOperations::new(vault_path, master_key);

    // List files in root directory
    let root = DirId::root();
    for file in vault.list_files(&root)? {
        println!("File: {}", file.decrypted_name);
    }

    // List subdirectories
    for dir in vault.list_directories(&root)? {
        println!("Directory: {}", dir.decrypted_name);
    }

    Ok(())
}
```

### Reading files

```rust
// Read a file using its vault path
let decrypted = vault.read_by_path("documents/secret.txt")?;
println!("Content: {}", String::from_utf8_lossy(&decrypted.content));

// Or read by directory ID and filename
let content = vault.read_file(&dir_id, "secret.txt")?;
```

### Writing files and creating directories

```rust
// Create a new directory
vault.create_directory_by_path("my_folder")?;

// Write a new file
vault.write_by_path("my_folder/notes.txt", b"Hello, encrypted world!")?;

// Create nested directory structure
vault.create_directory_by_path("documents/projects/2024")?;
```

### Directory tree exploration

```rust
use oxidized_cryptolib::fs::directory::{VaultExplorer, print_tree};

let explorer = VaultExplorer::new(&vault);
let tree = explorer.build_tree()?;
print_tree(&tree, 0);
```

### Working with symlinks

```rust
// Create a symlink
vault.create_symlink(&dir_id, "link_name", "../target/path")?;

// Read symlink target
let target = vault.read_symlink(&dir_id, "link_name")?;
```

## Project Structure

```
crates/
├── oxidized-cryptolib/       # Core library
│   ├── src/
│   │   ├── crypto/           # MasterKey, RFC 3394 key wrapping
│   │   ├── vault/            # VaultOperations, config, master key extraction
│   │   ├── fs/               # File/directory/symlink encryption
│   │   └── error/            # Unified error types
│   ├── benches/              # Performance and timing leak benchmarks
│   └── tests/                # Integration tests
├── oxidized-cli/             # CLI tool (oxcrypt)
│   └── src/commands/         # ls, cat, tree, mkdir, rm, cp, mv, mount, unmount, etc.
├── oxidized-gui/             # Desktop GUI (oxvault)
│   └── src/                  # Dioxus app, system tray, backend integration
├── oxidized-bench/           # Benchmark harness (oxbench)
│   └── src/                  # Benchmark runner, multi-backend comparison
├── oxidized-mount-common/    # Shared mount utilities
│   └── src/                  # MountBackend trait, WriteBuffer, caching, HandleTable
├── oxidized-fuse/            # FUSE backend
│   └── src/                  # fuser trait impl, inode table, attr cache
├── oxidized-fskit-legacy/    # FSKit via FSKitBridge (deprecated)
│   └── src/                  # Protobuf-based bridge protocol
├── oxidized-fskit-ffi/       # Native FSKit via Swift FFI
│   ├── src/                  # Rust FFI layer (swift-bridge)
│   └── swift/                # Generated Swift bindings
├── oxidized-webdav/          # WebDAV backend
│   └── src/                  # HTTP/WebDAV server, dav-server integration
└── oxidized-nfs/             # NFS backend
    └── src/                  # NFSv3 server via nfsserve
swift/
└── OxVaultFSExtension/       # Native macOS FSKit extension (Swift)
```

## Security

See [SECURITY.md](SECURITY.md) for the full threat model.

**What it protects against:**
- Unauthorized file/filename access (AES-256 encryption)
- Content tampering (AEAD authentication tags)
- Brute-force attacks (memory-hard Scrypt)
- Timing side-channels (constant-time comparisons, dudect verified)

**What it does NOT protect against:**
- Malware with local system access
- Physical attacks (cold boot, DMA)
- Denial of service

**Memory protection:**
- Keys wrapped in `MemSafe` with mlock and mprotect
- Automatic zeroization on drop
- `#![forbid(unsafe_code)]` in cryptographic modules

## Development

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Run library benchmarks
cargo bench -p oxidized-cryptolib

# Verify constant-time operations
cargo bench -p oxidized-cryptolib --bench timing_leaks
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features. Key milestones completed:
- ✅ Async I/O support (VaultOperationsAsync)
- ✅ Streaming API for large files
- ✅ FUSE filesystem backend (oxidized-fuse)
- ✅ FSKit filesystem backend (oxidized-fskit-ffi, macOS 15.4+)
- ✅ WebDAV server backend (oxidized-webdav, cross-platform)
- ✅ NFS server backend (oxidized-nfs, Linux/macOS)
- ✅ Desktop GUI with system tray (oxidized-gui)
- ✅ CLI mount/unmount commands with backend selection
- ✅ Cross-implementation benchmark harness (oxidized-bench)

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code is formatted (`cargo fmt`)
- No clippy warnings (`cargo clippy`)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
