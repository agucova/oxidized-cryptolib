# oxcrypt-fuse

A FUSE (Filesystem in Userspace) implementation for mounting [Cryptomator](https://cryptomator.org/) vaults as native filesystems.

Built on top of [oxcrypt-core](../oxcrypt-core), this crate provides transparent read/write access to encrypted vaults without requiring the official Cryptomator application.

## Features

- **Full read/write support** - Read, write, create, and delete files and directories
- **Symlink support** - Create and follow symbolic links within the vault
- **Attribute caching** - TTL-based caching for improved performance
- **Thread-safe** - Concurrent access via lock-free data structures (DashMap)
- **Cross-platform** - Supports macOS (via macFUSE) and Linux (via libfuse)

## Requirements

### macOS

Install [macFUSE](https://osxfuse.github.io/):

```bash
brew install --cask macfuse
```

After installation, you may need to allow the kernel extension in System Preferences > Security & Privacy.

### Linux

Install FUSE development libraries:

```bash
# Debian/Ubuntu
sudo apt install libfuse3-dev fuse3

# Fedora
sudo dnf install fuse3-devel fuse3

# Arch Linux
sudo pacman -S fuse3
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
oxcrypt-fuse = { git = "https://github.com/agucova/oxcrypt" }
```

Or use via the CLI:

```bash
cargo install --path crates/oxcrypt --features fuse
oxcrypt mount /path/to/vault /path/to/mountpoint
```

## Usage

### Command Line

Mount a vault using the `oxcrypt` CLI:

```bash
oxcrypt mount /path/to/vault /path/to/mountpoint
```

The tool will prompt for your vault password. To unmount:

```bash
oxcrypt unmount /path/to/mountpoint

# Or manually:
# macOS
umount /path/to/mountpoint

# Linux
fusermount -u /path/to/mountpoint
```

### As a Library

```rust
use oxcrypt_fuse::CryptomatorFS;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let vault_path = Path::new("/path/to/vault");
    let mountpoint = Path::new("/path/to/mountpoint");
    let password = "your-password";

    // Create the filesystem
    let fs = CryptomatorFS::new(vault_path, password)?;

    // Mount (blocks until unmounted)
    let options = vec![
        fuser::MountOption::RO,  // Read-only mount
        fuser::MountOption::FSName("cryptomator".to_string()),
    ];
    fuser::mount2(fs, mountpoint, &options)?;

    Ok(())
}
```

### Using FuseBackend (MountBackend trait)

For applications that need to manage mounts programmatically, use the `FuseBackend` which implements the `MountBackend` trait from oxcrypt-mount:

```rust
use oxcrypt_fuse::FuseBackend;
use oxcrypt_mount::MountBackend;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let backend = FuseBackend::new();

    // Check if FUSE is available
    if !backend.is_available() {
        eprintln!("FUSE not available: {:?}", backend.unavailable_reason());
        return Ok(());
    }

    // Mount the vault (returns a handle for lifecycle management)
    let handle = backend.mount(
        "my-vault",
        Path::new("/path/to/vault"),
        "password",
        Path::new("/path/to/mountpoint"),
    )?;

    println!("Mounted at: {:?}", handle.mountpoint());

    // The mount is automatically unmounted when handle is dropped
    // Or explicitly unmount:
    // handle.unmount()?;

    Ok(())
}
```

This is how `oxcrypt-desktop` and `oxbench` manage FUSE mounts.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CryptomatorFS                             │
│            (implements fuser::Filesystem trait)                  │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  InodeTable   │    │  AttrCache    │    │ VaultOpsAsync │
│ Path ↔ Inode  │    │  TTL-based    │    │  (from lib)   │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            ┌──────────────┐    ┌──────────────┐
            │ HandleTable  │    │   Crypto     │
            │ (file I/O)   │    │  (AES-GCM)   │
            └──────────────┘    └──────────────┘
```

### Key Components

- **InodeTable**: Bidirectional mapping between FUSE inodes and vault paths. Uses atomic counters for `nlookup` tracking required by FUSE protocol.

- **AttrCache**: TTL-based cache for file attributes. Reduces repeated calls to the vault layer for `getattr` operations.

- **DirCache**: Caches directory listings for efficient `readdir` with offset-based pagination.

- **VaultOperationsAsync**: The async vault operations layer from oxcrypt-core, providing actual file encryption/decryption.

## Performance

The FUSE layer adds negligible overhead compared to cryptographic operations:

| Operation | Time | Notes |
|-----------|------|-------|
| Inode lookup | ~10 ns | In-memory hash lookup |
| Attribute cache hit | ~26 ns | Cached getattr |
| Vault unlock | ~37 ms | One-time scrypt key derivation |
| List directory | ~80 µs | Filename decryption |
| Read file | ~82 µs | Content decryption |

The caching layer contributes <0.1% of total operation time. Performance is dominated by:
1. Disk I/O
2. AES-GCM/AES-SIV cryptographic operations
3. FUSE kernel-userspace context switches (~5-10 µs)

## Building

```bash
# Build the crate
cargo build -p oxcrypt-fuse

# Run tests
cargo test -p oxcrypt-fuse

# Run benchmarks
cargo bench -p oxcrypt-fuse
```

## Debugging with tokio-console

For async debugging during development, the FUSE backend supports [tokio-console](https://github.com/tokio-rs/console):

```bash
# Build with console support
cargo build -p oxcrypt --features fuse,tokio-console

# Run the mount (terminal 1)
./target/debug/oxcrypt mount ~/vault /mnt/point

# Connect console (terminal 2)
tokio-console
```

This shows real-time task states, poll times, and resource contention. The feature is opt-in with zero overhead in normal builds.

## Security Considerations

- **Password handling**: Passwords are passed to scrypt for key derivation and then zeroized from memory.
- **Master key protection**: The derived master key is protected using `memsafe` (mlock, mprotect).
- **Authenticated encryption**: All file content uses AES-GCM with authentication tags.
- **Filename encryption**: Filenames are encrypted with AES-SIV, bound to their parent directory.

This implementation follows the [Cryptomator Security Architecture](https://docs.cryptomator.org/en/latest/security/architecture/) for Vault Format 8.

## Limitations

- **No xattr support**: Extended attributes are not supported (returns ENOTSUP)
- **Single vault**: Each mount handles one vault; multiple mounts needed for multiple vaults
- **No hard links**: Cryptomator format doesn't support hard links

## License

MPL-2.0 - see the repository root for details.

## Related

- [oxcrypt-core](../oxcrypt-core) - Core cryptographic library
- [oxcrypt-mount](../oxcrypt-mount) - Shared mount utilities (`MountBackend` trait)
- [oxbench](../oxbench) - Benchmark harness
- [oxcrypt-desktop](../oxcrypt-desktop) - Desktop GUI
- [Cryptomator](https://cryptomator.org/) - The original cross-platform encryption tool
- [fuser](https://github.com/cberner/fuser) - Rust FUSE library used by this crate
