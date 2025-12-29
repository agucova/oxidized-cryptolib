# oxidized-fskit-legacy

> **DEPRECATED**: This crate is deprecated and will be replaced by `oxidized-fskit-ffi`. New development should use `oxidized-fskit-ffi` which provides a more robust Swift/Rust bridge for FSKit integration.

FSKit filesystem for Cryptomator vaults on macOS 15.4+.

This crate provides a native macOS filesystem implementation for Cryptomator vaults
using Apple's FSKit framework. Unlike FUSE, FSKit is Apple's official userspace filesystem
API and provides better integration with the macOS ecosystem.

## Requirements

- **macOS 15.4 or later** (FSKit was introduced in macOS 15.4)
- **FSKitBridge.app** installed from [releases](https://github.com/debox-network/FSKitBridge/releases)
- **FSKit extension enabled** in System Settings

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         macOS (15.4+)                           │
├─────────────────────────────────────────────────────────────────┤
│  VFS (Kernel)                                                   │
│       │ XPC                                                     │
│       ▼                                                         │
│  FSKitBridge.app/FSKitExt.appex (Swift, sandboxed)              │
│       │ TCP + Protobuf (127.0.0.1:35367)                        │
│       ▼                                                         │
│  oxidized-fskit-legacy (Rust) ◄── This crate                           │
│       │                                                         │
│       ▼                                                         │
│  VaultOperationsAsync (oxidized-cryptolib)                      │
│       │                                                         │
│       ▼                                                         │
│  Cryptomator Vault (encrypted files)                            │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### 1. Install FSKitBridge

Download and install FSKitBridge.app from the [releases page](https://github.com/debox-network/FSKitBridge/releases).

### 2. Enable FSKit Extension

1. Open **System Settings**
2. Go to **General → Login Items & Extensions**
3. Click **File System Extensions**
4. Enable **FSKitBridge**

### 3. Install oxmount-fskit

```bash
cargo install --path crates/oxidized-fskit-legacy
```

## Usage

### Command Line

```bash
# Mount a vault
oxmount-fskit /path/to/vault --mount-point /tmp/vault

# Mount with password from command line (not recommended for production)
oxmount-fskit /path/to/vault --mount-point /tmp/vault --password "secret"

# Enable debug logging
RUST_LOG=debug oxmount-fskit /path/to/vault --mount-point /tmp/vault
```

### Library Usage

```rust
use oxidized_fskit_legacy::CryptomatorFSKit;
use fskit_rs::{mount, MountOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Open the vault
    let fs = CryptomatorFSKit::new("/path/to/vault", "password")?;

    // Mount it
    let opts = MountOptions {
        mount_point: "/tmp/vault".into(),
        ..Default::default()
    };
    let session = mount(fs, opts).await?;

    // Keep mounted until Ctrl+C
    tokio::signal::ctrl_c().await?;
    drop(session);

    Ok(())
}
```

## Features

- **Full read/write support**: Read, write, create, delete files and directories
- **Symlink support**: Create and follow symbolic links
- **Streaming I/O**: Efficient reading of large files without loading into memory
- **Write buffering**: Random-access write support via in-memory buffering
- **Native macOS integration**: Uses Apple's official FSKit framework

## Comparison with oxidized-fuse

| Feature | oxidized-fskit-legacy | oxidized-fuse |
|---------|----------------|---------------|
| Platform | macOS 15.4+ only | Linux, macOS (via macFUSE) |
| API | Apple FSKit | FUSE |
| Integration | Native macOS | Third-party (macFUSE) |
| Maintenance | Active (Apple) | macOS support deprecated |

For macOS users on 15.4+, oxidized-fskit-legacy is available but deprecated.
New development should use oxidized-fskit-ffi instead. For Linux users or older
macOS versions, use oxidized-fuse.

## Debugging with tokio-console

For async debugging during development, oxmount-fskit supports [tokio-console](https://github.com/tokio-rs/console). The CLI is installed automatically by devenv.

```bash
# Build with console support
cargo build -p oxidized-fskit-legacy --features tokio-console

# Run the mount (terminal 1)
./target/debug/oxmount-fskit ~/vault --mount-point /tmp/vault

# Connect console (terminal 2)
tokio-console
```

This shows real-time async task states, poll times, and resource contention. The feature is opt-in with zero overhead in normal builds.

## Troubleshooting

### FSKitBridge not responding

Check if the FSKit extension is running:

```bash
log stream --predicate 'subsystem == "FSKitExt"'
```

### Mount point not accessible

Ensure the mount point exists and is writable:

```bash
mkdir -p /tmp/vault
chmod 755 /tmp/vault
```

### Authentication errors

If you get decryption errors, verify your password is correct by testing with
the CLI tool:

```bash
oxcrypt --vault /path/to/vault ls
```

## Technical Details

### Item IDs

FSKit uses 64-bit item IDs similar to FUSE inodes. The root directory has item ID 2
(ID 1 is reserved). The `ItemTable` maintains bidirectional mapping between item IDs
and vault paths.

### Send/Sync Handling

`VaultOperationsAsync` contains `RefCell` (via the memsafe crate) which is not `Sync`.
Since fskit-rs requires `Send` futures, vault operations are executed inside
`spawn_blocking` with a current-thread Tokio runtime.

### Error Mapping

Vault errors are mapped to POSIX errno codes for compatibility with the FSKit protocol.
See `error.rs` for the complete mapping.

## License

Same as the workspace (see root Cargo.toml).
