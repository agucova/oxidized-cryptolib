# oxidized-cryptolib

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

A Rust library for reading and writing [Cryptomator](https://cryptomator.org/) vaults (Vault Format 8).

This is the foundation for building a full-featured, high-performance Cryptomator client in Rust. It implements all the core cryptographic and vault operations a client would need: master key derivation, file and filename encryption/decryption, directory traversal, and file operations including symlinks.

The cryptographic operations use established RustCrypto libraries (aes-gcm, aes-siv, scrypt) rather than custom implementations. Keys are memory-protected using `secrecy` and `zeroize`, and timing-sensitive operations use constant-time comparisons via the `subtle` crate, verified with dudect. The codebase includes property-based tests, Wycheproof test vectors, and fuzz targets.

## Installation

```toml
[dependencies]
oxidized-cryptolib = "0.3.0"
```

## Usage

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

## API Overview

| Module | Description |
|--------|-------------|
| `crypto` | Low-level primitives: `MasterKey`, RFC 3394 key wrapping |
| `vault` | High-level `VaultOperations` API, vault configuration, master key extraction |
| `fs` | File/directory/symlink encryption and decryption |
| `error` | Unified error types with security context |

## Security

This library prioritizes security. See [SECURITY.md](SECURITY.md) for the full threat model.

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
- Keys wrapped in `SecretBox`, zeroized on drop
- Memory locking via `mlock` where supported
- `#![forbid(unsafe_code)]` in cryptographic modules

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench

# Verify constant-time operations
cargo bench --bench timing_leaks
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features:
- Async I/O support
- Streaming API for large files
- FUSE filesystem integration

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code is formatted (`cargo fmt`)
- No clippy warnings (`cargo clippy`)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
