# OxCrypt

**A fast, memory-safe Cryptomator client written in Rust.**

Mount your encrypted vaults with FUSE, FSKit, WebDAV, or NFS—no Java runtime required.

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

---

## Why OxCrypt?

I've used [Cryptomator](https://cryptomator.org/) for years. Great protocol, but the Java client has always been slow for me—directory listings lag, large file transfers crawl, and it eats memory.

I tried reading the Java source a while back to figure out why, but gave up. Started rewriting it in Rust instead. Got the crypto library working with full Vault Format 8 support, then hit the wall of FUSE/filesystem stuff and shelved it.

Recently picked it back up with Claude Code doing most of the filesystem plumbing—FUSE, WebDAV, NFS, CLI, GUI, the works. FSKit is still WIP (Apple's docs are... sparse).

The result is roughly **10x faster** for typical operations, in a ~5MB binary instead of a ~200MB JVM.

## Performance

Real-world workload benchmarks (Apple M4 Max, 15 iterations each):

| Workload | OxCrypt FUSE | Official Cryptomator (FUSE) | Speedup |
|----------|--------------|------------------------------|---------|
| **Folder Browse** | 10.5 ± 2.1 ms | 30.0 ± 8.2 ms | **2.87×** |
| **Backup/Sync** | 811 ± 17 ms | 2.15 ± 0.54 s | **2.65×** |
| **Code Editor** | 34.4 ± 3.4 ms | 57.6 ± 24.7 ms | **1.68×** |
| **Git Workflow** | 739 ± 227 ms | ❌ _fails (readdir bug)_ | ∞× |
| **Photo Library** | 547 ± 5 ms | 576 ± 42 ms | **1.05×** |
| **Video Playback** | 849 ± 6 ms | 869 ± 7 ms | **1.02×** |
| **SQLite Database** | 139.5 ± 4.8 ms | 139.2 ± 8.4 ms | ~1.0× |
| **Multi-Process** | 5.10 ± 0.01 s | 5.13 ± 0.02 s | ~1.0× |

**Key findings:**
- ✅ **2-3× faster** on metadata-heavy operations (directory traversal, backups)
- ✅ **Much more consistent** - typically <10% variance vs 25-40% on Cryptomator
- ✅ **More robust** - fixes critical readdir offset bug that causes official Cryptomator to fail on git operations

Run your own comparison:

```bash
cargo build --release -p oxcrypt-bench
./target/release/oxbench ~/vault fuse external \
  --external-vault /Volumes/YourCryptomatorMount \
  --suite workload --iterations 15
```

## Quick Start

```bash
# Install
cargo install oxcrypt --features fuse    # Linux/macOS
cargo install oxcrypt --features webdav  # Windows/cross-platform

# Mount
oxcrypt mount ~/Vaults/MyVault ~/mnt/decrypted
# Enter password, then use like any filesystem

# Unmount
oxcrypt unmount ~/mnt/decrypted
```

## Mount Backends

| Backend | Platforms | Kernel Extension | Best For |
|---------|-----------|------------------|----------|
| **FUSE** | Linux, macOS | Yes (macFUSE/libfuse) | Maximum throughput |
| **FSKit** | macOS 15.4+ | No | Native Finder integration *(WIP)* |
| **WebDAV** | All | No | Windows, Docker, portable |
| **NFS** | Linux, macOS | No | Headless servers, NAS |

```bash
oxcrypt mount ~/vault ~/mnt -b fuse    # Default on Unix
oxcrypt mount ~/vault ~/mnt -b webdav  # Cross-platform
oxcrypt mount ~/vault ~/mnt -b nfs     # NFSv3 server
# oxcrypt mount ~/vault ~/mnt -b fskit # macOS Sequoia native (WIP)
```

> **Note:** FSKit support is experimental and not yet usable. Apple's FSKit framework (macOS 15.4+) is promising for kernel-extension-free mounts with native Finder integration, but the API is still underdocumented and our implementation is incomplete.

## Security

**Important caveat:** I'm not a cryptographer. I did my best to maintain strict parity with Cryptomator's implementation, using established RustCrypto libraries (aes-gcm, aes-siv, scrypt) rather than rolling my own crypto. The test suite includes Wycheproof vectors, property-based tests, and fuzz targets. But I can't make guarantees—if you're protecting state secrets, get a professional audit first.

**What I did do:**
- `#![forbid(unsafe_code)]` in cryptographic modules
- Master keys protected with mlock (prevent swap) + mprotect (guard pages) + zeroization on drop
- Constant-time comparisons via `subtle` crate, verified with [dudect](https://github.com/rozbb/dudect)
- Full [Vault Format 8](https://docs.cryptomator.org/en/latest/security/architecture/) compatibility—your existing vaults work unchanged

See [SECURITY.md](SECURITY.md) for the full threat model.

## CLI

```bash
oxcrypt --vault ~/vault ls              # List files
oxcrypt --vault ~/vault tree            # Directory tree
oxcrypt --vault ~/vault cat secret.txt  # Read file
oxcrypt --vault ~/vault write notes.txt # Write from stdin
oxcrypt init ~/new-vault                # Create vault
oxcrypt backends                        # List backends
oxcrypt mounts                          # Active mounts
```

Set `OXCRYPT_VAULT` to skip `--vault` every time.

## Desktop GUI

```bash
cargo install oxcrypt-desktop --features fuse
```

- Vault browser with one-click mount/unmount
- System tray for background operation
- Backend selection per vault
- Real-time I/O statistics

## As a Library

```rust
use oxcrypt_core::vault::{config::extract_master_key, operations::VaultOperations, path::DirId};

let master_key = extract_master_key("./vault", "password")?;
let vault = VaultOperations::new("./vault", master_key);

for file in vault.list_files(&DirId::root())? {
    println!("{}", file.decrypted_name);
}
```

## Building

```bash
git clone https://github.com/agucova/oxcrypt
cd oxcrypt
cargo build --release -p oxcrypt --features fuse
```

**macOS:** `brew install --cask macfuse` first
**Linux:** `apt install libfuse3-dev` or equivalent

## Project Structure

```
crates/
├── oxcrypt-core     # Crypto library (the part I wrote years ago)
├── oxcrypt          # CLI
├── oxcrypt-desktop  # GUI (Dioxus)
├── oxcrypt-fuse     # FUSE backend
├── oxcrypt-fskit    # FSKit backend (Swift FFI)
├── oxcrypt-webdav   # WebDAV server
├── oxcrypt-nfs      # NFS server
├── oxcrypt-mount    # Shared mount infrastructure
└── oxbench          # Benchmark harness
```

## Roadmap

- [x] Core crypto library with full Vault Format 8 support
- [x] Four mount backends (FUSE, FSKit, WebDAV, NFS)
- [x] CLI and desktop GUI
- [x] Cross-implementation benchmark tool
- [ ] iOS/Android libraries
- [ ] Cloud storage backends (S3, GCS, rclone)
- [ ] Hardware key support (YubiKey)

## Contributing

PRs welcome! Run `cargo test && cargo clippy && cargo fmt --check` before submitting.

## License

[Mozilla Public License 2.0](LICENSE)

---

*Filesystem backends built with [Claude Code](https://claude.ai/code). I wrote the crypto core.*
