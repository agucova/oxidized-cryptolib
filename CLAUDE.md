# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Workspace Crates

**Applications:**
- `oxcrypt` - CLI tool - vault operations, mount/unmount, init
- `oxcrypt-desktop` - Desktop app using Dioxus with system tray
- `oxbench` - Benchmark harness for multi-backend comparison

**Libraries:**
- `oxcrypt-core` - Core Cryptomator encryption library (AES-GCM, AES-SIV, scrypt)
- `oxcrypt-mount` - Shared mount utilities (MountBackend trait, WriteBuffer, caching, HandleTable)

**Mount Backends:**
- `oxcrypt-fuse` - FUSE backend (Linux/macOS with macFUSE)
- `oxcrypt-fskit` - Native FSKit via Swift FFI (macOS 15.4+)
- `oxcrypt-webdav` - WebDAV server backend (cross-platform, no kernel extensions)
- `oxcrypt-nfs` - NFS server backend (Linux/macOS, no kernel extensions)

## Version Control

This is a jujutsu (jj) hybrid repo. Prefer `jj` over `git` for all VCS operations.

## Commands

Standard Cargo commands work: `cargo build`, `cargo check`, `cargo clippy`, `cargo fmt`.

**Adding dependencies**: Always use `cargo add` instead of manually editing `Cargo.toml` to ensure the latest version is used:
```bash
cargo add serde -p oxcrypt-core              # Add to specific crate
cargo add tokio -p oxcrypt --features full   # With features
```

**Testing** (uses `cargo-nextest`):
```bash
cargo nextest run                    # All tests
cargo nextest run -p oxcrypt-fuse --features fuse-tests  # FUSE integration tests
```

**Mount backend tests** (FUSE, WebDAV, NFS):
```bash
cargo nextest run -p oxcrypt-fuse --features fuse-tests   # FUSE integration tests
cargo nextest run -p oxcrypt-webdav                       # WebDAV tests
cargo nextest run -p oxcrypt-nfs                          # NFS tests
```

FUSE integration tests require external tools (pjdfstest, fsx) and include POSIX compliance, data integrity, and stress testing.

**FSKit prerequisites** (macOS 15.4+):
1. Build Swift package:
   ```bash
   cd crates/oxcrypt-fskit/extension
   swift build
   ```
2. Enable in System Settings → General → Login Items & Extensions → File System Extensions

**GUI development** (uses `dx` CLI from dioxus-cli):
```bash
dx serve -p oxcrypt-desktop              # Hot-reload dev server
dx serve -p oxcrypt-desktop --features fuse  # With FUSE backend
dx build -p oxcrypt-desktop --release    # Production build
dx bundle -p oxcrypt-desktop --release   # Bundle for distribution
```

**Benchmarking**: `cargo bench -p oxcrypt-core` or use `oxbench --help` for cross-implementation comparisons.

**CLI commands** (`oxcrypt`):
- Vault operations: `ls`, `cat`, `tree`, `mkdir`, `touch`, `rm`, `cp`, `mv`, `write`, `info`
- Vault creation: `init`
- Mount management: `mount`, `unmount`, `mounts`, `backends`, `stats`

Mount commands require backend features: `--features fuse,webdav,nfs`

**Debugging tools**: Code coverage (`cargo-llvm-cov`), timing leak detection (`dudect`), async introspection (`tokio-console`). See `docs/DEBUGGING.md` for details.

**Test vault**: `test_vault/` contains a sample vault for integration testing.

## Architecture

All mount backends share common infrastructure from `oxcrypt-mount`:
- `MountBackend` trait - unified interface for all backends
- `WriteBuffer` - read-modify-write pattern for AES-GCM chunks
- `HandleTable` - thread-safe file handle management
- `moka_cache` - TTL-based attribute/entry caching (sync and async variants)
- `VaultErrorCategory` - error classification for errno/HTTP status mapping

### FUSE Mount (oxcrypt-fuse)
```
CryptomatorFS (implements fuser::Filesystem)
        │
        ├── InodeTable (DashMap, lock-free)
        ├── SyncTtlCache (Moka-based, 1s TTL)
        └── VaultOperationsAsync
                │
                ├── HandleTable<WriteBuffer>
                └── Crypto (AES-GCM, AES-SIV)
```

### FSKit (oxcrypt-fskit, macOS 15.4+)
```
VFS (Kernel) → XPC → OxCryptFSExtension (Swift) → FFI → CryptoFilesystem (Rust)
        │
        ├── ItemTable (item_id ↔ VaultPath mapping)
        ├── HandleTable (open file handles)
        └── VaultOperationsAsync
```

Native FSKit via Swift FFI - no external bridge app required.

### WebDAV (oxcrypt-webdav)
```
WebDAV Client (Finder/Explorer) ←HTTP→ CryptomatorWebDav (dav-server)
        │
        ├── AsyncTtlCache (Moka-based)
        ├── HandleTable<WriteBuffer>
        └── VaultOperationsAsync
```

Cross-platform, no kernel extensions. Server binds to localhost only.

### NFS (oxcrypt-nfs)
```
NFS Client (kernel) ←TCP→ CryptomatorNFS (nfsserve)
        │
        ├── NfsInodeTable (fileid ↔ VaultPath)
        ├── HandleTable<WriteBuffer>
        └── VaultOperationsAsync
```

Userspace NFSv3 server. No kernel extensions required.

## Security

- `#![forbid(unsafe_code)]` in critical crypto modules
- Memory protection via `memsafe` (mlock, mprotect, zeroization on drop)
- Authenticated encryption (AES-GCM, AES-SIV) preventing tampering
- JWT signature validation for vault integrity
- Constant-time operations verified via dudect timing analysis
- `subtle` crate for constant-time comparisons in key unwrap

## Cryptomator Protocol Reference

### Vault Format 8
- **JWT-based config**: `vault.cryptomator` contains metadata signed with master keys
- **Cipher combo**: `SIV_GCM` (AES-SIV for filenames, AES-GCM for contents)
- **Filename threshold**: 220 chars before shortening to `.c9s` format
- **Directory structure**: Flattened under `/d/` with 2-char subdirectories

### Key Components
- **Master keys**: 256-bit encryption + 256-bit MAC keys (scrypt-derived)
- **File headers**: 68 bytes (12B nonce + 40B AES-GCM payload + 16B tag)
- **File content**: 32KB chunks with AES-GCM, chunk number + header nonce as AAD
- **Filename encryption**: AES-SIV with parent directory ID as associated data
- **Directory IDs**: Random UUIDs (root uses empty string)

### File Patterns
- Regular files: `{base64url-encrypted-name}.c9r`
- Directories: `{encrypted-name}.c9r/dir.c9r` (contains directory ID)
- Symlinks: `{encrypted-name}.c9r/symlink.c9r` (contains link target)
- Long names: `{sha1-hash}.c9s/name.c9s` + `contents.c9r`/`dir.c9r`/`symlink.c9r`

### Security Considerations
- **Accepted risk**: Filename swapping within same directory
- **Protected**: File contents, filenames, directory structure obfuscation
- **Not protected**: File sizes, timestamps, file count per directory

See `.claude/cryptomator_docs/` for complete protocol specifications.
