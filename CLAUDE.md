# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Workspace Crates

**Applications:**
- `oxidized-cli` - CLI tool (`oxcrypt`) - vault operations, mount/unmount, init
- `oxidized-gui` - Desktop app (`oxvault`) using Dioxus with system tray
- `oxidized-bench` - Benchmark harness (`oxbench`) for multi-backend comparison

**Libraries:**
- `oxidized-cryptolib` - Core Cryptomator encryption library (AES-GCM, AES-SIV, scrypt)
- `oxidized-mount-common` - Shared mount utilities (MountBackend trait, WriteBuffer, caching, HandleTable)

**Mount Backends:**
- `oxidized-fuse` - FUSE backend (Linux/macOS with macFUSE)
- `oxidized-fskit-legacy` - FSKit via FSKitBridge.app (macOS 15.4+, deprecated)
- `oxidized-fskit-ffi` - Native FSKit via Swift FFI (macOS 15.4+)
- `oxidized-webdav` - WebDAV server backend (cross-platform, no kernel extensions)
- `oxidized-nfs` - NFS server backend (Linux/macOS, no kernel extensions)

## Version Control

This is a jujutsu (jj) hybrid repo. Prefer `jj` over `git` for all VCS operations.

## Commands

Standard Cargo commands work: `cargo build`, `cargo check`, `cargo clippy`, `cargo fmt`.

**Adding dependencies**: Always use `cargo add` instead of manually editing `Cargo.toml` to ensure the latest version is used:
```bash
cargo add serde -p oxidized-cryptolib              # Add to specific crate
cargo add tokio -p oxidized-cli --features full    # With features
```

**Testing** (uses `cargo-nextest`):
```bash
cargo nextest run                    # All tests
cargo nextest run -p oxidized-fuse --features fuse-tests  # FUSE integration tests
```

**Mount backend tests** (FUSE, WebDAV, NFS):
```bash
cargo nextest run -p oxidized-fuse --features fuse-tests   # FUSE integration tests
cargo nextest run -p oxidized-webdav                       # WebDAV tests
cargo nextest run -p oxidized-nfs                          # NFS tests
```

FUSE integration tests require external tools (pjdfstest, fsx) and include POSIX compliance, data integrity, and stress testing.

**FSKit prerequisites** (macOS 15.4+):
1. `protoc` installed (provided by devenv)
2. For `oxidized-fskit-legacy`: FSKitBridge.app (deprecated)
3. For `oxidized-fskit-ffi`: Build Swift package:
   ```bash
   cd crates/oxidized-fskit-ffi/extension
   swift build
   ```
4. Enable in System Settings → General → Login Items & Extensions → File System Extensions

**GUI development** (uses `dx` CLI from dioxus-cli):
```bash
dx serve -p oxidized-gui              # Hot-reload dev server
dx serve -p oxidized-gui --features fuse  # With FUSE backend
dx build -p oxidized-gui --release    # Production build
dx bundle -p oxidized-gui --release   # Bundle for distribution
```

**Benchmarking**: `cargo bench -p oxidized-cryptolib` or use `oxbench --help` for cross-implementation comparisons.

**CLI commands** (`oxcrypt`):
- Vault operations: `ls`, `cat`, `tree`, `mkdir`, `touch`, `rm`, `cp`, `mv`, `write`, `info`
- Vault creation: `init`
- Mount management: `mount`, `unmount`, `mounts`, `backends`, `stats`

Mount commands require backend features: `--features fuse,webdav,nfs`

**Debugging tools**: Code coverage (`cargo-llvm-cov`), timing leak detection (`dudect`), async introspection (`tokio-console`). See `docs/DEBUGGING.md` for details.

**Test vault**: `test_vault/` contains a sample vault for integration testing.

## Architecture

All mount backends share common infrastructure from `oxidized-mount-common`:
- `MountBackend` trait - unified interface for all backends
- `WriteBuffer` - read-modify-write pattern for AES-GCM chunks
- `HandleTable` - thread-safe file handle management
- `moka_cache` - TTL-based attribute/entry caching (sync and async variants)
- `VaultErrorCategory` - error classification for errno/HTTP status mapping

### FUSE Mount (oxidized-fuse)
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

### FSKit (oxidized-fskit-ffi, macOS 15.4+)
```
VFS (Kernel) → XPC → OxVaultFSExtension (Swift) → FFI → CryptoFilesystem (Rust)
        │
        ├── ItemTable (item_id ↔ VaultPath mapping)
        ├── HandleTable (open file handles)
        └── VaultOperationsAsync
```

Native FSKit via Swift FFI - no external bridge app required.

### WebDAV (oxidized-webdav)
```
WebDAV Client (Finder/Explorer) ←HTTP→ CryptomatorWebDav (dav-server)
        │
        ├── AsyncTtlCache (Moka-based)
        ├── HandleTable<WriteBuffer>
        └── VaultOperationsAsync
```

Cross-platform, no kernel extensions. Server binds to localhost only.

### NFS (oxidized-nfs)
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
