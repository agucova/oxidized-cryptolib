# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Workspace Crates

- `oxidized-cryptolib` - Core Cryptomator encryption library (AES-GCM, AES-SIV, scrypt)
- `oxidized-cli` - CLI tool (`oxcrypt`) - ls, cat, tree, mkdir, rm, cp, mv, info
- `oxidized-fuse` - FUSE filesystem mount (`oxmount`) for Linux/macOS
- `oxidized-fskit` - FSKit filesystem mount (`oxmount-fskit`) for macOS 15.4+
- `oxidized-gui` - Desktop app (`oxvault`) using Dioxus
- `oxidized-bench` - Benchmark harness (`oxbench`) for comparing implementations

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

**FUSE integration tests** require external tools (pjdfstest, fsx) and include POSIX compliance, data integrity, and stress testing.

**FSKit prerequisites** (macOS 15.4+):
1. `protoc` installed (provided by devenv)
2. FSKitBridge.app (auto-installed to ~/Applications by devenv on first shell entry)
3. Enable in System Settings → General → Login Items & Extensions → File System Extensions

The `oxidized-fskit` crate provides setup utilities via `oxidized_fskit::setup`:
- `get_status()` / `get_status_sync()` - Check FSKitBridge availability
- `find_installation()` - Find FSKitBridge.app path
- With `setup` feature: `download_latest()`, `install_to()` - Download from GitHub

**GUI development** (uses `dx` CLI from dioxus-cli):
```bash
dx serve -p oxidized-gui              # Hot-reload dev server
dx serve -p oxidized-gui --features fuse  # With FUSE backend
dx build -p oxidized-gui --release    # Production build
dx bundle -p oxidized-gui --release   # Bundle for distribution
```

**Benchmarking**: `cargo bench -p oxidized-cryptolib` or use `oxbench --help` for cross-implementation comparisons.

**Debugging tools**: Code coverage (`cargo-llvm-cov`), timing leak detection (`dudect`), async introspection (`tokio-console`). See `docs/DEBUGGING.md` for details.

**Test vault**: `test_vault/` contains a sample vault for integration testing.

## Architecture

### FUSE Mount (oxidized-fuse)
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

### FSKit Mount (oxidized-fskit, macOS 15.4+)
```
VFS (Kernel) → XPC → FSKitBridge.app → TCP+Protobuf → CryptomatorFSKit
        │
        ├── ItemTable (item_id ↔ VaultPath mapping)
        ├── HandleTable (open file handles)
        └── VaultOperationsAsync (from oxidized-cryptolib)
```

FSKit provides native macOS integration without kernel extensions. Requires FSKitBridge.app to bridge XPC to Rust.

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
