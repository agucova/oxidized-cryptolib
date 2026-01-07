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
- `oxcrypt-fileprovider` - File Provider extension (macOS 14+, system integration)
- `oxcrypt-fskit` - FSKit backend via Swift FFI (macOS 15.4+, low-level VFS)
- `oxcrypt-webdav` - WebDAV server backend (cross-platform, no kernel extensions)
- `oxcrypt-nfs` - NFS server backend (Linux/macOS, no kernel extensions)

## Version Control

This is a jujutsu (jj) hybrid repo. Prefer `jj` over `git` for all VCS operations.

**IMPORTANT**: Running `jj restore` or any operation that reverts/discards changes **ALWAYS** requires explicit user permission. Never restore files without asking first.

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
1. Build using devenv scripts (handles Xcode environment isolation from nix):
   ```bash
   fskit-xcodebuild          # Build extension (no code signing)
   fskit-xcodebuild-signed   # Build with code signing + provisioning
   ```
   Or manually with clean environment to avoid nix linker issues:
   ```bash
   cd crates/oxcrypt-fskit/extension
   env -i HOME="$HOME" PATH="/usr/bin:/bin:/usr/sbin:/sbin:/Applications/Xcode.app/Contents/Developer/usr/bin" \
     DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer" \
     xcodebuild -project OxVaultFS.xcodeproj -scheme OxVaultFS -configuration Release -allowProvisioningUpdates build
   ```
2. Enable in System Settings → General → Login Items & Extensions → File System Extensions
3. Start Host App for XPC service:
   ```bash
   /path/to/OxVaultFS.app/Contents/MacOS/OxVaultFS --xpc &
   ```

**File Provider extension** (macOS 13+):
1. Build using devenv scripts:
   ```bash
   fileprovider-build          # Build Rust + Swift extension (signed)
   fileprovider-clean          # Clean build artifacts
   fileprovider-xcode          # Open in Xcode for debugging
   ```
   Or manually:
   ```bash
   cd crates/oxcrypt-fileprovider/extension
   ./build.sh                  # Uses XcodeGen + xcodebuild
   ```
2. Install and register:
   ```bash
   fileprovider-install                              # Copy to ~/Applications
   fileprovider-register /path/to/vault "My Vault"   # Register domain
   fileprovider-list                                 # List registered vaults
   ```

**Note**: The Xcode project (`.xcodeproj`) is auto-generated from `project.yml` via XcodeGen and should not be committed to git. Edit `project.yml` for configuration changes, not Xcode's UI.

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

**Debugging tools**: See `docs/DEBUGGING.md` for detailed guides on:
- Code coverage (`cargo-llvm-cov`)
- Timing leak detection (`dudect`)
- Async introspection (`tokio-console`)
- **Crash debugging with `rust-lldb`** - getting backtraces from segfaults, stack overflows, and aborts

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

**macFUSE ghost mounts**: When a FUSE process terminates ungracefully (crash, SIGKILL, etc.), macFUSE can leave "ghost mounts" in the kernel. These ghost mounts cause `mount`, `umount`, and `diskutil` commands to hang indefinitely. Always use timeouts when running these commands:
```bash
timeout 10 mount                              # List mounts with timeout
timeout 10 diskutil unmount force /path       # Force unmount with timeout
pkill -9 -f "oxmount|oxbench"                 # Kill stuck processes first
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

**⚠️ FSKit Limitation (as of macOS 26.0.1)**: FSKit extensions cannot currently be invoked by third-party applications. The `mount -F` command and private FSKit APIs require Apple-internal client entitlements that are not available to developers. fskitd logs show "entitlement no" and refuses to probe/mount non-Apple extensions for unentitled callers. See `docs/DEBUGGING.md` for full details. **Recommended**: Use FUSE, WebDAV, or NFS backends instead until Apple provides public FSKit client APIs.

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

## Rust Code Style

- **Error handling over panics**: Avoid `.unwrap()` and `.expect()` in library/application code—propagate errors with `?` or handle them explicitly. Panics are acceptable in tests, and also in application code when a condition is truly critical and the panic message clearly explains the invariant violation.
- **Crate-rooted imports**: Prefer `crate::` over `super::` for module imports. Clean up any lingering `super::` paths when you encounter them.
- **Minimal `pub use`**: Avoid `pub use` on imports unless you're intentionally re-exporting a dependency so downstream crates don't need to depend on it directly.
- **Explicit context over global state**: Skip `lazy_static!`, `OnceLock`, or similar global patterns; prefer passing explicit context structs for shared state.
- **Strong types over strings**: Use enums and newtypes when the domain is closed or requires validation, rather than raw strings.

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
