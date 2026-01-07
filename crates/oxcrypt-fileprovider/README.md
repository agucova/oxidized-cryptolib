# oxcrypt-fileprovider

Apple File Provider backend for Cryptomator vault mounting.

Integrates Cryptomator vaults with macOS File Provider interface for seamless cloud storage integration and system-wide access to encrypted files.

## Requirements

- macOS 13.0 or later
- Xcode 15.0+ (for building the extension)
- XcodeGen (install via `brew install xcodegen` or use devenv)
- Apple Developer account with File Provider entitlements (for code signing)

## Building

### Quick Start (Using devenv)

```bash
# Build both Rust library and Swift extension
fileprovider-build

# Clean build artifacts
fileprovider-clean

# Open project in Xcode for debugging
fileprovider-xcode
```

### Manual Build

```bash
cd crates/oxcrypt-fileprovider/extension
./build.sh
```

This script:
1. Builds the Rust library (`liboxcrypt_fileprovider.a`)
2. Verifies Swift bridge code generation
3. Generates Xcode project from `project.yml` using XcodeGen
4. Builds the File Provider extension with xcodebuild
5. Outputs to `extension/build/OxCryptFileProvider.app`

### Development Workflow

```bash
# Working on Swift code
vim crates/oxcrypt-fileprovider/extension/Sources/OxCryptItem.swift
fileprovider-build                    # Rebuild extension

# Working on Rust code
vim crates/oxcrypt-fileprovider/src/lib.rs
cargo build -p oxcrypt-fileprovider   # Fast iteration (no Xcode)
fileprovider-build                    # When ready to test Swift changes
```

### Code Signing

**Development mode** (automatic):
- Auto-detects team ID from keychain
- Uses Automatic signing with provisioning updates
- Requires "Apple Development" certificate installed

**CI mode** (manual):
- Set `CI=true` environment variable
- Requires `APPLE_TEAM_ID` and `APPLE_CODESIGN_IDENTITY`
- Uses Manual signing for explicit control

```bash
# Example: CI build
export CI=true
export APPLE_TEAM_ID="ABC123DEF4"
export APPLE_CODESIGN_IDENTITY="Apple Development"
./extension/build.sh
```

## Opening in Xcode

```bash
fileprovider-xcode
```

This generates the Xcode project (if needed) and opens it in Xcode.app for debugging.

**Note**: The `.xcodeproj` file is auto-generated from `project.yml` and should not be committed to git. Edit `project.yml` instead of using Xcode's project settings UI.

## Installation

After building, install the extension to `~/Applications`:

```bash
fileprovider-install
```

## Architecture

```
Host App (OxCryptFileProvider.app)
├── Embedded Extension (OxCryptFileProviderExtension.appex)
│   ├── Swift code (extension/Sources/)
│   │   ├── OxCryptExtension.swift    - Main NSFileProviderExtension
│   │   ├── OxCryptEnumerator.swift   - File enumeration
│   │   └── OxCryptItem.swift         - File metadata
│   └── Rust FFI (liboxcrypt_fileprovider.a)
│       └── Swift bridge bindings (generated)
└── Shared utilities (extension/Shared/)
    ├── BookmarkHelper.swift          - Security-scoped bookmarks
    ├── DomainManager.swift           - Domain registration
    ├── KeychainHelper.swift          - Password storage
    └── XPC services                  - Host ↔ Extension communication

Rust crate (oxcrypt-fileprovider)
├── Core filesystem logic
├── Swift bridge FFI (swift-bridge)
└── Extension manager
```

### Swift Bridge

The Rust library exposes functions to Swift via `swift-bridge`:
- FFI bindings auto-generated in `extension/Shared/generated/`
- Build script (`build.rs`) generates code during `cargo build`
- Swift project includes generated headers and implementation

## Troubleshooting

### "No Apple Development certificate found"

Install a development certificate from Xcode:
1. Open Xcode → Settings → Accounts
2. Add your Apple ID
3. Manage Certificates → + → Apple Development

Or set `APPLE_TEAM_ID` manually:
```bash
export APPLE_TEAM_ID="ABC123DEF4"
./extension/build.sh
```

### Build fails with "xcodegen: command not found"

Install XcodeGen:
```bash
brew install xcodegen
```

Or use devenv (includes XcodeGen automatically).

### Build fails with linker errors

Ensure the Rust library was built first:
```bash
cargo build --release --lib -p oxcrypt-fileprovider
```

### "Swift bridge code not generated"

The build script should generate FFI bindings automatically. If it fails:
```bash
cargo clean -p oxcrypt-fileprovider
cargo build --release --lib -p oxcrypt-fileprovider
```

Check that `extension/Shared/generated/SwiftBridgeCore.swift` exists.

### Extension not working after install

1. Check File Provider is enabled in System Settings:
   - General → Login Items & Extensions → File System Extensions
   - Enable "OxCryptFileProvider"

2. Register a vault domain:
   ```bash
   fileprovider-register /path/to/vault "My Vault"
   ```

3. Check system logs:
   ```bash
   log show --predicate 'subsystem CONTAINS "fileprovider"' --last 1m
   ```

### Changes not reflected after rebuild

1. Kill any running instances:
   ```bash
   pkill -f OxCryptFileProvider
   ```

2. Clean and rebuild:
   ```bash
   fileprovider-clean
   fileprovider-build
   fileprovider-install
   ```

## Build System Notes

This crate uses a **separate build** approach:
- Extension build is separate from `cargo build`
- Faster cargo iterations (no Xcode overhead)
- Matches patterns used by `oxcrypt-fskit` and `oxcrypt-desktop`

The Xcode project (`.xcodeproj`) is **generated by XcodeGen** from `project.yml`:
- Never edit `.pbxproj` directly
- Edit `project.yml` instead
- Project regenerates automatically during builds
- `.xcodeproj` is gitignored (not committed)

## License

Licensed under the Mozilla Public License 2.0.
