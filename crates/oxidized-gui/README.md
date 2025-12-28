# oxidized-gui

Desktop GUI for managing Cryptomator vaults using [Dioxus](https://dioxuslabs.com/).

## Features

- Create, open, and manage Cryptomator vaults
- Mount/unmount vaults as native filesystems
- Multiple backend support:
  - **FUSE** (Linux/macOS) - default
  - **FSKit** (macOS 15.4+) - optional, requires `--features fskit`
- Automatic backend selection based on platform capabilities
- System tray integration

## Installation

```bash
# Build and install
cargo install --path crates/oxidized-gui

# Run
oxvault
```

## Building with FSKit Support

FSKit provides native macOS filesystem integration without kernel extensions. Requires:
- macOS 15.4 (Sequoia) or later
- `protoc` installed (for building fskit-rs)
- [FSKitBridge.app](https://github.com/debox-network/FSKitBridge/releases) installed
- Extension enabled in System Settings

```bash
# Build with FSKit support
cargo build -p oxidized-gui --features fskit --release

# Run
./target/release/oxvault
```

## Architecture

```
oxvault (Dioxus desktop app)
     │
     ├── MountManager
     │        │
     │        ├── FuseBackend (from oxidized-fuse)
     │        └── FSKitBackend (real or stub)
     │
     ├── VaultState (app state)
     │
     └── Components (UI)
```

### Modules

| Module | Description |
|--------|-------------|
| `backend/` | Filesystem backend integration (FUSE, FSKit) |
| `state/` | Application state and vault management |
| `components/` | Dioxus UI components |
| `dialogs/` | Modal dialogs (password, create vault, etc.) |
| `tray/` | System tray integration |
| `error/` | Error handling and display |

## Backend Selection

The GUI supports automatic or manual backend selection:

| Backend | Platform | Requirements |
|---------|----------|--------------|
| FUSE | Linux, macOS | libfuse/macFUSE installed |
| FSKit | macOS 15.4+ | FSKitBridge.app, `--features fskit` |

When using `BackendType::Auto`, the GUI will:
1. Prefer FSKit if available (better macOS integration)
2. Fall back to FUSE otherwise

## Development

```bash
# Run in development mode
cargo run -p oxidized-gui

# Run with FSKit support
cargo run -p oxidized-gui --features fskit

# Run tests
cargo test -p oxidized-gui
```

## License

This project is licensed under the [Mozilla Public License 2.0](../../LICENSE).
