# oxcrypt-desktop

Desktop GUI for managing Cryptomator vaults using [Dioxus](https://dioxuslabs.com/).

## Features

- Create, open, and manage Cryptomator vaults
- Mount/unmount vaults as native filesystems
- Multiple backend support:
  - **FUSE** (Linux/macOS) - requires `--features fuse`
  - **WebDAV** (cross-platform) - requires `--features webdav`
  - **NFS** (Linux/macOS) - requires `--features nfs`
  - **File Provider** (macOS 13+) - requires `--features fileprovider`
- Automatic backend selection based on platform capabilities
- System tray integration
- Real-time vault statistics

## Installation

```bash
# Build and install
cargo install --path crates/oxcrypt-desktop --features fuse

# Run
oxcrypt-desktop
```

## Building with Different Backends

```bash
# FUSE backend (Linux/macOS with macFUSE)
cargo build -p oxcrypt-desktop --features fuse --release

# WebDAV backend (cross-platform, no kernel extensions)
cargo build -p oxcrypt-desktop --features webdav --release

# Multiple backends
cargo build -p oxcrypt-desktop --features fuse,webdav,nfs --release
```

## Architecture

```
oxcrypt-desktop (Dioxus desktop app)
     │
     ├── MountManager
     │        │
     │        ├── FuseBackend (from oxcrypt-fuse)
     │        ├── WebDavBackend (from oxcrypt-webdav)
     │        ├── NfsBackend (from oxcrypt-nfs)
     │        └── FileProviderBackend (from oxcrypt-fileprovider)
     │
     ├── VaultState (app state)
     │
     └── Components (UI)
```

### Modules

| Module | Description |
|--------|-------------|
| `backend/` | Filesystem backend integration |
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
| WebDAV | All | None (userspace server) |
| NFS | Linux, macOS | None (userspace server) |
| File Provider | macOS 13+ | Built-in system extension |

When using `BackendType::Auto`, the GUI will select the best available backend for your platform.

## Development

The project uses the Dioxus CLI (`dx`) for development. It's included in the devenv.

### Using dx (recommended)

```bash
# Hot-reload development server
dx serve -p oxcrypt-desktop

# With FUSE backend enabled
dx serve -p oxcrypt-desktop --features fuse

# With WebDAV backend enabled
dx serve -p oxcrypt-desktop --features webdav

# Production build
dx build -p oxcrypt-desktop --release

# Bundle for distribution (creates .app on macOS)
dx bundle -p oxcrypt-desktop --release
```

### Using cargo

```bash
# Run in development mode
cargo run -p oxcrypt-desktop --features fuse

# Run with WebDAV support
cargo run -p oxcrypt-desktop --features webdav

# Run tests
cargo test -p oxcrypt-desktop
```

## License

This project is licensed under the [Mozilla Public License 2.0](../../LICENSE).
