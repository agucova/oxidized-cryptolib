# oxcrypt-bench

Cross-implementation filesystem benchmark harness for comparing Cryptomator vault performance across different mounting backends.

## Overview

`oxbench` benchmarks and compares filesystem performance across:

- **FUSE** - FUSE implementation (`oxcrypt-fuse`)
- **FSKit** - Apple's native FSKit framework (`oxcrypt-fskit`, macOS 15.4+)
- **WebDAV** - WebDAV server backend (`oxcrypt-webdav`)
- **NFS** - NFS server backend (`oxcrypt-nfs`)
- **Official Cryptomator** - The official Cryptomator app (user-mounted)

This enables objective performance comparisons to guide users in choosing the best backend for their use case.

## Installation

```bash
cargo install --path crates/oxcrypt-bench
```

Or run directly:

```bash
cargo run -p oxcrypt-bench -- <vault_path> [options]
```

## Usage

### Basic Usage

```bash
# Benchmark FUSE implementation only
oxbench /path/to/vault fuse

# Benchmark specific implementations
oxbench /path/to/vault fuse webdav nfs

# Benchmark all available backends (macOS 15.4+)
oxbench /path/to/vault fuse fskit webdav nfs

# Compare with official Cryptomator (requires it to be mounted first)
oxbench /path/to/vault fuse --cryptomator /Volumes/MyVault
```

### Options

```
oxbench [OPTIONS] <vault> [implementations...]

Arguments:
  <vault>              Path to the Cryptomator vault
  [implementations]... Implementations to benchmark (default: fuse)
                       Values: fuse, fskit, webdav, nfs, cryptomator

Options:
  -m, --mount-prefix <PATH>    Mount point prefix (default: /tmp/oxbench)
  -c, --cryptomator <PATH>     Path to already-mounted Cryptomator vault
  -p, --password <PASSWORD>    Vault password (or OXBENCH_PASSWORD env var)
  -s, --suite <SUITE>          Benchmark suite: quick, read, write, full (default: full)
      --iterations <N>         Iterations per benchmark (default: 10)
      --no-color               Disable colored output
  -v, --verbose                Verbose output
  -h, --help                   Print help
```

### Benchmark Suites

| Suite | Description | Use Case |
|-------|-------------|----------|
| `quick` | 1MB read, single directory, 3 iterations | Quick sanity check |
| `read` | All read operations across file sizes | Read-heavy workloads |
| `write` | All write operations | Write-heavy workloads |
| `full` | Complete benchmark suite | Comprehensive comparison |

## Cache Clearing

For accurate comparisons, `oxbench` clears OS caches between implementations:

- **With sudo**: Uses `purge` (macOS) or `drop_caches` (Linux) for effective clearing
- **Without sudo**: Falls back to extended waits between implementations

When benchmarking multiple implementations, `oxbench` will prompt for sudo credentials:

```
Checking sudo access for cache clearing between implementations...
  Sudo access recommended for accurate benchmarks (clears OS caches).
  Enter password to enable, or press Ctrl+C to skip.
```

## Architecture

`oxbench` uses the unified `MountBackend` trait from `oxcrypt-mount`:

```
oxbench
      │
      ├── FuseBackend (from oxcrypt-fuse)
      ├── FSKitBackend (from oxcrypt-fskit)
      ├── WebDavBackend (from oxcrypt-webdav)
      ├── NfsBackend (from oxcrypt-nfs)
      └── ExternalMount (validates user-mounted Cryptomator)
```

### Sequential Mounting

Benchmarks run sequentially (one implementation at a time) to avoid:
- Concurrent access conflicts on the same vault
- OS page cache cross-contamination between implementations
- Write conflicts that could corrupt vault data

## Example Output

```
╔════════════════════════════════════════════════════════════╗
║            oxbench - Filesystem Benchmark                  ║
╚════════════════════════════════════════════════════════════╝

Vault: /path/to/vault
Suite: full
Iterations: 10
Implementations: FUSE, WebDAV

SEQUENTIAL READ (1MB)
╭───────────────┬────────────────┬────────────────┬──────────╮
│ Metric        │ FUSE           │ WebDAV         │ Winner   │
├───────────────┼────────────────┼────────────────┼──────────┤
│ Throughput    │ 245.3 MB/s     │ 189.2 MB/s     │ ✓ FUSE   │
│ Mean Latency  │ 4.08 ms        │ 5.29 ms        │ ✓ FUSE   │
│ P50 Latency   │ 3.95 ms        │ 5.05 ms        │ ✓ FUSE   │
│ P95 Latency   │ 5.12 ms        │ 6.15 ms        │ ✓ FUSE   │
╰───────────────┴────────────────┴────────────────┴──────────╯
```

## Benchmark Operations

| Operation | File Sizes | Description |
|-----------|------------|-------------|
| Sequential Read | 1KB, 32KB, 1MB, 10MB | Read entire file |
| Random Read | 32KB, 1MB | Seek + read random chunks |
| Sequential Write | 1KB, 32KB, 1MB, 10MB | Create and write file |
| Random Write | 32KB | Modify at random offsets |
| Directory Listing | 10, 100, 1000 files | readdir with decryption |
| Metadata | N/A | stat operations |
| File Creation | 100 files | Create files with content |
| File Deletion | 100 files | Delete files |

## Requirements

### FUSE

- **macOS**: [macFUSE](https://osxfuse.github.io/) installed
- **Linux**: libfuse3 or fuse3

### FSKit (macOS only)

- macOS 15.4 (Sequoia) or later
- Swift extension built and enabled

### Official Cryptomator Comparison

1. Install and run [Cryptomator](https://cryptomator.org/)
2. Unlock and mount your vault
3. Pass the mount path: `--cryptomator /Volumes/YourVault`

## Building

```bash
# Build
cargo build -p oxcrypt-bench

# Run tests
cargo test -p oxcrypt-bench

# Build release (faster benchmarks)
cargo build -p oxcrypt-bench --release
```

## License

MPL-2.0 - see the repository root for details.
