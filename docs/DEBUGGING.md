# Debugging & Profiling

Specialized debugging tools and techniques for development.

## Code Coverage

Uses `cargo-llvm-cov` (installed automatically by devenv):

```bash
cargo llvm-cov nextest --workspace           # Text summary
cargo llvm-cov nextest --workspace --html    # HTML report (target/llvm-cov/html/)
cargo llvm-cov nextest --workspace --open    # Open HTML report
cargo llvm-cov nextest --workspace --lcov --output-path lcov.info  # LCOV format
```

## Timing Leak Detection

Uses dudect statistical methodology to detect timing side-channels in cryptographic operations.

```bash
# Run all timing tests
cargo bench -p oxcrypt-core --bench timing_leaks

# Run specific test
cargo bench -p oxcrypt-core --bench timing_leaks -- --filter key_unwrap

# Continuous mode (runs until Ctrl+C)
cargo bench -p oxcrypt-core --bench timing_leaks -- --continuous key_unwrap
```

**Interpretation**: t-value < 4.5 = PASS (no timing leak), t-value > 4.5 = FAIL (potential leak)

**Tests include**:
- RFC 3394 key unwrap integrity check
- HMAC verification (via ring)
- AES-GCM file header/content decryption
- AES-SIV filename decryption

## Async Debugging with tokio-console

All mount backends (`oxcrypt-fuse`, `oxcrypt-fskit`, `oxcrypt-webdav`, `oxcrypt-nfs`) and the GUI support [tokio-console](https://github.com/tokio-rs/console) for real-time async task introspection.

```bash
# Build a specific backend with console support
cargo build -p oxcrypt-fuse --features tokio-console
cargo build -p oxcrypt-fskit --features tokio-console
cargo build -p oxcrypt-webdav --features tokio-console
cargo build -p oxcrypt-nfs --features tokio-console

# Or build CLI/GUI with console support (forwards to all enabled backends)
cargo build -p oxcrypt --features fuse,tokio-console
cargo build -p oxcrypt-desktop --features fuse,tokio-console

# Terminal 1: Run the mount or GUI
./target/debug/oxmount ~/vault /mnt/point
# or
./target/debug/oxvault

# Terminal 2: Connect console
tokio-console http://127.0.0.1:6669  # CLI tools (oxmount, oxcrypt, etc.)
tokio-console http://127.0.0.1:6670  # GUI (oxvault)
```

**Port Configuration**:
- CLI tools use port **6669** by default
- GUI uses port **6670** by default (to avoid conflicts)
- Override with `TOKIO_CONSOLE_PORT=<port>` environment variable
- If port is in use, the app will log a warning and continue without console instrumentation

**Requirements** (already configured in this repo):
- `tokio_unstable` cfg flag: Set via `.cargo/config.toml`
- `tokio/tracing` feature: Enabled by the `tokio-console` feature flag
- Per-layer filtering: The console layer has its own built-in filter; don't apply a global `EnvFilter` that might block tokio instrumentation events

**What you can observe**:
- Active async tasks and their states
- Task poll times and waker counts
- Resource contention (mutexes, semaphores)
- `spawn_blocking` threads for CPU-bound crypto (vault decryption operations)
- `block_on` calls from FUSE operations (filesystem.rs)

**Verification via gRPC** (if tokio-console TUI isn't available):

```bash
# Install grpcurl
brew install grpcurl

# Query the console endpoint directly
cd ~/.cargo/registry/src/*/console-api-*/proto
timeout 2 grpcurl -plaintext -import-path . -proto instrument.proto \
    127.0.0.1:6669 rs.tokio.console.instrument.Instrument/WatchUpdates \
    | jq '.taskUpdate.newTasks[]? | "\(.location.file):(\(.location.line))"'
```

**Troubleshooting**:
- **No tasks visible**: Trigger some vault operations (read files, list directories). Idle vaults won't show activity.
- **Port in use**: Another instance may be running. Check with `lsof -i :6669` and kill the old process.
- **grpc-status: 12**: The gRPC server is running but you sent an invalid request. Use proper protobuf encoding.
- **Console shows empty**: Ensure `tokio_unstable` cfg is set in `.cargo/config.toml` (already configured in this repo).

The `tokio-console` feature is opt-in and adds zero overhead to normal builds.
