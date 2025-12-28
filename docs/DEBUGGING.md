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
cargo bench -p oxidized-cryptolib --bench timing_leaks

# Run specific test
cargo bench -p oxidized-cryptolib --bench timing_leaks -- --filter key_unwrap

# Continuous mode (runs until Ctrl+C)
cargo bench -p oxidized-cryptolib --bench timing_leaks -- --continuous key_unwrap
```

**Interpretation**: t-value < 4.5 = PASS (no timing leak), t-value > 4.5 = FAIL (potential leak)

**Tests include**:
- RFC 3394 key unwrap integrity check
- HMAC verification (via ring)
- AES-GCM file header/content decryption
- AES-SIV filename decryption

## Async Debugging with tokio-console

Both `oxidized-fuse` and `oxidized-fskit` support [tokio-console](https://github.com/tokio-rs/console) for real-time async task introspection.

```bash
# Build with console support
cargo build -p oxidized-fuse --features tokio-console
cargo build -p oxidized-fskit --features tokio-console

# Terminal 1: Run the mount
./target/debug/oxmount ~/vault /mnt/point

# Terminal 2: Connect console
tokio-console
```

**What you can observe**:
- Active async tasks and their states
- Task poll times and waker counts
- Resource contention (mutexes, semaphores)
- `spawn_blocking` threads for CPU-bound crypto

The `tokio-console` feature is opt-in and adds zero overhead to normal builds.
