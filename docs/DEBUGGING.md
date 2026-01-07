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

## Crash Debugging with rust-lldb

When the binary crashes (segfault, abort, stack overflow), use `rust-lldb` to get backtraces with proper Rust symbol demangling.

### Getting a Backtrace from a Crash

```bash
# Build with debug symbols (release with debug info is fine)
cargo build -p oxcrypt-bench --release

# Run under rust-lldb with crash handler
# The -k flag runs commands WHEN process stops (not before!)
rust-lldb \
    -o "run" \
    -k "thread backtrace all" \
    -k "quit" \
    -- ./target/release/oxbench test_vault fuse --password PASSWORD --suite workloads
```

**Key flags**:
- `-o "run"`: Start execution immediately
- `-k "command"`: Run command when process **stops** (crash, signal, breakpoint)
- `-- args`: Arguments passed to the target binary

**Common `-k` commands**:
- `thread backtrace all`: Show all thread stacks (useful for hangs/deadlocks)
- `bt`: Show current thread backtrace only
- `register read`: Dump CPU registers
- `frame variable`: Show local variables in current frame

### Interactive Debugging

```bash
# Start interactively
rust-lldb ./target/release/oxbench

# In lldb prompt:
(lldb) run test_vault fuse --password PASSWORD --suite workloads
# ... wait for crash ...
(lldb) bt          # current thread backtrace
(lldb) bt all      # all threads
(lldb) frame select 5  # examine frame #5
(lldb) frame variable  # show locals
(lldb) expression someVar  # evaluate expression
```

### macOS Crash Reports

Crashes also generate `.ips` files in `~/Library/Logs/DiagnosticReports/`:

```bash
# Find recent crash reports
ls -lt ~/Library/Logs/DiagnosticReports/*.ips | head -5

# Read crash report (JSON format with symbolicated backtrace)
cat ~/Library/Logs/DiagnosticReports/oxcrypt-2024-*.ips | jq .

# Extract the thread backtrace
cat ~/Library/Logs/DiagnosticReports/oxcrypt-*.ips | jq '.threads[0].frames'
```

The `.ips` files contain:
- Exception type and signal
- Register state at crash
- Thread backtraces with symbolication
- Loaded images and their UUIDs

### Stack Overflow Debugging

Stack overflows appear as `EXC_BAD_ACCESS` with address near stack limit or as `SIGABRT` with malloc failure. The backtrace will show extreme recursion:

```
frame #0: __pthread_kill + 8
frame #1: abort + 124
frame #2: _rust_panic_cleanup + 96
...
frame #3707: std::sys::fs::unix::remove_dir_impl::remove_dir_all_recursive
```

Deep recursion (hundreds of frames) indicates infinite loop or unbounded recursion.

## FSKit Debugging (macOS 15.4+)

FSKit is Apple's user-space filesystem framework. Debugging requires understanding the multi-process architecture: your app → XPC → fskitd → FSKit extension.

### Viewing fskitd Logs

```bash
# Real-time fskitd logs
log stream --predicate 'subsystem == "com.apple.FSKit"' --level debug

# Historical logs with all FSKit-related processes
log show --predicate 'subsystem == "com.apple.FSKit" OR process == "fskitd" OR process == "mount"' --last 5m

# Save to file for analysis
log show --predicate 'subsystem == "com.apple.FSKit"' --last 10m > /tmp/fskit.log
```

### Extension Registration

```bash
# List registered FSKit extensions (+ prefix = enabled)
pluginkit -m -p com.apple.fskit.fsmodule

# Force extension refresh
pluginkit -e use -i com.agucova.oxcrypt.desktop.fsextension
```

### Host App XPC Service

```bash
# Start host app in XPC mode (for FSKit support)
~/Applications/OxVaultFS.app/Contents/MacOS/OxVaultFS --xpc 2>/tmp/oxcrypt-hostapp.err &

# Check XPC service is running
ps aux | grep -i "oxvault.*xpc"

# Tail host app logs
tail -f /tmp/oxcrypt-hostapp.err
```

### Extension Debug Logging

The extension writes debug logs to `/tmp/oxvault_fskit_debug.log`:

```bash
# Watch extension logs (if running)
tail -f /tmp/oxvault_fskit_debug.log

# Check if extension was ever loaded
cat /tmp/oxvault_fskit_debug.log
```

### Common fskitd Log Patterns

**Successful client connection:**
```
Hello FSClient! entitlement yes
About to get current agent for 501
Probing with <FSResource>...
```

**Missing entitlements (third-party mount command):**
```
Hello FSClient! entitlement no
About to get current agent for 501
[connection invalidated 10s later with no probe]
```

**Root user rejection:**
```
Attempt to start non-Apple extension <private> on behalf of root
```

## FSKit Limitations for Third-Party Developers

**Critical Finding (as of macOS 15.4/26.0.1)**: FSKit extensions **cannot be invoked by third-party applications** without Apple's private entitlements.

### The Entitlement Problem

FSKit's architecture requires:

1. **Extension entitlement** (`com.apple.developer.fskit.fsmodule`) - Available to developers via provisioning profile
2. **Client entitlement** (private) - Required to request fskitd to probe/mount; **NOT available to third-party developers**

When a third-party app (or the standard `mount` command) tries to mount an FSKit filesystem:

```
mount -F -t oxcrypt /dev/disk5 /mnt/point
```

The fskitd logs show:
```
Hello FSClient! entitlement no
About to get current agent for 501
[10 seconds later: connection invalidated - no probe ever happens]
```

The mount command lacks the FSKit client entitlement, so fskitd **never probes** the extension.

### What Works vs. What Doesn't

| Approach | Works? | Notes |
|----------|--------|-------|
| Extension with fsmodule entitlement | ✓ | Extension registers correctly |
| Host app stores password in Keychain | ✓ | Shared keychain access works |
| Host app creates/attaches trigger DMG | ✓ | hdiutil works fine |
| `mount -F -t fstype` command | ✗ | Lacks client entitlement |
| `sudo mount` as root | ✗ | "Attempt to start non-Apple extension on behalf of root" |
| FSClient private APIs | ✗ | Returns EPERM without entitlement |

### Why Content-Based Probing Doesn't Help

FSKit uses `FSMediaTypes` in the extension's Info.plist for content-based detection. Even with correctly configured media types:

```xml
<key>FSMediaTypes</key>
<dict>
    <key>Partitionless</key>
    <dict>
        <key>FSMediaProperties</key>
        <dict><key>Leaf</key><true/><key>Whole</key><true/></dict>
        <key>FSProbeOrder</key>
        <integer>5000</integer>
    </dict>
</dict>
```

The mount command itself is rejected before any probing occurs because it lacks entitlements.

### Apple's FSKit Filesystems Work Because

Apple's FSKit filesystems (exfat, msdos, FTP) have special mount helpers (`mount_exfat`, etc.) that:
1. Are Apple-signed with private entitlements
2. Are invoked by DiskArbitration when disks are inserted
3. Have full FSKit client access

Third-party developers cannot obtain these entitlements.

### Current Workarounds

For now, use alternative mount backends that don't require FSKit:

1. **FUSE** (macFUSE) - Works on macOS with kernel extension
2. **WebDAV** - Cross-platform, mounts via `mount_webdav`
3. **NFS** - Userspace NFSv3 server, mounts via standard `mount_nfs`

### Future Possibilities

Apple may provide:
- Public FSKit client entitlement in future macOS versions
- DiskArbitration hooks for third-party FSKit extensions
- A way to register custom "mount helpers" with proper entitlements

Until then, FSKit remains effectively Apple-only for invoking filesystem mounts.
