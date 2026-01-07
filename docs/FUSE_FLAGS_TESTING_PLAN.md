# FUSE Mount Flags Testing Plan

This document outlines a systematic approach to testing Cryptomator's FUSE mount flags for adoption in oxcrypt-fuse.

## Background Research Summary

### Sources
- [macFUSE Mount Options Wiki](https://github.com/macfuse/macfuse/wiki/Mount-Options)
- [Linux mount.fuse3 man page](https://man7.org/linux/man-pages/man8/mount.fuse3.8.html)
- [libfuse fuse_common.h](https://github.com/libfuse/libfuse/blob/master/include/fuse_common.h)

## Flags to Test

### Priority 1: High Impact, Low Risk

#### 1. `noappledouble` (macOS only)
**What it does**: Blocks all access to `._*` AppleDouble files and `.DS_Store` files. Makes them appear non-existent and prevents creation.

**Why Cryptomator uses it**: Prevents cluttering the encrypted vault with macOS resource fork files that sync to cloud storage unnecessarily.

**Current state in oxcrypt**: Only enabled in test harness, NOT in production.

**Risk level**: LOW - This is purely additive behavior that removes unwanted files.

**Expected impact**:
- Fewer files in vault (cleaner)
- Faster sync (fewer files to encrypt/upload)
- No functional regressions expected

---

#### 2. `uid` / `gid` (Both platforms)
**What it does**: Overrides the st_uid/st_gid fields returned by the filesystem to the specified values.

**Why Cryptomator uses it**: Ensures files appear owned by the mounting user, avoiding permission issues when `default_permissions` is enabled.

**Current state in oxcrypt**: NOT set - relies on whatever fuser/kernel defaults to.

**Risk level**: LOW - Standard practice for user-mounted filesystems.

**Expected impact**:
- Files correctly owned by mounting user
- Permission checks work correctly
- May fix permission-related test failures

---

#### 3. `auto_cache` (macOS only)
**What it does**: Automatically invalidates buffer cache when mtime changes during `getattr()` or `open()`. Generates kqueue notifications.

**Why Cryptomator uses it**: Keeps cached data consistent when files change externally.

**Current state in oxcrypt**:
- Enabled in `main.rs` (oxmount binary)
- NOT enabled in `backend.rs` (daemon/GUI mount path) - **inconsistency!**

**Risk level**: LOW - We already use it in one path.

**Expected impact**:
- Better cache coherency
- Prevents SIGBUS crashes with mmap (already noted in code comment)
- Slight performance overhead (extra mtime checks)

---

### Priority 2: Medium Impact, Medium Risk

#### 4. `atomic_o_trunc` (Both platforms)
**What it does**: Passes `O_TRUNC` flag directly to `open()` instead of calling `truncate()` then `open()` separately.

**Why Cryptomator uses it**: Atomic truncate-and-open semantics.

**Current state in oxcrypt**: NOT enabled (kernel capability).

**How to enable**: `config.add_capabilities(fuser::consts::FUSE_ATOMIC_O_TRUNC)`

**Risk level**: MEDIUM - Changes open() semantics; our `open()` implementation must handle `O_TRUNC`.

**Expected impact**:
- Faster truncate-on-open (1 syscall instead of 2)
- Better atomicity guarantees
- Requires verifying our `open()` handles truncation correctly

---

#### 5. `attr_timeout` (Linux only)
**What it does**: Sets kernel attribute cache timeout. Default is 1 second.

**Why Cryptomator uses it**: Sets to 5 seconds for better performance.

**Current state in oxcrypt**: NOT set (using kernel default of 1s).

**Risk level**: MEDIUM - Stale attributes visible longer.

**Expected impact**:
- Fewer `getattr()` calls from kernel
- Better performance for stat-heavy workloads
- May cause confusion if files change externally within timeout

---

#### 6. `auto_xattr` (macOS only)
**What it does**: Forces kernel to handle xattrs via AppleDouble files without consulting userspace filesystem.

**Why Cryptomator uses it**: Simplifies xattr handling - no need to implement xattr methods.

**Current state in oxcrypt**: NOT set.

**Risk level**: MEDIUM - Changes xattr behavior significantly.

**Expected impact**:
- Simplifies code (no xattr implementation needed)
- Creates `._*` files for xattrs (unless `noappledouble` is also set - conflict!)
- May break if `noappledouble` is set simultaneously

**NOTE**: `auto_xattr` and `noappledouble` may conflict! Cryptomator uses both, need to test interaction.

---

### Priority 3: Lower Priority / Experimental

#### 7. `daemon_timeout` (macOS only)
**What it does**: Auto-ejects volume if daemon doesn't respond within N seconds.

**Current state in oxcrypt**: Already set to 30s in `backend.rs` (good!).

**Action**: No change needed, already implemented.

---

#### 8. `entry_timeout` (Linux only)
**What it does**: Sets kernel name lookup cache timeout. Default is 1 second.

**Current state in oxcrypt**: NOT set.

**Risk level**: LOW - Similar to attr_timeout.

**Expected impact**: Fewer `lookup()` calls, better performance.

---

## Testing Methodology

For each flag, we will:

### Phase 1: Baseline (Before)
```bash
# Run full test suite
OXCRYPT_FAST_KDF=1 PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
  cargo nextest run -p oxcrypt-fuse --features fuse-tests

# Run benchmark (3 iterations)
OXCRYPT_FAST_KDF=1 ./target/release/oxbench test_vault fuse \
  --password 123456789 --suite synthetic --iterations 3
```

### Phase 2: Add Flag
Modify `crates/oxcrypt-fuse/src/backend.rs` and/or `main.rs` to add the flag.

### Phase 3: Validation (After)
```bash
# Run full test suite again
OXCRYPT_FAST_KDF=1 PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
  cargo nextest run -p oxcrypt-fuse --features fuse-tests

# Run same benchmark
OXCRYPT_FAST_KDF=1 ./target/release/oxbench test_vault fuse \
  --password 123456789 --suite synthetic --iterations 3
```

### Phase 4: Decision
- **ACCEPT** if: Tests pass AND (performance improves OR stays same)
- **REJECT** if: Tests fail OR significant performance regression
- **INVESTIGATE** if: Mixed results

---

## Implementation Order

Based on risk/reward analysis:

| Order | Flag | Platform | Risk | Expected Benefit |
|-------|------|----------|------|------------------|
| 1 | `noappledouble` | macOS | LOW | Cleaner vault |
| 2 | `uid`/`gid` | Both | LOW | Correct ownership |
| 3 | `auto_cache` consistency | macOS | LOW | Fix inconsistency |
| 4 | `atomic_o_trunc` | Both | MEDIUM | Atomicity |
| 5 | `attr_timeout=5` | Linux | MEDIUM | Performance |
| 6 | `entry_timeout=5` | Linux | LOW | Performance |
| 7 | `auto_xattr` | macOS | MEDIUM | Investigate conflict |

---

## Code Changes Required

### For `noappledouble`:
```rust
// In backend.rs and main.rs, add to macOS options:
#[cfg(target_os = "macos")]
options.push(MountOption::CUSTOM("noappledouble".to_string()));
```

### For `uid`/`gid`:
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::MetadataExt;
    let home = std::env::var("HOME").unwrap_or_default();
    if let Ok(meta) = std::fs::metadata(&home) {
        options.push(MountOption::CUSTOM(format!("uid={}", meta.uid())));
        options.push(MountOption::CUSTOM(format!("gid={}", meta.gid())));
    }
}
```

### For `atomic_o_trunc`:
```rust
// In filesystem.rs init():
config.add_capabilities(fuser::consts::FUSE_ATOMIC_O_TRUNC).ok();
```

### For `attr_timeout` (Linux):
```rust
#[cfg(target_os = "linux")]
options.push(MountOption::CUSTOM("attr_timeout=5".to_string()));
```

---

## Questions to Answer During Testing

1. Does `noappledouble` + `auto_xattr` cause conflicts?
2. Does `atomic_o_trunc` require changes to our `open()` implementation?
3. Does `attr_timeout=5` cause visible staleness issues?
4. What's the performance delta for metadata-heavy workloads with these flags?

---

## Acceptance Criteria

A flag is accepted if:
1. All existing tests pass (no regressions)
2. Performance is equal or better (within noise margin)
3. The flag's behavior is well understood and documented
4. The flag aligns with security/correctness requirements
