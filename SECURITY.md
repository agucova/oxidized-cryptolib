# Security Model

This document describes the security goals, threat model, and accepted trade-offs for `oxidized-cryptolib`.

## What This Library Is

`oxidized-cryptolib` is a Rust implementation for reading and writing [Cryptomator](https://cryptomator.org/) vaults (Vault Format 8). It provides cryptographic operations for:

- Encrypting and decrypting file contents
- Encrypting and decrypting filenames
- Deriving master keys from passphrases
- Validating vault integrity

## Security Goals

### Primary Goals

| Goal | Mechanism |
|------|-----------|
| **Confidentiality of file contents** | AES-256-GCM authenticated encryption with per-file content keys |
| **Confidentiality of filenames** | AES-256-SIV deterministic authenticated encryption |
| **Integrity of file contents** | AEAD authentication tags detect any tampering |
| **Integrity of vault configuration** | HMAC-SHA256 signature on JWT claims |
| **Master key protection at rest** | Scrypt key derivation + RFC 3394 AES key wrapping |

### Secondary Goals

| Goal | Mechanism |
|------|-----------|
| **Memory protection** | Keys wrapped in `MemSafe`, zeroized on drop |
| **Timing attack resistance** | Constant-time comparisons via `subtle` crate, verified with dudect |
| **Swap protection** | Memory locking via `mlock` (implemented via `memsafe`) |
| **API misuse resistance** | Private fields enforce scoped key access patterns |

## What This Library Protects Against

### In-Scope Threats

| Threat | Mitigation |
|--------|------------|
| **Unauthorized file access** | AES-256-GCM encryption with 256-bit keys |
| **File content tampering** | 16-byte authentication tags per chunk |
| **Chunk reordering/truncation** | AAD includes chunk number + header nonce |
| **Filename discovery** | AES-SIV encryption with directory ID as context |
| **Brute-force password attacks** | Scrypt with N=2^16, r=8, p=1 (memory-hard) |
| **Master key extraction from file** | RFC 3394 key wrapping with integrity check |
| **Timing side-channels** | Constant-time comparisons, statistical verification |

### Mitigations in Detail

**Timing Attack Resistance:**
- RFC 3394 integrity check uses `subtle::ConstantTimeEq`
- Timing leak detection via dudect statistical methodology
- All cryptographic operations use constant-time primitives from RustCrypto

**Memory Protection:**
- All key material stored in `MemSafe<[u8; N]>` containers
- Memory locking (`mlock`) prevents swapping to disk
- Access control via `mprotect(PROT_NONE)` when not in use
- Automatic zeroization on drop via `zeroize` crate
- Scoped access pattern prevents key material from escaping callbacks

## What This Library Does NOT Protect Against

### Out-of-Scope Threats

| Threat | Rationale |
|--------|-----------|
| **Malware on local system** | Cannot protect against keyloggers, memory scrapers, or code injection |
| **Physical access attacks** | Cold boot, DMA attacks require hardware/OS-level mitigations |
| **Denial of service** | Attacker with write access can corrupt vault (detected but not prevented) |

### Inherited from Cryptomator Protocol

These are **not encrypted** by design (required for cloud synchronization):

| Metadata | Visibility |
|----------|------------|
| File sizes | Approximate plaintext size is visible |
| Timestamps | Access, modification, creation times |
| File/folder count | Number of items per directory |
| Vault existence | `.c9r`/`.c9s` extensions and `vault.cryptomator` are recognizable |

## Accepted Risks

### Protocol-Level Trade-offs

| Risk | Severity | Rationale |
|------|----------|-----------|
| **Filename swapping within directory** | Low | Attacker with write access can swap encrypted filenames within a directory. File contents remain secure and tamper-proof. See [GHSA-qwfw-w5qf-7wcj](https://github.com/cryptomator/cryptomator/security/advisories/GHSA-qwfw-w5qf-7wcj). |
| **Directory structure inference** | Low | Number of files per directory is visible; directory hierarchy is obfuscated but depth may be inferred |

### Implementation-Level Trade-offs

| Risk | Severity | Mitigation Status |
|------|----------|-------------------|
| **JWT library doesn't zeroize** | Low | `jsonwebtoken` crate copies key material internally. Exposure window minimized via scoped access. Documented in code. |
| **Keys may swap to disk** | Medium | Memory locking (`mlock`) planned to prevent swap exposure |

## Dependency Trust Model

This library relies on well-audited cryptographic implementations:

| Crate | Purpose | Trust Basis |
|-------|---------|-------------|
| `aes`, `aes-gcm`, `aes-siv` | Symmetric encryption | RustCrypto project, widely reviewed |
| `ring` | HMAC, SHA, RNG | Derived from BoringSSL, extensively audited |
| `scrypt` | Key derivation | RustCrypto, implements RFC 7914 |
| `memsafe`, `zeroize` | Memory protection | Memory locking (mlock), access control (mprotect), zeroization |
| `subtle` | Constant-time operations | RustCrypto, modeled after Go's `subtle` |
| `jsonwebtoken` | JWT parsing | Popular crate, **not** RustCrypto (documented limitation) |

### Unsafe Code Policy

All cryptographic modules use `#![forbid(unsafe_code)]`. Unsafe operations are delegated to audited upstream crates.

## Verification

### Automated Testing

| Test Type | Coverage |
|-----------|----------|
| Property-based tests | 1000 cases per property (encrypt/decrypt roundtrips, integrity) |
| RFC 3394 test vectors | Official NIST vectors for key wrap/unwrap |
| Timing leak detection | dudect statistical analysis on crypto operations |
| Integration tests | Real Cryptomator vault decryption |

### Running Security Tests

```bash
# Property-based crypto tests
cargo test --test crypto_tests

# Timing leak detection (quick)
cargo bench --release --bench timing_leaks -- --quick

# Timing leak detection (thorough)
cargo bench --release --bench timing_leaks
```

**Timing test interpretation:** t-value < 4.5 indicates no detectable timing leak.

### Dependency Auditing

The project uses `cargo-deny` for continuous dependency auditing. Run locally with:

```bash
# Full audit (advisories, licenses, bans, sources)
cargo deny check

# Individual checks
cargo deny check advisories   # CVE/vulnerability scanning
cargo deny check licenses     # License compliance
cargo deny check bans         # Banned crate detection
cargo deny check sources      # Source verification
```

Configuration is in `deny.toml`. The audit runs automatically in CI on every push and pull request.

#### Audit Policy

| Check | Policy |
|-------|--------|
| **Advisories** | Deny all known vulnerabilities; dev-only deps may be ignored with justification |
| **Licenses** | Allow MIT, Apache-2.0, BSD, ISC, MPL-2.0; deny copyleft (GPL/LGPL) |
| **Bans** | Deny deprecated crypto crates (rust-crypto, openssl) |
| **Sources** | Deny non-crates.io sources (git dependencies, unknown registries) |

#### Current Acknowledged Advisories

The following advisories are acknowledged in `deny.toml`:

| Advisory | Crate | Reason for Ignoring |
|----------|-------|---------------------|
| RUSTSEC-2021-0139 | ansi_term | Unmaintained; dev dependency only via dudect-bencher |
| RUSTSEC-2021-0145 | atty | Unaligned read (Windows only); dev dependency only |
| RUSTSEC-2024-0375 | atty | Unmaintained; dev dependency only via dudect-bencher |

These are acceptable because they only affect development/benchmarking builds, not production code.
