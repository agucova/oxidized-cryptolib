# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build and Development
- **Build**: `cargo build` (compile the library and binary)
- **Run**: `cargo run` (runs the main.rs demo with test_vault using password "123456789")
- **Check**: `cargo check` (fast compile check without generating binaries)
- **Format**: `cargo fmt` (format all Rust code using rustfmt)
- **Lint**: `cargo clippy` (static analysis and linting)
- **Clean**: `cargo clean` (remove target directory)

### Testing
- **All tests**: `cargo test` (runs unit tests and integration tests)
- **Integration tests**: `cargo test --test crypto_tests` (runs property-based crypto tests)
- **Specific test**: `cargo test [test_name]` (run a specific test function)
- **Test with output**: `cargo test -- --nocapture` (show println! output during tests)

### Benchmarking
- **All benchmarks**: `cargo bench` (runs all criterion-based performance benchmarks)
- **Specific benchmark**: `cargo bench --bench crypto_operations` (runs crypto operation benchmarks)
- **Quick benchmarks**: `cargo bench -- --quick` (faster execution for development)
- **Baseline benchmarks**: `cargo bench -- --save-baseline [name]` (save performance baseline)
- **Compare benchmarks**: `cargo bench -- --baseline [name]` (compare against saved baseline)

## Architecture Overview

**oxidized-cryptolib** is a Rust implementation for decrypting and exploring Cryptomator vaults. The project demonstrates modern cryptographic practices and implements the Cryptomator encryption protocol.

### Core Components

#### Cryptographic Modules
- **`master_key.rs`**: Core MasterKey struct with AES and MAC keys (32 bytes each), uses `secrecy` crate for memory protection
- **`master_key_file.rs`**: Scrypt-based key derivation from passphrases with RFC 3394 AES key wrapping  
- **`rfc_3394.rs`**: Pure Rust implementation of AES Key Wrap algorithm per RFC 3394
- **`names.rs`**: Filename encryption/decryption using AES-SIV with directory ID as associated data
- **`files.rs`**: File content encryption/decryption using AES-GCM with 32KB chunk processing

#### Vault Operations
- **`vault.rs`**: JWT-based vault configuration parsing, master key extraction, claim validation
- **`main.rs`**: Demo application showing vault exploration with directory tree reconstruction

### Security Features
- Uses `#![forbid(unsafe_code)]` in critical modules
- Memory zeroization for sensitive data via `secrecy` crate
- Authenticated encryption (AES-GCM, AES-SIV) preventing tampering
- JWT signature validation for vault integrity
- Property-based testing with 1000 test cases for crypto operations

### Project Structure
- **Library**: Core cryptographic operations exposed via `lib.rs`
- **Binary**: Demo vault explorer in `main.rs` (hardcoded to use test_vault with password "123456789")
- **Integration tests**: Comprehensive crypto roundtrip tests in `tests/crypto_tests.rs`
- **Test vault**: Real Cryptomator vault structure in `test_vault/` for testing

### Dependencies
Key cryptographic dependencies include:
- `aes-gcm`, `aes-siv` for authenticated encryption
- `ring` for cryptographic primitives  
- `scrypt` for key derivation
- `jsonwebtoken` for vault configuration validation
- `proptest` for property-based testing
- `secrecy` for secure memory handling

### Development Notes
- The main binary demonstrates vault exploration with detailed debug output
- Property-based tests use 1000 test cases to verify cryptographic correctness
- Code follows Rust 2021 edition with modern async patterns where applicable
- Uses nightly features (`#![feature(test)]`, `#![feature(int_roundings)]`)

## Cryptomator Protocol Reference

### Vault Format 8 (Current)
The implementation follows Cryptomator Vault Format 8, introduced in Cryptomator 1.6.0:
- **JWT-based vault configuration**: `vault.cryptomator` contains vault metadata signed with master keys
- **Cipher combo**: `SIV_GCM` (AES-SIV for filenames, AES-GCM for file contents)
- **Filename threshold**: 220 characters before shortening to `.c9s` format
- **Directory structure**: Flattened under `/d/` with 2-character subdirectories

### Key Cryptographic Components
- **Master keys**: 256-bit encryption + 256-bit MAC keys derived via scrypt
- **File headers**: 68 bytes (12-byte nonce + 40-byte AES-GCM payload + 16-byte tag)
- **File content**: 32KB chunks with AES-GCM, chunk number + header nonce as AAD
- **Filename encryption**: AES-SIV with parent directory ID as associated data
- **Directory IDs**: Random UUIDs (root directory uses empty string)

### File Structure Patterns
- **Regular files**: `{base64url-encrypted-name}.c9r`
- **Directories**: `{encrypted-name}.c9r/dir.c9r` (contains directory ID)
- **Symlinks**: `{encrypted-name}.c9r/symlink.c9r` (contains link target)
- **Long names**: `{sha1-hash}.c9s/name.c9s` + `contents.c9r`/`dir.c9r`/`symlink.c9r`

### Security Considerations
- **Accepted risk**: Filename swapping within same directory (performance vs security tradeoff)
- **Protected**: File contents, filenames, directory structure obfuscation
- **Not protected**: File sizes, timestamps, number of files per directory

Refer to `.claude/cryptomator_docs/` for complete protocol specifications.