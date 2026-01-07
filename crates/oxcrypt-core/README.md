# oxcrypt-core

Core Cryptomator vault encryption library for OxCrypt.

Provides AES-GCM and AES-SIV encryption for Cryptomator Format 8 vaults, including key derivation with scrypt, vault configuration management, and both sync and async file operations.

## Features

- **AES-GCM** encryption for file contents with AEAD authentication
- **AES-SIV** encryption for filenames with deterministic ciphertexts
- **Scrypt** key derivation for password-based master keys
- **JWT** vault configuration signing and validation
- **Async/Sync** support via feature flags
- **Memory-safe** operations with zeroization and mlocking

## License

Licensed under the Mozilla Public License 2.0.
