//! Testing utilities for mount backend integration tests.
//!
//! This module provides shared test infrastructure for FUSE, FSKit, and WebDAV
//! backends. It includes:
//!
//! - **Generators**: Chunk-aware test data generation (32KB boundaries)
//! - **Assertions**: Content verification with helpful error messages
//! - **Vault utilities**: Temporary vault creation and management
//!
//! # Usage
//!
//! ```ignore
//! use oxcrypt_mount::testing::{
//!     one_chunk_content, all_byte_values, CHUNK_SIZE,
//!     sha256, assert_bytes_equal,
//!     TempVault,
//! };
//!
//! #[test]
//! fn test_chunk_boundary_write() {
//!     let vault = TempVault::new();
//!     let content = one_chunk_content();
//!     // ... mount and write content ...
//! }
//! ```

pub mod assertions;
pub mod generators;
pub mod vault;

// Re-export commonly used items at the module level
pub use assertions::{assert_bytes_equal, assert_hash_equal, assert_io_err, assert_io_ok, sha256};
pub use generators::{
    all_byte_values, chunk_minus_one, chunk_plus_one, deep_path, long_filename,
    multi_chunk_content, one_chunk_content, partial_final_chunk, patterned_chunks,
    problematic_binary, random_bytes, special_filename, unicode_content, unicode_filename,
    CHUNK_SIZE, FILENAME_THRESHOLD,
};
pub use vault::{shared_vault_path, TempVault, SHARED_VAULT_PASSWORD, TEST_PASSWORD};

#[cfg(unix)]
pub use assertions::assert_errno;
