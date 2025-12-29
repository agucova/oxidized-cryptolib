//! Common test utilities for WebDAV integration tests.

pub mod assertions;
pub mod harness;

pub use assertions::*;
pub use harness::*;

// Import test data generators from shared mount-common testing module
pub use oxidized_mount_common::testing::{
    all_byte_values, chunk_minus_one, chunk_plus_one, deep_path, long_filename,
    multi_chunk_content, one_chunk_content, partial_final_chunk, patterned_chunks,
    problematic_binary, random_bytes, sha256, special_filename, unicode_content,
    unicode_filename, CHUNK_SIZE, FILENAME_THRESHOLD,
};
