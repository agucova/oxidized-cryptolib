//! Common test infrastructure for FUSE integration tests.
//!
//! Provides the `TestMount` harness and assertions for testing
//! the FUSE filesystem through actual kernel mounts.

pub mod assertions;
pub mod harness;

pub use assertions::*;
pub use harness::TestMount;

// Re-export testing utilities from mount-common
// (not all test files use all utilities, so suppress unused import warnings)
#[allow(unused_imports)]
pub use oxidized_mount_common::testing::{
    // Generators
    all_byte_values, chunk_minus_one, chunk_plus_one, deep_path, long_filename,
    multi_chunk_content, one_chunk_content, partial_final_chunk, patterned_chunks,
    problematic_binary, random_bytes, special_filename, unicode_content, unicode_filename,
    CHUNK_SIZE,
    // Assertions
    sha256,
};

// Macros (skip_if_no_fuse!, require_mount!) are #[macro_export] so they're
// available at the crate root. No need to re-export them here.
