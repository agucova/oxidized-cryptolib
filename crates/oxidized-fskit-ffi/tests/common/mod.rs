//! Common test utilities for oxidized-fskit-ffi integration tests.
//!
//! This module re-exports the test harness and utilities from `oxidized_mount_common::testing`
//! for convenient access in test files.

pub mod harness;

// Re-export the main test harness
pub use harness::TestFilesystem;

// Re-export commonly used testing utilities from mount-common
pub use oxidized_mount_common::testing::{
    // Generators for chunk-aware test content
    chunk_minus_one, chunk_plus_one, multi_chunk_content, one_chunk_content, random_bytes,
    CHUNK_SIZE,
    // Assertions
    assert_bytes_equal, sha256,
};
