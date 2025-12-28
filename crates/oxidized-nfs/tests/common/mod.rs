//! Common test utilities for NFS integration tests.

pub mod assertions;
pub mod generators;
pub mod harness;

pub use assertions::*;
pub use generators::*;
pub use harness::{TestMount, TEST_PASSWORD};

/// Skip test if mounting failed (e.g., no permissions).
#[macro_export]
macro_rules! skip_if_not_mounted {
    ($mount:expr) => {
        if !$mount.is_mounted() {
            eprintln!("Skipping test: NFS mount not available (may need sudo)");
            return;
        }
    };
}
