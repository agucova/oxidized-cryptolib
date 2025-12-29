//! Realistic workload benchmarks.
//!
//! These benchmarks simulate real-world application access patterns rather than
//! synthetic lab benchmarks. They exercise caches, test temporal locality, and
//! reflect how users actually interact with encrypted vaults.

mod ide;
mod working_set;
mod git;
mod tree;
mod concurrent;
mod database;
mod media;

pub use ide::IdeWorkload;
pub use working_set::WorkingSetWorkload;
pub use git::GitWorkload;
pub use tree::DirectoryTreeWorkload;
pub use concurrent::ConcurrentWorkload;
pub use database::DatabaseWorkload;
pub use media::MediaStreamingWorkload;

use std::time::Duration;

/// Minimum duration for a workload to meaningfully exercise caches.
pub const MIN_WORKLOAD_DURATION: Duration = Duration::from_secs(30);

/// Create all workload benchmarks.
pub fn create_workloads() -> Vec<Box<dyn crate::bench::Benchmark>> {
    vec![
        Box::new(IdeWorkload::new()),
        Box::new(WorkingSetWorkload::new()),
        // GitWorkload disabled: libgit2 requires atomic rename operations that
        // userspace filesystems (FUSE/WebDAV/NFS) don't fully support.
        // TODO: Re-enable when FUSE rename-over-existing is fixed.
        // Box::new(GitWorkload::new()),
        Box::new(DirectoryTreeWorkload::new()),
        Box::new(ConcurrentWorkload::new()),
        Box::new(DatabaseWorkload::new()),
        Box::new(MediaStreamingWorkload::new()),
    ]
}
