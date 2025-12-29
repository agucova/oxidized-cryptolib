//! Cross-implementation filesystem benchmark harness for Cryptomator vaults.
//!
//! This crate provides a comprehensive benchmark suite for comparing the performance
//! of different Cryptomator vault filesystem implementations:
//!
//! - **oxcrypt-fuse**: FUSE-based filesystem (cross-platform)
//! - **oxcrypt-fskit**: FSKit-based filesystem (macOS 15.4+ only)
//! - **Official Cryptomator**: External mount for comparison
//!
//! # Usage
//!
//! ```text
//! oxbench [OPTIONS] <vault> [implementations...]
//!
//! Arguments:
//!   <vault>              Path to the Cryptomator vault
//!   [implementations]... Implementations to benchmark
//!
//! Options:
//!   -m, --mount-prefix <PATH>    Mount point prefix (default: /tmp/oxbench)
//!   -c, --cryptomator <PATH>     Path to already-mounted Cryptomator vault
//!   -p, --password <PASSWORD>    Vault password (or OXBENCH_PASSWORD env)
//!   -s, --suite <SUITE>          Benchmark suite: quick, read, write, full
//!       --iterations <N>         Iterations per benchmark (default: 10)
//!   -v, --verbose                Verbose output
//!   -h, --help                   Print help
//! ```

pub mod assets;
pub mod bench;
pub mod cli;
pub mod config;
pub mod mount;
pub mod platform;
pub mod results;

pub use bench::{Benchmark, BenchmarkResult, BenchmarkRunner};
pub use cli::Cli;
pub use config::{BenchmarkConfig, BenchmarkSuite, FileSize, Implementation, OperationType};
pub use mount::{BenchMount, MountBackend, MountHandle};
pub use results::{BenchmarkStats, LatencyStats, Throughput};
