//! Configuration types for the benchmark harness.

use std::path::PathBuf;
use std::time::Duration;

/// Filesystem implementation to benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Implementation {
    /// Our FUSE implementation (oxidized-fuse)
    OxidizedFuse,
    /// Our FSKit implementation (oxidized-fskit, macOS 15.4+ only)
    OxidizedFsKit,
    /// Official Cryptomator application (user-mounted)
    OfficialCryptomator,
}

impl Implementation {
    /// Get the display name for this implementation.
    pub fn name(&self) -> &'static str {
        match self {
            Self::OxidizedFuse => "FUSE",
            Self::OxidizedFsKit => "FSKit",
            Self::OfficialCryptomator => "Cryptomator",
        }
    }

    /// Get a short name (for compact displays).
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::OxidizedFuse => "FUSE",
            Self::OxidizedFsKit => "FSKit",
            Self::OfficialCryptomator => "Official",
        }
    }

    /// Get all implementations (platform-dependent).
    pub fn all() -> Vec<Self> {
        let mut impls = vec![Self::OxidizedFuse];

        #[cfg(target_os = "macos")]
        {
            impls.push(Self::OxidizedFsKit);
        }

        impls.push(Self::OfficialCryptomator);
        impls
    }
}

impl std::fmt::Display for Implementation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Benchmark suite to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BenchmarkSuite {
    /// Quick sanity check: 1MB read, single directory listing, 3 iterations
    Quick,
    /// Read-only operations
    Read,
    /// Write operations only
    Write,
    /// Complete benchmark suite
    #[default]
    Full,
}

impl std::str::FromStr for BenchmarkSuite {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" => Ok(Self::Quick),
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "full" => Ok(Self::Full),
            _ => Err(format!("Unknown suite: {s}. Valid options: quick, read, write, full")),
        }
    }
}

impl std::fmt::Display for BenchmarkSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quick => write!(f, "quick"),
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Full => write!(f, "full"),
        }
    }
}

/// Standard file sizes for benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSize {
    /// 1 KB
    Tiny,
    /// 32 KB (one encryption chunk)
    OneChunk,
    /// 100 KB
    Medium,
    /// 1 MB
    Large,
    /// 10 MB
    XLarge,
}

impl FileSize {
    /// Get the size in bytes.
    pub fn bytes(&self) -> usize {
        match self {
            Self::Tiny => 1024,
            Self::OneChunk => 32 * 1024,
            Self::Medium => 100 * 1024,
            Self::Large => 1024 * 1024,
            Self::XLarge => 10 * 1024 * 1024,
        }
    }

    /// Get a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tiny => "1KB",
            Self::OneChunk => "32KB",
            Self::Medium => "100KB",
            Self::Large => "1MB",
            Self::XLarge => "10MB",
        }
    }

    /// Get all standard file sizes.
    pub fn all() -> Vec<Self> {
        vec![Self::Tiny, Self::OneChunk, Self::Medium, Self::Large, Self::XLarge]
    }

    /// Get file sizes for the quick suite.
    pub fn quick() -> Vec<Self> {
        vec![Self::Large]
    }
}

impl std::fmt::Display for FileSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Type of benchmark operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Sequential file read
    SequentialRead,
    /// Random offset reads
    RandomRead,
    /// Sequential file write
    SequentialWrite,
    /// Random offset writes
    RandomWrite,
    /// Directory listing (readdir)
    DirectoryListing,
    /// File metadata (stat/getattr)
    Metadata,
    /// File creation
    FileCreation,
    /// File deletion
    FileDeletion,
}

impl OperationType {
    /// Get the display name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SequentialRead => "Sequential Read",
            Self::RandomRead => "Random Read",
            Self::SequentialWrite => "Sequential Write",
            Self::RandomWrite => "Random Write",
            Self::DirectoryListing => "Directory Listing",
            Self::Metadata => "Metadata",
            Self::FileCreation => "File Creation",
            Self::FileDeletion => "File Deletion",
        }
    }

    /// Whether this operation modifies the filesystem.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Self::SequentialWrite | Self::RandomWrite | Self::FileCreation | Self::FileDeletion
        )
    }
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Configuration for running benchmarks.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Path to the Cryptomator vault.
    pub vault_path: PathBuf,
    /// Vault password.
    pub password: String,
    /// Mount point prefix for auto-generated mount points.
    pub mount_prefix: PathBuf,
    /// Path to user-mounted Cryptomator vault (if using official app).
    pub cryptomator_path: Option<PathBuf>,
    /// Implementations to benchmark.
    pub implementations: Vec<Implementation>,
    /// Benchmark suite to run.
    pub suite: BenchmarkSuite,
    /// Number of iterations per benchmark.
    pub iterations: usize,
    /// Number of warmup iterations.
    pub warmup_iterations: usize,
    /// Enable colored output.
    pub color: bool,
    /// Verbose output.
    pub verbose: bool,
}

impl BenchmarkConfig {
    /// Create a new configuration with defaults.
    pub fn new(vault_path: PathBuf, password: String) -> Self {
        Self {
            vault_path,
            password,
            mount_prefix: PathBuf::from("/tmp/oxbench"),
            cryptomator_path: None,
            implementations: vec![Implementation::OxidizedFuse],
            suite: BenchmarkSuite::Full,
            iterations: 10,
            warmup_iterations: 3,
            color: true,
            verbose: false,
        }
    }

    /// Get mount point for a specific implementation.
    pub fn mount_point(&self, implementation: Implementation) -> PathBuf {
        match implementation {
            Implementation::OfficialCryptomator => {
                self.cryptomator_path.clone().unwrap_or_else(|| self.mount_prefix.join("cryptomator"))
            }
            Implementation::OxidizedFuse => self.mount_prefix.join("fuse"),
            Implementation::OxidizedFsKit => self.mount_prefix.join("fskit"),
        }
    }

    /// Get file sizes for the current suite.
    pub fn file_sizes(&self) -> Vec<FileSize> {
        match self.suite {
            BenchmarkSuite::Quick => FileSize::quick(),
            _ => FileSize::all(),
        }
    }

    /// Get directory sizes for benchmarks.
    pub fn directory_sizes(&self) -> Vec<usize> {
        match self.suite {
            BenchmarkSuite::Quick => vec![10],
            _ => vec![10, 100, 1000],
        }
    }

    /// Get effective iterations (fewer for quick suite).
    pub fn effective_iterations(&self) -> usize {
        match self.suite {
            BenchmarkSuite::Quick => 3.min(self.iterations),
            _ => self.iterations,
        }
    }

    /// Check if we should run read benchmarks.
    pub fn run_reads(&self) -> bool {
        matches!(self.suite, BenchmarkSuite::Quick | BenchmarkSuite::Read | BenchmarkSuite::Full)
    }

    /// Check if we should run write benchmarks.
    pub fn run_writes(&self) -> bool {
        matches!(self.suite, BenchmarkSuite::Write | BenchmarkSuite::Full)
    }
}

/// Timeout durations for various operations.
pub struct Timeouts;

impl Timeouts {
    /// Timeout for mount operation.
    pub const MOUNT: Duration = Duration::from_secs(30);
    /// Timeout for mount readiness polling.
    pub const MOUNT_READY: Duration = Duration::from_secs(10);
    /// Polling interval for mount readiness.
    pub const MOUNT_POLL: Duration = Duration::from_millis(100);
    /// Maximum time for a single benchmark iteration.
    pub const BENCHMARK_ITERATION: Duration = Duration::from_secs(300);
}
