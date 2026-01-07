//! Benchmark workloads.
//!
//! All benchmarks (both synthetic micro-benchmarks and realistic application
//! workloads) are unified under this module. Each can be selected individually
//! via `--workload NAME` or composed into suites.

// Allow numeric casts in workload config scaling
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

mod archive;
mod backup;
mod coldstart;
mod concurrent;
mod database;
mod git;
mod ide;
mod media;
mod photo;
mod tree;
mod working_set;

pub use archive::ArchiveExtractionWorkload;
pub use backup::BackupSyncWorkload;
pub use coldstart::ColdStartWorkload;
pub use concurrent::ConcurrentWorkload;
pub use database::DatabaseWorkload;
pub use git::GitWorkload;
pub use ide::IdeWorkload;
pub use media::MediaStreamingWorkload;
pub use photo::PhotoLibraryWorkload;
pub use tree::DirectoryTreeWorkload;
pub use working_set::WorkingSetWorkload;

use crate::bench::{
    DirectoryListingBenchmark, FileCreationBenchmark, FileDeletionBenchmark,
    MetadataBenchmark, RandomReadBenchmark, RandomWriteBenchmark,
    SequentialReadBenchmark, SequentialWriteBenchmark,
};
use crate::config::FileSize;
use std::fs::File;
use std::io;
use std::path::Path;
use std::time::Duration;

/// Default scale for workload sizes and durations (10% of full size for quick runs).
pub const DEFAULT_WORKLOAD_SCALE: f64 = 0.1;

/// Configuration for workload scaling and behavior.
#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    /// Scale factor for counts, sizes, and durations (0.0-1.0).
    /// 1.0 = full workload, 0.1 = 10% of full workload.
    pub scale: f64,
    /// Whether to use real assets (downloaded media files) instead of synthetic data.
    pub real_assets: bool,
    /// Unique session identifier to avoid directory name conflicts.
    /// This prevents stale cache entries from blocking directory creation.
    pub session_id: u64,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self::new(DEFAULT_WORKLOAD_SCALE)
    }
}

impl WorkloadConfig {
    /// Create a new config with the given scale.
    pub fn new(scale: f64) -> Self {
        // Generate unique session ID from current timestamp
        let session_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            scale: scale.clamp(0.01, 1.0),
            real_assets: false,
            session_id,
        }
    }

    /// Enable real assets (downloaded media files).
    #[must_use]
    pub fn with_real_assets(mut self, real_assets: bool) -> Self {
        self.real_assets = real_assets;
        self
    }

    /// Scale a count value, respecting minimum bounds.
    pub fn scale_count(&self, base: usize, min: usize) -> usize {
        let scaled = (base as f64 * self.scale).round() as usize;
        scaled.clamp(min, base.max(min))
    }

    /// Scale a byte size value, respecting minimum bounds.
    pub fn scale_bytes(&self, base: usize, min: usize) -> usize {
        let scaled = (base as f64 * self.scale).round() as usize;
        scaled.clamp(min, base.max(min))
    }

    /// Scale a duration, respecting minimum bounds.
    pub fn scale_duration(&self, base: Duration, min: Duration) -> Duration {
        let secs = base.as_secs_f64() * self.scale;
        Duration::from_secs_f64(secs.max(min.as_secs_f64()))
    }

    /// Get file size based on scale.
    ///
    /// Returns a representative file size for benchmarks:
    /// - scale < 0.25: 32KB (one chunk)
    /// - scale < 0.5: 100KB
    /// - scale < 0.75: 1MB
    /// - scale >= 0.75: 10MB
    pub fn file_size(&self) -> FileSize {
        if self.scale < 0.25 {
            FileSize::OneChunk
        } else if self.scale < 0.5 {
            FileSize::Medium
        } else if self.scale < 0.75 {
            FileSize::Large
        } else {
            FileSize::XLarge
        }
    }

    /// Get directory size (number of files) based on scale.
    pub fn directory_size(&self) -> usize {
        self.scale_count(1000, 10)
    }
}

/// Available workload names for CLI selection.
///
/// Each workload can be selected by its canonical name or aliases.
/// Organized into categories:
///
/// **Synthetic I/O:**
/// - seq-read, rand-read, seq-write, rand-write
///
/// **Synthetic Metadata:**
/// - readdir, stat
///
/// **Synthetic Lifecycle:**
/// - create, delete
///
/// **Realistic Workloads:**
/// - ide, working-set, git, tree, concurrent, database, media, photo, archive, backup, coldstart
pub const WORKLOAD_NAMES: &[(&str, &[&str])] = &[
    // === Synthetic I/O benchmarks ===
    ("seq-read", &["sequential-read", "seqread"]),
    ("rand-read", &["random-read", "randread"]),
    ("seq-write", &["sequential-write", "seqwrite"]),
    ("rand-write", &["random-write", "randwrite"]),
    // === Synthetic metadata benchmarks ===
    ("readdir", &["directory-listing", "ls"]),
    ("stat", &["metadata", "getattr"]),
    // === Synthetic lifecycle benchmarks ===
    ("create", &["file-creation"]),
    ("delete", &["file-deletion", "unlink"]),
    // === Realistic application workloads ===
    ("ide", &["ide-workload"]),
    ("working-set", &["workingset", "zipf"]),
    ("git", &["git-workload", "vcs"]),
    ("tree", &["directory-tree", "dirtree"]),
    ("concurrent", &["parallel", "threads"]),
    ("database", &["db", "chinook", "sqlite"]),
    ("media", &["media-streaming", "video"]),
    ("photo", &["photo-library", "photos", "exif"]),
    ("archive", &["archive-extraction", "tar", "zip"]),
    ("backup", &["backup-sync", "sync", "rsync"]),
    ("coldstart", &["cold-start", "mount-latency"]),
];

/// Get all available workload names (canonical names only).
pub fn workload_names() -> Vec<&'static str> {
    WORKLOAD_NAMES.iter().map(|(name, _)| *name).collect()
}

/// Normalize a workload name by checking canonical names and aliases.
fn normalize_workload_name(name: &str) -> Option<&'static str> {
    let name_lower = name.to_lowercase();
    for (canonical, aliases) in WORKLOAD_NAMES {
        if *canonical == name_lower {
            return Some(canonical);
        }
        for alias in *aliases {
            if *alias == name_lower {
                return Some(canonical);
            }
        }
    }
    None
}

/// Create a single workload by name.
///
/// Returns `None` if the workload name is not recognized.
pub fn create_workload_by_name(
    name: &str,
    config: &WorkloadConfig,
) -> Option<Box<dyn crate::bench::Benchmark>> {
    let canonical = normalize_workload_name(name)?;
    match canonical {
        // Synthetic I/O
        "seq-read" => Some(Box::new(SequentialReadBenchmark::new(config.file_size()))),
        "rand-read" => Some(Box::new(RandomReadBenchmark::new(config.file_size()))),
        "seq-write" => Some(Box::new(SequentialWriteBenchmark::new(config.file_size()))),
        "rand-write" => Some(Box::new(RandomWriteBenchmark::new(config.file_size()))),
        // Synthetic metadata
        "readdir" => Some(Box::new(DirectoryListingBenchmark::new(config.directory_size()))),
        "stat" => Some(Box::new(MetadataBenchmark::new(config.scale_count(100, 10)))),
        // Synthetic lifecycle
        "create" => Some(Box::new(FileCreationBenchmark::new(config.scale_count(100, 10)))),
        "delete" => Some(Box::new(FileDeletionBenchmark::new(config.scale_count(100, 10)))),
        // Realistic workloads
        "ide" => Some(Box::new(IdeWorkload::new(config.clone()))),
        "working-set" => Some(Box::new(WorkingSetWorkload::new(config.clone()))),
        "git" => Some(Box::new(GitWorkload::new(config.clone()))),
        "tree" => Some(Box::new(DirectoryTreeWorkload::new(config.clone()))),
        "concurrent" => Some(Box::new(ConcurrentWorkload::new(config.clone()))),
        "database" => Some(Box::new(DatabaseWorkload::new(config.clone()))),
        "media" => Some(Box::new(MediaStreamingWorkload::new(config.clone()))),
        "photo" => Some(Box::new(PhotoLibraryWorkload::new(config.clone()))),
        "archive" => Some(Box::new(ArchiveExtractionWorkload::new(config.clone()))),
        "backup" => Some(Box::new(BackupSyncWorkload::new(config.clone()))),
        "coldstart" => Some(Box::new(ColdStartWorkload::new(config.clone()))),
        _ => None,
    }
}

/// Create multiple workloads by names.
pub fn create_workloads_by_names(
    names: &[&str],
    config: &WorkloadConfig,
) -> Vec<Box<dyn crate::bench::Benchmark>> {
    names
        .iter()
        .filter_map(|name| create_workload_by_name(name, config))
        .collect()
}

/// Workload category for suite composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadCategory {
    /// Read I/O benchmarks
    Read,
    /// Write I/O benchmarks
    Write,
    /// Metadata operations
    Metadata,
    /// File lifecycle (create/delete)
    Lifecycle,
    /// Realistic application workloads
    Realistic,
}

/// Get workload names by category.
pub fn workloads_by_category(category: WorkloadCategory) -> &'static [&'static str] {
    match category {
        WorkloadCategory::Read => &["seq-read", "rand-read"],
        WorkloadCategory::Write => &["seq-write", "rand-write"],
        WorkloadCategory::Metadata => &["readdir", "stat"],
        WorkloadCategory::Lifecycle => &["create", "delete"],
        WorkloadCategory::Realistic => &[
            "ide",
            "working-set",
            "git",
            "tree",
            "concurrent",
            "database",
            "media",
            "photo",
            // "archive", // Disabled: FUSE iteration 2+ fails, use --workload archive to test individually
            "backup",
            "coldstart",
        ],
    }
}

/// Create all synthetic I/O workloads (reads + writes).
pub fn create_io_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    let mut workloads = Vec::new();
    workloads.extend(create_workloads_by_names(
        workloads_by_category(WorkloadCategory::Read),
        config,
    ));
    workloads.extend(create_workloads_by_names(
        workloads_by_category(WorkloadCategory::Write),
        config,
    ));
    workloads
}

/// Create all synthetic metadata workloads.
pub fn create_metadata_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    create_workloads_by_names(workloads_by_category(WorkloadCategory::Metadata), config)
}

/// Create all synthetic lifecycle workloads.
pub fn create_lifecycle_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    create_workloads_by_names(workloads_by_category(WorkloadCategory::Lifecycle), config)
}

/// Create all synthetic workloads (I/O + metadata + lifecycle).
pub fn create_synthetic_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    let mut workloads = create_io_workloads(config);
    workloads.extend(create_metadata_workloads(config));
    workloads.extend(create_lifecycle_workloads(config));
    workloads
}

/// Create all realistic application workloads.
pub fn create_realistic_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    create_workloads_by_names(workloads_by_category(WorkloadCategory::Realistic), config)
}

/// Create all workload benchmarks with the given configuration.
pub fn create_workloads(config: &WorkloadConfig) -> Vec<Box<dyn crate::bench::Benchmark>> {
    let mut workloads = create_synthetic_workloads(config);
    workloads.extend(create_realistic_workloads(config));
    workloads
}

/// Create selected workload benchmarks.
///
/// If `selected` is empty, creates all realistic workloads (not synthetic).
/// Returns an error string for any unrecognized workload names.
pub fn create_workloads_filtered(
    config: &WorkloadConfig,
    selected: &[String],
) -> Result<Vec<Box<dyn crate::bench::Benchmark>>, String> {
    if selected.is_empty() {
        return Ok(create_realistic_workloads(config));
    }

    let mut benchmarks = Vec::new();
    let mut unknown = Vec::new();

    for name in selected {
        if let Some(workload) = create_workload_by_name(name, config) {
            benchmarks.push(workload);
        } else {
            unknown.push(name.as_str());
        }
    }

    if !unknown.is_empty() {
        let valid_names = workload_names().join(", ");
        return Err(format!(
            "Unknown workload(s): {}. Valid options: {}",
            unknown.join(", "),
            valid_names
        ));
    }

    Ok(benchmarks)
}

/// Copy a file without preserving permissions.
///
/// Unlike `fs::copy()`, this function does not attempt to preserve the source file's
/// permissions by calling `setattr`. This is necessary when copying to filesystems
/// that don't support Unix permissions (like FUSE-mounted Cryptomator vaults),
/// which return ENOTSUP when attempting to set permissions.
///
/// # Example
/// ```no_run
/// # use std::path::Path;
/// # use oxcrypt_bench::bench::workloads::copy_file_contents;
/// copy_file_contents(
///     Path::new("/source/file.db"),
///     Path::new("/vault/file.db")
/// )?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn copy_file_contents<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    let mut reader = File::open(from.as_ref())?;
    let mut writer = File::create(to.as_ref())?;
    io::copy(&mut reader, &mut writer)
}
