//! Directory Tree Workload
//!
//! Simulates file explorer, find command, and rsync operations.
//! Tests directory entry caching, inode table efficiency, and path resolution performance.

// Allow recursive helpers
#![allow(clippy::self_only_used_in_recursion)]

use crate::bench::workloads::WorkloadConfig;
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::config::OperationType;
use anyhow::Result;
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Base values for full-scale workload
const BASE_TREE_DEPTH: usize = 5;
const BASE_DIRS_PER_LEVEL: usize = 6;
const BASE_FILES_PER_DIR: usize = 5;
const BASE_TREE_WALKS: usize = 4;
const BASE_RANDOM_ACCESSES: usize = 20;

// Minimum values
const MIN_TREE_DEPTH: usize = 3;
const MIN_DIRS_PER_LEVEL: usize = 3;
const MIN_FILES_PER_DIR: usize = 2;
const MIN_TREE_WALKS: usize = 2;
const MIN_RANDOM_ACCESSES: usize = 5;

/// Directory tree workload phases for progress reporting.
const TREE_PHASES: &[&str] = &[
    "First tree walk",
    "Repeated walks",
    "Random access",
];

/// Directory Tree Workload.
///
/// Creates a nested directory structure:
/// - 5 levels deep (full scale)
/// - 6 directories per level (full scale)
/// - 5 files per directory (full scale)
/// - Total: ~15,000+ entries (full scale)
///
/// Phases:
/// 1. Full tree walk - Recursive readdir + stat on everything
/// 2. Repeated walks - Walk same tree 3 more times (cache should improve)
/// 3. Targeted access - Access random files at various depths
pub struct DirectoryTreeWorkload {
    config: WorkloadConfig,
    seed: u64,
    tree_depth: usize,
    dirs_per_level: usize,
    files_per_dir: usize,
    tree_walks: usize,
    random_accesses: usize,
}

impl DirectoryTreeWorkload {
    pub fn new(config: WorkloadConfig) -> Self {
        let tree_depth = config.scale_count(BASE_TREE_DEPTH, MIN_TREE_DEPTH);
        let dirs_per_level = config.scale_count(BASE_DIRS_PER_LEVEL, MIN_DIRS_PER_LEVEL);
        let files_per_dir = config.scale_count(BASE_FILES_PER_DIR, MIN_FILES_PER_DIR);
        let tree_walks = config.scale_count(BASE_TREE_WALKS, MIN_TREE_WALKS);
        let random_accesses = config.scale_count(BASE_RANDOM_ACCESSES, MIN_RANDOM_ACCESSES);

        Self {
            config,
            seed: 0x0007_EEA1,
            tree_depth,
            dirs_per_level,
            files_per_dir,
            tree_walks,
            random_accesses,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_tree_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn tree_root(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("root")
    }

    /// Create directory tree recursively.
    fn create_tree(&self, rng: &mut ChaCha8Rng, path: &Path, depth: usize) -> Result<()> {
        if depth >= self.tree_depth {
            return Ok(());
        }

        fs::create_dir_all(path)?;

        // Create files in this directory
        for file_num in 0..self.files_per_dir {
            let file_path = path.join(format!("file_{file_num:03}.dat"));
            let size = 256 + rng.random_range(0..1024); // 256B-1.25KB files
            let mut content = vec![0u8; size];
            rng.fill_bytes(&mut content);

            let mut file = File::create(&file_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Create subdirectories
        for dir_num in 0..self.dirs_per_level {
            let subdir = path.join(format!("dir_{dir_num:02}"));
            self.create_tree(rng, &subdir, depth + 1)?;
        }

        Ok(())
    }

    /// Walk the entire tree, collecting stats on all entries.
    fn walk_tree(&self, path: &Path) -> Result<TreeStats> {
        let mut stats = TreeStats::default();
        self.walk_tree_recursive(path, &mut stats)?;
        Ok(stats)
    }

    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_tree_recursive(&self, path: &Path, stats: &mut TreeStats) -> Result<()> {
        if path.is_dir() {
            stats.directories += 1;

            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();

                // Stat each entry
                let metadata = fs::metadata(&entry_path)?;
                std::hint::black_box(metadata.len());
                std::hint::black_box(metadata.modified()?);

                if entry_path.is_dir() {
                    self.walk_tree_recursive(&entry_path, stats)?;
                } else {
                    stats.files += 1;
                    stats.total_size += metadata.len();
                }
            }
        }

        Ok(())
    }

    /// Collect all file paths in the tree for random access.
    fn collect_all_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.collect_files_recursive(path, &mut files)?;
        Ok(files)
    }

    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn collect_files_recursive(&self, path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();

                if entry_path.is_dir() {
                    self.collect_files_recursive(&entry_path, files)?;
                } else {
                    files.push(entry_path);
                }
            }
        }
        Ok(())
    }
}

impl Default for DirectoryTreeWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

#[derive(Default)]
struct TreeStats {
    files: usize,
    directories: usize,
    total_size: u64,
}

impl Benchmark for DirectoryTreeWorkload {
    fn name(&self) -> &'static str {
        "Folder Browse"
    }

    fn operation(&self) -> OperationType {
        OperationType::DirectoryTreeWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("depth".to_string(), self.tree_depth.to_string());
        params.insert("dirs_per_level".to_string(), self.dirs_per_level.to_string());
        params.insert("files_per_dir".to_string(), self.files_per_dir.to_string());
        params.insert("tree_walks".to_string(), self.tree_walks.to_string());
        params.insert("random_accesses".to_string(), self.random_accesses.to_string());

        // Calculate expected totals based on scaled values
        let mut total_dirs = 0;
        for d in 0..self.tree_depth {
            #[allow(clippy::cast_possible_truncation)]  // tree_depth is small, bounded by MAX_DEPTH
            let d_u32 = d as u32;
            total_dirs += self.dirs_per_level.pow(d_u32);
        }
        let total_files = total_dirs * self.files_per_dir;
        params.insert("expected_dirs".to_string(), total_dirs.to_string());
        params.insert("expected_files".to_string(), total_files.to_string());
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));

        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create the directory tree
        let root = self.tree_root(mount_point, iteration);
        self.create_tree(&mut rng, &root, 0)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let root = self.tree_root(mount_point, iteration);

        // ===== Phase 1: First full tree walk =====
        let stats = self.walk_tree(&root)?;
        std::hint::black_box(stats.files);
        std::hint::black_box(stats.directories);
        std::hint::black_box(stats.total_size);

        // ===== Phase 2: Repeated walks (should benefit from cache) =====
        for _ in 1..self.tree_walks {
            let stats = self.walk_tree(&root)?;
            std::hint::black_box(stats.files);
        }

        // ===== Phase 3: Targeted random access =====
        // Collect all file paths
        let all_files = self.collect_all_files(&root)?;

        if !all_files.is_empty() {
            // Access random files at various depths
            for _ in 0..self.random_accesses {
                let idx = rng.random_range(0..all_files.len());
                let path = &all_files[idx];

                // Read the file content
                let content = fs::read(path)?;
                std::hint::black_box(&content);

                // Also stat the parent directories (tests path resolution cache)
                let mut current = path.parent();
                while let Some(parent) = current {
                    if parent == root || !parent.starts_with(&root) {
                        break;
                    }
                    let metadata = fs::metadata(parent)?;
                    std::hint::black_box(metadata.len());
                    current = parent.parent();
                }
            }
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(TREE_PHASES)
    }

    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        let report = |phase_idx: usize, items_done: Option<usize>, items_total: Option<usize>| {
            if let Some(cb) = progress {
                cb(PhaseProgress {
                    phase_name: TREE_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: TREE_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let root = self.tree_root(mount_point, iteration);

        // ===== Phase 1: First full tree walk =====
        report(0, Some(0), Some(1));
        let stats = self.walk_tree(&root)?;
        std::hint::black_box(stats.files);
        std::hint::black_box(stats.directories);
        std::hint::black_box(stats.total_size);
        report(0, Some(1), Some(1));

        // ===== Phase 2: Repeated walks (should benefit from cache) =====
        let repeated_walks = self.tree_walks.saturating_sub(1);
        report(1, Some(0), Some(repeated_walks));
        for i in 0..repeated_walks {
            let stats = self.walk_tree(&root)?;
            std::hint::black_box(stats.files);
            report(1, Some(i + 1), Some(repeated_walks));
        }

        // ===== Phase 3: Targeted random access =====
        // Collect all file paths
        let all_files = self.collect_all_files(&root)?;
        report(2, Some(0), Some(self.random_accesses));

        if !all_files.is_empty() {
            // Access random files at various depths
            for i in 0..self.random_accesses {
                let idx = rng.random_range(0..all_files.len());
                let path = &all_files[idx];

                // Read the file content
                let content = fs::read(path)?;
                std::hint::black_box(&content);

                // Also stat the parent directories (tests path resolution cache)
                let mut current = path.parent();
                while let Some(parent) = current {
                    if parent == root || !parent.starts_with(&root) {
                        break;
                    }
                    let metadata = fs::metadata(parent)?;
                    std::hint::black_box(metadata.len());
                    current = parent.parent();
                }

                if (i + 1) % 5 == 0 || i + 1 == self.random_accesses {
                    report(2, Some(i + 1), Some(self.random_accesses));
                }
            }
        }

        Ok(start.elapsed())
    }
}
