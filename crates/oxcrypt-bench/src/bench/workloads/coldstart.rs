//! Cold Start Workload
//!
//! Measures performance of first-access operations that would be slow
//! on a cold cache or freshly mounted filesystem:
//! - First directory listing (root and subdirectories)
//! - First file metadata access
//! - First file read operations
//! - First tree traversal
//!
//! This simulates the user experience when opening a vault for the first time
//! or after the cache has been cleared.
//!
//! Note: This benchmark measures cold cache behavior within a running mount.
//! True mount latency measurement would require runner changes to support
//! unmount/remount between phases.

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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Base values for full-scale workload
const BASE_NUM_TOP_DIRS: usize = 10;
const BASE_FILES_PER_DIR: usize = 20;
const BASE_NESTED_DEPTH: usize = 3;
const BASE_SUBDIRS_PER_LEVEL: usize = 3;

// Minimum values
const MIN_NUM_TOP_DIRS: usize = 3;
const MIN_FILES_PER_DIR: usize = 5;
const MIN_NESTED_DEPTH: usize = 2;
const MIN_SUBDIRS_PER_LEVEL: usize = 2;

// File size (not scaled)
const FILE_SIZE: usize = 64 * 1024;  // 64KB files

/// Cold start workload phases for progress reporting.
const COLDSTART_PHASES: &[&str] = &[
    "Root readdir",
    "Nested readdir",
    "Metadata batch",
    "File reads",
    "Tree walk",
];

/// Cold Start Workload.
///
/// Measures first-access latencies that simulate opening a vault cold:
///
/// 1. Setup - Create a realistic directory structure with files
/// 2. First root readdir - List the root directory
/// 3. First nested readdir - List subdirectories
/// 4. First metadata batch - stat() on multiple files
/// 5. First file reads - Read file contents for the first time
/// 6. First tree walk - Complete traversal of the directory tree
///
/// Each phase represents operations that would hit a cold cache on a
/// freshly mounted filesystem.
pub struct ColdStartWorkload {
    config: WorkloadConfig,
    seed: u64,
    num_top_dirs: usize,
    files_per_dir: usize,
    nested_depth: usize,
    subdirs_per_level: usize,
}

impl ColdStartWorkload {
    /// Create a new cold start workload.
    pub fn new(config: WorkloadConfig) -> Self {
        let num_top_dirs = config.scale_count(BASE_NUM_TOP_DIRS, MIN_NUM_TOP_DIRS);
        let files_per_dir = config.scale_count(BASE_FILES_PER_DIR, MIN_FILES_PER_DIR);
        let nested_depth = config.scale_count(BASE_NESTED_DEPTH, MIN_NESTED_DEPTH);
        let subdirs_per_level = config.scale_count(BASE_SUBDIRS_PER_LEVEL, MIN_SUBDIRS_PER_LEVEL);

        Self {
            config,
            seed: 0xC01D_57A2,
            num_top_dirs,
            files_per_dir,
            nested_depth,
            subdirs_per_level,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_coldstart_workload_{}_iter{}", self.config.session_id, iteration))
    }

    /// Create test directory structure.
    fn create_test_structure(&self, base_dir: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        for top_idx in 0..self.num_top_dirs {
            let top_dir = base_dir.join(format!("dir_{top_idx:02}"));
            self.create_nested_dir(&mut rng, &top_dir, self.nested_depth)?;
        }

        Ok(())
    }

    /// Recursively create nested directories with files.
    fn create_nested_dir(&self, rng: &mut ChaCha8Rng, dir: &Path, depth: usize) -> Result<()> {
        fs::create_dir_all(dir)?;

        // Create files in this directory
        for file_idx in 0..self.files_per_dir {
            let filename = format!("file_{file_idx:03}.dat");
            let file_path = dir.join(&filename);
            self.write_random_file(rng, &file_path)?;
        }

        // Create nested subdirectories if depth allows
        if depth > 0 {
            for sub_idx in 0..self.subdirs_per_level {
                let subdir = dir.join(format!("subdir_{sub_idx}"));
                self.create_nested_dir(rng, &subdir, depth - 1)?;
            }
        }

        Ok(())
    }

    /// Write a file with random content.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn write_random_file(&self, rng: &mut ChaCha8Rng, path: &Path) -> Result<()> {
        let mut content = vec![0u8; FILE_SIZE];
        rng.fill_bytes(&mut content);

        let mut file = File::create(path)?;
        file.write_all(&content)?;
        safe_sync(&file)?;
        Ok(())
    }

    /// Collect all files in a directory (non-recursive).
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn list_dir(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            entries.push(entry.path());
        }
        Ok(entries)
    }

    /// Collect all files recursively.
    fn collect_all_files(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_files(dir, &mut files)?;
        Ok(files)
    }

    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_files(&self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                self.walk_files(&path, files)?;
            } else if path.is_file() {
                files.push(path);
            }
        }
        Ok(())
    }

    /// Collect all directories recursively.
    fn collect_all_dirs(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut dirs = Vec::new();
        self.walk_dirs(dir, &mut dirs)?;
        Ok(dirs)
    }

    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_dirs(&self, dir: &Path, dirs: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path.clone());
                self.walk_dirs(&path, dirs)?;
            }
        }
        Ok(())
    }
}

impl Default for ColdStartWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for ColdStartWorkload {
    fn name(&self) -> &'static str {
        "Cold Start"
    }

    fn operation(&self) -> OperationType {
        OperationType::ColdStartWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        // Calculate total structure size
        let files_per_dir = self.files_per_dir;
        let subdirs = self.subdirs_per_level;

        fn count_files(depth: usize, files_per_dir: usize, subdirs: usize) -> usize {
            if depth == 0 {
                files_per_dir
            } else {
                files_per_dir + subdirs * count_files(depth - 1, files_per_dir, subdirs)
            }
        }

        fn count_dirs(depth: usize, subdirs: usize) -> usize {
            if depth == 0 {
                1
            } else {
                1 + subdirs * count_dirs(depth - 1, subdirs)
            }
        }

        let files_per_tree = count_files(self.nested_depth, files_per_dir, subdirs);
        let dirs_per_tree = count_dirs(self.nested_depth, subdirs);
        let total_files = self.num_top_dirs * files_per_tree;
        let total_dirs = self.num_top_dirs * dirs_per_tree;
        let total_size = total_files * FILE_SIZE;

        params.insert("top_directories".to_string(), self.num_top_dirs.to_string());
        params.insert("files_per_dir".to_string(), self.files_per_dir.to_string());
        params.insert("nesting_depth".to_string(), self.nested_depth.to_string());
        params.insert("subdirs_per_level".to_string(), self.subdirs_per_level.to_string());
        params.insert("total_files".to_string(), total_files.to_string());
        params.insert("total_dirs".to_string(), total_dirs.to_string());
        params.insert(
            "total_size".to_string(),
            format!("~{}MB", total_size / (1024 * 1024)),
        );
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        fs::create_dir_all(&workload_dir)?;
        self.create_test_structure(&workload_dir)?;
        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let start = Instant::now();
        let workload_dir = self.workload_dir(mount_point, iteration);

        // ===== Phase 1: First root readdir =====
        // This would be cold on a fresh mount
        {
            let entries = self.list_dir(&workload_dir)?;
            std::hint::black_box(&entries);
            tracing::debug!("Root readdir: {} entries", entries.len());
        }

        // ===== Phase 2: First nested readdir =====
        // Read all subdirectories
        {
            let all_dirs = self.collect_all_dirs(&workload_dir)?;
            for dir in &all_dirs {
                let entries = self.list_dir(dir)?;
                std::hint::black_box(&entries);
            }
            tracing::debug!("Nested readdir: {} directories", all_dirs.len());
        }

        // ===== Phase 3: First metadata batch =====
        // Get metadata for all files
        {
            let all_files = self.collect_all_files(&workload_dir)?;
            for file in &all_files {
                let metadata = fs::metadata(file)?;
                std::hint::black_box(&metadata);
            }
            tracing::debug!("Metadata batch: {} files", all_files.len());
        }

        // ===== Phase 4: First file reads =====
        // Read a sample of files
        {
            let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
            let all_files = self.collect_all_files(&workload_dir)?;

            // Read 10% of files or at least 50
            let sample_size = (all_files.len() / 10).max(50).min(all_files.len());
            let mut indices: Vec<usize> = (0..all_files.len()).collect();
            indices.shuffle(&mut rng);

            let mut buffer = Vec::new();
            for &idx in indices.iter().take(sample_size) {
                buffer.clear();
                let mut file = File::open(&all_files[idx])?;
                file.read_to_end(&mut buffer)?;
                std::hint::black_box(&buffer);
            }
            tracing::debug!("First reads: {} files", sample_size);
        }

        // ===== Phase 5: Full tree walk =====
        // Complete traversal simulating file manager expanding all folders
        {
            let mut file_count = 0;
            let mut dir_count = 0;
            let mut total_bytes = 0u64;

            self.walk_tree(&workload_dir, &mut |path, is_dir| {
                if is_dir {
                    dir_count += 1;
                } else {
                    file_count += 1;
                    if let Ok(meta) = fs::metadata(path) {
                        total_bytes += meta.len();
                    }
                }
                Ok(())
            })?;

            tracing::debug!(
                "Tree walk: {} files, {} dirs, {} bytes",
                file_count,
                dir_count,
                total_bytes
            );
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
        0 // No warmup - we want to measure cold access
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(COLDSTART_PHASES)
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
                    phase_name: COLDSTART_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: COLDSTART_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let start = Instant::now();
        let workload_dir = self.workload_dir(mount_point, iteration);

        // ===== Phase 1: First root readdir =====
        report(0, Some(0), Some(1));
        {
            let entries = self.list_dir(&workload_dir)?;
            std::hint::black_box(&entries);
            tracing::debug!("Root readdir: {} entries", entries.len());
        }
        report(0, Some(1), Some(1));

        // ===== Phase 2: First nested readdir =====
        {
            let all_dirs = self.collect_all_dirs(&workload_dir)?;
            report(1, Some(0), Some(all_dirs.len()));
            for (i, dir) in all_dirs.iter().enumerate() {
                let entries = self.list_dir(dir)?;
                std::hint::black_box(&entries);
                if (i + 1) % 10 == 0 || i + 1 == all_dirs.len() {
                    report(1, Some(i + 1), Some(all_dirs.len()));
                }
            }
            tracing::debug!("Nested readdir: {} directories", all_dirs.len());
        }

        // ===== Phase 3: First metadata batch =====
        {
            let all_files = self.collect_all_files(&workload_dir)?;
            report(2, Some(0), Some(all_files.len()));
            for (i, file) in all_files.iter().enumerate() {
                let metadata = fs::metadata(file)?;
                std::hint::black_box(&metadata);
                if (i + 1) % 50 == 0 || i + 1 == all_files.len() {
                    report(2, Some(i + 1), Some(all_files.len()));
                }
            }
            tracing::debug!("Metadata batch: {} files", all_files.len());
        }

        // ===== Phase 4: First file reads =====
        {
            let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
            let all_files = self.collect_all_files(&workload_dir)?;

            // Read 10% of files or at least 50
            let sample_size = (all_files.len() / 10).max(50).min(all_files.len());
            let mut indices: Vec<usize> = (0..all_files.len()).collect();
            indices.shuffle(&mut rng);

            report(3, Some(0), Some(sample_size));
            let mut buffer = Vec::new();
            for (i, &idx) in indices.iter().take(sample_size).enumerate() {
                buffer.clear();
                let mut file = File::open(&all_files[idx])?;
                file.read_to_end(&mut buffer)?;
                std::hint::black_box(&buffer);
                if (i + 1) % 20 == 0 || i + 1 == sample_size {
                    report(3, Some(i + 1), Some(sample_size));
                }
            }
            tracing::debug!("First reads: {} files", sample_size);
        }

        // ===== Phase 5: Full tree walk =====
        report(4, Some(0), None);
        {
            let mut file_count = 0;
            let mut dir_count = 0;
            let mut total_bytes = 0u64;

            self.walk_tree(&workload_dir, &mut |path, is_dir| {
                if is_dir {
                    dir_count += 1;
                } else {
                    file_count += 1;
                    if let Ok(meta) = fs::metadata(path) {
                        total_bytes += meta.len();
                    }
                }
                Ok(())
            })?;

            tracing::debug!(
                "Tree walk: {} files, {} dirs, {} bytes",
                file_count,
                dir_count,
                total_bytes
            );
        }
        report(4, Some(1), Some(1));

        Ok(start.elapsed())
    }
}

impl ColdStartWorkload {
    /// Walk the tree calling callback for each entry.
    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_tree<F>(&self, dir: &Path, callback: &mut F) -> Result<()>
    where
        F: FnMut(&Path, bool) -> Result<()>,
    {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let is_dir = path.is_dir();
            callback(&path, is_dir)?;

            if is_dir {
                self.walk_tree(&path, callback)?;
            }
        }
        Ok(())
    }
}
