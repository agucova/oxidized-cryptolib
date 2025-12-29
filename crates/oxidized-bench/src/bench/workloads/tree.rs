//! Directory Tree Workload
//!
//! Simulates file explorer, find command, and rsync operations.
//! Tests directory entry caching, inode table efficiency, and path resolution performance.

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::Result;
use oxidized_mount_common::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TREE_DEPTH: usize = 5;
const DIRS_PER_LEVEL: usize = 6;
const FILES_PER_DIR: usize = 5;
const TREE_WALKS: usize = 4;
const RANDOM_ACCESSES: usize = 20;

/// Directory Tree Workload.
///
/// Creates a nested directory structure:
/// - 5 levels deep
/// - 6 directories per level
/// - 5 files per directory
/// - Total: ~15,000+ entries
///
/// Phases:
/// 1. Full tree walk - Recursive readdir + stat on everything
/// 2. Repeated walks - Walk same tree 3 more times (cache should improve)
/// 3. Targeted access - Access random files at various depths
pub struct DirectoryTreeWorkload {
    seed: u64,
}

impl DirectoryTreeWorkload {
    pub fn new() -> Self {
        Self { seed: 0x0007_EEA1 }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_tree_workload")
    }

    fn tree_root(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("root")
    }

    /// Create directory tree recursively.
    fn create_tree(&self, rng: &mut ChaCha8Rng, path: &Path, depth: usize) -> Result<()> {
        if depth >= TREE_DEPTH {
            return Ok(());
        }

        fs::create_dir_all(path)?;

        // Create files in this directory
        for file_num in 0..FILES_PER_DIR {
            let file_path = path.join(format!("file_{:03}.dat", file_num));
            let size = 256 + rng.random_range(0..1024); // 256B-1.25KB files
            let mut content = vec![0u8; size];
            rng.fill_bytes(&mut content);

            let mut file = File::create(&file_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Create subdirectories
        for dir_num in 0..DIRS_PER_LEVEL {
            let subdir = path.join(format!("dir_{:02}", dir_num));
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
        Self::new()
    }
}

#[derive(Default)]
struct TreeStats {
    files: usize,
    directories: usize,
    total_size: u64,
}

impl Benchmark for DirectoryTreeWorkload {
    fn name(&self) -> &str {
        "Directory Tree"
    }

    fn operation(&self) -> OperationType {
        OperationType::DirectoryTreeWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("depth".to_string(), TREE_DEPTH.to_string());
        params.insert("dirs_per_level".to_string(), DIRS_PER_LEVEL.to_string());
        params.insert("files_per_dir".to_string(), FILES_PER_DIR.to_string());
        params.insert("tree_walks".to_string(), TREE_WALKS.to_string());
        params.insert("random_accesses".to_string(), RANDOM_ACCESSES.to_string());

        // Calculate expected totals
        // Total dirs at each level: 6^0 + 6^1 + 6^2 + 6^3 + 6^4 = 1 + 6 + 36 + 216 + 1296 = 1555
        // Total files: 1555 * 5 = 7775
        let mut total_dirs = 0;
        for d in 0..TREE_DEPTH {
            total_dirs += DIRS_PER_LEVEL.pow(d as u32);
        }
        let total_files = total_dirs * FILES_PER_DIR;
        params.insert("expected_dirs".to_string(), total_dirs.to_string());
        params.insert("expected_files".to_string(), total_files.to_string());

        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create the directory tree
        let root = self.tree_root(mount_point);
        self.create_tree(&mut rng, &root, 0)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let root = self.tree_root(mount_point);

        // ===== Phase 1: First full tree walk =====
        let stats = self.walk_tree(&root)?;
        std::hint::black_box(stats.files);
        std::hint::black_box(stats.directories);
        std::hint::black_box(stats.total_size);

        // ===== Phase 2: Repeated walks (should benefit from cache) =====
        for _ in 1..TREE_WALKS {
            let stats = self.walk_tree(&root)?;
            std::hint::black_box(stats.files);
        }

        // ===== Phase 3: Targeted random access =====
        // Collect all file paths
        let all_files = self.collect_all_files(&root)?;

        if !all_files.is_empty() {
            // Access random files at various depths
            for _ in 0..RANDOM_ACCESSES {
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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }
}
