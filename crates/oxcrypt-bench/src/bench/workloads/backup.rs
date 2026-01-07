//! Backup/Sync Workload
//!
//! Simulates backup and synchronization applications:
//! - Initial backup (write a file set with directory structure)
//! - Incremental changes (modify 5% of files)
//! - Delta detection (read metadata + compute checksums)
//! - Incremental backup (copy only changed files)
//! - Restore (read all backed up files)
//!
//! Uses synthetic data with realistic patterns. Tests metadata operations,
//! checksum computation, and selective file copying.

// Allow recursive helpers
#![allow(clippy::self_only_used_in_recursion)]

use crate::bench::workloads::{copy_file_contents, WorkloadConfig};
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::config::OperationType;
use anyhow::Result;
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

// Base values for full-scale workload
const BASE_NUM_DIRECTORIES: usize = 20;
const BASE_FILES_PER_DIRECTORY: usize = 50;
const BASE_NESTED_FILES: usize = 5;

// Minimum values
const MIN_NUM_DIRECTORIES: usize = 5;
const MIN_FILES_PER_DIRECTORY: usize = 10;
const MIN_NESTED_FILES: usize = 2;

// File size bounds (not scaled)
const MIN_FILE_SIZE: usize = 4 * 1024;      // 4KB
const MAX_FILE_SIZE: usize = 512 * 1024;    // 512KB
const CHANGE_PERCENTAGE: f64 = 0.05;        // 5% of files modified

/// Backup workload phases for progress reporting.
const BACKUP_PHASES: &[&str] = &[
    "Create source",
    "Initial backup",
    "Apply changes",
    "Delta detection",
    "Incremental backup",
    "Restore",
];

/// Backup/Sync Workload.
///
/// Phases:
/// 1. Initial backup - Create source file set
/// 2. First backup - Copy all files to backup destination
/// 3. Incremental changes - Modify 5% of source files
/// 4. Delta detection - Scan and checksum to find changes
/// 5. Incremental backup - Copy only changed files
/// 6. Restore - Read all backed up files
///
/// Tests metadata operations, hash computation, and selective copying.
pub struct BackupSyncWorkload {
    config: WorkloadConfig,
    seed: u64,
    num_directories: usize,
    files_per_directory: usize,
    nested_files: usize,
}

impl BackupSyncWorkload {
    /// Create a new backup/sync workload.
    pub fn new(config: WorkloadConfig) -> Self {
        let num_directories = config.scale_count(BASE_NUM_DIRECTORIES, MIN_NUM_DIRECTORIES);
        let files_per_directory = config.scale_count(BASE_FILES_PER_DIRECTORY, MIN_FILES_PER_DIRECTORY);
        let nested_files = config.scale_count(BASE_NESTED_FILES, MIN_NESTED_FILES);

        Self {
            config,
            seed: 0xBAC_0DAD,
            num_directories,
            files_per_directory,
            nested_files,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_backup_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn source_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("source")
    }

    fn backup_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("backup")
    }

    fn restore_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("restore")
    }

    /// Generate source file set.
    fn create_source_files(&self, source_dir: &Path) -> Result<Vec<PathBuf>> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut files = Vec::new();

        for dir_num in 0..self.num_directories {
            let dir_name = format!("dir_{dir_num:03}");
            let dir_path = source_dir.join(&dir_name);
            fs::create_dir_all(&dir_path)?;

            // Create nested subdirectory for some dirs
            if dir_num % 4 == 0 {
                let nested = dir_path.join("nested");
                fs::create_dir_all(&nested)?;

                for i in 0..self.nested_files {
                    let filename = format!("nested_{i:03}.dat");
                    let path = nested.join(&filename);
                    let size = rng.random_range(MIN_FILE_SIZE..MAX_FILE_SIZE);
                    self.write_random_file(&mut rng, &path, size)?;
                    files.push(path);
                }
            }

            for file_num in 0..self.files_per_directory {
                let filename = format!("file_{file_num:03}.dat");
                let path = dir_path.join(&filename);
                let size = rng.random_range(MIN_FILE_SIZE..MAX_FILE_SIZE);
                self.write_random_file(&mut rng, &path, size)?;
                files.push(path);
            }
        }

        Ok(files)
    }

    /// Write a file with random content.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn write_random_file(&self, rng: &mut ChaCha8Rng, path: &Path, size: usize) -> Result<()> {
        let mut content = vec![0u8; size];
        rng.fill_bytes(&mut content);

        let mut file = File::create(path)?;
        file.write_all(&content)?;
        safe_sync(&file)?;
        Ok(())
    }

    /// Collect all files in a directory tree.
    fn collect_files(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_files(dir, &mut files)?;
        files.sort();
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

    /// Copy a file to the backup directory, preserving relative path.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn copy_to_backup(&self, source_file: &Path, source_root: &Path, backup_root: &Path) -> Result<()> {
        let rel_path = source_file.strip_prefix(source_root)
            .map_err(|e| anyhow::anyhow!("Path strip error: {e}"))?;
        let dest_path = backup_root.join(rel_path);

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        copy_file_contents(source_file, &dest_path)?;
        Ok(())
    }

    /// Get file metadata for delta detection.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn get_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path)?;
        let mtime = metadata.modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        Ok(FileInfo {
            size: metadata.len(),
            mtime,
        })
    }

    /// Compute SHA256 hash of a file.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn compute_hash(&self, path: &Path) -> Result<[u8; 32]> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        #[allow(clippy::large_stack_arrays)]  // 64KB buffer is reasonable for I/O performance
        let mut buffer = [0u8; 64 * 1024];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Modify a portion of files to simulate changes.
    fn apply_changes(&self, files: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]  // Percentage calculation, bounded by files.len()
        let num_changes = usize::try_from(((files.len() as f64) * CHANGE_PERCENTAGE) as i64).unwrap_or(0);
        let num_changes = num_changes.max(1); // At least one change

        let mut indices: Vec<usize> = (0..files.len()).collect();
        indices.shuffle(&mut rng);

        let mut changed = Vec::new();
        for &idx in indices.iter().take(num_changes) {
            let path = &files[idx];
            let size = rng.random_range(MIN_FILE_SIZE..MAX_FILE_SIZE);
            self.write_random_file(&mut rng, path, size)?;
            changed.push(path.clone());
        }

        Ok(changed)
    }

    /// Detect changes by comparing metadata and hashes.
    fn detect_changes(
        &self,
        source_files: &[PathBuf],
        source_root: &Path,
        backup_root: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut changed = Vec::new();

        for source_file in source_files {
            let rel_path = source_file.strip_prefix(source_root)
                .map_err(|e| anyhow::anyhow!("Path strip error: {e}"))?;
            let backup_file = backup_root.join(rel_path);

            // Check if backup exists
            if !backup_file.exists() {
                changed.push(source_file.clone());
                continue;
            }

            // Quick check: size and mtime
            let source_info = self.get_file_info(source_file)?;
            let backup_info = self.get_file_info(&backup_file)?;

            if source_info.size != backup_info.size {
                changed.push(source_file.clone());
                continue;
            }

            // Expensive check: hash comparison
            let source_hash = self.compute_hash(source_file)?;
            let backup_hash = self.compute_hash(&backup_file)?;

            if source_hash != backup_hash {
                changed.push(source_file.clone());
            }
        }

        Ok(changed)
    }
}

impl Default for BackupSyncWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

/// File metadata for delta detection.
struct FileInfo {
    size: u64,
    #[allow(dead_code)]
    mtime: SystemTime,
}

impl Benchmark for BackupSyncWorkload {
    fn name(&self) -> &'static str {
        "Backup/Sync"
    }

    fn operation(&self) -> OperationType {
        OperationType::BackupSyncWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        let total_files = self.num_directories * self.files_per_directory
            + (self.num_directories / 4) * self.nested_files; // Nested files
        let avg_size = usize::midpoint(MIN_FILE_SIZE, MAX_FILE_SIZE);
        let total_size = total_files * avg_size;

        params.insert("directories".to_string(), self.num_directories.to_string());
        params.insert("files_per_dir".to_string(), self.files_per_directory.to_string());
        params.insert("nested_files".to_string(), self.nested_files.to_string());
        params.insert("total_files".to_string(), total_files.to_string());
        params.insert(
            "total_size".to_string(),
            format!("~{}MB", total_size / (1024 * 1024)),
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]  // Percentage constant, always positive and small
        let change_pct = (CHANGE_PERCENTAGE * 100.0) as u32;
        params.insert(
            "change_rate".to_string(),
            format!("{change_pct}%"),
        );
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        // Create directories
        fs::create_dir_all(self.source_dir(mount_point, iteration))?;
        fs::create_dir_all(self.backup_dir(mount_point, iteration))?;
        fs::create_dir_all(self.restore_dir(mount_point, iteration))?;
        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let start = Instant::now();

        let source_dir = self.source_dir(mount_point, iteration);
        let backup_dir = self.backup_dir(mount_point, iteration);
        let restore_dir = self.restore_dir(mount_point, iteration);

        // ===== Phase 1: Create source files =====
        let source_files = self.create_source_files(&source_dir)?;
        tracing::debug!("Created {} source files", source_files.len());

        // ===== Phase 2: Initial full backup =====
        for source_file in &source_files {
            self.copy_to_backup(source_file, &source_dir, &backup_dir)?;
        }
        tracing::debug!("Completed initial backup");

        // ===== Phase 3: Apply incremental changes =====
        let changed_files = self.apply_changes(&source_files)?;
        tracing::debug!("Modified {} files", changed_files.len());

        // ===== Phase 4: Delta detection =====
        let detected_changes = self.detect_changes(&source_files, &source_dir, &backup_dir)?;
        tracing::debug!("Detected {} changed files", detected_changes.len());

        // Verify detection accuracy
        if detected_changes.len() != changed_files.len() {
            tracing::warn!(
                "Change detection mismatch: expected {}, found {}",
                changed_files.len(),
                detected_changes.len()
            );
        }

        // ===== Phase 5: Incremental backup =====
        for changed_file in &detected_changes {
            self.copy_to_backup(changed_file, &source_dir, &backup_dir)?;
        }
        tracing::debug!("Completed incremental backup");

        // ===== Phase 6: Restore (read all backed up files) =====
        let backup_files = self.collect_files(&backup_dir)?;
        let mut buffer = Vec::new();

        for backup_file in &backup_files {
            buffer.clear();
            let mut file = File::open(backup_file)?;
            file.read_to_end(&mut buffer)?;

            // Simulate restore by copying to restore dir
            self.copy_to_backup(backup_file, &backup_dir, &restore_dir)?;
        }
        tracing::debug!("Restored {} files", backup_files.len());

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
        0 // No warmup - backup/sync is stateful
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(BACKUP_PHASES)
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
                    phase_name: BACKUP_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: BACKUP_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let start = Instant::now();

        let source_dir = self.source_dir(mount_point, iteration);
        let backup_dir = self.backup_dir(mount_point, iteration);
        let restore_dir = self.restore_dir(mount_point, iteration);

        // ===== Phase 1: Create source files =====
        report(0, None, None);
        let source_files = self.create_source_files(&source_dir)?;
        tracing::debug!("Created {} source files", source_files.len());
        report(0, Some(source_files.len()), Some(source_files.len()));

        // ===== Phase 2: Initial full backup =====
        report(1, Some(0), Some(source_files.len()));
        for (i, source_file) in source_files.iter().enumerate() {
            self.copy_to_backup(source_file, &source_dir, &backup_dir)?;
            if i % 50 == 0 || i == source_files.len() - 1 {
                report(1, Some(i + 1), Some(source_files.len()));
            }
        }
        tracing::debug!("Completed initial backup");

        // ===== Phase 3: Apply incremental changes =====
        report(2, None, None);
        let changed_files = self.apply_changes(&source_files)?;
        tracing::debug!("Modified {} files", changed_files.len());
        report(2, Some(changed_files.len()), Some(changed_files.len()));

        // ===== Phase 4: Delta detection =====
        report(3, Some(0), Some(source_files.len()));
        let detected_changes = self.detect_changes(&source_files, &source_dir, &backup_dir)?;
        tracing::debug!("Detected {} changed files", detected_changes.len());
        report(3, Some(source_files.len()), Some(source_files.len()));

        // Verify detection accuracy
        if detected_changes.len() != changed_files.len() {
            tracing::warn!(
                "Change detection mismatch: expected {}, found {}",
                changed_files.len(),
                detected_changes.len()
            );
        }

        // ===== Phase 5: Incremental backup =====
        report(4, Some(0), Some(detected_changes.len()));
        for (i, changed_file) in detected_changes.iter().enumerate() {
            self.copy_to_backup(changed_file, &source_dir, &backup_dir)?;
            report(4, Some(i + 1), Some(detected_changes.len()));
        }
        tracing::debug!("Completed incremental backup");

        // ===== Phase 6: Restore (read all backed up files) =====
        let backup_files = self.collect_files(&backup_dir)?;
        report(5, Some(0), Some(backup_files.len()));
        let mut buffer = Vec::new();

        for (i, backup_file) in backup_files.iter().enumerate() {
            buffer.clear();
            let mut file = File::open(backup_file)?;
            file.read_to_end(&mut buffer)?;

            // Simulate restore by copying to restore dir
            self.copy_to_backup(backup_file, &backup_dir, &restore_dir)?;
            if i % 50 == 0 || i == backup_files.len() - 1 {
                report(5, Some(i + 1), Some(backup_files.len()));
            }
        }
        tracing::debug!("Restored {} files", backup_files.len());

        Ok(start.elapsed())
    }
}
