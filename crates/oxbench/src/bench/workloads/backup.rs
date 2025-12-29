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

use crate::bench::Benchmark;
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

// Workload parameters
const NUM_DIRECTORIES: usize = 20;
const FILES_PER_DIRECTORY: usize = 50;
const MIN_FILE_SIZE: usize = 4 * 1024;      // 4KB
const MAX_FILE_SIZE: usize = 512 * 1024;    // 512KB
const CHANGE_PERCENTAGE: f64 = 0.05;        // 5% of files modified

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
    seed: u64,
}

impl BackupSyncWorkload {
    /// Create a new backup/sync workload.
    pub fn new() -> Self {
        Self {
            seed: 0xBAC_0DAD,
        }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_backup_workload")
    }

    fn source_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("source")
    }

    fn backup_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("backup")
    }

    fn restore_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("restore")
    }

    /// Generate source file set.
    fn create_source_files(&self, source_dir: &Path) -> Result<Vec<PathBuf>> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut files = Vec::new();

        for dir_num in 0..NUM_DIRECTORIES {
            let dir_name = format!("dir_{:03}", dir_num);
            let dir_path = source_dir.join(&dir_name);
            fs::create_dir_all(&dir_path)?;

            // Create nested subdirectory for some dirs
            if dir_num % 4 == 0 {
                let nested = dir_path.join("nested");
                fs::create_dir_all(&nested)?;

                for i in 0..5 {
                    let filename = format!("nested_{:03}.dat", i);
                    let path = nested.join(&filename);
                    let size = rng.random_range(MIN_FILE_SIZE..MAX_FILE_SIZE);
                    self.write_random_file(&mut rng, &path, size)?;
                    files.push(path);
                }
            }

            for file_num in 0..FILES_PER_DIRECTORY {
                let filename = format!("file_{:03}.dat", file_num);
                let path = dir_path.join(&filename);
                let size = rng.random_range(MIN_FILE_SIZE..MAX_FILE_SIZE);
                self.write_random_file(&mut rng, &path, size)?;
                files.push(path);
            }
        }

        Ok(files)
    }

    /// Write a file with random content.
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
    fn copy_to_backup(&self, source_file: &Path, source_root: &Path, backup_root: &Path) -> Result<()> {
        let rel_path = source_file.strip_prefix(source_root)
            .map_err(|e| anyhow::anyhow!("Path strip error: {}", e))?;
        let dest_path = backup_root.join(rel_path);

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(source_file, &dest_path)?;
        Ok(())
    }

    /// Get file metadata for delta detection.
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
    fn compute_hash(&self, path: &Path) -> Result<[u8; 32]> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
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
        let num_changes = ((files.len() as f64) * CHANGE_PERCENTAGE) as usize;
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
                .map_err(|e| anyhow::anyhow!("Path strip error: {}", e))?;
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
        Self::new()
    }
}

/// File metadata for delta detection.
struct FileInfo {
    size: u64,
    #[allow(dead_code)]
    mtime: SystemTime,
}

impl Benchmark for BackupSyncWorkload {
    fn name(&self) -> &str {
        "Backup/Sync"
    }

    fn operation(&self) -> OperationType {
        OperationType::BackupSyncWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        let total_files = NUM_DIRECTORIES * FILES_PER_DIRECTORY
            + (NUM_DIRECTORIES / 4) * 5; // Nested files
        let avg_size = (MIN_FILE_SIZE + MAX_FILE_SIZE) / 2;
        let total_size = total_files * avg_size;

        params.insert("directories".to_string(), NUM_DIRECTORIES.to_string());
        params.insert("total_files".to_string(), total_files.to_string());
        params.insert(
            "total_size".to_string(),
            format!("~{}MB", total_size / (1024 * 1024)),
        );
        params.insert(
            "change_rate".to_string(),
            format!("{}%", (CHANGE_PERCENTAGE * 100.0) as u32),
        );
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Create directories
        fs::create_dir_all(self.source_dir(mount_point))?;
        fs::create_dir_all(self.backup_dir(mount_point))?;
        fs::create_dir_all(self.restore_dir(mount_point))?;
        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let start = Instant::now();

        let source_dir = self.source_dir(mount_point);
        let backup_dir = self.backup_dir(mount_point);
        let restore_dir = self.restore_dir(mount_point);

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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup - backup/sync is stateful
    }
}
