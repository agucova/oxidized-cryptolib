//! Archive Extraction Workload
//!
//! Simulates extracting and working with compressed archives:
//! - Extract all files from archive to vault (many file creates)
//! - Verify extraction by traversing and counting files
//! - Random access to extracted files
//! - Re-archive files (create new archive from extracted content)
//! - Cleanup (delete all extracted files)
//!
//! Supports real archives (Node.js source, Boost headers) or synthetic
//! fallback with generated directory structure.
//!
//! Tests bulk file creation, directory traversal, and delete operations.

// Allow recursive helpers
#![allow(clippy::self_only_used_in_recursion)]

use crate::assets::{AssetDownloader, manifest};
use crate::bench::workloads::WorkloadConfig;
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::config::OperationType;
use anyhow::{Context, Result};
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Base values for full-scale workload
const BASE_NUM_DIRS: usize = 50;
const BASE_FILES_PER_DIR: usize = 20;
const BASE_NESTED_FILES_PER_SUBDIR: usize = 5;
const BASE_RANDOM_ACCESS_COUNT: usize = 100;

// Minimum values
const MIN_NUM_DIRS: usize = 10;
const MIN_FILES_PER_DIR: usize = 5;
const MIN_NESTED_FILES_PER_SUBDIR: usize = 2;
const MIN_RANDOM_ACCESS_COUNT: usize = 20;

// Fixed technical parameters (not scaled)
const SYNTHETIC_FILE_SIZE_MIN: usize = 1024;       // 1KB
const SYNTHETIC_FILE_SIZE_MAX: usize = 64 * 1024;  // 64KB

/// Archive workload phases for progress reporting.
const ARCHIVE_PHASES: &[&str] = &[
    "Extract/Create",
    "Verify",
    "Random access",
    "Re-archive",
    "Cleanup",
];

/// Archive Extraction Workload.
///
/// Phases:
/// 1. Extract - Unpack archive to vault (many file creates)
/// 2. Verify - Traverse and count files
/// 3. Random access - Read random extracted files
/// 4. Re-archive - Create new tar.gz from extracted files
/// 5. Cleanup - Delete all extracted files
///
/// When `use_real_assets` is enabled, downloads and uses real source
/// archives (Node.js, Boost) for authentic file structure and content.
pub struct ArchiveExtractionWorkload {
    config: WorkloadConfig,
    seed: u64,
    use_real_assets: bool,
    num_dirs: usize,
    files_per_dir: usize,
    nested_files_per_subdir: usize,
    random_access_count: usize,
}

impl ArchiveExtractionWorkload {
    /// Create a new archive extraction workload.
    pub fn new(config: WorkloadConfig) -> Self {
        let use_real_assets = config.real_assets;
        let num_dirs = config.scale_count(BASE_NUM_DIRS, MIN_NUM_DIRS);
        let files_per_dir = config.scale_count(BASE_FILES_PER_DIR, MIN_FILES_PER_DIR);
        let nested_files_per_subdir = config.scale_count(BASE_NESTED_FILES_PER_SUBDIR, MIN_NESTED_FILES_PER_SUBDIR);
        let random_access_count = config.scale_count(BASE_RANDOM_ACCESS_COUNT, MIN_RANDOM_ACCESS_COUNT);

        Self {
            config,
            seed: 0xA2C_41FE,
            use_real_assets,
            num_dirs,
            files_per_dir,
            nested_files_per_subdir,
            random_access_count,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_archive_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn extracted_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("extracted")
    }

    fn output_archive(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("repacked.tar.gz")
    }

    /// Download real archive asset and return the path.
    #[allow(clippy::unused_self)]  // May access self fields in future
    fn download_real_asset(&self) -> Result<PathBuf> {
        let downloader = AssetDownloader::new()?;

        // Use ripgrep source (~500 files) - practical for FUSE benchmarking
        // Node.js has ~75,000 files which makes deletion extremely slow through FUSE
        match downloader.ensure(&manifest::GIT_RIPGREP) {
            Ok(path) => return Ok(path),
            Err(e) => {
                tracing::warn!("Failed to download ripgrep archive: {}", e);
            }
        }

        // Fall back to Node.js (much larger, slower)
        match downloader.ensure(&manifest::ARCHIVE_NODEJS) {
            Ok(path) => Ok(path),
            Err(e) => {
                tracing::warn!("Failed to download Node.js archive: {}", e);
                Err(e)
            }
        }
    }

    /// Extract a tar.gz archive to the destination directory.
    fn extract_archive(&self, archive_path: &Path, dest_dir: &Path) -> Result<usize> {
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz);

        // Disable mtime preservation - FUSE mounts can fail when setting mtime
        // after write due to attribute cache timing or AppleDouble file interference
        archive.set_preserve_mtime(false);

        // Unpack to destination
        if let Err(e) = archive.unpack(dest_dir) {
            tracing::error!("tar unpack failed: {:?}", e);
            return Err(e).with_context(|| format!("Failed to extract to {}", dest_dir.display()));
        }

        // Count extracted files
        let count = self.count_files(dest_dir)?;
        Ok(count)
    }

    /// Generate synthetic archive content directly to destination.
    fn generate_synthetic_content(&self, dest_dir: &Path) -> Result<usize> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut file_count = 0;

        for dir_num in 0..self.num_dirs {
            let dir_name = format!("dir_{dir_num:03}");
            let dir_path = dest_dir.join(&dir_name);
            fs::create_dir_all(&dir_path)?;

            // Create some subdirectories
            if dir_num % 5 == 0 {
                let subdir = dir_path.join("subdir");
                fs::create_dir_all(&subdir)?;

                for file_num in 0..self.nested_files_per_subdir {
                    let size = rng.random_range(SYNTHETIC_FILE_SIZE_MIN..SYNTHETIC_FILE_SIZE_MAX);
                    let filename = format!("nested_{file_num:03}.txt");
                    let file_path = subdir.join(&filename);
                    self.write_random_file(&mut rng, &file_path, size)?;
                    file_count += 1;
                }
            }

            for file_num in 0..self.files_per_dir {
                let size = rng.random_range(SYNTHETIC_FILE_SIZE_MIN..SYNTHETIC_FILE_SIZE_MAX);
                let ext = match file_num % 4 {
                    0 => "txt",
                    1 => "c",
                    2 => "h",
                    _ => "js",
                };
                let filename = format!("file_{file_num:03}.{ext}");
                let file_path = dir_path.join(&filename);
                self.write_random_file(&mut rng, &file_path, size)?;
                file_count += 1;
            }
        }

        Ok(file_count)
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

    /// Count all files in a directory tree.
    fn count_files(&self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        self.walk_files(dir, &mut |_| {
            count += 1;
            Ok(())
        })?;
        Ok(count)
    }

    /// Collect all file paths in a directory tree.
    fn collect_files(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_files(dir, &mut |path| {
            files.push(path.to_path_buf());
            Ok(())
        })?;
        Ok(files)
    }

    /// Walk all files in a directory tree.
    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_files<F>(&self, dir: &Path, callback: &mut F) -> Result<()>
    where
        F: FnMut(&Path) -> Result<()>,
    {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                self.walk_files(&path, callback)?;
            } else if path.is_file() {
                callback(&path)?;
            }
        }
        Ok(())
    }

    /// Create a tar.gz archive from a directory.
    ///
    /// This manually walks the directory and appends files one-by-one
    /// with detailed timing to identify bottlenecks.
    fn create_archive(&self, source_dir: &Path, output_path: &Path) -> Result<u64> {
        let start = Instant::now();

        let file = File::create(output_path)?;
        tracing::debug!("create_archive: file created in {:?}", start.elapsed());

        let gz_start = Instant::now();
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(gz);
        tracing::debug!("create_archive: encoder setup in {:?}", gz_start.elapsed());

        // Manually append files with timing
        let append_start = Instant::now();
        let mut file_count = 0;
        let mut total_read_time = Duration::ZERO;
        let mut total_append_time = Duration::ZERO;

        self.walk_files(source_dir, &mut |path| {
            file_count += 1;

            // Time reading the file
            let read_start = Instant::now();
            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            total_read_time += read_start.elapsed();

            // Time appending to tar
            let append_time_start = Instant::now();
            let relative_path = path.strip_prefix(source_dir)
                .unwrap_or(path);
            builder.append_data(
                &mut tar::Header::new_gnu(),
                relative_path,
                &buffer[..]
            )?;
            total_append_time += append_time_start.elapsed();

            Ok(())
        })?;

        tracing::debug!(
            "create_archive: processed {} files - read time {:?}, tar append time {:?}, total {:?}",
            file_count,
            total_read_time,
            total_append_time,
            append_start.elapsed()
        );

        let finish_start = Instant::now();
        let gz = builder.into_inner()?;
        tracing::debug!("create_archive: builder.into_inner took {:?}", finish_start.elapsed());

        let gz_finish_start = Instant::now();
        let file = gz.finish()?;
        tracing::debug!("create_archive: gz.finish took {:?}", gz_finish_start.elapsed());

        let sync_start = Instant::now();
        safe_sync(&file)?;
        tracing::debug!("create_archive: safe_sync took {:?}", sync_start.elapsed());

        let size = fs::metadata(output_path)?.len();
        tracing::debug!("create_archive: total time {:?}, size {} bytes", start.elapsed(), size);
        Ok(size)
    }

    /// Delete a directory tree, counting deletions.
    fn delete_tree(&self, dir: &Path) -> Result<usize> {
        let mut count = 0;

        // First count and delete files
        self.walk_files(dir, &mut |path| {
            fs::remove_file(path)?;
            count += 1;
            Ok(())
        })?;

        // Then remove directories (have to do multiple passes due to nesting)
        let mut dirs_to_remove: Vec<PathBuf> = Vec::new();
        self.collect_dirs(dir, &mut dirs_to_remove)?;

        // Sort by depth (deepest first)
        dirs_to_remove.sort_by(|a, b| {
            let depth_a = a.components().count();
            let depth_b = b.components().count();
            depth_b.cmp(&depth_a)
        });

        for dir_path in dirs_to_remove {
            if dir_path.exists() {
                fs::remove_dir(&dir_path)?;
            }
        }

        // Remove the root dir
        if dir.exists() {
            fs::remove_dir(dir)?;
        }

        Ok(count)
    }

    /// Collect all directories in a tree.
    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn collect_dirs(&self, dir: &Path, dirs: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path.clone());
                self.collect_dirs(&path, dirs)?;
            }
        }
        Ok(())
    }
}

impl Default for ArchiveExtractionWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for ArchiveExtractionWorkload {
    fn name(&self) -> &'static str {
        "Archive Extraction"
    }

    fn operation(&self) -> OperationType {
        OperationType::ArchiveExtractionWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        if self.use_real_assets {
            params.insert("asset_type".to_string(), "real".to_string());
            params.insert("source".to_string(), "Node.js/ripgrep".to_string());
        } else {
            let total_files = self.num_dirs * self.files_per_dir
                + (self.num_dirs / 5) * self.nested_files_per_subdir;  // Nested files
            params.insert("asset_type".to_string(), "synthetic".to_string());
            params.insert("directories".to_string(), self.num_dirs.to_string());
            params.insert("files_per_dir".to_string(), self.files_per_dir.to_string());
            params.insert("nested_files".to_string(), self.nested_files_per_subdir.to_string());
            params.insert("total_files".to_string(), total_files.to_string());
        }

        params.insert("random_accesses".to_string(), self.random_access_count.to_string());
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point, iteration))?;
        fs::create_dir_all(self.extracted_dir(mount_point, iteration))?;
        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();
        let extracted_dir = self.extracted_dir(mount_point, iteration);

        // Clean up any leftover files from previous runs (e.g., if previous run timed out)
        // Use rm -rf for speed - it's much faster than Rust's recursive implementation through FUSE
        if extracted_dir.exists() {
            let _ = std::process::Command::new("rm")
                .args(["-rf", &extracted_dir.to_string_lossy()])
                .status();
        }
        fs::create_dir_all(&extracted_dir)?;

        // ===== Phase 1: Extract/Create files =====
        let file_count = if self.use_real_assets {
            match self.download_real_asset() {
                Ok(archive_path) => {
                    tracing::debug!("Extracting real archive: {}", archive_path.display());
                    self.extract_archive(&archive_path, &extracted_dir)?
                }
                Err(e) => {
                    tracing::warn!("Failed to get real archive, using synthetic: {}", e);
                    self.generate_synthetic_content(&extracted_dir)?
                }
            }
        } else {
            self.generate_synthetic_content(&extracted_dir)?
        };
        tracing::debug!("Extracted/created {} files", file_count);

        // ===== Phase 2: Verify (traverse and count) =====
        let verified_count = self.count_files(&extracted_dir)?;
        if verified_count != file_count {
            tracing::warn!(
                "File count mismatch: created {} but found {}",
                file_count,
                verified_count
            );
        }

        // ===== Phase 3: Random access reads =====
        {
            let files = self.collect_files(&extracted_dir)?;
            if !files.is_empty() {
                let mut buffer = Vec::new();
                let access_count = self.random_access_count.min(files.len());
                for _ in 0..access_count {
                    let idx = rng.random_range(0..files.len());
                    let path = &files[idx];
                    buffer.clear();
                    let mut file = File::open(path)?;
                    file.read_to_end(&mut buffer)?;
                    std::hint::black_box(&buffer);
                }
            }
        }

        // ===== Phase 4: Re-archive =====
        let output_archive = self.output_archive(mount_point, iteration);
        let archive_size = self.create_archive(&extracted_dir, &output_archive)?;
        tracing::debug!("Created archive: {} bytes", archive_size);

        // ===== Phase 5: Cleanup (delete extracted files) =====
        let deleted_count = self.delete_tree(&extracted_dir)?;
        tracing::debug!("Deleted {} files", deleted_count);

        // Also remove the re-packed archive
        if output_archive.exists() {
            fs::remove_file(&output_archive)?;
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            // Use shell command for faster cleanup - rm is optimized for bulk deletion
            // and avoids the overhead of Rust's recursive implementation through FUSE
            let status = std::process::Command::new("rm")
                .args(["-rf", &workload_dir.to_string_lossy()])
                .status();

            match status {
                Ok(s) if s.success() => {}
                _ => {
                    // Fall back to Rust implementation if rm fails
                    let _ = fs::remove_dir_all(&workload_dir);
                }
            }
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup - archive extraction is destructive
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(ARCHIVE_PHASES)
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
                    phase_name: ARCHIVE_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: ARCHIVE_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();
        let extracted_dir = self.extracted_dir(mount_point, iteration);

        // Clean up any leftover files from previous runs (e.g., if previous run timed out)
        // Use rm -rf for speed - it's much faster than Rust's recursive implementation through FUSE
        if extracted_dir.exists() {
            let _ = std::process::Command::new("rm")
                .args(["-rf", &extracted_dir.to_string_lossy()])
                .status();
        }
        fs::create_dir_all(&extracted_dir)?;

        // ===== Phase 1: Extract/Create files =====
        report(0, None, None);
        let file_count = if self.use_real_assets {
            match self.download_real_asset() {
                Ok(archive_path) => {
                    tracing::debug!("Extracting real archive: {}", archive_path.display());
                    self.extract_archive(&archive_path, &extracted_dir)?
                }
                Err(e) => {
                    tracing::warn!("Failed to get real archive, using synthetic: {}", e);
                    self.generate_synthetic_content(&extracted_dir)?
                }
            }
        } else {
            self.generate_synthetic_content(&extracted_dir)?
        };
        tracing::debug!("Extracted/created {} files", file_count);
        report(0, Some(file_count), Some(file_count));

        // ===== Phase 2: Verify (traverse and count) =====
        report(1, Some(0), Some(file_count));
        let verified_count = self.count_files(&extracted_dir)?;
        if verified_count != file_count {
            tracing::warn!(
                "File count mismatch: created {} but found {}",
                file_count,
                verified_count
            );
        }
        report(1, Some(verified_count), Some(file_count));

        // ===== Phase 3: Random access reads =====
        let files = self.collect_files(&extracted_dir)?;
        let access_count = self.random_access_count.min(files.len());
        report(2, Some(0), Some(access_count));
        if !files.is_empty() {
            let mut buffer = Vec::new();
            for i in 0..access_count {
                let idx = rng.random_range(0..files.len());
                let path = &files[idx];
                buffer.clear();
                let mut file = File::open(path)?;
                file.read_to_end(&mut buffer)?;
                std::hint::black_box(&buffer);
                if i % 10 == 0 || i == access_count - 1 {
                    report(2, Some(i + 1), Some(access_count));
                }
            }
        }

        // ===== Phase 4: Re-archive =====
        report(3, None, None);
        let output_archive = self.output_archive(mount_point, iteration);
        let archive_size = self.create_archive(&extracted_dir, &output_archive)?;
        tracing::debug!("Created archive: {} bytes", archive_size);
        report(3, Some(1), Some(1));

        // ===== Phase 5: Cleanup (delete extracted files) =====
        report(4, Some(0), Some(file_count));
        let deleted_count = self.delete_tree(&extracted_dir)?;
        tracing::debug!("Deleted {} files", deleted_count);
        report(4, Some(deleted_count), Some(file_count));

        // Also remove the re-packed archive
        if output_archive.exists() {
            fs::remove_file(&output_archive)?;
        }

        Ok(start.elapsed())
    }
}
