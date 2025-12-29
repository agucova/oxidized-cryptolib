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

use crate::assets::{AssetDownloader, manifest};
use crate::bench::Benchmark;
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

// Synthetic archive parameters
const SYNTHETIC_NUM_DIRS: usize = 50;
const SYNTHETIC_FILES_PER_DIR: usize = 20;
const SYNTHETIC_FILE_SIZE_MIN: usize = 1024;       // 1KB
const SYNTHETIC_FILE_SIZE_MAX: usize = 64 * 1024;  // 64KB
const RANDOM_ACCESS_COUNT: usize = 100;

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
    seed: u64,
    /// Whether to use real downloaded archive assets.
    use_real_assets: bool,
}

impl ArchiveExtractionWorkload {
    /// Create a new archive extraction workload with synthetic content.
    pub fn new() -> Self {
        Self {
            seed: 0xA2C_41FE,
            use_real_assets: false,
        }
    }

    /// Create a new archive extraction workload with real downloaded assets.
    pub fn with_real_assets() -> Self {
        Self {
            seed: 0xA2C_41FE,
            use_real_assets: true,
        }
    }

    /// Set whether to use real assets.
    pub fn set_real_assets(&mut self, use_real: bool) {
        self.use_real_assets = use_real;
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_archive_workload")
    }

    fn extracted_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("extracted")
    }

    fn output_archive(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("repacked.tar.gz")
    }

    /// Download real archive asset and return the path.
    fn download_real_asset(&self) -> Result<PathBuf> {
        let downloader = AssetDownloader::new()?;

        // Try Node.js source first (smaller, faster)
        match downloader.ensure(&manifest::ARCHIVE_NODEJS) {
            Ok(path) => return Ok(path),
            Err(e) => {
                tracing::warn!("Failed to download Node.js archive: {}", e);
            }
        }

        // Fall back to ripgrep (even smaller)
        match downloader.ensure(&manifest::GIT_RIPGREP) {
            Ok(path) => return Ok(path),
            Err(e) => {
                tracing::warn!("Failed to download ripgrep archive: {}", e);
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

        // Unpack to destination
        archive.unpack(dest_dir)
            .with_context(|| format!("Failed to extract to {}", dest_dir.display()))?;

        // Count extracted files
        let count = self.count_files(dest_dir)?;
        Ok(count)
    }

    /// Generate synthetic archive content directly to destination.
    fn generate_synthetic_content(&self, dest_dir: &Path) -> Result<usize> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut file_count = 0;

        for dir_num in 0..SYNTHETIC_NUM_DIRS {
            let dir_name = format!("dir_{:03}", dir_num);
            let dir_path = dest_dir.join(&dir_name);
            fs::create_dir_all(&dir_path)?;

            // Create some subdirectories
            if dir_num % 5 == 0 {
                let subdir = dir_path.join("subdir");
                fs::create_dir_all(&subdir)?;

                for file_num in 0..5 {
                    let size = rng.random_range(SYNTHETIC_FILE_SIZE_MIN..SYNTHETIC_FILE_SIZE_MAX);
                    let filename = format!("nested_{:03}.txt", file_num);
                    let file_path = subdir.join(&filename);
                    self.write_random_file(&mut rng, &file_path, size)?;
                    file_count += 1;
                }
            }

            for file_num in 0..SYNTHETIC_FILES_PER_DIR {
                let size = rng.random_range(SYNTHETIC_FILE_SIZE_MIN..SYNTHETIC_FILE_SIZE_MAX);
                let ext = match file_num % 4 {
                    0 => "txt",
                    1 => "c",
                    2 => "h",
                    _ => "js",
                };
                let filename = format!("file_{:03}.{}", file_num, ext);
                let file_path = dir_path.join(&filename);
                self.write_random_file(&mut rng, &file_path, size)?;
                file_count += 1;
            }
        }

        Ok(file_count)
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
    fn create_archive(&self, source_dir: &Path, output_path: &Path) -> Result<u64> {
        let file = File::create(output_path)?;
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(gz);

        // Add all files from source directory
        builder.append_dir_all(".", source_dir)?;
        let gz = builder.into_inner()?;
        let file = gz.finish()?;
        safe_sync(&file)?;

        let size = fs::metadata(output_path)?.len();
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
        Self::new()
    }
}

impl Benchmark for ArchiveExtractionWorkload {
    fn name(&self) -> &str {
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
            let total_files = SYNTHETIC_NUM_DIRS * SYNTHETIC_FILES_PER_DIR
                + (SYNTHETIC_NUM_DIRS / 5) * 5;  // Nested files
            params.insert("asset_type".to_string(), "synthetic".to_string());
            params.insert("directories".to_string(), SYNTHETIC_NUM_DIRS.to_string());
            params.insert("total_files".to_string(), total_files.to_string());
        }

        params.insert("random_accesses".to_string(), RANDOM_ACCESS_COUNT.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point))?;
        fs::create_dir_all(self.extracted_dir(mount_point))?;
        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();
        let extracted_dir = self.extracted_dir(mount_point);

        // ===== Phase 1: Extract/Create files =====
        let file_count = if self.use_real_assets {
            match self.download_real_asset() {
                Ok(archive_path) => {
                    tracing::info!("Extracting real archive: {}", archive_path.display());
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
                for _ in 0..RANDOM_ACCESS_COUNT {
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
        let output_archive = self.output_archive(mount_point);
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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup - archive extraction is destructive
    }
}
