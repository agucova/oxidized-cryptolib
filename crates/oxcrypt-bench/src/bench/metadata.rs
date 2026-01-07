//! Metadata operation benchmarks.

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::Result;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Directory listing benchmark.
pub struct DirectoryListingBenchmark {
    num_files: usize,
    include_stat: bool,
}

impl DirectoryListingBenchmark {
    /// Create a new directory listing benchmark.
    pub fn new(num_files: usize) -> Self {
        Self {
            num_files,
            include_stat: true,
        }
    }

    /// Get the test directory path.
    fn test_dir_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_readdir_{}_iter{}", self.num_files, iteration))
    }
}

impl Benchmark for DirectoryListingBenchmark {
    fn name(&self) -> &'static str {
        "Directory Listing"
    }

    fn operation(&self) -> OperationType {
        OperationType::DirectoryListing
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("num_files".to_string(), format!("{}", self.num_files));
        params.insert("include_stat".to_string(), self.include_stat.to_string());
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Create directory
        let start = Instant::now();
        fs::create_dir_all(&dir_path)?;
        tracing::debug!("Created directory in {:?}", start.elapsed());

        // Create files
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let file_start = Instant::now();
        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("file_{i:05}.txt"));
            let iter_start = Instant::now();
            let mut file = File::create(&file_path)?;

            // Small content (1KB)
            let mut content = vec![0u8; 1024];
            rng.fill_bytes(&mut content);
            file.write_all(&content)?;

            // Log every 100 files or if any single file takes > 100ms
            let iter_elapsed = iter_start.elapsed();
            if i % 100 == 0 || iter_elapsed > Duration::from_millis(100) {
                tracing::debug!(
                    "File {}/{}: {:?} (total: {:?})",
                    i + 1, self.num_files, iter_elapsed, file_start.elapsed()
                );
            }
        }
        #[allow(clippy::cast_possible_truncation)] // num_files is bounded by benchmarks
        let avg_time_per_file = file_start.elapsed() / u32::try_from(self.num_files).unwrap_or(1);
        tracing::info!(
            "Created {} files in {:?} ({:?}/file avg)",
            self.num_files,
            file_start.elapsed(),
            avg_time_per_file
        );

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        let start = Instant::now();

        let mut count = 0;
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip macOS AppleDouble/resource fork files (._*)
            // These are automatically created for extended attributes
            if name.starts_with("._") {
                continue;
            }

            std::hint::black_box(entry.file_name());

            if self.include_stat {
                std::hint::black_box(entry.metadata()?);
            }

            count += 1;
        }

        let elapsed = start.elapsed();

        // Verify count
        if count != self.num_files {
            anyhow::bail!("Listed {} files, expected {}", count, self.num_files);
        }

        Ok(elapsed)
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);
        if dir_path.exists() {
            // Remove all entries first (including hidden files like .DS_Store and subdirectories)
            if let Ok(entries) = fs::read_dir(&dir_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() || path.is_symlink() {
                        let _ = fs::remove_file(&path);
                    } else if path.is_dir() {
                        let _ = fs::remove_dir_all(&path);
                    }
                }
            }
            // Brief pause to let filesystem sync
            std::thread::sleep(Duration::from_millis(50));
            // Now remove the directory
            fs::remove_dir_all(&dir_path).or_else(|_| {
                // If remove_dir_all fails, try removing just the directory
                fs::remove_dir(&dir_path)
            })?;
        }
        Ok(())
    }
}

/// Metadata (stat) benchmark.
pub struct MetadataBenchmark {
    num_files: usize,
    iterations: usize,
}

impl MetadataBenchmark {
    /// Create a new metadata benchmark.
    pub fn new(num_files: usize) -> Self {
        Self {
            num_files,
            iterations: 100, // Stat each file multiple times
        }
    }

    /// Get the test directory path.
    fn test_dir_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_stat_{}_iter{}", self.num_files, iteration))
    }
}

impl Benchmark for MetadataBenchmark {
    fn name(&self) -> &'static str {
        "Metadata"
    }

    fn operation(&self) -> OperationType {
        OperationType::Metadata
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("num_files".to_string(), format!("{}", self.num_files));
        params.insert("iterations".to_string(), format!("{}", self.iterations));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Create directory
        fs::create_dir_all(&dir_path)?;

        // Create files
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("file_{i:05}.txt"));
            let mut file = File::create(&file_path)?;

            // Variable size content
            let size = rng.random_range(1024..10240);
            let mut content = vec![0u8; size];
            rng.fill_bytes(&mut content);
            file.write_all(&content)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Collect file paths first
        let file_paths: Vec<PathBuf> = (0..self.num_files)
            .map(|i| dir_path.join(format!("file_{i:05}.txt")))
            .collect();

        let start = Instant::now();

        for _ in 0..self.iterations {
            for path in &file_paths {
                std::hint::black_box(fs::metadata(path)?);
            }
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);
        if dir_path.exists() {
            // Remove all files first (including hidden files like .DS_Store)
            if let Ok(entries) = fs::read_dir(&dir_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
            // Now remove the directory
            fs::remove_dir_all(&dir_path).or_else(|_| {
                fs::remove_dir(&dir_path)
            })?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        // More warmup for cache-sensitive operations
        5
    }
}
