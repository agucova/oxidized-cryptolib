//! File lifecycle (creation/deletion) benchmarks.

use crate::bench::Benchmark;
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

/// File creation benchmark.
pub struct FileCreationBenchmark {
    num_files: usize,
    file_size: usize,
}

impl FileCreationBenchmark {
    /// Create a new file creation benchmark.
    pub fn new(num_files: usize) -> Self {
        Self {
            num_files,
            file_size: 1024, // 1KB files
        }
    }

    /// Get the test directory path.
    fn test_dir_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_create_{}_iter{}", self.num_files, iteration))
    }
}

impl Benchmark for FileCreationBenchmark {
    fn name(&self) -> &'static str {
        "File Creation"
    }

    fn operation(&self) -> OperationType {
        OperationType::FileCreation
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("num_files".to_string(), format!("{}", self.num_files));
        params.insert("file_size".to_string(), format!("{}B", self.file_size));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Ensure directory exists and is empty
        if dir_path.exists() {
            fs::remove_dir_all(&dir_path)?;
        }
        fs::create_dir_all(&dir_path)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Prepare content
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let mut content = vec![0u8; self.file_size];
        rng.fill_bytes(&mut content);

        let start = Instant::now();

        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("created_{i:05}.txt"));
            let mut file = File::create(&file_path)?;
            file.write_all(&content)?;
            // Don't fsync each file - too slow
        }

        // Single sync at the end
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(dir) = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(&dir_path)
            {
                let _ = safe_sync(&dir);
            }
        }

        let elapsed = start.elapsed();

        // Clean up created files
        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("created_{i:05}.txt"));
            fs::remove_file(&file_path)?;
        }

        Ok(elapsed)
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
            fs::remove_dir_all(&dir_path).or_else(|_| fs::remove_dir(&dir_path))?;
        }
        Ok(())
    }
}

/// File deletion benchmark.
pub struct FileDeletionBenchmark {
    num_files: usize,
    file_size: usize,
}

impl FileDeletionBenchmark {
    /// Create a new file deletion benchmark.
    pub fn new(num_files: usize) -> Self {
        Self {
            num_files,
            file_size: 1024, // 1KB files
        }
    }

    /// Get the test directory path.
    fn test_dir_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_delete_{}_iter{}", self.num_files, iteration))
    }
}

impl Benchmark for FileDeletionBenchmark {
    fn name(&self) -> &'static str {
        "File Deletion"
    }

    fn operation(&self) -> OperationType {
        OperationType::FileDeletion
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("num_files".to_string(), format!("{}", self.num_files));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Create directory and files
        if dir_path.exists() {
            fs::remove_dir_all(&dir_path)?;
        }
        fs::create_dir_all(&dir_path)?;

        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let mut content = vec![0u8; self.file_size];
        rng.fill_bytes(&mut content);

        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("to_delete_{i:05}.txt"));
            let mut file = File::create(&file_path)?;
            file.write_all(&content)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let dir_path = self.test_dir_path(mount_point, iteration);

        // Recreate files before each iteration (not timed)
        // This ensures each iteration has a fresh set of files to delete
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let mut content = vec![0u8; self.file_size];
        rng.fill_bytes(&mut content);

        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("to_delete_{i:05}.txt"));
            let mut file = File::create(&file_path)?;
            file.write_all(&content)?;
        }

        // Now measure only the deletion time
        let start = Instant::now();

        for i in 0..self.num_files {
            let file_path = dir_path.join(format!("to_delete_{i:05}.txt"));
            fs::remove_file(&file_path)?;
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
            fs::remove_dir_all(&dir_path).or_else(|_| fs::remove_dir(&dir_path))?;
        }
        Ok(())
    }
}
