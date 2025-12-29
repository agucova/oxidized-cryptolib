//! Write operation benchmarks.

use crate::bench::Benchmark;
use crate::config::{FileSize, OperationType};
use anyhow::Result;
use oxidized_mount_common::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Sequential write benchmark.
pub struct SequentialWriteBenchmark {
    file_size: FileSize,
    buffer_size: usize,
    include_fsync: bool,
}

impl SequentialWriteBenchmark {
    /// Create a new sequential write benchmark.
    pub fn new(file_size: FileSize) -> Self {
        Self {
            file_size,
            buffer_size: 64 * 1024, // 64KB buffer
            include_fsync: true,
        }
    }

    /// Get the test file path.
    fn test_file_path(&self, mount_point: &Path) -> PathBuf {
        mount_point.join(format!("bench_seq_write_{}.bin", self.file_size.name()))
    }
}

impl Benchmark for SequentialWriteBenchmark {
    fn name(&self) -> &str {
        "Sequential Write"
    }

    fn operation(&self) -> OperationType {
        OperationType::SequentialWrite
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("file_size".to_string(), self.file_size.name().to_string());
        params.insert("buffer_size".to_string(), format!("{}KB", self.buffer_size / 1024));
        params.insert("fsync".to_string(), self.include_fsync.to_string());
        params
    }

    fn setup(&self, _mount_point: &Path) -> Result<()> {
        // No setup needed - we create the file during the benchmark
        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let file_path = self.test_file_path(mount_point);

        // Generate deterministic content
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut buffer = vec![0u8; self.buffer_size];
        rng.fill_bytes(&mut buffer);

        let start = Instant::now();

        let mut file = File::create(&file_path)?;
        let mut written = 0;

        while written < self.file_size.bytes() {
            let to_write = std::cmp::min(self.buffer_size, self.file_size.bytes() - written);
            file.write_all(&buffer[..to_write])?;
            written += to_write;
        }

        if self.include_fsync {
            safe_sync(&file)?;
        }

        let elapsed = start.elapsed();

        // Clean up the file we just created
        drop(file);
        std::fs::remove_file(&file_path)?;

        Ok(elapsed)
    }

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let file_path = self.test_file_path(mount_point);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }
        Ok(())
    }
}

/// Random write benchmark.
pub struct RandomWriteBenchmark {
    file_size: FileSize,
    chunk_size: usize,
    num_writes: usize,
    seed: u64,
}

impl RandomWriteBenchmark {
    /// Create a new random write benchmark.
    pub fn new(file_size: FileSize) -> Self {
        Self {
            file_size,
            chunk_size: 4096, // 4KB chunks
            num_writes: 50,   // 50 random writes
            seed: 54321,
        }
    }

    /// Get the test file path.
    fn test_file_path(&self, mount_point: &Path) -> PathBuf {
        mount_point.join(format!("bench_rand_write_{}.bin", self.file_size.name()))
    }
}

impl Benchmark for RandomWriteBenchmark {
    fn name(&self) -> &str {
        "Random Write"
    }

    fn operation(&self) -> OperationType {
        OperationType::RandomWrite
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("file_size".to_string(), self.file_size.name().to_string());
        params.insert("chunk_size".to_string(), format!("{}B", self.chunk_size));
        params.insert("num_writes".to_string(), format!("{}", self.num_writes));
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let file_path = self.test_file_path(mount_point);

        // Create a file with initial content
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut content = vec![0u8; self.file_size.bytes()];
        rng.fill_bytes(&mut content);

        let mut file = File::create(&file_path)?;
        file.write_all(&content)?;
        safe_sync(&file)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let file_path = self.test_file_path(mount_point);
        let max_offset = self.file_size.bytes().saturating_sub(self.chunk_size);

        // Generate random write data and offsets
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut buffer = vec![0u8; self.chunk_size];
        rng.fill_bytes(&mut buffer);

        let offsets: Vec<u64> = (0..self.num_writes)
            .map(|_| rng.gen_range(0..=max_offset) as u64)
            .collect();

        let start = Instant::now();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)?;

        for offset in offsets {
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&buffer)?;
        }

        safe_sync(&file)?;

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let file_path = self.test_file_path(mount_point);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }
        Ok(())
    }
}
